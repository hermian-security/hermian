//! The long-running daemon: wires event sources into the engine and alerts
//! into the notifier.

use std::collections::{HashMap, VecDeque};
use std::fs;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::Utc;
use hermian_core::alert::Finding;
use hermian_core::{Alert, Baseline, Config, DetectionId, Engine, Event, ExecEvent, Severity};
use tokio::sync::mpsc;

use crate::{
    actions, audit, auditnetlink, authlog, config, configdiff, ebpf, fallback, health, heartbeat,
    isolate, notify, pamsock, paths, procsrc, retention, selfprotect, sessions, sshkeys, status,
    tgbot, watchers,
};

/// Persisted across restarts so reference ids never repeat within a day.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct EngineState {
    ref_day: String,
    ref_seq: u32,
    #[serde(default)]
    counters: Option<hermian_core::Counters>,
    /// "Remind me in 7 days" on the root-password warning.
    #[serde(default)]
    root_warning_snoozed_until: Option<chrono::DateTime<Utc>>,
}

fn load_engine_state() -> Option<EngineState> {
    let text = fs::read_to_string(paths::engine_state_file()).ok()?;
    serde_json::from_str(&text).ok()
}

fn save_engine_state(engine: &Engine) {
    let (day, seq) = engine.refs.state();
    let st = EngineState {
        ref_day: day.to_string(),
        ref_seq: seq,
        counters: Some(engine.counters.clone()),
        root_warning_snoozed_until: engine.root_warning_snoozed_until,
    };
    if let Ok(text) = serde_json::to_string(&st) {
        let _ = config::write_secure(&paths::engine_state_file(), &text);
    }
}

pub fn run() -> Result<()> {
    config::require_root()?;
    // Not dumpable: no core dumps with alert data in them, and other users'
    // processes can't ptrace it or read its memory through /proc.
    // SAFETY: plain prctl with integer arguments.
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
    let cfg = config::load_config()?;
    let allowlist = cfg.allowlist.clone();
    let host = if cfg.general.hostname.is_empty() {
        procsrc::hostname()
    } else {
        cfg.general.hostname.clone()
    };
    // No baseline.json (deleted to start over, or started without `hermian
    // enable`): learn afresh. Loading it as Default used to mean "disabled",
    // which silently switched every novelty rule off.
    let mut baseline = if paths::baseline_file().exists() {
        config::load_baseline()?
    } else {
        let fresh = Baseline::new(
            cfg.baseline.enabled,
            cfg.baseline.duration_hours,
            Utc::now(),
        );
        config::save_baseline(&fresh)?;
        fresh
    };
    if cfg.baseline.enabled && !baseline.complete && baseline.started_at.is_none() {
        baseline = Baseline::new(true, cfg.baseline.duration_hours, Utc::now());
        config::save_baseline(&baseline)?;
    }

    notify::ensure_log_dir()?;
    fs::create_dir_all(paths::state_dir())?;
    fs::create_dir_all(paths::run_dir())?;

    // The dead-man switch watches the heartbeat; the marker tells the next
    // start whether this run stopped cleanly, and the watchdog leaves a note
    // when it had to restart the previous one.
    let unclean_prev = heartbeat::start(&paths::run_marker_file());
    let watchdog_note = heartbeat::take_restart_note(&paths::watchdog_note_file());
    let panic_note = heartbeat::take_restart_note(&paths::panic_note_file());
    heartbeat::install_panic_note(paths::panic_note_file());

    let mut engine = Engine::new(cfg.clone(), allowlist, baseline, host);
    engine.self_pid = std::process::id();
    if let Some(st) = load_engine_state() {
        engine.restore(Utc::now(), &st.ref_day, st.ref_seq, st.counters);
        engine.root_warning_snoozed_until = st.root_warning_snoozed_until;
    }
    if let Some(on) = sessions::root_password_login() {
        engine.set_root_password_login(on);
    }
    engine.set_user_names(procsrc::load_user_names());
    for path in ["/etc/passwd", "/etc/group"] {
        if let Some(content) = procsrc::read_file(path) {
            engine.seed_file_snapshot(path, content);
        }
    }
    // Seed the full process tree so ancestry is known for processes that were
    // already running when we started (sshd sessions, web servers...).
    for p in procsrc::scan_processes() {
        engine.tree.upsert(p);
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .context("failed to build tokio runtime")?;
    let cause = unclean_prev.map(|prev| {
        (
            prev,
            unclean_cause(panic_note.as_deref(), watchdog_note.as_deref()),
        )
    });
    let result = rt.block_on(async_main(cfg, engine, cause));
    // Don't hang on a blocking-pool thread (the eBPF converter, a delivery in
    // flight) once main is done.
    rt.shutdown_timeout(Duration::from_secs(2));
    result
}

struct Sources {
    ebpf: Option<Vec<&'static str>>,
    audit: bool,
    auth: authlog::AuthSource,
    pam: bool,
    watch_health: Option<watchers::SharedWatchHealth>,
}

/// Why the previous run stopped uncleanly, as `(sentence, fact label)`. A
/// panic note is the most specific; the watchdog's note comes next.
fn unclean_cause(panic: Option<&str>, watchdog: Option<&str>) -> (String, &'static str) {
    match (panic, watchdog) {
        (Some(p), _) => (format!("It crashed ({})", p), "Crash"),
        (None, Some(note)) => (
            format!(
                "The watchdog restarted it after it stopped responding ({})",
                note
            ),
            "Watchdog restart",
        ),
        (None, None) => (
            "The process died without cleanup (SIGKILL, OOM kill, or power loss).".to_string(),
            "Unexpected stop",
        ),
    }
}

async fn async_main(
    initial_cfg: Config,
    mut engine: Engine,
    unclean: Option<(String, (String, &'static str))>,
) -> Result<()> {
    let initial_notify = status::read_state()
        .map(|s| notify::NotifyState {
            last_delivery: s.last_delivery,
            last_delivery_note: s.last_delivery_note,
            failures: s.failures,
            pending: 0,
            last_error: String::new(),
            ..Default::default()
        })
        .unwrap_or_default();
    let notifier =
        notify::Notifier::spawn(initial_cfg.notifications.clone(), initial_notify.clone());

    // --- Self-protection -------------------------------------------------
    let integrity = selfprotect::verify_at_startup();
    if !integrity.binary_ok {
        emit_self(
            &notifier,
            self_alert(
            &mut engine,
            Severity::Critical,
            "Hermian binary modified",
            "The running Hermian binary does not match the hash recorded at install time.",
            "The security daemon itself may have been replaced or patched. Nothing it reports can be trusted until this is resolved.",
            &[
                "Reinstall Hermian from a signed package or verified tarball.",
                "Compare the binary hash with the release checksum.",
                "Treat the host as potentially compromised.",
            ],
            &[("Binary hash", &integrity.binary_hash)],
            "selfprotect|binary",
            ),
        );
    }
    if !integrity.config_ok {
        emit_self(
            &notifier,
            self_alert(
                &mut engine,
                Severity::Critical,
                "Hermian configuration modified while stopped",
                "The configuration file changed while the daemon was not running.",
                "Configuration changes can disable detections, widen allowlists or redirect alerts.",
                &[
                    "Review /etc/hermian/config.toml against your last known version.",
                    "Restore it if the change was not yours.",
                ],
                &[("Config hash", &integrity.config_hash)],
                "selfprotect|config",
            ),
        );
    }
    let missing: Vec<&str> = [
        (integrity.binary_record_missing, "binary"),
        (integrity.config_record_missing, "configuration"),
    ]
    .iter()
    .filter(|(m, _)| *m)
    .map(|(_, n)| *n)
    .collect();
    if !missing.is_empty() {
        emit_self(
            &notifier,
            self_alert(
                &mut engine,
                Severity::High,
                "Hermian integrity record missing",
                &format!(
                    "The stored hash for the {} was missing at startup, so it couldn't be checked. The current value has been recorded.",
                    missing.join(" and ")
                ),
                "'hermian enable' records these hashes before the first start. A missing one means it was deleted (deleting it and swapping the binary would otherwise go unnoticed) or an upgrade skipped 'hermian enable'.",
                &[
                    "If you just upgraded from a tarball without 'hermian enable', re-run it.",
                    "Otherwise verify the binary against the release checksums and review the config.",
                ],
                &[
                    ("Binary hash", &integrity.binary_hash),
                    ("Config hash", &integrity.config_hash),
                ],
                "selfprotect|record-missing",
            ),
        );
    }

    // --- Unclean restart ------------------------------------------------
    if let Some((prev, (cause, cause_label))) = unclean {
        emit_self(
            &notifier,
            self_alert(
                &mut engine,
                Severity::High,
                "Hermian restarted after an unclean shutdown",
                &format!(
                    "The previous run ({}) did not stop through systemd. {}. Activity between its last heartbeat and this start was not monitored.",
                    prev.trim(),
                    cause
                ),
                "A clean stop sends a 'Hermian is stopping' notice; a crash or kill cannot. Killing the security daemon is a cheap way to get an unmonitored window, so leftovers are reported rather than silently overwritten.",
                &[
                    "Check what happened right before: journalctl -u hermian -n 100.",
                    "If this wasn't the watchdog reacting to a hang, treat it as suspicious.",
                ],
                &[("Previous run", prev.trim()), (cause_label, &cause)],
                "selfprotect|unclean",
            ),
        );
    }

    // --- Event sources ---------------------------------------------------
    let (event_tx, mut event_rx) = mpsc::channel::<Event>(16384);
    let shutdown = Arc::new(AtomicBool::new(false));
    let mut sources = Sources {
        ebpf: None,
        audit: false,
        auth: authlog::AuthSource::None,
        pam: pamsock::pam_active(),
        watch_health: None,
    };
    let mut _ebpf_runtime: Option<ebpf::EbpfRuntime> = None;
    let mut audit_thread: Option<std::thread::JoinHandle<()>> = None;

    if procsrc::kernel_supports_ebpf() {
        let (raw_tx, raw_rx) = mpsc::channel::<ebpf::RawEvent>(16384);
        match ebpf::load_and_attach(raw_tx) {
            Ok(runtime) => {
                sources.ebpf = Some(runtime.attached.clone());
                // chmod reported as it happens: the setuid sweep can slow down.
                if ["sys_enter_fchmodat", "sys_enter_fchmod"]
                    .iter()
                    .all(|t| runtime.attached.contains(t))
                {
                    fallback::PRIV_HOOKED.store(true, Ordering::Relaxed);
                }
                _ebpf_runtime = Some(runtime);
                // Several /proc reads per event: on a blocking thread, not
                // one of the runtime's two workers, so an exec storm can't
                // stall the event loop (and back up into ring loss).
                let tx = event_tx.clone();
                tokio::task::spawn_blocking(move || convert_ebpf_events(raw_rx, tx));
            }
            Err(e) => {
                // Verifier output can be thousands of lines; keep the first.
                let full = format!("{:#}", e);
                let first = full.lines().next().unwrap_or("").trim_end_matches(':');
                log_daemon(
                    Severity::Low,
                    &format!(
                        "eBPF unavailable ({}); using /proc and audit fallback",
                        first
                    ),
                );
            }
        }
    } else {
        log_daemon(
            Severity::Low,
            &format!(
                "kernel {} is below 5.8; running with reduced coverage (/proc polling, audit)",
                procsrc::kernel_release()
            ),
        );
    }
    if sources.ebpf.is_none() {
        fallback::spawn_proc_poller(event_tx.clone(), shutdown.clone())?;
        if auditnetlink::audit_usable() {
            match auditnetlink::spawn_audit_reader(event_tx.clone(), shutdown.clone()) {
                Ok(handle) => {
                    sources.audit = true;
                    audit_thread = Some(handle);
                }
                Err(e) => log_daemon(Severity::Low, &format!("audit source unavailable: {:#}", e)),
            }
        } else {
            log_daemon(
                Severity::Info,
                "auditd is running; leaving the audit socket to it",
            );
        }
    }

    sources.watch_health = Some(watchers::spawn_watchers(
        event_tx.clone(),
        paths::config_path(),
        shutdown.clone(),
    )?);
    match authlog::spawn_authlog_tailer(event_tx.clone(), shutdown.clone()) {
        Ok(src) => sources.auth = src,
        Err(e) => log_daemon(
            Severity::Low,
            &format!("auth log source unavailable: {:#}", e),
        ),
    }
    // The PAM module reports an "attempt" for every authentication, before
    // the outcome is known. With a log source already reporting failures,
    // counting attempts too would double every failure and count successful
    // logins as failures, so they're only used when there's no log source.
    let pam_attempts = sources.auth == authlog::AuthSource::None;
    if let Err(e) = pamsock::spawn_pam_listener(event_tx.clone(), shutdown.clone(), pam_attempts) {
        log_daemon(Severity::Low, &format!("PAM socket unavailable: {:#}", e));
    }
    if sources.auth == authlog::AuthSource::None && !sources.pam {
        log_daemon(
            Severity::Low,
            "no SSH authentication source (no auth.log, no journalctl, no PAM module); D2 auth coverage reduced",
        );
    }
    let (listener_close_tx, mut listener_close_rx) = mpsc::channel::<fallback::ListenerKey>(256);
    fallback::spawn_listener_poller(event_tx.clone(), listener_close_tx, shutdown.clone())?;
    fallback::spawn_suid_sweeper(event_tx.clone(), shutdown.clone())?;

    // --- Telegram response buttons ---------------------------------------
    // The poller follows config reloads through this shared copy; it idles
    // while actions are off.
    let tg_cfg = Arc::new(std::sync::Mutex::new(
        initial_cfg.notifications.telegram.clone(),
    ));
    let (action_tx, mut action_rx) = mpsc::channel::<tgbot::ActionRequest>(64);
    tgbot::spawn_poller(tg_cfg.clone(), action_tx, shutdown.clone())?;

    // --- Signals ---------------------------------------------------------
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sighup = signal(SignalKind::hangup())?;
    let mut sigusr2 = signal(SignalKind::user_defined2())?;

    let mut next_sshd_audit = std::time::Instant::now();
    let mut ticker = tokio::time::interval(heartbeat::INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let mut cpu_ring: VecDeque<f64> = VecDeque::new();
    let mut last_cpu = procsrc::self_cpu_sample();
    let mut first_tick = true;
    let mut current_cfg = initial_cfg;
    // Hash of the config actually in effect. Reloads compare against this,
    // not config.sha256: writing that file first, then the config, used to
    // make the change skip both the reload and its alert.
    let mut applied_hash = integrity.config_hash.clone();
    let mut dropped_seen = health::snapshot();
    let mut compat_seen: HashMap<String, bool> = HashMap::new();
    // First pass shortly after start, then hourly.
    let mut next_retention = std::time::Instant::now() + Duration::from_secs(60);
    let mut hotplug_reported: Vec<u32> = Vec::new();
    let started_at = Utc::now();
    let config_path = paths::config_path();

    if initial_notify.last_delivery.is_none() {
        emit_self(
            &notifier,
            self_alert(
                &mut engine,
                Severity::Info,
                "Hermian is active",
                "This is the one-time confirmation sent when Hermian starts for the first time on this host.",
                "It proves the alert path works end to end. You will not hear from Hermian again unless something needs your attention.",
                &["Run 'hermian status' at any time to confirm coverage."],
                &[],
                "selftest|install",
            ),
        );
    }

    // Start-up audit. An intrusion already in place when Hermian starts is
    // invisible to the rules until it acts, and the baseline would learn its
    // routine as normal: on a failed audit, learning stops and novelty is
    // judged from now on, against nothing learned on this host.
    // Hermian checks itself first: injected code would make everything
    // below untrustworthy. Then again every ten minutes (cheap when the
    // daemon's mappings haven't changed).
    let mut self_maps: Vec<String> = Vec::new();
    run_self_check(&mut engine, &notifier, &mut self_maps);

    let signs = audit::run_audit();
    if signs.iter().any(|s| s.severity >= Severity::High) {
        let learning = engine.baseline.enabled && !engine.baseline.complete;
        if learning {
            engine.baseline = Baseline::judging_from(Utc::now(), engine.baseline.duration_hours);
            let _ = config::save_baseline(&engine.baseline);
        }
        let note = learning.then_some(
            "learning stopped, so nothing on this host is learned as normal; new sources, \
             destinations and programs are judged from now on",
        );
        if let Some(f) = hermian_core::audit::finding(&signs, note) {
            emit_self(&notifier, engine.alert_from(f, Utc::now()));
        }
        log_daemon(
            Severity::High,
            &format!(
                "start-up audit: {} sign(s) of an earlier intrusion (hermian audit)",
                signs.len()
            ),
        );
    }

    write_status_snapshot(
        &engine,
        &notifier,
        &sources,
        &current_cfg,
        &integrity,
        &cpu_ring,
        started_at,
    );
    // Start the heartbeat before the first tick so the watchdog doesn't see
    // a "never written" daemon during a slow startup.
    let _ = heartbeat::touch(&paths::heartbeat_file());
    log_daemon(
        Severity::Info,
        &format!("Hermian {} started", hermian_core::VERSION),
    );

    loop {
        tokio::select! {
            maybe = event_rx.recv() => {
                let Some(ev) = maybe else { break };
                if let Event::File(f) = &ev {
                    if std::path::Path::new(&f.path) == config_path {
                        reload_config(&mut engine, &notifier, &mut current_cfg, &mut applied_hash, "file change");
                        sync_tg_cfg(&tg_cfg, &current_cfg);
                        continue;
                    }
                }
                if let (Event::Exec(e), true) = (&ev, sources.ebpf.is_some()) {
                    check_compat_exec(&mut engine, &notifier, &mut compat_seen, e);
                }
                match &ev {
                    Event::Exec(e) => seed_missing_ancestors(&mut engine, e.ppid, e.ts),
                    // A process that forked without exec'ing (or started before
                    // us and never exec'd since) isn't in the tree; without it
                    // a connect or ptrace has no exe or chain, and a forked
                    // child that calls itself "gdb" passed as a debugger.
                    Event::Connect(c) => seed_process(&mut engine, c.pid, c.ts),
                    Event::Ptrace(p) => seed_process(&mut engine, p.pid, p.ts),
                    _ => {}
                }
                for alert in engine.process(ev) {
                    let isolate = alert.auto_isolate_eligible();
                    if alert.severity == Severity::Critical && !isolate
                        && current_cfg.response.auto_isolate
                    {
                        log_daemon(
                            Severity::High,
                            &format!(
                                "auto-isolate skipped for {}: the service in its chain isn't installed in a root-owned location",
                                alert.ref_id
                            ),
                        );
                    }
                    notifier.send(alert);
                    if isolate {
                        isolate::auto_isolate_if_enabled(&current_cfg);
                    }
                }
            }
            Some((proto, addr, port)) = listener_close_rx.recv() => {
                engine.forget_listener(&proto, addr, port);
            }
            Some(req) = action_rx.recv() => {
                handle_action(&mut engine, &notifier, &current_cfg, req);
            }
            _ = ticker.tick() => {
                // The dead-man switch reads this; it must be the first thing
                // a slow tick refreshes.
                let _ = heartbeat::touch(&paths::heartbeat_file());
                let now = Utc::now();
                engine.reap_exited(&procsrc::live_pids(), now);
                for a in engine.tick(now) {
                    notifier.send(a);
                }
                let dropped_now = health::snapshot();
                let grown = health::grown(&dropped_seen, &dropped_now);
                if !grown.is_empty() {
                    report_dropped_events(&mut engine, &notifier, &grown, &dropped_now);
                }
                dropped_seen = dropped_now;
                let unmonitored = ebpf::unmonitored_cpus();
                if !unmonitored.is_empty() && unmonitored != hotplug_reported {
                    report_unmonitored_cpus(&mut engine, &notifier, &unmonitored);
                }
                hotplug_reported = unmonitored;
                if std::time::Instant::now() >= next_retention {
                    next_retention = std::time::Instant::now() + Duration::from_secs(3600);
                    let days = current_cfg.general.alert_retention_days;
                    tokio::task::spawn_blocking(move || retention::run(days));
                    // sshd settings can change any time; recheck hourly.
                    tokio::task::spawn_blocking(sessions::refresh_root_password_login);
                }
                if let Some(on) = sessions::cached_root_password_login() {
                    engine.set_root_password_login(on);
                }
                // Hidden key sources in sshd's effective config: audited at
                // start and every ten minutes, each reported once.
                if std::time::Instant::now() >= next_sshd_audit {
                    next_sshd_audit = std::time::Instant::now() + Duration::from_secs(600);
                    run_self_check(&mut engine, &notifier, &mut self_maps);
                    tokio::task::spawn_blocking(sshkeys::refresh);
                }
                if let Some(sshd_t) = sshkeys::take_fresh() {
                    for a in engine.check_sshd_config(&sshd_t, now) {
                        notifier.send(a);
                    }
                }
                let _ = config::save_baseline(&engine.baseline);
                save_engine_state(&engine);

                let sample = procsrc::self_cpu_sample();
                let dt = sample.1 - last_cpu.1;
                // The first interval includes the startup process scan and eBPF
                // load, which is not representative of steady-state overhead.
                if dt > 0.0 && !first_tick {
                    let dticks = sample.0.saturating_sub(last_cpu.0);
                    let pct = (dticks as f64 / (dt * procsrc::clock_ticks() as f64)) * 100.0;
                    cpu_ring.push_back(pct);
                    while cpu_ring.len() > 120 {
                        cpu_ring.pop_front();
                    }
                }
                first_tick = false;
                last_cpu = sample;
                write_status_snapshot(&engine, &notifier, &sources, &current_cfg, &integrity, &cpu_ring, started_at);
            }
            _ = sigterm.recv() => {
                log_daemon(Severity::Info, "SIGTERM received; shutting down");
                announce_stop(&mut engine, &notifier, "SIGTERM").await;
                break;
            }
            _ = sigint.recv() => {
                announce_stop(&mut engine, &notifier, "SIGINT").await;
                break;
            }
            _ = sighup.recv() => {
                reload_config(&mut engine, &notifier, &mut current_cfg, &mut applied_hash, "SIGHUP");
                sync_tg_cfg(&tg_cfg, &current_cfg);
            }
            _ = sigusr2.recv() => {
                reload_config(&mut engine, &notifier, &mut current_cfg, &mut applied_hash, "SIGUSR2");
                sync_tg_cfg(&tg_cfg, &current_cfg);
            }
        }
    }

    shutdown.store(true, Ordering::Relaxed);
    // Reaching here means a handled signal (SIGTERM/SIGINT) or a closed event
    // channel: a clean stop. Crashes and SIGKILLs skip this, and the next
    // start reports the leftover marker.
    heartbeat::clean_stop(&paths::run_marker_file());
    let _ = config::save_baseline(&engine.baseline);
    save_engine_state(&engine);
    // Give the notifier a moment to flush persisted alerts.
    tokio::time::sleep(Duration::from_millis(200)).await;
    // Let the audit thread notice and drop its socket, which removes our
    // exec rule; returning first left the rule (and audit enabled) behind.
    if let Some(h) = audit_thread {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !h.is_finished() && std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    Ok(())
}

/// Page when telemetry was dropped since the last tick. The engine's dedup
/// window keeps a sustained loss to one alert per source every few minutes.
fn report_dropped_events(
    engine: &mut Engine,
    notifier: &notify::Notifier,
    grown: &[(String, u64)],
    totals: &std::collections::BTreeMap<String, u64>,
) {
    for (source, n) in grown {
        let total = totals.get(source).copied().unwrap_or(*n).to_string();
        let recent = n.to_string();
        emit_self(
            notifier,
            self_alert(
                engine,
                Severity::High,
                "Hermian dropped telemetry",
                &format!(
                    "{} {} lost in the last interval ({} since start). Activity in that window may not have been seen.",
                    recent, source, total
                ),
                "Buffers overflow under bursts of activity. A fork/exec or file-change flood is also a cheap way to slip something past a monitor, so losses are reported rather than just logged.",
                &[
                    "Check what was running at the time (load, a build, a backup, or something unexpected).",
                    "Review 'hermian status' and recent alerts for that window.",
                ],
                &[("Source", source.as_str()), ("Lost", &recent), ("Since start", &total)],
                &format!("selfprotect|dropped|{}", source),
            ),
        );
    }
}

fn sync_tg_cfg(shared: &Arc<std::sync::Mutex<hermian_core::config::TelegramCfg>>, cfg: &Config) {
    if let Ok(mut c) = shared.lock() {
        *c = cfg.notifications.telegram.clone();
    }
}

/// Carry out a Telegram button press that passed every check (see tgbot).
///
/// Quick engine-side choices (ignore, snooze) happen here; firewall and
/// process work runs on a blocking thread. Either way the outcome is posted
/// as a reply to the alert, one line per target (see `actions`), and the
/// alert's buttons are updated to show it. Every press is also recorded as
/// a local alert.
fn handle_action(
    engine: &mut Engine,
    notifier: &notify::Notifier,
    cfg: &Config,
    req: tgbot::ActionRequest,
) {
    use actions::{Line, Mark};
    use hermian_core::ResponseAction as A;
    let now = Utc::now();
    let label = req.action.label();
    emit_self(
        notifier,
        self_alert(
            engine,
            Severity::Low,
            &format!("Telegram response: {}", label),
            &format!("{} chose '{}' on alert {}.", req.by, label, req.alert_ref),
            "Recorded so every remote response has an audit trail.",
            &["Undo a block with 'hermian unblock <ip>'; list them with 'hermian blocked'."],
            &[("By", req.by.as_str()), ("Alert", req.alert_ref.as_str())],
            &format!(
                "selfprotect|tg-action|{}|{}",
                req.alert_ref,
                now.timestamp_nanos_opt().unwrap_or(0)
            ),
        ),
    );
    let tg = cfg.notifications.telegram.clone();
    let host = engine.host.clone();
    let cfg = cfg.clone();
    // An Undo lasts as long as the block, up to a day.
    let undo_mins = (cfg.response.block_duration_hours.max(1) * 60).min(1440);
    let conclude =
        move |req: tgbot::ActionRequest, lines: Vec<Line>, undo: Vec<std::net::IpAddr>| {
            let now = Utc::now();
            let text = actions::render(&host, &req.by, &lines, now);
            log_daemon(
                Severity::High,
                &format!("{}: {}", req.action.label(), text.replace('\n', "; ")),
            );
            let summary = actions::summary(&req.action, &lines, &req.by, now);
            let reply = actions::needs_reply(&req.action, &lines);
            let undo = (!undo.is_empty()).then_some((A::Unblock { sources: undo }, undo_mins));
            tgbot::finish(&tg, &req, &text, &summary, reply, undo, now);
        };
    match req.action.clone() {
        A::Ignore { sources, hours } => {
            let line = if sources.is_empty() || hours == 0 {
                Line::new(Mark::Done, "Ignored")
            } else {
                engine.ignore_sources(&sources, now + chrono::Duration::hours(i64::from(hours)));
                Line::new(
                    Mark::Done,
                    format!(
                        "Ignoring {} source(s) for {}h; logins from them still alert",
                        sources.len(),
                        hours
                    ),
                )
            };
            tokio::task::spawn_blocking(move || conclude(req, vec![line], Vec::new()));
        }
        A::SnoozeRootPasswordWarning { days } => {
            engine.snooze_root_warning(now + chrono::Duration::days(i64::from(days)));
            save_engine_state(engine);
            let line = Line::new(
                Mark::Done,
                format!("Root password warning snoozed for {} days", days),
            );
            tokio::task::spawn_blocking(move || conclude(req, vec![line], Vec::new()));
        }
        A::Block { sources } => {
            for ip in &sources {
                engine.brute.forget(ip);
            }
            tokio::task::spawn_blocking(move || {
                let ctx = action_ctx(&cfg, &req);
                let mut undo = Vec::new();
                let lines = sources
                    .iter()
                    .map(|ip| {
                        let l = actions::block(&ctx, *ip);
                        if l.mark == Mark::Done {
                            undo.push(*ip);
                        }
                        l
                    })
                    .collect();
                conclude(req.clone(), lines, undo);
            });
        }
        A::Unblock { sources } => {
            tokio::task::spawn_blocking(move || {
                let ctx = action_ctx(&cfg, &req);
                let lines = sources
                    .iter()
                    .map(|ip| actions::unblock(&ctx, *ip))
                    .collect();
                conclude(req.clone(), lines, Vec::new());
            });
        }
        A::Disconnect {
            source,
            port,
            user,
            block,
        } => {
            tokio::task::spawn_blocking(move || {
                let ctx = action_ctx(&cfg, &req);
                let mut lines = Vec::new();
                let mut undo = Vec::new();
                // Block first: otherwise the session can come right back.
                if block {
                    let l = actions::block(&ctx, source);
                    if l.mark == Mark::Done {
                        undo.push(source);
                    }
                    lines.push(l);
                }
                let blocked = lines
                    .iter()
                    .any(|l| l.mark != Mark::Failed && l.mark != Mark::Refused);
                let d = actions::disconnect(&ctx, source, port, &user);
                let ended = d.mark == Mark::Done;
                lines.push(d);
                if ended {
                    lines.push(actions::after_disconnect(blocked));
                }
                conclude(req.clone(), lines, undo);
            });
        }
    }
}

/// What the action decisions need for a button press.
fn action_ctx<'a>(cfg: &'a Config, req: &'a tgbot::ActionRequest) -> actions::Ctx<'a> {
    actions::Ctx {
        host: &actions::RealHost,
        ledger: actions::ledger(),
        cfg,
        by: &req.by,
        alert_ref: &req.alert_ref,
        now: Utc::now(),
    }
}

/// Cap on remembered exe paths for the 32-bit check.
const COMPAT_CACHE: usize = 4096;

/// A 32-bit program on x86_64 uses compat syscalls, which the eBPF
/// `sys_enter_*` hooks don't see: its connects and ptrace calls are
/// invisible. Rare on servers, so each such program is logged once (LOW,
/// not paged) to make the blind spot visible.
fn check_compat_exec(
    engine: &mut Engine,
    notifier: &notify::Notifier,
    seen: &mut HashMap<String, bool>,
    e: &ExecEvent,
) {
    // Each exe is checked (and, if 32-bit, reported) once.
    if seen.contains_key(&e.exe) {
        return;
    }
    let compat = procsrc::is_compat_binary(&e.exe);
    if seen.len() >= COMPAT_CACHE {
        seen.clear();
    }
    seen.insert(e.exe.clone(), compat);
    if !compat {
        return;
    }
    emit_self(
        notifier,
        self_alert(
            engine,
            Severity::Low,
            "32-bit program started (partly unmonitored)",
            &format!(
                "{} (pid {}) is a 32-bit program. Its network connections and ptrace calls aren't visible to Hermian's eBPF hooks.",
                e.exe, e.pid
            ),
            "32-bit programs make compat syscalls that the syscall tracepoints skip. Legitimate ones are rare on a 64-bit server, and attackers use them to get around syscall monitoring.",
            &["Check what the program is and why it runs.", "Allowlist nothing here; just know its network activity isn't covered."],
            &[("Executable", e.exe.as_str())],
            &format!("selfprotect|compat|{}", e.exe),
        ),
    );
}

fn report_unmonitored_cpus(engine: &mut Engine, notifier: &notify::Notifier, cpus: &[u32]) {
    let list = cpus
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    emit_self(
        notifier,
        self_alert(
            engine,
            Severity::High,
            "CPUs came online without eBPF monitoring",
            &format!("CPU(s) {} came online after Hermian started and have no event reader.", list),
            "Exec, connect and ptrace events on those CPUs are neither delivered nor counted as lost until the daemon restarts.",
            &["Restart Hermian: systemctl restart hermian"],
            &[("CPUs", list.as_str())],
            &format!("selfprotect|hotplug|{}", list),
        ),
    );
}

/// Tell the alert channels the daemon is stopping, and give delivery a few
/// seconds. A clean `systemctl stop` used to be silent remotely; that's the
/// simplest way to blind a host. (A SIGKILL still can't be reported.)
/// Whether the marker `hermian enable` leaves before restarting the daemon
/// is fresh: written within the last two minutes (a little clock skew
/// allowed). An old or garbled marker doesn't count.
fn planned_restart(marker: &str, now: chrono::DateTime<Utc>) -> bool {
    marker
        .trim()
        .parse::<i64>()
        .map(|t| (-5..=120).contains(&(now.timestamp() - t)))
        .unwrap_or(false)
}

async fn announce_stop(engine: &mut Engine, notifier: &notify::Notifier, signal: &str) {
    // A restart by `hermian enable` (installs and upgrades) is routine:
    // logged, not paged. The marker is used once.
    let marker = paths::planned_restart_file();
    let planned = fs::read_to_string(&marker)
        .map(|m| planned_restart(&m, Utc::now()))
        .unwrap_or(false);
    let _ = fs::remove_file(&marker);
    if planned {
        let alert = self_alert(
            engine,
            Severity::Info,
            "Hermian is restarting (install or upgrade)",
            &format!(
                "hermian enable restarted the daemon ({}). Monitoring resumes in a few seconds.",
                signal
            ),
            "Logged for the record. A stop without this is still paged.",
            &[],
            &[("Signal", signal)],
            &format!("selfprotect|restart|{}", Utc::now().timestamp()),
        );
        if let Some(a) = alert {
            notifier.send(a);
        }
        return;
    }
    let alert = self_alert(
        engine,
        Severity::High,
        "Hermian is stopping",
        &format!("The daemon received {} and is shutting down. Nothing is monitored until it starts again.", signal),
        "Package upgrades and planned maintenance stop the daemon briefly. An unexplained stop means monitoring was switched off, which is often the first thing an intruder does.",
        &[
            "If this wasn't planned, check who stopped it: journalctl -u hermian, and your auth logs.",
            "Start it again with 'systemctl start hermian'.",
        ],
        &[("Signal", signal)],
        &format!("selfprotect|stop|{}", Utc::now().timestamp()),
    );
    if let Some(a) = alert {
        let ref_id = a.ref_id.clone();
        notifier.send(a);
        notifier
            .wait_delivered(&ref_id, Duration::from_secs(STOP_NOTICE_WAIT_SECS))
            .await;
    }
}

/// How long shutdown waits for the stop notice. The unit's TimeoutStopSec
/// must be comfortably above this.
const STOP_NOTICE_WAIT_SECS: u64 = 6;

/// Walk up from `ev.ppid` and make sure every ancestor is present and current.
///
/// "Current" matters: a process may have renamed itself (prctl PR_SET_NAME,
/// which is how nginx/postgres/php-fpm workers get their titles) or exec'd a
/// new image since we last saw it. Ancestors are refreshed from /proc when the
/// recorded comm no longer matches, so role classification uses the live name.
fn seed_missing_ancestors(engine: &mut Engine, ppid: u32, now: chrono::DateTime<Utc>) {
    let mut pid = ppid;
    let mut depth = 0;
    while depth < 16 && pid > 1 {
        let known = engine.tree.get(pid).map(|p| (p.comm.clone(), p.ppid));
        match known {
            Some((comm, ppid)) => {
                // Cheap check: has the comm changed since we recorded it?
                match procsrc::comm_of(pid) {
                    Some(live) if live != comm => {
                        if let Some(info) = procsrc::proc_info(pid, now) {
                            engine.tree.upsert(info);
                        }
                    }
                    _ => engine.tree.touch(pid, now),
                }
                pid = ppid;
            }
            None => match procsrc::proc_info(pid, now) {
                Some(info) => {
                    let next = info.ppid;
                    engine.tree.upsert(info);
                    pid = next;
                }
                None => break,
            },
        }
        depth += 1;
    }
}

/// Make sure `pid` itself (and its ancestry) is in the tree, reading /proc
/// if we never saw it exec.
fn seed_process(engine: &mut Engine, pid: u32, now: chrono::DateTime<Utc>) {
    if pid <= 1 {
        return;
    }
    let ppid = match engine.tree.get(pid) {
        Some(p) => p.ppid,
        None => match procsrc::proc_info(pid, now) {
            Some(info) => {
                let ppid = info.ppid;
                engine.tree.upsert(info);
                ppid
            }
            None => return,
        },
    };
    seed_missing_ancestors(engine, ppid, now);
}

/// Runs on a blocking thread (see the caller).
fn convert_ebpf_events(mut raw_rx: mpsc::Receiver<ebpf::RawEvent>, tx: mpsc::Sender<Event>) {
    let self_pid = std::process::id();
    while let Some(raw) = raw_rx.blocking_recv() {
        let ev = match raw {
            ebpf::RawEvent::Exec(raw) => {
                if raw.pid == self_pid {
                    continue;
                }
                let pid = raw.pid;
                // sched_process_exec delivers the live image: filename is the
                // resolved path and comm is the new program's. No /proc race.
                let filename = ebpf::to_str(&raw.filename);
                let argv0 = ebpf::to_str(&raw.argv0);
                let bpf_comm = ebpf::to_str(&raw.comm);
                // ppid from the kernel task_struct is exact even if the parent
                // has already exited; /proc reparents to 1 in that case.
                let (proc_ppid, tty_nr, _start) = procsrc::stat_of(pid).unwrap_or((0, 0, 0));
                let ppid = if raw.ppid != 0 { raw.ppid } else { proc_ppid };
                // /proc/<pid>/exe is authoritative for "(deleted)"/memfd; fall
                // back to the tracepoint's filename when the process is gone.
                let (exe, deleted) = match procsrc::exe_of(pid) {
                    Some((exe, deleted)) if !exe.is_empty() => (exe, deleted),
                    _ => (filename.clone(), false),
                };
                let fileless = exe.contains("memfd:")
                    || filename.contains("memfd:")
                    || (raw.via_execveat != 0
                        && (filename.starts_with("/proc/") || filename.contains("/fd/")));
                let comm = if !bpf_comm.is_empty() {
                    bpf_comm
                } else {
                    procsrc::comm_of(pid).unwrap_or_else(|| {
                        std::path::Path::new(&exe)
                            .file_name()
                            .map(|s| s.to_string_lossy().chars().take(15).collect())
                            .unwrap_or_default()
                    })
                };
                let (container, container_id) = procsrc::container_info(pid);
                let exe = if deleted {
                    exe
                } else {
                    procsrc::judged_exe(pid, &comm, &exe)
                };
                Event::Exec(ExecEvent {
                    ts: Utc::now(),
                    pid,
                    ppid,
                    uid: raw.uid,
                    gid: raw.gid,
                    comm,
                    exe,
                    argv0: if argv0.is_empty() { filename } else { argv0 },
                    ld_preload: raw.ld_preload != 0,
                    deleted_exe: deleted || fileless,
                    tty_nr,
                    container,
                    container_id,
                })
            }
            ebpf::RawEvent::Connect(raw) => {
                if raw.pid == self_pid {
                    continue;
                }
                let Some(daddr) = ebpf::connect_to_ip(&raw) else {
                    continue;
                };
                let comm = procsrc::comm_of(raw.pid).unwrap_or_default();
                let (container, _) = procsrc::container_info(raw.pid);
                Event::Connect(hermian_core::ConnectEvent {
                    ts: Utc::now(),
                    pid: raw.pid,
                    uid: raw.uid,
                    daddr,
                    dport: raw.dport,
                    comm,
                    container,
                })
            }
            ebpf::RawEvent::Ptrace(raw) => {
                let comm = procsrc::comm_of(raw.pid).unwrap_or_default();
                Event::Ptrace(hermian_core::PtraceEvent {
                    ts: Utc::now(),
                    pid: raw.pid,
                    uid: raw.uid,
                    comm,
                    target_pid: raw.target_pid,
                    request: raw.request,
                })
            }
            ebpf::RawEvent::Priv(raw) => match priv_event(&raw) {
                Some(ev) => Event::File(ev),
                None => continue,
            },
        };
        if tx.blocking_send(ev).is_err() {
            return;
        }
    }
}

/// A chmod or setxattr that gave a file setuid/setgid bits or capabilities.
/// The hook fires on entry, before the call has done anything: wait a moment
/// for it to land, and report nothing if it never does (it failed).
fn priv_event(raw: &ebpf::RawPriv) -> Option<hermian_core::FileEvent> {
    let rel = ebpf::to_str(&raw.path);
    // chmod and setcap are usually gone before /proc can say what their fd
    // or working directory was: then find the inode the kernel gave us.
    let path = procsrc::path_at(raw.pid, raw.fd, &rel).or_else(|| {
        let base = fallback::find_inode(fallback::st_dev_of_kernel(raw.dev), raw.ino)?;
        procsrc::join_at(&base, &rel)
    })?;
    // The kernel's comm and uid still say who when the process is gone
    // (writer_info then has an empty comm and uid 0).
    let mut writer = procsrc::writer_info(raw.pid)
        .map(fallback::writer_from)
        .unwrap_or(hermian_core::WriterInfo {
            pid: raw.pid,
            uid: raw.uid,
            comm: String::new(),
            exe: String::new(),
            tty_nr: 0,
        });
    if writer.comm.is_empty() {
        writer.comm = ebpf::to_str(&raw.comm);
        writer.uid = raw.uid;
    }
    let writer = Some(writer);
    for _ in 0..5 {
        if let Some(ev) = fallback::privileged_file_event(
            path.clone(),
            hermian_core::FileKind::Modified,
            writer.clone(),
        ) {
            let has_it = match raw.kind {
                ebpf::PRIV_SETID => ev.is_suid,
                ebpf::PRIV_CAPS => ev.has_file_caps,
                _ => false,
            };
            if has_it {
                fallback::note_priv_reported(ev.dev, ev.ino);
                return Some(ev);
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    None
}

/// Re-read, validate and apply the configuration.
fn reload_config(
    engine: &mut Engine,
    notifier: &notify::Notifier,
    current_cfg: &mut Config,
    applied_hash: &mut String,
    trigger: &str,
) {
    let path = paths::config_path();
    let text = match fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => {
            emit_self(
                notifier,
                self_alert(
                    engine,
                    Severity::Critical,
                    "Hermian configuration unreadable",
                    &format!("The configuration file could not be read: {}.", e),
                    "A missing or unreadable config is either an accident or an attempt to disrupt monitoring. The previous configuration remains active.",
                    &["Check permissions and ownership of /etc/hermian/config.toml.", "Restore it from backup if it was removed."],
                    &[("Trigger", trigger)],
                    "selfprotect|config-unreadable",
                ),
            );
            return;
        }
    };
    let new_hash = selfprotect::sha256_hex(text.as_bytes());
    // Compared with what's in effect, not with config.sha256 on disk, which
    // anyone who can write the config can also rewrite first.
    if new_hash == *applied_hash {
        // Touched but unchanged (editor re-save, SIGHUP with no edit).
        return;
    }
    let parsed = Config::parse(&text)
        .map_err(|e| e.to_string())
        .and_then(|c| c.validate().map(|_| c).map_err(|e| e.to_string()));
    match parsed {
        Ok(new_cfg) => {
            let diff = configdiff::diff(current_cfg, &new_cfg);
            let functional = diff.is_functional();
            let alert = self_alert(
                engine,
                if functional {
                    Severity::Critical
                } else {
                    Severity::Info
                },
                if !functional {
                    "Hermian configuration reloaded with no functional change"
                } else if diff.destinations_changed {
                    "Hermian alert destinations changed and reloaded"
                } else {
                    "Hermian configuration changed and reloaded"
                },
                "The configuration file changed while the daemon was running. It validated and has been applied.",
                "Changing a security daemon's configuration at runtime is how an attacker blinds a host. If this was you, no action is needed.",
                &["Confirm the change was yours.", "Review the active configuration with 'hermian status'."],
                &[("Trigger", trigger), ("Changes", &diff.summary), ("Config hash", &new_hash)],
                &reload_signature(functional, &new_hash),
            );
            // If alerts are being repointed, the old destinations must hear
            // about it too: otherwise the notice goes only to whoever did it.
            if diff.destinations_changed {
                if let Some(a) = &alert {
                    notify_old_destinations(a.clone(), current_cfg.notifications.clone());
                }
            }
            engine.set_config(new_cfg.clone(), new_cfg.allowlist.clone());
            notifier.reconfigure(new_cfg.notifications.clone());
            *current_cfg = new_cfg;
            let _ = selfprotect::update_config_hash(&new_hash);
            *applied_hash = new_hash.clone();
            emit_self(notifier, alert);
        }
        Err(e) => {
            emit_self(
                notifier,
                self_alert(
                    engine,
                    Severity::Low,
                    "Hermian configuration changed but is INVALID",
                    &format!("The configuration file changed but failed validation: {}. The previous configuration remains active.", e),
                    "Usually a typo while editing. The daemon keeps the last good configuration.",
                    &["Fix /etc/hermian/config.toml.", "Reload with 'systemctl reload hermian' (SIGHUP)."],
                    &[("Trigger", trigger)],
                    "selfprotect|config-invalid",
                ),
            );
        }
    }
}

/// Best-effort, one-shot delivery to the notifying channels of a config that
/// is about to be replaced. Runs off the event loop; failures are only logged.
fn notify_old_destinations(alert: Alert, old: hermian_core::config::NotificationsCfg) {
    let _ = std::thread::Builder::new()
        .name("hermian-old-dest".into())
        .spawn(move || {
            for ch in notify::NOTIFYING_CHANNELS {
                if *ch == "stdout" || !old.has_channel(ch) {
                    continue;
                }
                if let Err(e) = notify::notify_one(ch, &alert, &old) {
                    log_daemon(
                        Severity::Low,
                        &format!("could not tell the previous {} destination: {}", ch, e),
                    );
                }
            }
        });
}

/// Dedup signature for the reload alert. Each distinct functional config gets
/// its own, so a second change within the dedup window still pages: with one
/// fixed signature, a harmless edit followed by the real one within five
/// minutes left the second silent (seen on the test VM when auto_isolate was
/// switched on). No-op reloads share one signature, they're only INFO.
fn reload_signature(functional: bool, config_hash: &str) -> String {
    if functional {
        format!("selfprotect|config-reload|{}", config_hash)
    } else {
        "selfprotect|config-reload-noop".to_string()
    }
}

/// See [`audit::self_check`].
fn run_self_check(engine: &mut Engine, notifier: &notify::Notifier, last: &mut Vec<String>) {
    let Some(signs) = audit::self_check(last) else {
        return;
    };
    if let Some(f) = audit::self_finding(&signs) {
        log_daemon(
            Severity::Critical,
            "self-check: the daemon has foreign code loaded",
        );
        emit_self(notifier, engine.alert_from(f, Utc::now()));
    }
}

fn emit_self(notifier: &notify::Notifier, alert: Option<Alert>) {
    if let Some(alert) = alert {
        notifier.send(alert);
    }
}

#[allow(clippy::too_many_arguments)]
fn self_alert(
    engine: &mut Engine,
    severity: Severity,
    title: &str,
    what: &str,
    why: &str,
    actions: &[&str],
    facts: &[(&str, &str)],
    signature: &str,
) -> Option<Alert> {
    let mut finding = Finding::new(DetectionId::Self_, severity, title, signature)
        .what(what)
        .why(why)
        .actions(actions.iter().copied());
    for (k, v) in facts {
        finding = finding.fact(*k, *v);
    }
    engine.alert_from(finding, Utc::now())
}

pub fn log_daemon(severity: Severity, msg: &str) {
    // Under systemd, stderr already lands in the journal; avoid double entries.
    let under_systemd =
        std::env::var_os("INVOCATION_ID").is_some() || std::env::var_os("JOURNAL_STREAM").is_some();
    if under_systemd {
        eprintln!("hermian: {}", msg);
    } else {
        notify::syslog_msg(severity, &format!("hermian: {}", msg));
        if severity >= Severity::Low {
            eprintln!("hermian: {}", msg);
        }
    }
}

fn write_status_snapshot(
    engine: &Engine,
    notifier: &notify::Notifier,
    sources: &Sources,
    cfg: &Config,
    integrity: &selfprotect::IntegrityStatus,
    cpu_ring: &VecDeque<f64>,
    started_at: chrono::DateTime<Utc>,
) {
    let now = Utc::now();
    let cpu_avg = if cpu_ring.is_empty() {
        0.0
    } else {
        cpu_ring.iter().sum::<f64>() / cpu_ring.len() as f64
    };
    let det = engine.cfg.detections;
    let ebpf_on = sources.ebpf.is_some();
    let exec_src = if ebpf_on {
        "eBPF"
    } else if sources.audit {
        "audit + /proc"
    } else {
        "/proc"
    };
    let auth_src = auth_source_label(sources.pam, sources.auth);
    let mut detections = std::collections::BTreeMap::new();
    detections.insert("d1".to_string(), line(det.d1_process_chains, exec_src));
    detections.insert("d2".to_string(), line(det.d2_auth, auth_src));
    detections.insert("d3".to_string(), line(det.d3_persistence, "inotify"));
    detections.insert(
        "d4".to_string(),
        line(
            det.d4_priv_esc,
            if ebpf_on { "eBPF + inotify" } else { "inotify" },
        ),
    );
    detections.insert(
        "d5".to_string(),
        line(
            det.d5_network,
            if ebpf_on { "eBPF + /proc" } else { "/proc" },
        ),
    );

    let ns = notifier.snapshot();
    let wh = sources
        .watch_health
        .as_ref()
        .and_then(|h| h.lock().ok().map(|g| g.clone()))
        .unwrap_or_default();
    let state = status::StatusState {
        version: hermian_core::VERSION.to_string(),
        host: engine.host.clone(),
        pid: std::process::id(),
        started_at,
        kernel: procsrc::kernel_release(),
        ebpf: if ebpf_on {
            "full".into()
        } else {
            "reduced".into()
        },
        ebpf_hooks: sources
            .ebpf
            .clone()
            .unwrap_or_default()
            .iter()
            .map(|s| s.to_string())
            .collect(),
        baseline_state: if engine.baseline.complete {
            "complete".into()
        } else {
            "learning".into()
        },
        baseline_remaining_minutes: engine
            .baseline
            .remaining(now)
            .map(|d| d.num_minutes().max(0)),
        detections,
        cpu_avg_1h: cpu_avg,
        rss_mb: procsrc::self_rss_kb() / 1024,
        events_processed: engine.counters.events_processed,
        alerts_today: engine.counters.alerts_today,
        alerts_by_severity: engine.counters.by_severity.clone(),
        tracked_processes: engine.tree.len(),
        watches_active: wh.active,
        watches_failed: wh.failed,
        watch_error: wh.last_error.clone(),
        heartbeat_age_secs: heartbeat::age(&paths::heartbeat_file(), std::time::SystemTime::now())
            .map(|d| d.as_secs()),
        channels: cfg.notifications.channels.clone(),
        min_severity: cfg.notifications.min_severity.clone(),
        last_delivery: ns.last_delivery,
        last_delivery_note: ns.last_delivery_note,
        failures: ns.failures,
        pending_notifications: ns.pending,
        last_notify_error: ns.last_error.clone(),
        delivered_per_channel: ns.per_channel.clone(),
        dropped_per_channel: ns.dropped_by_channel.clone(),
        events_dropped: health::snapshot(),
        telegram_actions: if cfg.notifications.telegram.actions_enabled() {
            format!(
                "on ({} user{})",
                cfg.notifications.telegram.allowed_user_ids.len(),
                if cfg.notifications.telegram.allowed_user_ids.len() == 1 {
                    ""
                } else {
                    "s"
                }
            )
        } else {
            "off".to_string()
        },
        telegram_poll_error: tgbot::last_poll_error(),
        config_hash: integrity.config_hash.clone(),
        binary_hash: integrity.binary_hash.clone(),
        integrity_ok: integrity.binary_ok && integrity.config_ok,
        updated_at: now,
    };
    let _ = status::write_state(&state);
}

/// Every SSH auth source actually in use. PAM used to hide the log source
/// (and was claimed whenever the .so existed, even with no hook).
fn auth_source_label(pam: bool, log: authlog::AuthSource) -> &'static str {
    match (pam, log) {
        (true, authlog::AuthSource::File) => "PAM + auth.log + inotify",
        (true, authlog::AuthSource::Journal) => "PAM + journald + inotify",
        (true, authlog::AuthSource::None) => "PAM + inotify",
        (false, authlog::AuthSource::File) => "auth.log + inotify",
        (false, authlog::AuthSource::Journal) => "journald + inotify",
        (false, authlog::AuthSource::None) => "inotify only",
    }
}

fn line(enabled: bool, source: &str) -> String {
    if enabled {
        source.to_string()
    } else {
        "disabled".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hermian_core::{Allowlist, Baseline};

    /// The upgrade restart (#198 on the test VPS) paged HIGH. Only a fresh
    /// marker from `hermian enable` makes a stop routine.
    #[test]
    fn only_a_fresh_marker_is_a_planned_restart() {
        let now = Utc::now();
        let ts = |secs_ago: i64| (now.timestamp() - secs_ago).to_string();
        assert!(planned_restart(&ts(3), now));
        assert!(planned_restart(
            &format!(
                "{}
",
                ts(119)
            ),
            now
        ));
        assert!(!planned_restart(&ts(600), now), "stale");
        assert!(!planned_restart(&ts(-60), now), "from the future");
        assert!(!planned_restart("yes", now));
        assert!(!planned_restart("", now));
    }

    #[test]
    fn auth_label_names_every_source() {
        use authlog::AuthSource::*;
        assert_eq!(auth_source_label(false, Journal), "journald + inotify");
        assert_eq!(auth_source_label(true, Journal), "PAM + journald + inotify");
        assert_eq!(auth_source_label(true, None), "PAM + inotify");
        assert_eq!(auth_source_label(false, None), "inotify only");
    }

    fn engine() -> Engine {
        Engine::new(
            Config::default(),
            Allowlist::default(),
            Baseline::default(),
            "t".into(),
        )
    }

    fn reload(eng: &mut Engine, functional: bool, hash: &str) -> Option<Alert> {
        let sev = if functional {
            Severity::Critical
        } else {
            Severity::Info
        };
        let f = Finding::new(
            DetectionId::Self_,
            sev,
            "reload",
            &reload_signature(functional, hash),
        );
        eng.alert_from(f, Utc::now())
    }

    #[test]
    fn unclean_cause_prefers_the_panic_note() {
        let (text, label) = unclean_cause(Some("panic in thread 'x': boom"), Some("stale"));
        assert_eq!(label, "Crash");
        assert!(text.contains("boom"), "{}", text);
        assert_eq!(unclean_cause(None, Some("stale")).1, "Watchdog restart");
        assert_eq!(unclean_cause(None, None).1, "Unexpected stop");
    }

    #[test]
    fn every_distinct_config_change_pages() {
        let mut eng = engine();
        assert!(reload(&mut eng, true, "aaa").is_some());
        // A second, different change a moment later must not be deduped away.
        assert!(reload(&mut eng, true, "bbb").is_some());
        // The same config again (e.g. a re-save) is.
        assert!(reload(&mut eng, true, "bbb").is_none());
        // No-op reloads stay collapsed.
        assert!(reload(&mut eng, false, "c1").is_some());
        assert!(reload(&mut eng, false, "c2").is_none());
    }
}
