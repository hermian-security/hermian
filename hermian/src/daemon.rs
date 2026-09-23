//! The long-running daemon: wires event sources into the engine and alerts
//! into the notifier.

use std::collections::VecDeque;
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
    auditnetlink, authlog, config, configdiff, ebpf, fallback, isolate, notify, pamsock, paths,
    procsrc, selfprotect, status, watchers,
};

/// Persisted across restarts so reference ids never repeat within a day.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct EngineState {
    ref_day: String,
    ref_seq: u32,
    #[serde(default)]
    counters: Option<hermian_core::Counters>,
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
    };
    if let Ok(text) = serde_json::to_string(&st) {
        let _ = config::write_secure(&paths::engine_state_file(), &text);
    }
}

pub fn run() -> Result<()> {
    config::require_root()?;
    let cfg = config::load_config()?;
    let allowlist = cfg.allowlist.clone();
    let host = if cfg.general.hostname.is_empty() {
        procsrc::hostname()
    } else {
        cfg.general.hostname.clone()
    };
    let mut baseline = config::load_baseline()?;
    if cfg.baseline.enabled && !baseline.complete && baseline.started_at.is_none() {
        baseline = Baseline::new(true, cfg.baseline.duration_hours, Utc::now());
        config::save_baseline(&baseline)?;
    }

    notify::ensure_log_dir()?;
    fs::create_dir_all(paths::state_dir())?;
    fs::create_dir_all(paths::run_dir())?;

    let mut engine = Engine::new(cfg.clone(), allowlist, baseline, host);
    if let Some(st) = load_engine_state() {
        engine.restore(Utc::now(), &st.ref_day, st.ref_seq, st.counters);
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
    rt.block_on(async_main(cfg, engine))
}

struct Sources {
    ebpf: Option<Vec<&'static str>>,
    audit: bool,
    auth: authlog::AuthSource,
    pam: bool,
    watch_health: Option<watchers::SharedWatchHealth>,
}

async fn async_main(initial_cfg: Config, mut engine: Engine) -> Result<()> {
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
            "HERMIAN binary modified",
            "The running HERMIAN binary does not match the hash recorded at install time.",
            "The security daemon itself may have been replaced or patched. Nothing it reports can be trusted until this is resolved.",
            &[
                "Reinstall HERMIAN from a signed package or verified tarball.",
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
                "HERMIAN configuration modified while stopped",
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

    if procsrc::kernel_supports_ebpf() {
        let (raw_tx, raw_rx) = mpsc::channel::<ebpf::RawEvent>(16384);
        match ebpf::load_and_attach(raw_tx) {
            Ok(runtime) => {
                sources.ebpf = Some(runtime.attached.clone());
                _ebpf_runtime = Some(runtime);
                tokio::spawn(convert_ebpf_events(raw_rx, event_tx.clone()));
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
                Ok(()) => sources.audit = true,
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
    let (listener_close_tx, mut listener_close_rx) = mpsc::channel::<(String, u16)>(256);
    fallback::spawn_listener_poller(event_tx.clone(), listener_close_tx, shutdown.clone())?;
    fallback::spawn_suid_sweeper(event_tx.clone(), shutdown.clone())?;

    // --- Signals ---------------------------------------------------------
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sighup = signal(SignalKind::hangup())?;
    let mut sigusr2 = signal(SignalKind::user_defined2())?;

    let mut ticker = tokio::time::interval(Duration::from_secs(30));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let mut cpu_ring: VecDeque<f64> = VecDeque::new();
    let mut last_cpu = procsrc::self_cpu_sample();
    let mut first_tick = true;
    let mut current_cfg = initial_cfg;
    let started_at = Utc::now();
    let config_path = paths::config_path();

    if initial_notify.last_delivery.is_none() {
        emit_self(
            &notifier,
            self_alert(
                &mut engine,
                Severity::Info,
                "HERMIAN is active",
                "This is the one-time confirmation sent when HERMIAN starts for the first time on this host.",
                "It proves the alert path works end to end. You will not hear from HERMIAN again unless something needs your attention.",
                &["Run 'hermian status' at any time to confirm coverage."],
                &[],
                "selftest|install",
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
    log_daemon(
        Severity::Info,
        &format!("HERMIAN {} started", hermian_core::VERSION),
    );

    loop {
        tokio::select! {
            maybe = event_rx.recv() => {
                let Some(ev) = maybe else { break };
                if let Event::File(f) = &ev {
                    if std::path::Path::new(&f.path) == config_path {
                        reload_config(&mut engine, &notifier, &mut current_cfg, "file change");
                        continue;
                    }
                }
                if let Event::Exec(e) = &ev {
                    seed_missing_ancestors(&mut engine, e);
                }
                for alert in engine.process(ev) {
                    let critical = alert.severity == Severity::Critical;
                    notifier.send(alert);
                    if critical {
                        isolate::auto_isolate_if_enabled(&current_cfg);
                    }
                }
            }
            Some((proto, port)) = listener_close_rx.recv() => {
                engine.forget_listener(&proto, port);
            }
            _ = ticker.tick() => {
                let now = Utc::now();
                engine.reap_exited(&procsrc::live_pids(), now);
                for a in engine.tick(now) {
                    notifier.send(a);
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
                break;
            }
            _ = sigint.recv() => {
                break;
            }
            _ = sighup.recv() => {
                reload_config(&mut engine, &notifier, &mut current_cfg, "SIGHUP");
            }
            _ = sigusr2.recv() => {
                reload_config(&mut engine, &notifier, &mut current_cfg, "SIGUSR2");
            }
        }
    }

    shutdown.store(true, Ordering::Relaxed);
    let _ = config::save_baseline(&engine.baseline);
    save_engine_state(&engine);
    // Give the notifier a moment to flush persisted alerts.
    tokio::time::sleep(Duration::from_millis(200)).await;
    Ok(())
}

/// Walk up from `ev.ppid` and make sure every ancestor is present and current.
///
/// "Current" matters: a process may have renamed itself (prctl PR_SET_NAME,
/// which is how nginx/postgres/php-fpm workers get their titles) or exec'd a
/// new image since we last saw it. Ancestors are refreshed from /proc when the
/// recorded comm no longer matches, so role classification uses the live name.
fn seed_missing_ancestors(engine: &mut Engine, ev: &ExecEvent) {
    let now = ev.ts;
    let mut pid = ev.ppid;
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

async fn convert_ebpf_events(mut raw_rx: mpsc::Receiver<ebpf::RawEvent>, tx: mpsc::Sender<Event>) {
    let self_pid = std::process::id();
    while let Some(raw) = raw_rx.recv().await {
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
        };
        if tx.send(ev).await.is_err() {
            return;
        }
    }
}

/// Re-read, validate and apply the configuration.
fn reload_config(
    engine: &mut Engine,
    notifier: &notify::Notifier,
    current_cfg: &mut Config,
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
                    "HERMIAN configuration unreadable",
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
    if new_hash == selfprotect::stored_config_hash().unwrap_or_default() {
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
                    "HERMIAN configuration reloaded with no functional change"
                } else if diff.destinations_changed {
                    "HERMIAN alert destinations changed and reloaded"
                } else {
                    "HERMIAN configuration changed and reloaded"
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
            emit_self(notifier, alert);
        }
        Err(e) => {
            emit_self(
                notifier,
                self_alert(
                    engine,
                    Severity::Low,
                    "HERMIAN configuration changed but is INVALID",
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
        channels: cfg.notifications.channels.clone(),
        min_severity: cfg.notifications.min_severity.clone(),
        last_delivery: ns.last_delivery,
        last_delivery_note: ns.last_delivery_note,
        failures: ns.failures,
        pending_notifications: ns.pending,
        last_notify_error: ns.last_error.clone(),
        delivered_per_channel: ns.per_channel.clone(),
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
