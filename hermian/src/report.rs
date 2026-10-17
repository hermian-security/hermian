//! `hermian report`: a summary a beta tester can read, then choose to send.
//!
//! Counts and versions only. No host name, addresses, user names, paths or
//! commands: the report is meant to be pasted into a public issue.

use std::collections::BTreeMap;

use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use hermian_core::{Alert, Severity};
use serde::Serialize;

use crate::cli::ReportArgs;
use crate::status::StatusState;
use crate::ui::{humanize_secs, Style};

/// Rules listed by name; the rest are summed in "other".
const MAX_RULES: usize = 15;

#[derive(Debug, Serialize, PartialEq)]
pub struct Report {
    pub version: String,
    pub os: String,
    pub kernel: String,
    pub arch: String,
    /// Days since the baseline started (the install), when known.
    pub installed_days: Option<i64>,
    /// Seconds the daemon has been up, when it's running.
    pub daemon_uptime_secs: Option<i64>,
    pub ebpf: String,
    pub baseline: String,
    pub coverage: BTreeMap<String, String>,
    pub days: u32,
    pub alerts_total: u64,
    pub alerts_by_severity: BTreeMap<String, u64>,
    pub alerts_by_rule: Vec<RuleCount>,
    pub other_rules: u64,
    pub channels: Vec<String>,
    pub delivered_per_channel: BTreeMap<String, u64>,
    pub delivery_failures: u64,
    pub dropped_notifications: u64,
    pub events_dropped: u64,
    pub cpu_avg_1h: Option<f64>,
    pub rss_mb: Option<u64>,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct RuleCount {
    pub detection: String,
    pub severity: String,
    pub title: String,
    pub count: u64,
}

/// What's known about the machine, gathered by the caller.
pub struct HostFacts {
    pub os: String,
    pub kernel: String,
    pub arch: String,
}

/// An alert title safe to publish: dedup summaries fold into their rule,
/// " via <process>" suffixes go, and a title that still carries a path or
/// an address is withheld.
fn public_title(title: &str) -> String {
    let t = title.strip_prefix("Repeated: ").unwrap_or(title);
    let t = t.split(" via ").next().unwrap_or(t).trim();
    let looks_private = t.contains('/')
        || t.split(|c: char| c.is_whitespace() || c == ',' || c == '(' || c == ')')
            .any(|w| w.parse::<std::net::IpAddr>().is_ok());
    if looks_private {
        "(title withheld: it named a path or an address)".to_string()
    } else {
        t.to_string()
    }
}

pub fn build(
    alerts: &[Alert],
    state: Option<&StatusState>,
    installed_at: Option<DateTime<Utc>>,
    host: HostFacts,
    days: u32,
    now: DateTime<Utc>,
) -> Report {
    let since = now - Duration::days(days.max(1) as i64);
    let recent: Vec<&Alert> = alerts.iter().filter(|a| a.ts >= since).collect();

    let mut by_sev: BTreeMap<String, u64> = BTreeMap::new();
    for s in [
        Severity::Critical,
        Severity::High,
        Severity::Low,
        Severity::Info,
    ] {
        by_sev.insert(s.as_str().to_string(), 0);
    }
    let mut rules: BTreeMap<(String, Severity, String), u64> = BTreeMap::new();
    for a in &recent {
        *by_sev.entry(a.severity.as_str().to_string()).or_default() += 1;
        *rules
            .entry((
                a.detection.short().to_string(),
                a.severity,
                public_title(&a.title),
            ))
            .or_default() += 1;
    }
    // Most frequent first, then most severe.
    let mut rules: Vec<_> = rules.into_iter().collect();
    rules.sort_by(|a, b| b.1.cmp(&a.1).then(b.0 .1.cmp(&a.0 .1)).then(a.0.cmp(&b.0)));
    let other_rules = rules.iter().skip(MAX_RULES).map(|(_, n)| n).sum();
    let alerts_by_rule = rules
        .into_iter()
        .take(MAX_RULES)
        .map(|((det, sev, title), count)| RuleCount {
            detection: det,
            severity: sev.as_str().to_string(),
            title,
            count,
        })
        .collect();

    let running = state.filter(|s| crate::status::pid_alive(s.pid));
    Report {
        version: hermian_core::VERSION.to_string(),
        os: host.os,
        kernel: host.kernel,
        arch: host.arch,
        installed_days: installed_at.map(|t| (now - t).num_days().max(0)),
        daemon_uptime_secs: running.map(|s| (now - s.started_at).num_seconds().max(0)),
        ebpf: state.map(|s| s.ebpf.clone()).unwrap_or_default(),
        baseline: state.map(|s| s.baseline_state.clone()).unwrap_or_default(),
        coverage: state.map(|s| s.detections.clone()).unwrap_or_default(),
        days,
        alerts_total: recent.len() as u64,
        alerts_by_severity: by_sev,
        alerts_by_rule,
        other_rules,
        channels: state.map(|s| s.channels.clone()).unwrap_or_default(),
        delivered_per_channel: state
            .map(|s| s.delivered_per_channel.clone())
            .unwrap_or_default(),
        delivery_failures: state.map(|s| s.failures).unwrap_or(0),
        dropped_notifications: state
            .map(|s| s.dropped_per_channel.values().sum())
            .unwrap_or(0),
        events_dropped: state.map(|s| s.events_dropped.values().sum()).unwrap_or(0),
        cpu_avg_1h: state.map(|s| s.cpu_avg_1h),
        rss_mb: state.map(|s| s.rss_mb),
    }
}

/// Names for the coverage keys `status` writes (d1..d5).
fn coverage_name(key: &str) -> &str {
    match key {
        "d1" => "Process chains",
        "d2" => "SSH and authentication",
        "d3" => "Persistence",
        "d4" => "Privilege escalation",
        "d5" => "Network correlation",
        other => other,
    }
}

pub fn render(r: &Report, st: &Style) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{}\n",
        st.masthead("report", &format!("last {} days", r.days))
    ));

    out.push_str(&format!("\n{}\n", st.heading("HOST")));
    out.push_str(&format!("{}\n", st.row("Version", &r.version)));
    out.push_str(&format!(
        "{}\n",
        st.row("System", &format!("{} ({})", r.os, r.arch))
    ));
    out.push_str(&format!("{}\n", st.row("Kernel", &r.kernel)));
    if let Some(d) = r.installed_days {
        out.push_str(&format!(
            "{}\n",
            st.row("Installed", &format!("{} days ago", d))
        ));
    }
    out.push_str(&format!(
        "{}\n",
        st.row(
            "Daemon",
            &match r.daemon_uptime_secs {
                Some(s) => format!("running, up {}", humanize_secs(s as u64)),
                None => "not running".to_string(),
            }
        )
    ));

    out.push_str(&format!("\n{}\n", st.heading("COVERAGE")));
    for (k, v) in &r.coverage {
        out.push_str(&format!("{}\n", st.row(coverage_name(k), v)));
    }
    if !r.ebpf.is_empty() {
        out.push_str(&format!("{}\n", st.row("eBPF", &r.ebpf)));
    }
    if !r.baseline.is_empty() {
        out.push_str(&format!("{}\n", st.row("Baseline", &r.baseline)));
    }

    out.push_str(&format!("\n{}\n", st.heading("ALERTS")));
    // BTreeMap order is alphabetical; show most severe first.
    let order = ["CRITICAL", "HIGH", "LOW", "INFO"];
    let sev_line = order
        .iter()
        .map(|k| {
            format!(
                "{} {}",
                r.alerts_by_severity.get(*k).copied().unwrap_or(0),
                k.to_lowercase()
            )
        })
        .collect::<Vec<_>>()
        .join(" \u{00B7} ");
    out.push_str(&format!(
        "{}\n",
        st.row("Total", &format!("{}  ({})", r.alerts_total, sev_line))
    ));
    for rc in &r.alerts_by_rule {
        out.push_str(&format!(
            "  {:>5}  {:<8} {:<5} {}\n",
            rc.count, rc.severity, rc.detection, rc.title
        ));
    }
    if r.other_rules > 0 {
        out.push_str(&format!("  {:>5}  other rules\n", r.other_rules));
    }

    out.push_str(&format!("\n{}\n", st.heading("DELIVERY")));
    out.push_str(&format!(
        "{}\n",
        st.row(
            "Channels",
            &if r.channels.is_empty() {
                "unknown (daemon not running?)".to_string()
            } else {
                r.channels.join(", ")
            }
        )
    ));
    if !r.delivered_per_channel.is_empty() {
        let d = r
            .delivered_per_channel
            .iter()
            .map(|(k, v)| format!("{} {}", k, v))
            .collect::<Vec<_>>()
            .join(" \u{00B7} ");
        out.push_str(&format!("{}\n", st.row("Delivered", &d)));
    }
    out.push_str(&format!(
        "{}\n",
        st.row(
            "Problems",
            &format!(
                "{} failures \u{00B7} {} notifications dropped \u{00B7} {} events dropped",
                r.delivery_failures, r.dropped_notifications, r.events_dropped
            )
        )
    ));
    if let (Some(cpu), Some(rss)) = (r.cpu_avg_1h, r.rss_mb) {
        out.push_str(&format!(
            "{}\n",
            st.row(
                "Overhead",
                &format!("{:.1}% CPU (1 h) \u{00B7} {} MB RSS", cpu, rss)
            )
        ));
    }
    out.push_str(&format!("{}\n", st.rule()));
    out.push_str(&format!(
        "  {}\n  {}\n",
        st.dim("No host name, addresses, users, paths or commands are included."),
        st.dim("Paste it into a GitHub issue, or send it to contact@hermian.me.")
    ));
    out
}

fn os_name() -> String {
    std::fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|t| {
            t.lines().find_map(|l| {
                l.strip_prefix("PRETTY_NAME=")
                    .map(|v| v.trim_matches('"').to_string())
            })
        })
        .unwrap_or_else(|| "unknown".to_string())
}

fn uname_field(f: fn(&libc::utsname) -> &[libc::c_char]) -> String {
    // SAFETY: uname fills the struct; the fields are NUL-terminated.
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut u) } != 0 {
        return "unknown".to_string();
    }
    let bytes: Vec<u8> = f(&u)
        .iter()
        .take_while(|c| **c != 0)
        .map(|c| c.to_ne_bytes()[0])
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

pub fn cmd_report(args: &ReportArgs) -> Result<()> {
    let alerts = crate::alerts::load_all()?;
    let state = crate::status::read_state();
    let installed_at = crate::config::load_baseline()
        .ok()
        .and_then(|b| b.started_at);
    let host = HostFacts {
        os: os_name(),
        kernel: uname_field(|u| &u.release),
        arch: uname_field(|u| &u.machine),
    };
    let r = build(
        &alerts,
        state.as_ref(),
        installed_at,
        host,
        args.days.clamp(1, 365),
        Utc::now(),
    );
    if args.json {
        println!("{}", serde_json::to_string_pretty(&r)?);
    } else {
        print!("{}", render(&r, &Style::detect()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hermian_core::{DetectionId, Finding};

    fn alert(det: DetectionId, sev: Severity, title: &str, ago_hours: i64) -> Alert {
        let now = Utc::now();
        Alert::from_finding(
            Finding::new(det, sev, title, "x"),
            "HER-1".into(),
            "secret-host-01".into(),
            now - Duration::hours(ago_hours),
        )
    }

    fn host() -> HostFacts {
        HostFacts {
            os: "Ubuntu 22.04.5 LTS".into(),
            kernel: "5.15.0-170-generic".into(),
            arch: "x86_64".into(),
        }
    }

    #[test]
    fn titles_never_carry_paths_or_addresses() {
        assert_eq!(public_title("Web shell via php-fpm"), "Web shell");
        assert_eq!(
            public_title("Repeated: Root login from a new source"),
            "Root login from a new source"
        );
        assert!(public_title("Change to /etc/pam.d/sshd").contains("withheld"));
        assert!(public_title("Connection to 203.0.113.9").contains("withheld"));
        assert!(public_title("Listener on (2001:db8::1)").contains("withheld"));
        assert_eq!(
            public_title("Hermian 0.1.0-beta.10 started"),
            "Hermian 0.1.0-beta.10 started"
        );
    }

    #[test]
    fn counts_the_window_and_leaves_the_host_out() {
        let alerts = vec![
            alert(
                DetectionId::D1,
                Severity::Info,
                "Script executed from a shell",
                1,
            ),
            alert(
                DetectionId::D1,
                Severity::Info,
                "Script executed from a shell",
                2,
            ),
            alert(DetectionId::Self_, Severity::High, "Hermian is stopping", 3),
            alert(
                DetectionId::D2,
                Severity::High,
                "Root login from a new source",
                24 * 10,
            ),
        ];
        let r = build(
            &alerts,
            None,
            Some(Utc::now() - Duration::days(26)),
            host(),
            7,
            Utc::now(),
        );
        assert_eq!(r.alerts_total, 3);
        assert_eq!(r.alerts_by_severity["HIGH"], 1);
        assert_eq!(r.alerts_by_severity["INFO"], 2);
        assert_eq!(r.alerts_by_severity["CRITICAL"], 0);
        assert_eq!(r.alerts_by_rule[0].title, "Script executed from a shell");
        assert_eq!(r.alerts_by_rule[0].count, 2);
        assert_eq!(r.installed_days, Some(26));
        assert_eq!(r.daemon_uptime_secs, None);
        let st = Style { color: false };
        let text = render(&r, &st);
        let json = serde_json::to_string(&r).unwrap();
        for out in [&text, &json] {
            assert!(!out.contains("secret-host-01"), "{}", out);
            assert!(!out.contains("HER-1"), "{}", out);
        }
        assert!(
            text.contains("3  (0 critical \u{00B7} 1 high \u{00B7} 0 low \u{00B7} 2 info)"),
            "{}",
            text
        );
        assert!(text.contains("Ubuntu 22.04.5 LTS (x86_64)"), "{}", text);
        assert!(text.contains("hermian  report"), "masthead: {}", text);
    }

    #[test]
    fn long_tails_fold_into_other() {
        let alerts: Vec<Alert> = (0..20)
            .map(|i| {
                alert(
                    DetectionId::D3,
                    Severity::Info,
                    &format!("Rule number {}", i),
                    1,
                )
            })
            .collect();
        let r = build(&alerts, None, None, host(), 7, Utc::now());
        assert_eq!(r.alerts_by_rule.len(), MAX_RULES);
        assert_eq!(r.other_rules, 5);
    }
}
