//! `hermian status` and the state snapshot the daemon publishes for it.

use std::collections::BTreeMap;
use std::fs;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::paths;
use crate::ui::{ago, humanize_secs, Style};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StatusState {
    pub version: String,
    pub host: String,
    pub pid: u32,
    pub started_at: DateTime<Utc>,
    pub kernel: String,
    pub ebpf: String,
    pub ebpf_hooks: Vec<String>,
    pub baseline_state: String,
    pub baseline_remaining_minutes: Option<i64>,
    pub detections: BTreeMap<String, String>,
    pub cpu_avg_1h: f64,
    pub rss_mb: u64,
    pub events_processed: u64,
    pub alerts_today: u64,
    pub alerts_by_severity: BTreeMap<String, u64>,
    pub tracked_processes: usize,
    pub watches_active: usize,
    pub watches_failed: usize,
    pub watch_error: String,
    pub channels: Vec<String>,
    pub min_severity: String,
    pub last_delivery: Option<DateTime<Utc>>,
    pub last_delivery_note: String,
    pub failures: u64,
    pub pending_notifications: usize,
    pub last_notify_error: String,
    pub delivered_per_channel: BTreeMap<String, u64>,
    pub config_hash: String,
    pub binary_hash: String,
    pub integrity_ok: bool,
    pub updated_at: DateTime<Utc>,
}

impl Default for StatusState {
    fn default() -> Self {
        StatusState {
            version: String::new(),
            host: String::new(),
            pid: 0,
            started_at: Utc::now(),
            kernel: String::new(),
            ebpf: String::new(),
            ebpf_hooks: Vec::new(),
            baseline_state: String::new(),
            baseline_remaining_minutes: None,
            detections: BTreeMap::new(),
            cpu_avg_1h: 0.0,
            rss_mb: 0,
            events_processed: 0,
            alerts_today: 0,
            alerts_by_severity: BTreeMap::new(),
            tracked_processes: 0,
            watches_active: 0,
            watches_failed: 0,
            watch_error: String::new(),
            channels: Vec::new(),
            min_severity: String::new(),
            last_delivery: None,
            last_delivery_note: String::new(),
            failures: 0,
            pending_notifications: 0,
            last_notify_error: String::new(),
            delivered_per_channel: BTreeMap::new(),
            config_hash: String::new(),
            binary_hash: String::new(),
            integrity_ok: true,
            updated_at: Utc::now(),
        }
    }
}

pub fn write_state(state: &StatusState) -> Result<()> {
    let text = serde_json::to_string_pretty(state)?;
    crate::config::write_secure(&paths::state_file(), &text)
}

pub fn read_state() -> Option<StatusState> {
    let text = fs::read_to_string(paths::state_file()).ok()?;
    serde_json::from_str(&text).ok()
}

pub fn pid_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    // SAFETY: kill with signal 0 only checks existence/permission.
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

const DETECTIONS: &[(&str, &str)] = &[
    ("d1", "Process chains"),
    ("d2", "SSH and authentication"),
    ("d3", "Persistence"),
    ("d4", "Privilege escalation"),
    ("d5", "Network correlation"),
];

pub fn render_status(state: &StatusState, st: &Style) -> String {
    let mut out = String::new();
    let uptime = (Utc::now() - state.started_at).num_seconds().max(0) as u64;

    let health = if !state.integrity_ok {
        st.bad("INTEGRITY FAILURE")
    } else if state.watches_active == 0
        && state
            .detections
            .get("d3")
            .map(|s| s != "disabled")
            .unwrap_or(false)
    {
        st.bad("DEGRADED: FILE WATCHERS DOWN")
    } else if state.failures > 0 || state.pending_notifications > 0 || state.watches_failed > 0 {
        st.warn("DEGRADED")
    } else {
        st.ok("PROTECTED")
    };
    out.push_str(&st.banner(
        &format!("HERMIAN {}", state.version),
        &format!("{} \u{00B7} up {}", state.host, humanize_secs(uptime)),
    ));
    out.push('\n');
    out.push_str(&st.rule());
    out.push('\n');
    out.push_str(&format!("  {}\n\n", health));

    out.push_str(&st.heading("Coverage"));
    out.push('\n');
    for (key, label) in DETECTIONS {
        let src = state.detections.get(*key).cloned().unwrap_or_default();
        let value = if src.is_empty() || src == "disabled" {
            st.dim("disabled")
        } else {
            format!("{} {}", st.ok("on"), st.dim(&src))
        };
        out.push_str(&st.row(label, &value));
        out.push('\n');
    }
    let kernel_line = match state.ebpf.as_str() {
        "full" => format!("{} {}", state.kernel, st.dim("eBPF")),
        _ => format!("{} {}", state.kernel, st.warn("reduced: no eBPF")),
    };
    out.push_str(&st.row("Kernel", &kernel_line));
    out.push('\n');
    let baseline = match state.baseline_remaining_minutes {
        Some(m) => st.warn(&format!("learning, {}h {:02}m remaining", m / 60, m % 60)),
        None => st.dim(&state.baseline_state),
    };
    out.push_str(&st.row("Baseline", &baseline));
    out.push_str("\n\n");

    out.push_str(&st.heading("Today"));
    out.push('\n');
    let mut sev_parts = Vec::new();
    for s in ["CRITICAL", "HIGH", "LOW", "INFO"] {
        if let Some(n) = state.alerts_by_severity.get(s) {
            if *n > 0 {
                let sev: hermian_core::Severity = s.parse().unwrap_or(hermian_core::Severity::Info);
                sev_parts.push(st.sev(sev, &format!("{} {}", n, s.to_lowercase())));
            }
        }
    }
    let alerts_value = if state.alerts_today == 0 {
        st.ok("none")
    } else {
        format!(
            "{}  {}",
            state.alerts_today,
            st.dim(&sev_parts.join(" \u{00B7} "))
        )
    };
    out.push_str(&st.row("Alerts", &alerts_value));
    out.push('\n');
    out.push_str(&st.row("Events processed", &state.events_processed.to_string()));
    out.push('\n');
    out.push_str(&st.row("Processes tracked", &state.tracked_processes.to_string()));
    out.push('\n');
    let watches = if state.watches_failed > 0 {
        format!(
            "{} {}",
            state.watches_active,
            st.warn(&format!(
                "({} failed: {})",
                state.watches_failed, state.watch_error
            ))
        )
    } else {
        state.watches_active.to_string()
    };
    out.push_str(&st.row("File watches", &watches));
    out.push('\n');
    out.push_str(&st.row(
        "Overhead",
        &format!(
            "{:.1}% cpu \u{00B7} {} MB rss",
            state.cpu_avg_1h, state.rss_mb
        ),
    ));
    out.push_str("\n\n");

    out.push_str(&st.heading("Notifications"));
    out.push('\n');
    out.push_str(&st.row(
        "Channels",
        &format!(
            "{} {}",
            state.channels.join(", "),
            st.dim(&format!("(notify at {}+)", state.min_severity))
        ),
    ));
    out.push('\n');
    let last = match &state.last_delivery {
        Some(ts) => format!("{} {}", ago(*ts), st.dim(&state.last_delivery_note)),
        None => st.dim("none yet"),
    };
    out.push_str(&st.row("Last delivery", &last));
    out.push('\n');
    if !state.delivered_per_channel.is_empty() {
        let parts: Vec<String> = state
            .delivered_per_channel
            .iter()
            .map(|(k, v)| format!("{} {}", k, v))
            .collect();
        out.push_str(&st.row("Delivered", &st.dim(&parts.join(" \u{00B7} "))));
        out.push('\n');
    }
    if state.pending_notifications > 0 {
        out.push_str(&st.row(
            "Queued",
            &st.warn(&format!("{} undelivered", state.pending_notifications)),
        ));
        out.push('\n');
    }
    if !state.last_notify_error.is_empty()
        && (state.pending_notifications > 0 || state.failures > 0)
    {
        out.push_str(&st.row("Last error", &st.warn(&state.last_notify_error)));
        out.push('\n');
    }
    if state.failures > 0 {
        out.push_str(&st.row("Delivery failures", &st.warn(&state.failures.to_string())));
        out.push('\n');
    }
    out.push('\n');

    out.push_str(&st.heading("Integrity"));
    out.push('\n');
    out.push_str(&st.row("Binary", &st.dim(&short_hash(&state.binary_hash))));
    out.push('\n');
    out.push_str(&st.row("Config", &st.dim(&short_hash(&state.config_hash))));
    out.push('\n');
    out.push_str(&st.rule());
    out.push('\n');
    if state.alerts_today == 0 {
        out.push_str(&st.dim("Nothing needs your attention."));
    } else {
        out.push_str(&st.dim("Review with: hermian alerts"));
    }
    out.push('\n');
    out
}

fn short_hash(h: &str) -> String {
    if h.len() >= 16 {
        format!("sha256:{}\u{2026}{}", &h[..8], &h[h.len() - 8..])
    } else {
        h.to_string()
    }
}

pub fn cmd_status(json: bool) -> Result<()> {
    let st = Style::detect();
    let state = read_state();
    if json {
        match state {
            Some(s) => println!("{}", serde_json::to_string_pretty(&s)?),
            None => println!("{{\"status\":\"inactive\"}}"),
        }
        return Ok(());
    }
    match state {
        Some(state) => {
            let stale = Utc::now() - state.updated_at > chrono::Duration::minutes(2);
            if stale && !pid_alive(state.pid) {
                println!(
                    "{}",
                    st.banner(&format!("HERMIAN {}", state.version), &st.bad("INACTIVE"))
                );
                println!("{}", st.rule());
                println!("  The daemon is not running. Start it with:\n\n    sudo systemctl start hermian\n");
                println!("  {}", st.dim("Logs: journalctl -u hermian -n 50"));
            } else if stale {
                println!(
                    "{}",
                    st.banner(&format!("HERMIAN {}", state.version), &st.warn("STARTING"))
                );
                println!("{}", st.rule());
                println!("  Run 'hermian status' again in a moment.");
            } else {
                print!("{}", render_status(&state, &st));
            }
        }
        None => {
            println!(
                "{}",
                st.banner(
                    &format!("HERMIAN {}", hermian_core::VERSION),
                    &st.bad("NOT INSTALLED")
                )
            );
            println!("{}", st.rule());
            println!("  The daemon has never run on this host. Install it with:\n\n    sudo hermian enable\n");
        }
    }
    Ok(())
}
