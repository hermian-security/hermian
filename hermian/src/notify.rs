//! Alert delivery.
//!
//! Every alert is persisted as JSON and written to the always-on channels
//! (journald, file). Notifying channels (stdout, webhook) only receive alerts
//! at or above `notifications.min_severity`. Failed deliveries are retried with
//! backoff; if delivery keeps failing for 15 minutes a CRITICAL is logged
//! locally so the operator learns the alert path is broken.

use std::collections::VecDeque;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex, Once};
use std::time::Duration;

use chrono::{DateTime, Utc};
use hermian_core::config::{NotificationsCfg, WebhookCfg};
use hermian_core::{Alert, Severity, Theme};
use tokio::sync::mpsc;

use crate::config;
use crate::paths;

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct NotifyState {
    pub last_delivery: Option<DateTime<Utc>>,
    pub last_delivery_note: String,
    pub failures: u64,
    #[serde(default)]
    pub pending: usize,
    /// Most recent channel error, e.g. "telegram: HTTP 401 Unauthorized".
    #[serde(default)]
    pub last_error: String,
    /// Successful deliveries per channel since the daemon started.
    #[serde(default)]
    pub per_channel: std::collections::BTreeMap<String, u64>,
}

pub struct Notifier {
    tx: mpsc::UnboundedSender<Msg>,
    pub state: Arc<Mutex<NotifyState>>,
}

enum Msg {
    Alert(Alert),
    Reconfigure(NotificationsCfg),
}

static OPENLOG: Once = Once::new();

fn syslog_prio(severity: Severity) -> libc::c_int {
    match severity {
        Severity::Critical => libc::LOG_CRIT,
        Severity::High => libc::LOG_ERR,
        Severity::Low => libc::LOG_WARNING,
        Severity::Info => libc::LOG_INFO,
    }
}

pub fn syslog_msg(severity: Severity, text: &str) -> bool {
    OPENLOG.call_once(|| {
        // SAFETY: static NUL-terminated ident; openlog keeps the pointer.
        unsafe {
            libc::openlog(
                c"hermian".as_ptr(),
                libc::LOG_PID | libc::LOG_NDELAY,
                libc::LOG_DAEMON,
            );
        }
    });
    let Ok(cstr) = std::ffi::CString::new(text) else {
        return false;
    };
    // SAFETY: format string is a static "%s"; cstr outlives the call.
    unsafe {
        libc::syslog(syslog_prio(severity), c"%s".as_ptr(), cstr.as_ptr());
    }
    true
}

impl Notifier {
    pub fn spawn(cfg: NotificationsCfg, initial: NotifyState) -> Notifier {
        let (tx, rx) = mpsc::unbounded_channel();
        let state = Arc::new(Mutex::new(initial));
        let worker_state = state.clone();
        tokio::spawn(async move {
            worker(rx, cfg, worker_state).await;
        });
        Notifier { tx, state }
    }

    pub fn send(&self, alert: Alert) {
        let _ = self.tx.send(Msg::Alert(alert));
    }

    pub fn reconfigure(&self, cfg: NotificationsCfg) {
        let _ = self.tx.send(Msg::Reconfigure(cfg));
    }

    pub fn snapshot(&self) -> NotifyState {
        self.state.lock().map(|s| s.clone()).unwrap_or_default()
    }
}

/// Alerts waiting for a notifying channel to accept them.
const MAX_PENDING: usize = 500;

/// Channels that deliver to a human (gated by `min_severity`, retried).
pub const NOTIFYING_CHANNELS: &[&str] = &["telegram", "email", "webhook", "stdout"];

/// An alert plus the channels that have not yet accepted it, so a failure on
/// one channel never causes a duplicate on another.
struct Pending {
    alert: Alert,
    owed: Vec<&'static str>,
}

async fn worker(
    mut rx: mpsc::UnboundedReceiver<Msg>,
    mut cfg: NotificationsCfg,
    state: Arc<Mutex<NotifyState>>,
) {
    let mut pending: VecDeque<Pending> = VecDeque::new();
    let mut failing_since: Option<DateTime<Utc>> = None;
    let mut failing_alarm_sent = false;
    let mut backoff = Duration::from_secs(5);
    let mut retry = tokio::time::interval(backoff);
    retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            maybe = rx.recv() => {
                match maybe {
                    Some(Msg::Alert(alert)) => {
                        // Always-on channels + JSON persistence happen immediately and
                        // never block on network.
                        let rendered_plain = hermian_core::render(&alert, Theme::Plain);
                        persist(&alert, &rendered_plain, &cfg);
                        let owed = notifying_channels(&cfg);
                        if alert.severity >= cfg.min_severity() && !owed.is_empty() {
                            if pending.len() >= MAX_PENDING {
                                pending.pop_front();
                            }
                            pending.push_back(Pending { alert, owed });
                        } else {
                            mark_delivered(&state, &alert);
                        }
                    }
                    Some(Msg::Reconfigure(new_cfg)) => {
                        cfg = new_cfg;
                    }
                    None => return,
                }
            }
            _ = retry.tick() => {}
        }

        // Attempt delivery of everything pending, in order, stop at first failure
        // to preserve ordering and avoid hammering a down endpoint. Network I/O
        // runs on the blocking pool so the daemon's event loop is never stalled
        // by a slow SMTP server.
        let mut delivered_any = false;
        let mut last_error = String::new();
        while let Some(p) = pending.front_mut() {
            let alert = p.alert.clone();
            let owed = p.owed.clone();
            let cfg_c = cfg.clone();
            let results = tokio::task::spawn_blocking(move || {
                owed.iter()
                    .map(|ch| (*ch, notify_one(ch, &alert, &cfg_c)))
                    .collect::<Vec<_>>()
            })
            .await
            .unwrap_or_default();
            let mut still_owed = Vec::new();
            for (ch, r) in results {
                match r {
                    Ok(()) => {
                        delivered_any = true;
                        if let Ok(mut s) = state.lock() {
                            *s.per_channel.entry(ch.to_string()).or_default() += 1;
                        }
                    }
                    Err(e) => {
                        last_error = format!("{}: {}", ch, e);
                        if let Ok(mut s) = state.lock() {
                            s.last_error = last_error.clone();
                        }
                        still_owed.push(ch);
                    }
                }
            }
            if still_owed.is_empty() {
                mark_delivered(&state, &p.alert);
                pending.pop_front();
            } else {
                p.owed = still_owed;
                break;
            }
        }
        if pending.is_empty() {
            failing_since = None;
            failing_alarm_sent = false;
            backoff = Duration::from_secs(5);
        } else {
            let now = Utc::now();
            let since = *failing_since.get_or_insert(now);
            if now - since > chrono::Duration::minutes(15) && !failing_alarm_sent {
                failing_alarm_sent = true;
                if let Ok(mut s) = state.lock() {
                    s.failures += 1;
                }
                syslog_msg(
                    Severity::Critical,
                    &format!(
                        "HERMIAN CRITICAL: alert notification delivery has been failing for more than 15 minutes ({} queued, last error: {})",
                        pending.len(),
                        last_error
                    ),
                );
            }
            backoff = if delivered_any {
                Duration::from_secs(5)
            } else {
                (backoff * 2).min(Duration::from_secs(120))
            };
        }
        if let Ok(mut s) = state.lock() {
            s.pending = pending.len();
        }
        retry = tokio::time::interval(backoff);
        retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        retry.tick().await; // consume the immediate first tick
    }
}

fn notifying_channels(cfg: &NotificationsCfg) -> Vec<&'static str> {
    NOTIFYING_CHANNELS
        .iter()
        .copied()
        .filter(|c| cfg.has_channel(c))
        .collect()
}

/// Deliver one alert to one notifying channel.
pub fn notify_one(channel: &str, alert: &Alert, cfg: &NotificationsCfg) -> Result<(), String> {
    match channel {
        "stdout" => {
            println!("{}", hermian_core::render(alert, Theme::Plain));
            Ok(())
        }
        "webhook" => webhook::send(alert, &cfg.webhook),
        "telegram" => crate::channels::telegram::send(alert, &cfg.telegram),
        "email" => crate::channels::email::send(alert, &cfg.email),
        other => Err(format!("unknown channel {}", other)),
    }
}

fn mark_delivered(state: &Arc<Mutex<NotifyState>>, alert: &Alert) {
    if let Ok(mut s) = state.lock() {
        s.last_delivery = Some(Utc::now());
        s.last_delivery_note = format!("{} {}", alert.ref_id, alert.title);
    }
}

/// Always-on: JSON record, journald, alerts.log.
fn persist(alert: &Alert, rendered: &str, cfg: &NotificationsCfg) {
    save_alert_json(alert);
    if cfg.has_channel("journald") {
        // journald gets the compact headline as the message and the full body
        // so `journalctl -t hermian` stays scannable.
        syslog_msg(alert.severity, &alert.headline());
        syslog_msg(alert.severity, rendered);
    }
    if cfg.has_channel("file") {
        if let Err(e) = append_alert_log(rendered) {
            eprintln!("hermian: failed to write alert log: {}", e);
        }
    }
}

fn append_alert_log(rendered: &str) -> anyhow::Result<()> {
    let path = paths::alerts_log();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    config::write_secure_append(&path, &format!("{}\n", rendered))
}

fn save_alert_json(alert: &Alert) {
    let dir = paths::alerts_dir();
    if fs::create_dir_all(&dir).is_err() {
        return;
    }
    let path = dir.join(format!("{}.json", alert.ref_id));
    if let Ok(text) = serde_json::to_string_pretty(alert) {
        let _ = config::write_secure(&path, &text);
    }
}

pub fn ensure_log_dir() -> anyhow::Result<()> {
    let dir = paths::log_dir();
    fs::create_dir_all(&dir)?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

pub mod webhook {
    use super::*;
    use serde_json::{json, Value};

    fn colour(sev: Severity) -> u32 {
        match sev {
            Severity::Critical => 0xD62828,
            Severity::High => 0xF77F00,
            Severity::Low => 0xFCBF49,
            Severity::Info => 0x8D99AE,
        }
    }

    fn slack_colour(sev: Severity) -> &'static str {
        match sev {
            Severity::Critical => "#D62828",
            Severity::High => "#F77F00",
            Severity::Low => "#FCBF49",
            Severity::Info => "#8D99AE",
        }
    }

    fn chain_line(alert: &Alert) -> String {
        alert
            .chain
            .iter()
            .map(|n| format!("{}({})", n.comm, n.pid))
            .collect::<Vec<_>>()
            .join(" \u{2192} ")
    }

    pub fn payload(alert: &Alert, format: &str) -> Value {
        let compact = hermian_core::render(alert, Theme::Compact);
        let title = format!("{} \u{00B7} {}", alert.severity.as_str(), alert.title);
        match format {
            "slack" => {
                let mut fields = vec![
                    json!({"title": "Host", "value": alert.host, "short": true}),
                    json!({"title": "Detection", "value": format!("{} {}", alert.detection.short(), alert.detection.name()), "short": true}),
                ];
                if !alert.chain.is_empty() {
                    fields.push(json!({"title": "Process chain", "value": format!("`{}`", chain_line(alert)), "short": false}));
                }
                for f in &alert.facts {
                    fields.push(json!({"title": f.label, "value": f.value, "short": true}));
                }
                let mut text = alert.what.clone();
                if let Some(a) = alert.actions.first() {
                    text.push_str(&format!("\n*Next:* {}", a));
                }
                json!({
                    "text": format!("HERMIAN {}", title),
                    "attachments": [{
                        "color": slack_colour(alert.severity),
                        "title": title,
                        "text": text,
                        "fields": fields,
                        "footer": format!("hermian show {}", alert.ref_id),
                        "ts": alert.ts.timestamp(),
                    }]
                })
            }
            "discord" => {
                let mut fields = vec![
                    json!({"name": "Host", "value": alert.host, "inline": true}),
                    json!({"name": "Detection", "value": format!("{} {}", alert.detection.short(), alert.detection.name()), "inline": true}),
                ];
                if !alert.chain.is_empty() {
                    fields.push(json!({"name": "Process chain", "value": format!("`{}`", chain_line(alert)), "inline": false}));
                }
                for f in &alert.facts {
                    fields.push(json!({"name": f.label, "value": f.value, "inline": true}));
                }
                let mut description = alert.what.clone();
                if !alert.actions.is_empty() {
                    description.push_str("\n\n**Recommended action**\n");
                    for (i, a) in alert.actions.iter().enumerate() {
                        description.push_str(&format!("{}. {}\n", i + 1, a));
                    }
                }
                json!({
                    "username": "HERMIAN",
                    "embeds": [{
                        "title": title,
                        "description": description,
                        "color": colour(alert.severity),
                        "fields": fields,
                        "footer": {"text": format!("{}  \u{00B7}  hermian show {}", alert.ref_id, alert.ref_id)},
                        "timestamp": alert.ts.to_rfc3339(),
                    }]
                })
            }
            "ntfy" => json!({
                "title": format!("HERMIAN {} on {}", alert.severity.as_str(), alert.host),
                "message": compact,
                "priority": match alert.severity {
                    Severity::Critical => 5,
                    Severity::High => 4,
                    Severity::Low => 3,
                    Severity::Info => 2,
                },
                "tags": [alert.detection.short().to_lowercase(), alert.severity.as_str().to_lowercase()],
            }),
            _ => json!({
                "source": "hermian",
                "version": hermian_core::VERSION,
                "alert": alert,
                "text": compact,
            }),
        }
    }

    pub fn send(alert: &Alert, cfg: &WebhookCfg) -> Result<(), String> {
        let body = payload(alert, &cfg.format);
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(cfg.timeout_secs.clamp(2, 60)))
            .user_agent(&format!("hermian/{}", hermian_core::VERSION))
            .build();
        let mut req = agent.post(&cfg.url).set("Content-Type", "application/json");
        if !cfg.token.is_empty() {
            req = req.set("Authorization", &format!("Bearer {}", cfg.token));
        }
        match req.send_json(body) {
            Ok(_) => Ok(()),
            Err(ureq::Error::Status(code, _)) => Err(format!("webhook returned HTTP {}", code)),
            Err(e) => Err(format!("webhook request failed: {}", e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hermian_core::{DetectionId, Finding};

    fn alert() -> Alert {
        let f = Finding::new(
            DetectionId::D1,
            Severity::High,
            "Web server spawned a shell",
            "d1|x",
        )
        .what("nginx spawned bash.")
        .fact("Command", "bash -c id")
        .action("Review access logs.");
        Alert::from_finding(f, "HER-2025-0101-001".into(), "web-01".into(), Utc::now())
    }

    #[test]
    fn webhook_payloads_have_expected_shape() {
        let a = alert();
        let g = webhook::payload(&a, "generic");
        assert_eq!(g["source"], "hermian");
        assert_eq!(g["alert"]["ref_id"], "HER-2025-0101-001");
        let s = webhook::payload(&a, "slack");
        assert!(s["attachments"][0]["title"]
            .as_str()
            .unwrap()
            .contains("HIGH"));
        let d = webhook::payload(&a, "discord");
        assert_eq!(d["embeds"][0]["color"], 0xF77F00);
        let n = webhook::payload(&a, "ntfy");
        assert_eq!(n["priority"], 4);
    }
}
