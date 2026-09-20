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

async fn worker(
    mut rx: mpsc::UnboundedReceiver<Msg>,
    mut cfg: NotificationsCfg,
    state: Arc<Mutex<NotifyState>>,
) {
    let mut pending: VecDeque<Alert> = VecDeque::new();
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
                        if alert.severity >= cfg.min_severity() && has_notifying_channel(&cfg) {
                            if pending.len() >= MAX_PENDING {
                                pending.pop_front();
                            }
                            pending.push_back(alert);
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
        // to preserve ordering and avoid hammering a down endpoint.
        let mut delivered_any = false;
        while let Some(alert) = pending.front() {
            match notify(alert, &cfg) {
                Ok(()) => {
                    mark_delivered(&state, alert);
                    pending.pop_front();
                    delivered_any = true;
                }
                Err(e) => {
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
                                e
                            ),
                        );
                    }
                    break;
                }
            }
        }
        if delivered_any || pending.is_empty() {
            failing_since = None;
            failing_alarm_sent = false;
            backoff = Duration::from_secs(5);
        } else {
            backoff = (backoff * 2).min(Duration::from_secs(120));
        }
        if let Ok(mut s) = state.lock() {
            s.pending = pending.len();
        }
        retry = tokio::time::interval(backoff);
        retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        retry.tick().await; // consume the immediate first tick
    }
}

fn has_notifying_channel(cfg: &NotificationsCfg) -> bool {
    cfg.has_channel("webhook") || cfg.has_channel("stdout")
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

/// Notifying channels; returns Err if any configured channel failed.
fn notify(alert: &Alert, cfg: &NotificationsCfg) -> Result<(), String> {
    if cfg.has_channel("stdout") {
        println!("{}", hermian_core::render(alert, Theme::Plain));
    }
    if cfg.has_channel("webhook") {
        webhook::send(alert, &cfg.webhook)?;
    }
    Ok(())
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
