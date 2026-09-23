//! Alert delivery.
//!
//! Every alert is persisted as JSON and written to the always-on channels
//! (journald, file). Notifying channels (stdout, webhook) only receive alerts
//! at or above `notifications.min_severity`. Each notifying channel has its own
//! queue and backoff, so one broken channel doesn't hold up the others. Alerts
//! a channel will never accept (HTTP 400/413, SMTP 5xx) are dropped for that
//! channel; other failures are retried. If a channel keeps failing for 15
//! minutes a CRITICAL is logged locally so the operator learns the alert path
//! is broken.

use std::collections::{BTreeMap, VecDeque};
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
    pub per_channel: BTreeMap<String, u64>,
    /// Alerts each notifying channel still owes.
    #[serde(default)]
    pub pending_by_channel: BTreeMap<String, usize>,
    /// Alerts a channel gave up on: queue overflow or a permanent rejection.
    #[serde(default)]
    pub dropped_by_channel: BTreeMap<String, u64>,
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

/// Alerts waiting for one notifying channel to accept them.
const MAX_PENDING: usize = 500;

/// Channels that deliver to a human (gated by `min_severity`, retried).
pub const NOTIFYING_CHANNELS: &[&str] = &["telegram", "email", "webhook", "stdout"];

const FIRST_BACKOFF: Duration = Duration::from_secs(5);
const MAX_BACKOFF: Duration = Duration::from_secs(120);

/// A delivery failure. Permanent ones (a request the endpoint will never
/// accept, e.g. HTTP 400/413 or an SMTP 5xx) drop the alert for that channel
/// instead of blocking everything queued behind it.
#[derive(Debug, Clone)]
pub struct SendError {
    pub msg: String,
    pub permanent: bool,
}

impl SendError {
    pub fn transient(msg: impl Into<String>) -> Self {
        SendError {
            msg: msg.into(),
            permanent: false,
        }
    }

    pub fn permanent(msg: impl Into<String>) -> Self {
        SendError {
            msg: msg.into(),
            permanent: true,
        }
    }

    /// Classify an HTTP error status. Auth, not-found and rate-limit errors
    /// stay transient: fixing the config (or waiting) makes them succeed.
    pub fn http(code: u16, msg: impl Into<String>) -> Self {
        SendError {
            msg: msg.into(),
            permanent: matches!(code, 400 | 413 | 414 | 415 | 422),
        }
    }
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.msg)
    }
}

enum ChanMsg {
    Alert(Box<Alert>),
    Config(Box<NotificationsCfg>),
}

/// Persist every alert right away, then hand notifying channels their copy.
/// Each channel runs as its own task with its own queue and backoff, so a
/// broken or slow channel never delays the others (or local persistence).
async fn worker(
    mut rx: mpsc::UnboundedReceiver<Msg>,
    mut cfg: NotificationsCfg,
    state: Arc<Mutex<NotifyState>>,
) {
    let mut channels: BTreeMap<&'static str, mpsc::UnboundedSender<ChanMsg>> = BTreeMap::new();
    sync_channels(&mut channels, &cfg, &state);
    while let Some(msg) = rx.recv().await {
        match msg {
            Msg::Alert(alert) => {
                let rendered_plain = hermian_core::render(&alert, Theme::Plain);
                persist(&alert, &rendered_plain, &cfg);
                if alert.severity >= cfg.min_severity() && !channels.is_empty() {
                    for tx in channels.values() {
                        let _ = tx.send(ChanMsg::Alert(Box::new(alert.clone())));
                    }
                } else {
                    mark_delivered(&state, &alert);
                }
            }
            Msg::Reconfigure(new_cfg) => {
                cfg = new_cfg;
                sync_channels(&mut channels, &cfg, &state);
            }
        }
    }
}

/// Start tasks for newly enabled channels, stop removed ones (dropping the
/// sender ends the task and its queue), and pass the new config to the rest.
fn sync_channels(
    channels: &mut BTreeMap<&'static str, mpsc::UnboundedSender<ChanMsg>>,
    cfg: &NotificationsCfg,
    state: &Arc<Mutex<NotifyState>>,
) {
    let wanted = notifying_channels(cfg);
    channels.retain(|name, _| wanted.contains(name));
    if let Ok(mut s) = state.lock() {
        s.pending_by_channel
            .retain(|name, _| wanted.contains(&name.as_str()));
        s.pending = s.pending_by_channel.values().sum();
    }
    for name in wanted {
        match channels.get(name) {
            Some(tx) => {
                let _ = tx.send(ChanMsg::Config(Box::new(cfg.clone())));
            }
            None => {
                let (tx, rx) = mpsc::unbounded_channel();
                tokio::spawn(channel_task(name, rx, cfg.clone(), state.clone()));
                channels.insert(name, tx);
            }
        }
    }
}

struct ChannelQueue {
    name: &'static str,
    queue: VecDeque<Alert>,
    cfg: NotificationsCfg,
    backoff: Duration,
    failing_since: Option<DateTime<Utc>>,
    alarm_sent: bool,
    /// Alerts given up on since start (overflow or permanent rejection).
    dropped: u64,
}

impl ChannelQueue {
    /// Make room when the queue is full: drop the oldest alert below
    /// CRITICAL, or the oldest overall if everything queued is CRITICAL.
    fn make_room(&mut self) {
        if self.queue.len() < MAX_PENDING {
            return;
        }
        let victim = self
            .queue
            .iter()
            .position(|a| a.severity < Severity::Critical)
            .unwrap_or(0);
        if let Some(a) = self.queue.remove(victim) {
            self.note_drop(&a, "queue full");
        }
    }

    fn note_drop(&mut self, alert: &Alert, why: &str) {
        self.dropped += 1;
        // Every drop is logged locally, so the alert isn't lost outright.
        syslog_msg(
            Severity::High,
            &format!(
                "hermian: {} dropped alert {} ({}): {} ({} dropped since start)",
                self.name, alert.ref_id, alert.severity, why, self.dropped
            ),
        );
    }

    /// Returns false once the channel has been removed.
    fn take(&mut self, msg: Option<ChanMsg>) -> bool {
        match msg {
            Some(ChanMsg::Alert(a)) => {
                self.make_room();
                self.queue.push_back(*a);
                true
            }
            Some(ChanMsg::Config(c)) => {
                self.cfg = *c;
                // New settings deserve a prompt retry.
                self.backoff = FIRST_BACKOFF;
                true
            }
            None => false,
        }
    }

    fn publish(&self, state: &Arc<Mutex<NotifyState>>) {
        if let Ok(mut s) = state.lock() {
            s.pending_by_channel
                .insert(self.name.to_string(), self.queue.len());
            s.pending = s.pending_by_channel.values().sum();
            if self.dropped > 0 {
                s.dropped_by_channel
                    .insert(self.name.to_string(), self.dropped);
            }
        }
    }

    fn record_error(&mut self, e: &SendError, state: &Arc<Mutex<NotifyState>>) {
        let err = format!("{}: {}", self.name, e);
        if let Ok(mut s) = state.lock() {
            s.last_error = err.clone();
        }
        let now = Utc::now();
        let since = *self.failing_since.get_or_insert(now);
        if now - since > chrono::Duration::minutes(15) && !self.alarm_sent {
            self.alarm_sent = true;
            if let Ok(mut s) = state.lock() {
                s.failures += 1;
            }
            syslog_msg(
                Severity::Critical,
                &format!(
                    "HERMIAN CRITICAL: {} alert delivery has been failing for more than 15 minutes \
                     ({} queued, last error: {})",
                    self.name,
                    self.queue.len(),
                    err
                ),
            );
        }
    }
}

type SendFn = fn(&str, &Alert, &NotificationsCfg) -> Result<(), SendError>;

async fn channel_task(
    name: &'static str,
    rx: mpsc::UnboundedReceiver<ChanMsg>,
    cfg: NotificationsCfg,
    state: Arc<Mutex<NotifyState>>,
) {
    run_channel(name, rx, cfg, state, send_classified).await
}

async fn run_channel(
    name: &'static str,
    mut rx: mpsc::UnboundedReceiver<ChanMsg>,
    cfg: NotificationsCfg,
    state: Arc<Mutex<NotifyState>>,
    send: SendFn,
) {
    let mut q = ChannelQueue {
        name,
        queue: VecDeque::new(),
        cfg,
        backoff: FIRST_BACKOFF,
        failing_since: None,
        alarm_sent: false,
        dropped: 0,
    };
    loop {
        // Pick up everything already queued without waiting.
        loop {
            match rx.try_recv() {
                Ok(m) => {
                    q.take(Some(m));
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => return,
            }
        }
        q.publish(&state);
        let Some(alert) = q.queue.front().cloned() else {
            if !q.take(rx.recv().await) {
                return;
            }
            continue;
        };
        let cfg = q.cfg.clone();
        let result = tokio::task::spawn_blocking(move || send(name, &alert, &cfg))
            .await
            // A panicking send is a failure, not a delivery.
            .unwrap_or_else(|e| Err(SendError::transient(format!("send panicked: {}", e))));
        match result {
            Ok(()) => {
                if let Some(a) = q.queue.pop_front() {
                    mark_delivered(&state, &a);
                }
                if let Ok(mut s) = state.lock() {
                    *s.per_channel.entry(name.to_string()).or_default() += 1;
                }
                q.backoff = FIRST_BACKOFF;
                q.failing_since = None;
                q.alarm_sent = false;
            }
            Err(e) if e.permanent => {
                if let Some(a) = q.queue.pop_front() {
                    q.note_drop(&a, &e.msg);
                }
                q.record_error(&e, &state);
            }
            Err(e) => {
                q.record_error(&e, &state);
                q.publish(&state);
                let deadline = tokio::time::Instant::now() + q.backoff;
                q.backoff = (q.backoff * 2).min(MAX_BACKOFF);
                // New alerts join the queue but don't cut the backoff short;
                // a config change does.
                loop {
                    tokio::select! {
                        m = rx.recv() => {
                            let is_config = matches!(m, Some(ChanMsg::Config(_)));
                            if !q.take(m) {
                                return;
                            }
                            q.publish(&state);
                            if is_config {
                                break;
                            }
                        }
                        _ = tokio::time::sleep_until(deadline) => break,
                    }
                }
            }
        }
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
    send_classified(channel, alert, cfg).map_err(|e| e.msg)
}

fn send_classified(channel: &str, alert: &Alert, cfg: &NotificationsCfg) -> Result<(), SendError> {
    match channel {
        "stdout" => {
            println!("{}", hermian_core::render(alert, Theme::Plain));
            Ok(())
        }
        "webhook" => webhook::send(alert, &cfg.webhook),
        "telegram" => crate::channels::telegram::send(alert, &cfg.telegram),
        "email" => crate::channels::email::send(alert, &cfg.email),
        other => Err(SendError::permanent(format!("unknown channel {}", other))),
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

    /// `scheme://host[:port]` only. Slack/Discord/ntfy webhook URLs carry
    /// their secret in the path or query, so the full URL must never be
    /// shown in status, logs or errors.
    pub fn display_url(url: &str) -> String {
        match url.split_once("://") {
            Some((scheme, rest)) => {
                let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
                let host = authority.rsplit('@').next().unwrap_or(authority);
                format!("{}://{}/…", scheme, host)
            }
            None => "<webhook>".to_string(),
        }
    }

    /// ureq errors include the request URL; replace it (and the bearer
    /// token, should it ever appear) before the text goes anywhere.
    fn redact(cfg: &WebhookCfg, e: impl std::fmt::Display) -> String {
        let mut s = e.to_string();
        if !cfg.url.is_empty() {
            s = s.replace(&cfg.url, &display_url(&cfg.url));
        }
        if !cfg.token.is_empty() {
            s = s.replace(&cfg.token, "<token>");
        }
        s
    }

    pub fn send(alert: &Alert, cfg: &WebhookCfg) -> Result<(), SendError> {
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
            Err(ureq::Error::Status(code, _)) => Err(SendError::http(
                code,
                format!("webhook returned HTTP {}", code),
            )),
            Err(e) => Err(SendError::transient(format!(
                "webhook request failed: {}",
                redact(cfg, e)
            ))),
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

    #[test]
    fn webhook_urls_are_never_shown_in_full() {
        assert_eq!(
            webhook::display_url("https://hooks.slack.com/services/T0/B0/SECRET"),
            "https://hooks.slack.com/…"
        );
        assert_eq!(
            webhook::display_url("https://u:pw@ntfy.example:8443/topic?auth=x"),
            "https://ntfy.example:8443/…"
        );
    }

    fn queue() -> ChannelQueue {
        ChannelQueue {
            name: "webhook",
            queue: VecDeque::new(),
            cfg: NotificationsCfg::default(),
            backoff: FIRST_BACKOFF,
            failing_since: None,
            alarm_sent: false,
            dropped: 0,
        }
    }

    #[test]
    fn a_full_queue_sheds_non_critical_alerts_first() {
        let mut q = queue();
        let mut crit = alert();
        crit.severity = Severity::Critical;
        crit.ref_id = "HER-CRIT".into();
        q.take(Some(ChanMsg::Alert(Box::new(crit))));
        for i in 0..MAX_PENDING + 10 {
            let mut a = alert();
            a.ref_id = format!("HER-{}", i);
            q.take(Some(ChanMsg::Alert(Box::new(a))));
        }
        assert_eq!(q.queue.len(), MAX_PENDING);
        assert_eq!(q.dropped, 11);
        assert_eq!(q.queue.front().unwrap().ref_id, "HER-CRIT");
    }

    #[test]
    fn http_errors_are_classified() {
        assert!(SendError::http(400, "x").permanent);
        assert!(SendError::http(413, "x").permanent);
        for code in [401, 403, 404, 408, 429, 500, 502, 503] {
            assert!(!SendError::http(code, "x").permanent, "{}", code);
        }
    }

    fn with_ref(r: &str) -> Alert {
        let mut a = alert();
        a.ref_id = r.into();
        a
    }

    fn reject_bad(_: &str, a: &Alert, _: &NotificationsCfg) -> Result<(), SendError> {
        if a.ref_id.ends_with("BAD") {
            Err(SendError::permanent("HTTP 400 message is too long"))
        } else {
            Ok(())
        }
    }

    fn always_down(_: &str, _: &Alert, _: &NotificationsCfg) -> Result<(), SendError> {
        Err(SendError::transient("connection refused"))
    }

    fn panics(_: &str, _: &Alert, _: &NotificationsCfg) -> Result<(), SendError> {
        panic!("boom")
    }

    async fn settle() {
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn permanent_failure_does_not_block_the_queue() {
        let state = Arc::new(Mutex::new(NotifyState::default()));
        let (tx, rx) = mpsc::unbounded_channel();
        for r in ["HER-1-BAD", "HER-2", "HER-3"] {
            tx.send(ChanMsg::Alert(Box::new(with_ref(r)))).unwrap();
        }
        tokio::spawn(run_channel(
            "webhook",
            rx,
            NotificationsCfg::default(),
            state.clone(),
            reject_bad,
        ));
        settle().await;
        let s = state.lock().unwrap().clone();
        assert_eq!(s.per_channel.get("webhook"), Some(&2), "{:?}", s);
        assert_eq!(s.pending, 0);
        assert!(s.last_error.contains("too long"), "{:?}", s.last_error);
        assert_eq!(s.dropped_by_channel.get("webhook"), Some(&1));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_down_channel_does_not_delay_another() {
        let state = Arc::new(Mutex::new(NotifyState::default()));
        let (down_tx, down_rx) = mpsc::unbounded_channel();
        let (up_tx, up_rx) = mpsc::unbounded_channel();
        tokio::spawn(run_channel(
            "telegram",
            down_rx,
            NotificationsCfg::default(),
            state.clone(),
            always_down,
        ));
        tokio::spawn(run_channel(
            "email",
            up_rx,
            NotificationsCfg::default(),
            state.clone(),
            reject_bad,
        ));
        for r in ["HER-1", "HER-2"] {
            down_tx.send(ChanMsg::Alert(Box::new(with_ref(r)))).unwrap();
            up_tx.send(ChanMsg::Alert(Box::new(with_ref(r)))).unwrap();
        }
        settle().await;
        let s = state.lock().unwrap().clone();
        assert_eq!(s.per_channel.get("email"), Some(&2), "{:?}", s);
        assert_eq!(s.per_channel.get("telegram"), None);
        assert_eq!(s.pending_by_channel.get("telegram"), Some(&2));
        assert_eq!(s.pending, 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_panicking_send_is_not_a_delivery() {
        let state = Arc::new(Mutex::new(NotifyState::default()));
        let (tx, rx) = mpsc::unbounded_channel();
        tx.send(ChanMsg::Alert(Box::new(with_ref("HER-1"))))
            .unwrap();
        tokio::spawn(run_channel(
            "webhook",
            rx,
            NotificationsCfg::default(),
            state.clone(),
            panics,
        ));
        settle().await;
        let s = state.lock().unwrap().clone();
        assert!(s.last_delivery.is_none(), "{:?}", s);
        assert_eq!(s.pending, 1);
    }
}
