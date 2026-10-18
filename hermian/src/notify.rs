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
use std::path::{Path, PathBuf};
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
    /// Channels that just passed 15 minutes of failures, with their last
    /// error, for the daemon to page about (see `take_failing`).
    #[serde(skip)]
    pub newly_failing: Vec<(String, String)>,
}

pub struct Notifier {
    tx: mpsc::Sender<Msg>,
    pub state: Arc<Mutex<NotifyState>>,
}

/// Alerts waiting to be persisted and fanned out. Bounded: if persistence
/// stalls (a hung disk) during an alert flood, memory mustn't grow forever.
const NOTIFIER_QUEUE: usize = 8192;

// Both are sent by value on purpose: alerts are the hot path and stay
// unboxed, and a reconfigure is rare enough that its size doesn't matter.
#[allow(clippy::large_enum_variant)]
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
        let (tx, rx) = mpsc::channel(NOTIFIER_QUEUE);
        let state = Arc::new(Mutex::new(initial));
        let worker_state = state.clone();
        tokio::spawn(async move {
            worker(rx, cfg, worker_state).await;
        });
        Notifier { tx, state }
    }

    pub fn send(&self, alert: Alert) {
        if let Err(mpsc::error::TrySendError::Full(Msg::Alert(a))) =
            self.tx.try_send(Msg::Alert(alert))
        {
            // Still logged locally, so the alert isn't lost outright.
            syslog_msg(
                a.severity,
                &format!("hermian: alert queue full, not persisted: {}", a.headline()),
            );
            if let Ok(mut s) = self.state.lock() {
                *s.dropped_by_channel.entry("queue".to_string()).or_default() += 1;
            }
        }
    }

    pub fn reconfigure(&self, cfg: NotificationsCfg) {
        // In order with alerts when there's room (the reload notice must go
        // to the new channels); config changes are rare and must not be lost,
        // so wait for room otherwise.
        if let Err(mpsc::error::TrySendError::Full(m)) = self.tx.try_send(Msg::Reconfigure(cfg)) {
            let tx = self.tx.clone();
            tokio::spawn(async move {
                let _ = tx.send(m).await;
            });
        }
    }

    /// Channels that started failing for good since the last call.
    pub fn take_failing(&self) -> Vec<(String, String)> {
        self.state
            .lock()
            .map(|mut s| std::mem::take(&mut s.newly_failing))
            .unwrap_or_default()
    }

    pub fn snapshot(&self) -> NotifyState {
        self.state.lock().map(|s| s.clone()).unwrap_or_default()
    }

    /// Wait until `ref_id` has reached at least one notifying channel (or
    /// was persisted locally, if it's below `min_severity` or no channel is
    /// set up), up to `timeout`. Returns whether it got there.
    pub async fn wait_delivered(&self, ref_id: &str, timeout: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        let prefix = format!("{} ", ref_id);
        loop {
            let done = self
                .state
                .lock()
                .map(|s| s.last_delivery_note.starts_with(&prefix))
                .unwrap_or(false);
            if done {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
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
    mut rx: mpsc::Receiver<Msg>,
    mut cfg: NotificationsCfg,
    state: Arc<Mutex<NotifyState>>,
) {
    let mut channels: BTreeMap<&'static str, mpsc::UnboundedSender<ChanMsg>> = BTreeMap::new();
    sync_channels(&mut channels, &cfg, &state);
    while let Some(msg) = rx.recv().await {
        match msg {
            Msg::Alert(alert) => {
                // fsync'd file writes and syslog: off the async workers.
                let (a, c) = (alert.clone(), cfg.clone());
                let _ = tokio::task::spawn_blocking(move || {
                    let rendered_plain = hermian_core::render(&a, Theme::Plain);
                    persist(&a, &rendered_plain, &c);
                })
                .await;
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

/// One alert waiting for a channel, with its on-disk copy. The copy makes
/// delivery survive a daemon restart (at-least-once: a crash mid-send can
/// duplicate an alert, never lose one).
struct Pending {
    alert: Alert,
    file: Option<PathBuf>,
}

struct ChannelQueue {
    name: &'static str,
    queue: VecDeque<Pending>,
    /// Where queued alerts are persisted; `None` disables the disk copy.
    pending_dir: Option<PathBuf>,
    cfg: NotificationsCfg,
    backoff: Duration,
    failing_since: Option<DateTime<Utc>>,
    alarm_sent: bool,
    /// Alerts given up on since start (overflow or permanent rejection).
    dropped: u64,
}

impl ChannelQueue {
    /// Persist `alert` so it survives a restart, returning the file to
    /// delete on delivery. Best-effort: without it, delivery still works
    /// but a crash loses the alert.
    fn save(&self, alert: &Alert) -> Option<PathBuf> {
        let dir = self.pending_dir.as_ref()?;
        let result = (|| -> anyhow::Result<PathBuf> {
            fs::create_dir_all(dir)?;
            let text = serde_json::to_string_pretty(alert)?;
            let mut path = dir.join(format!(
                "{}-{}.json",
                alert.ts.timestamp_millis(),
                alert.ref_id
            ));
            let mut n = 1;
            while path.exists() && n < 1000 {
                path = dir.join(format!(
                    "{}-{}.{}.json",
                    alert.ts.timestamp_millis(),
                    alert.ref_id,
                    n
                ));
                n += 1;
            }
            config::write_secure(&path, &text)?;
            Ok(path)
        })();
        match result {
            Ok(path) => Some(path),
            Err(e) => {
                syslog_msg(
                    Severity::High,
                    &format!(
                        "hermian: {} could not persist queued alert {}: {:#}",
                        self.name, alert.ref_id, e
                    ),
                );
                None
            }
        }
    }

    fn forget(file: &Option<PathBuf>) {
        if let Some(p) = file {
            let _ = fs::remove_file(p);
        }
    }

    /// Make room when the queue is full: drop the oldest alert below
    /// CRITICAL, or the oldest overall if everything queued is CRITICAL.
    fn make_room(&mut self) {
        if self.queue.len() < MAX_PENDING {
            return;
        }
        let victim = self
            .queue
            .iter()
            .position(|p| p.alert.severity < Severity::Critical)
            .unwrap_or(0);
        if let Some(p) = self.queue.remove(victim) {
            Self::forget(&p.file);
            self.note_drop(&p.alert, "queue full");
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
                let file = self.save(&a);
                self.queue.push_back(Pending { alert: *a, file });
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
                s.newly_failing.push((self.name.to_string(), e.msg.clone()));
            }
            syslog_msg(
                Severity::Critical,
                &format!(
                    "Hermian CRITICAL: {} alert delivery has been failing for more than 15 minutes \
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

/// Alerts a previous run left on disk, oldest first. Files that don't parse
/// are removed, not retried forever.
fn load_pending(dir: &Path) -> VecDeque<Pending> {
    let Ok(entries) = fs::read_dir(dir) else {
        return VecDeque::new();
    };
    let mut files: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .collect();
    files.sort();
    // Over the cap, the oldest go: they matter least, and the alert store
    // still has them.
    while files.len() > MAX_PENDING {
        let _ = fs::remove_file(files.remove(0));
    }
    let mut out = VecDeque::new();
    for path in files {
        match fs::read_to_string(&path)
            .ok()
            .and_then(|t| serde_json::from_str::<Alert>(&t).ok())
        {
            Some(alert) => out.push_back(Pending {
                alert,
                file: Some(path),
            }),
            None => {
                let _ = fs::remove_file(&path);
            }
        }
    }
    out
}

async fn channel_task(
    name: &'static str,
    rx: mpsc::UnboundedReceiver<ChanMsg>,
    cfg: NotificationsCfg,
    state: Arc<Mutex<NotifyState>>,
) {
    run_channel(
        name,
        rx,
        cfg,
        state,
        Some(paths::pending_dir_channel(name)),
        send_classified,
    )
    .await
}

async fn run_channel(
    name: &'static str,
    mut rx: mpsc::UnboundedReceiver<ChanMsg>,
    cfg: NotificationsCfg,
    state: Arc<Mutex<NotifyState>>,
    pending_dir: Option<PathBuf>,
    send: SendFn,
) {
    let queued = pending_dir.as_deref().map(load_pending).unwrap_or_default();
    let mut q = ChannelQueue {
        name,
        queue: queued,
        pending_dir,
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
        let Some(pending) = q.queue.front() else {
            if !q.take(rx.recv().await) {
                return;
            }
            continue;
        };
        let alert = pending.alert.clone();
        let cfg = q.cfg.clone();
        let result = tokio::task::spawn_blocking(move || send(name, &alert, &cfg))
            .await
            // A panicking send is a failure, not a delivery. (Release builds
            // abort on panic instead; see Cargo.toml.)
            .unwrap_or_else(|e| Err(SendError::transient(format!("send panicked: {}", e))));
        match result {
            Ok(()) => {
                if let Some(p) = q.queue.pop_front() {
                    ChannelQueue::forget(&p.file);
                    mark_delivered(&state, &p.alert);
                }
                if let Ok(mut s) = state.lock() {
                    *s.per_channel.entry(name.to_string()).or_default() += 1;
                }
                q.backoff = FIRST_BACKOFF;
                q.failing_since = None;
                q.alarm_sent = false;
            }
            Err(e) if e.permanent => {
                if let Some(p) = q.queue.pop_front() {
                    ChannelQueue::forget(&p.file);
                    q.note_drop(&p.alert, &e.msg);
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

/// Record an alert and deliver it to every channel right now, synchronously.
/// Used by `hermian watchdog`: with the daemon down there is no worker to
/// hand this to. Returns the channels that failed.
pub fn store_and_send(alert: &Alert, cfg: &NotificationsCfg) -> Vec<(String, String)> {
    persist(alert, &hermian_core::render(alert, Theme::Plain), cfg);
    let mut errors = Vec::new();
    if alert.severity >= cfg.min_severity() {
        for channel in notifying_channels(cfg) {
            if let Err(e) = notify_one(channel, alert, cfg) {
                errors.push((channel.to_string(), e));
            }
        }
    }
    errors
}

fn send_classified(channel: &str, alert: &Alert, cfg: &NotificationsCfg) -> Result<(), SendError> {
    // Minimal content: what leaves the host is the reference, not the story.
    let minimal;
    let alert = if cfg.content == "minimal" && leaves_host(channel) {
        minimal = alert.minimal();
        &minimal
    } else {
        alert
    };
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

/// Channels that send the alert to someone else's server.
fn leaves_host(channel: &str) -> bool {
    matches!(channel, "webhook" | "telegram" | "email")
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
    let result = (|| -> anyhow::Result<()> {
        fs::create_dir_all(&dir)?;
        let text = serde_json::to_string_pretty(alert)?;
        // Never replace an existing record: if a ref id ever repeats (state
        // lost, clock trouble), keep both.
        let mut path = dir.join(format!("{}.json", alert.ref_id));
        let mut n = 1;
        while path.exists() && n < 1000 {
            path = dir.join(format!("{}.{}.json", alert.ref_id, n));
            n += 1;
        }
        config::write_secure(&path, &text)
    })();
    if let Err(e) = result {
        // Was silent; `show`/`collect` would then say the alert doesn't exist.
        syslog_msg(
            Severity::High,
            &format!("hermian: could not store alert {}: {:#}", alert.ref_id, e),
        );
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

    fn slack_colour(sev: Severity) -> &'static str {
        match sev {
            Severity::Critical => "#D62828",
            Severity::High => "#F77F00",
            Severity::Low => "#FCBF49",
            Severity::Info => "#8D99AE",
        }
    }

    /// The mark, served from the site. Discord's servers fetch it, not the
    /// host, so nothing about the host leaks.
    const AVATAR_URL: &str = "https://hermian.me/icon-192.png";

    /// Severity colours from the identity's dark palette (Discord is dark).
    fn discord_colour(sev: Severity) -> u32 {
        match sev {
            Severity::Critical => 0xFF6B81,
            Severity::High => 0x9A8CF7,
            Severity::Low => 0x8D8AA8,
            Severity::Info => 0x6B6888,
        }
    }

    /// Cut to Discord's per-field limits, marking the cut.
    fn cut(s: &str, max: usize) -> String {
        if s.chars().count() <= max {
            return s.to_string();
        }
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('\u{2026}');
        out
    }

    /// Inline code that a backtick in the value can't break out of.
    fn code(s: &str) -> String {
        format!("`{}`", s.replace('`', "'"))
    }

    /// Author line with meter and detection, the title alone, the sentence
    /// as a quote (the path in it as code), host and a live relative time,
    /// then risk, steps and the command.
    fn discord(alert: &Alert) -> Value {
        let mut what = cut(&alert.what, 1500);
        if let Some(p) = alert.facts.iter().find(|f| f.label == "Path") {
            if p.value.len() > 1 && !p.value.contains('`') {
                what = what.replacen(&p.value, &code(&p.value), 1);
            }
        }
        let ts = alert.ts.timestamp();
        let mut fields = vec![
            json!({"name": "Host", "value": code(&cut(&alert.host, 200)), "inline": true}),
            json!({"name": "Detected", "value": format!("<t:{}:t> \u{00B7} <t:{}:R>", ts, ts), "inline": true}),
        ];
        if !alert.chain.is_empty() {
            fields.push(json!({"name": "Process chain", "value": code(&cut(&chain_line(alert), 900)), "inline": false}));
        }
        for f in alert.facts.iter().filter(|f| f.label != "Path").take(6) {
            fields.push(
                json!({"name": cut(&f.label, 200), "value": cut(&f.value, 1000), "inline": true}),
            );
        }
        if !alert.why.is_empty() {
            fields.push(json!({"name": "Risk", "value": cut(&alert.why, 1000), "inline": false}));
        }
        if !alert.actions.is_empty() {
            let steps = alert
                .actions
                .iter()
                .take(5)
                .enumerate()
                .map(|(i, a)| format!("{}. {}", i + 1, cut(a, 180)))
                .collect::<Vec<_>>()
                .join("\n");
            fields.push(json!({"name": "Next steps", "value": steps, "inline": false}));
        }
        fields.push(json!({
            "name": "\u{200B}",
            "value": format!("```\nhermian show {}\n```", alert.ref_id.replace('`', "'")),
            "inline": false
        }));
        json!({
            "username": "Hermian",
            "avatar_url": AVATAR_URL,
            // Alert text carries attacker-controlled strings (an SSH user
            // named "@everyone"); never let it ping anyone.
            "allowed_mentions": {"parse": []},
            "embeds": [{
                "author": {"name": format!(
                    "{}  {}  \u{00B7}  {} {}",
                    hermian_core::alert::severity_meter(alert.severity),
                    alert.severity.as_str(),
                    alert.detection.short(),
                    alert.detection.family()
                )},
                "title": cut(&alert.title, 250),
                "description": format!("> {}", what.replace('\n', "\n> ")),
                "color": discord_colour(alert.severity),
                "fields": fields,
                "footer": {"text": format!("Hermian \u{00B7} {}", alert.ref_id), "icon_url": AVATAR_URL},
                "timestamp": alert.ts.to_rfc3339(),
            }]
        })
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
                    "text": format!("Hermian {}", title),
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
            "discord" => discord(alert),
            // m.room.message; Matrix clients render formatted_body.
            "matrix" => json!({
                "msgtype": "m.text",
                "body": compact,
                "format": "org.matrix.custom.html",
                "formatted_body": format!(
                    "<b>{}</b> \u{00B7} {}<br>{}<br><code>hermian show {}</code>",
                    html_escape(&title),
                    html_escape(&alert.host),
                    html_escape(&alert.what),
                    html_escape(alert.short_ref())
                ),
            }),
            "ntfy" => json!({
                "title": format!("Hermian {} on {}", alert.severity.as_str(), alert.host),
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
        // The library may print the URL normalised (host case, escaping), so
        // the literal replace above can miss it: cut every URL in the text
        // down to scheme://host as well.
        strip_url_paths(&s)
    }

    /// `... https://host/secret/path?q ...` -> `... https://host/… ...`.
    pub fn strip_url_paths(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let mut rest = s;
        while let Some(i) = rest.find("://") {
            let (before, after) = rest.split_at(i + 3);
            out.push_str(before);
            let end = after
                .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ')' | '>' | ','))
                .unwrap_or(after.len());
            let url = &after[..end];
            let authority = url.split(['/', '?', '#']).next().unwrap_or("");
            let host = authority.rsplit('@').next().unwrap_or(authority);
            out.push_str(host);
            if url.len() > authority.len() {
                out.push_str("/…");
            }
            rest = &after[end..];
        }
        out.push_str(rest);
        out
    }

    fn html_escape(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    }

    /// `https://ntfy.example/alerts` -> (`https://ntfy.example/`, `alerts`).
    /// The topic is the URL's last path segment; a self-hosted server under a
    /// sub-path (`https://host/ntfy/alerts`) keeps its prefix in the root.
    pub fn ntfy_target(url: &str) -> Option<(String, String)> {
        let (scheme, rest) = url.split_once("://")?;
        let rest = rest.split(['?', '#']).next().unwrap_or("");
        let (authority, path) = rest.split_once('/')?;
        let path = path.trim_end_matches('/');
        let (prefix, topic) = match path.rsplit_once('/') {
            Some((prefix, topic)) => (format!("{}/", prefix), topic),
            None => (String::new(), path),
        };
        if authority.is_empty() || topic.is_empty() {
            return None;
        }
        Some((
            format!("{}://{}/{}", scheme, authority, prefix),
            topic.to_string(),
        ))
    }

    /// Matrix sends are a PUT to `<room send endpoint>/<transaction id>`; the
    /// id makes a retried delivery post once.
    pub fn matrix_url(base: &str, alert: &Alert) -> String {
        let txn: String = format!("hermian-{}-{}", alert.ref_id, alert.ts.timestamp_millis())
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
            .collect();
        format!("{}/{}", base.trim_end_matches('/'), txn)
    }

    pub fn send(alert: &Alert, cfg: &WebhookCfg) -> Result<(), SendError> {
        let body = payload(alert, &cfg.format);
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(cfg.timeout_secs.clamp(2, 60)))
            .user_agent(&format!("hermian/{}", hermian_core::VERSION))
            .build();
        let mut body = body;
        let mut req = if cfg.format == "matrix" {
            agent.put(&matrix_url(&cfg.url, alert))
        } else if cfg.format == "ntfy" {
            // ntfy only reads a JSON body at the server root, with the topic
            // inside it; posted to the topic URL, the JSON is shown as text.
            match ntfy_target(&cfg.url) {
                Some((root, topic)) => {
                    body["topic"] = json!(topic);
                    agent.post(&root)
                }
                None => agent.post(&cfg.url),
            }
        } else {
            agent.post(&cfg.url)
        }
        .set("Content-Type", "application/json");
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
    use serde_json::json;

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
        assert_eq!(d["embeds"][0]["color"], 0x9A8CF7);
        let m = webhook::payload(&a, "matrix");
        assert_eq!(m["msgtype"], "m.text");
        assert!(m["formatted_body"]
            .as_str()
            .unwrap()
            .contains("hermian show 001"));
        assert_eq!(
            webhook::matrix_url("https://m.example/_matrix/client/v3/rooms/!r:m.example/send/m.room.message/", &a),
            format!(
                "https://m.example/_matrix/client/v3/rooms/!r:m.example/send/m.room.message/hermian-HER-2025-0101-001-{}",
                a.ts.timestamp_millis()
            )
        );
        assert_eq!(
            webhook::ntfy_target("https://ntfy.sh/hermian-alerts"),
            Some(("https://ntfy.sh/".into(), "hermian-alerts".into()))
        );
        assert_eq!(
            webhook::ntfy_target("https://host.example:8443/ntfy/servers/?x=1"),
            Some(("https://host.example:8443/ntfy/".into(), "servers".into()))
        );
        assert_eq!(webhook::ntfy_target("https://ntfy.sh/"), None);
        let n = webhook::payload(&a, "ntfy");
        assert_eq!(n["priority"], 4);
    }

    /// Meter and detection in the author line, the title alone, the path
    /// as code in the quoted sentence, the risk and steps as fields, and
    /// alert text can never ping anyone.
    #[test]
    fn discord_embed_layout() {
        let f = Finding::new(
            DetectionId::D3,
            Severity::High,
            "Shell profile changed with no session present",
            "x",
        )
        .what("/root/.bashrc was moved into place by @everyone.")
        .fact("Path", "/root/.bashrc")
        .why("Shell profiles execute on every login.")
        .action("Review the tail of the file.");
        let a = Alert::from_finding(f, "HER-4".into(), "web`01".into(), Utc::now());
        let d = webhook::payload(&a, "discord");
        assert_eq!(d["allowed_mentions"]["parse"], json!([]));
        assert_eq!(d["avatar_url"], "https://hermian.me/icon-192.png");
        let e = &d["embeds"][0];
        assert_eq!(
            e["author"]["name"],
            "\u{25C9}\u{25C9}\u{25C9}\u{25CB}  HIGH  \u{00B7}  D3 Persistence"
        );
        assert_eq!(e["title"], "Shell profile changed with no session present");
        assert_eq!(
            e["description"],
            "> `/root/.bashrc` was moved into place by @everyone."
        );
        let fields = e["fields"].as_array().unwrap();
        let named = |n: &str| fields.iter().find(|f| f["name"] == n).unwrap()["value"].clone();
        assert_eq!(named("Host"), "`web'01`");
        assert!(named("Detected").as_str().unwrap().contains(":R>"));
        assert_eq!(named("Risk"), "Shell profiles execute on every login.");
        assert_eq!(named("Next steps"), "1. Review the tail of the file.");
        assert!(
            !fields.iter().any(|f| f["name"] == "Path"),
            "path is in the quote"
        );
        assert_eq!(e["footer"]["text"], "Hermian \u{00B7} HER-4");
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

    #[test]
    fn urls_in_error_text_lose_their_secret_parts() {
        let e = "Network Error: https://Hooks.Slack.com/services/T0/B0/SECRET: connection reset";
        let s = webhook::strip_url_paths(e);
        assert!(!s.contains("SECRET"), "{}", s);
        assert!(s.contains("https://Hooks.Slack.com/…"), "{}", s);
        let e = "error (http://user:pw@10.0.0.5:8080/h?token=abc) failed";
        let s = webhook::strip_url_paths(e);
        assert!(!s.contains("pw") && !s.contains("abc"), "{}", s);
        assert_eq!(webhook::strip_url_paths("no urls here"), "no urls here");
    }

    fn queue() -> ChannelQueue {
        ChannelQueue {
            name: "webhook",
            queue: VecDeque::new(),
            pending_dir: None,
            cfg: NotificationsCfg::default(),
            backoff: FIRST_BACKOFF,
            failing_since: None,
            alarm_sent: false,
            dropped: 0,
        }
    }

    fn scratch(name: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("hermian-notify-{}-{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
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
        assert_eq!(q.queue.front().unwrap().alert.ref_id, "HER-CRIT");
    }

    #[test]
    fn queued_alerts_are_persisted_and_cleaned_up_as_they_leave() {
        let d = scratch("qdisk");
        let mut q = queue();
        q.pending_dir = Some(d.clone());
        q.take(Some(ChanMsg::Alert(Box::new(with_ref("HER-1")))));
        q.take(Some(ChanMsg::Alert(Box::new(with_ref("HER-2")))));
        assert_eq!(fs::read_dir(&d).unwrap().count(), 2);
        // Overflow: the dropped alert's copy goes with it.
        for i in 0..MAX_PENDING {
            let mut a = alert();
            a.ref_id = format!("HER-CRIT-{}", i);
            a.severity = Severity::Critical;
            q.take(Some(ChanMsg::Alert(Box::new(a))));
        }
        assert_eq!(fs::read_dir(&d).unwrap().count(), MAX_PENDING);
        // Delivery removes the copy it was carrying.
        let delivered = q.queue.pop_front().unwrap();
        ChannelQueue::forget(&delivered.file);
        assert_eq!(fs::read_dir(&d).unwrap().count(), MAX_PENDING - 1);
        fs::remove_dir_all(&d).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pending_alerts_are_delivered_after_a_restart() {
        let d = scratch("reload");
        for r in ["HER-1", "HER-2"] {
            let a = with_ref(r);
            let name = format!("{}-{}.json", a.ts.timestamp_millis(), a.ref_id);
            fs::write(d.join(name), serde_json::to_string(&a).unwrap()).unwrap();
        }
        // A file that doesn't parse is dropped, not retried forever.
        fs::write(d.join("junk.json"), "{not json").unwrap();
        let state = Arc::new(Mutex::new(NotifyState::default()));
        let (_tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(run_channel(
            "email",
            rx,
            NotificationsCfg::default(),
            state.clone(),
            Some(d.clone()),
            reject_bad,
        ));
        settle().await;
        let s = state.lock().unwrap().clone();
        assert_eq!(s.per_channel.get("email"), Some(&2), "{:?}", s);
        assert_eq!(s.pending, 0);
        assert_eq!(fs::read_dir(&d).unwrap().count(), 0);
        fs::remove_dir_all(&d).unwrap();
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
            None,
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
            None,
            always_down,
        ));
        tokio::spawn(run_channel(
            "email",
            up_rx,
            NotificationsCfg::default(),
            state.clone(),
            None,
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
            None,
            panics,
        ));
        settle().await;
        let s = state.lock().unwrap().clone();
        assert!(s.last_delivery.is_none(), "{:?}", s);
        assert_eq!(s.pending, 1);
    }
}
