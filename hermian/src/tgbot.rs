//! Telegram response buttons.
//!
//! Alerts that offer responses get an inline keyboard. Each button carries a
//! random one-time id that points at an action kept here until it expires,
//! and saved in the state directory so a restart doesn't kill it. Button
//! presses are fetched by long-polling `getUpdates` (outbound only, so
//! Hermian still listens on no port, and it keeps working during isolation
//! since Telegram stays reachable). A press is only acted on if it comes
//! from the configured chat *and* from one of `allowed_user_ids`; anything
//! else is refused and logged.
//!
//! Destructive actions (Block, Disconnect) take two presses: the first swaps
//! the keyboard for "Confirm" and "Cancel", which expire after two minutes.
//!
//! Every press gets an answer that says what happened (see `actions`): a
//! used button turns into a label with the outcome, pressing a button again
//! or after someone else's choice says who did what and when, and an
//! expired button gives the command that does the same thing.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use chrono::{DateTime, Utc};
use hermian_core::config::TelegramCfg;
use hermian_core::ResponseAction;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::mpsc;

use crate::actions::{at, short};

/// Prefix of our callback data, so stray buttons from elsewhere are ignored.
const PREFIX: &str = "hm:";
/// Most pending actions kept (oldest dropped first).
const MAX_PENDING: usize = 2000;
/// Long-poll wait, seconds. The HTTP timeout must be longer.
const POLL_SECS: u64 = 25;
/// How long a "Confirm" button stays valid.
const CONFIRM_SECS: i64 = 120;
/// How long used buttons and result labels keep answering.
const KEEP_HOURS: i64 = 24;
/// Telegram's limit for a callback answer.
const ANSWER_MAX: usize = 200;

/// Where a button sits in the flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Step {
    /// One of the alert's own buttons (or an Undo), at this position.
    Offer(usize),
    /// "Confirm: ..." for the destructive offer with this id.
    Confirm { offer: String },
    /// "Cancel": put the alert's buttons back.
    Cancel { offer: String },
    /// Pressed, or retired by someone's choice on the same alert.
    Used {
        by: String,
        at: DateTime<Utc>,
        note: String,
    },
    /// Shows `text` (a result or a hint) when pressed; does nothing else.
    /// `shown` is what the button itself reads.
    Label {
        text: String,
        #[serde(default)]
        shown: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pending {
    pub action: ResponseAction,
    pub alert_ref: String,
    pub expires: DateTime<Utc>,
    pub message_id: Option<i64>,
    pub step: Step,
}

/// What the poller does after answering a press.
#[derive(Debug, Clone, Default)]
pub struct Outcome {
    /// Carry out this action.
    pub request: Option<ActionRequest>,
    /// Replace the message's buttons with these (empty: remove them).
    pub keyboard: Option<(i64, Vec<(String, String)>)>,
}

/// Block and Disconnect change the host: they ask first.
fn needs_confirmation(a: &ResponseAction) -> bool {
    matches!(
        a,
        ResponseAction::Block { .. } | ResponseAction::Disconnect { .. }
    )
}

/// A press that passed every check, for the daemon to carry out.
#[derive(Debug, Clone)]
pub struct ActionRequest {
    pub action: ResponseAction,
    pub alert_ref: String,
    /// Who pressed, for the audit trail ("@name (id 123)").
    pub by: String,
    pub message_id: Option<i64>,
}

fn store() -> &'static Mutex<HashMap<String, Pending>> {
    static S: OnceLock<Mutex<HashMap<String, Pending>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Results that couldn't be posted, sent with the next message that can.
fn undelivered() -> &'static Mutex<Vec<String>> {
    static U: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
    U.get_or_init(|| Mutex::new(Vec::new()))
}

/// Buttons are saved to disk only by the running poller, not in tests.
static PERSIST: AtomicBool = AtomicBool::new(false);
static STARTED: OnceLock<DateTime<Utc>> = OnceLock::new();
/// HTTP 409s from getUpdates since the daemon last asked: something else
/// is polling this bot.
static CONFLICTS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Poll conflicts since the last call (see `daemon::report_bot_conflict`).
pub fn take_conflicts() -> u32 {
    CONFLICTS.swap(0, Ordering::Relaxed)
}

#[derive(Default, Serialize, Deserialize)]
struct Saved {
    buttons: HashMap<String, Pending>,
    #[serde(default)]
    undelivered: Vec<String>,
}

fn saved_path() -> std::path::PathBuf {
    crate::paths::state_dir().join("buttons.json")
}

/// Write the buttons (and undelivered results) out. Call with the store
/// lock held, so writes don't interleave.
fn save(s: &HashMap<String, Pending>) {
    if !PERSIST.load(Ordering::Relaxed) {
        return;
    }
    let saved = Saved {
        buttons: s.clone(),
        undelivered: undelivered().lock().map(|u| u.clone()).unwrap_or_default(),
    };
    if let Ok(text) = serde_json::to_string(&saved) {
        let _ = crate::config::write_secure(&saved_path(), &text);
    }
}

/// Load what a previous run saved; expired offers are tidied by the sweep.
fn load_saved(now: DateTime<Utc>) {
    let saved: Saved = std::fs::read_to_string(saved_path())
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default();
    if let Ok(mut s) = store().lock() {
        for (id, p) in saved.buttons {
            if keep(&p, now) {
                s.entry(id).or_insert(p);
            }
        }
    }
    if let Ok(mut u) = undelivered().lock() {
        u.extend(saved.undelivered);
    }
}

/// Still worth keeping: live, or an expired offer whose keyboard the sweep
/// hasn't tidied yet.
fn keep(p: &Pending, now: DateTime<Utc>) -> bool {
    match p.step {
        Step::Offer(_) => p.expires > now - chrono::Duration::hours(KEEP_HOURS),
        _ => p.expires > now,
    }
}

/// Last poll problem, for `hermian status` (empty when fine).
fn poll_error() -> &'static Mutex<String> {
    static E: OnceLock<Mutex<String>> = OnceLock::new();
    E.get_or_init(|| Mutex::new(String::new()))
}

pub fn last_poll_error() -> String {
    poll_error().lock().map(|e| e.clone()).unwrap_or_default()
}

fn set_poll_error(e: &str) {
    if let Ok(mut s) = poll_error().lock() {
        *s = e.to_string();
    }
}

/// 96 random bits, hex. Unguessable, so a button id can't be forged even by
/// someone who sees other buttons.
fn random_id() -> String {
    use std::io::Read;
    let mut b = [0u8; 12];
    let ok = std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .is_ok();
    if !ok {
        // Practically unreachable; still unique, if not secret.
        let n =
            Utc::now().timestamp_nanos_opt().unwrap_or(0) as u128 ^ (std::process::id() as u128);
        b.copy_from_slice(&n.to_le_bytes()[..12]);
    }
    hex::encode(b)
}

/// Drop the oldest entries past the cap.
fn trim(s: &mut HashMap<String, Pending>) {
    while s.len() > MAX_PENDING {
        let oldest = s
            .iter()
            .min_by_key(|(_, p)| p.expires)
            .map(|(k, _)| k.clone());
        match oldest {
            Some(k) => {
                s.remove(&k);
            }
            None => break,
        }
    }
}

/// Keep actions for these buttons; returns `(callback_data, label)` pairs.
pub fn register(
    alert_ref: &str,
    actions: &[ResponseAction],
    ttl_mins: u32,
    now: DateTime<Utc>,
) -> Vec<(String, String)> {
    let expires = now + chrono::Duration::minutes(i64::from(ttl_mins.max(1)));
    let Ok(mut s) = store().lock() else {
        return Vec::new();
    };
    s.retain(|_, p| keep(p, now));
    let mut out = Vec::new();
    for (i, a) in actions.iter().enumerate() {
        let id = random_id();
        s.insert(
            id.clone(),
            Pending {
                action: a.clone(),
                alert_ref: alert_ref.to_string(),
                expires,
                message_id: None,
                step: Step::Offer(i),
            },
        );
        out.push((format!("{}{}", PREFIX, id), a.label()));
    }
    trim(&mut s);
    save(&s);
    out
}

/// Remember which message the buttons are on (to answer and tidy it up).
pub fn attach_message(buttons: &[(String, String)], message_id: i64) {
    if let Ok(mut s) = store().lock() {
        for (data, _) in buttons {
            if let Some(p) = data.strip_prefix(PREFIX).and_then(|id| s.get_mut(id)) {
                p.message_id = Some(message_id);
            }
        }
        save(&s);
    }
}

/// `reply_markup` for these buttons: one per row, so long labels fit.
pub fn keyboard(buttons: &[(String, String)]) -> Value {
    let rows: Vec<Value> = buttons
        .iter()
        .map(|(data, label)| json!([{ "text": label, "callback_data": data }]))
        .collect();
    json!({ "inline_keyboard": rows })
}

/// The alert's own buttons still live, in their original order.
fn offers_of(
    s: &HashMap<String, Pending>,
    alert_ref: &str,
    now: DateTime<Utc>,
) -> Vec<(String, String)> {
    let mut v: Vec<(usize, String, String)> = s
        .iter()
        .filter(|(_, p)| p.alert_ref == alert_ref && p.expires > now)
        .filter_map(|(id, p)| match p.step {
            Step::Offer(i) => Some((i, format!("{}{}", PREFIX, id), p.action.label())),
            _ => None,
        })
        .collect();
    v.sort();
    v.into_iter().map(|(_, d, l)| (d, l)).collect()
}

/// A label button: shows `text` when pressed. Returns its keyboard entry.
fn add_label(
    s: &mut HashMap<String, Pending>,
    like: &Pending,
    shown: &str,
    text: &str,
    now: DateTime<Utc>,
) -> (String, String) {
    let id = random_id();
    s.insert(
        id.clone(),
        Pending {
            action: like.action.clone(),
            alert_ref: like.alert_ref.clone(),
            expires: now + chrono::Duration::hours(KEEP_HOURS),
            message_id: like.message_id,
            step: Step::Label {
                text: text.to_string(),
                shown: shown.to_string(),
            },
        },
    );
    (format!("{}{}", PREFIX, id), shown.to_string())
}

/// What an expired button says: how long they last, and the command that
/// does the same thing from the host.
fn expired_text(hints: &[String], ttl_mins: u32) -> String {
    let head = format!("Expired (buttons last {} min).", ttl_mins);
    if hints.is_empty() {
        format!("{} Nothing was done.", head)
    } else {
        format!("{} From the host: {}", head, hints.join("  |  "))
    }
}

/// Swap an alert's expired buttons for one "Buttons expired" label, keeping
/// any result labels. Returns the message's new keyboard.
fn expire_alert(
    s: &mut HashMap<String, Pending>,
    alert_ref: &str,
    ttl_mins: u32,
    now: DateTime<Utc>,
) -> Option<(i64, Vec<(String, String)>)> {
    let offers: Vec<(String, Pending)> = s
        .iter()
        .filter(|(_, p)| p.alert_ref == alert_ref && matches!(p.step, Step::Offer(_)))
        .map(|(k, p)| (k.clone(), p.clone()))
        .collect();
    let first = offers
        .iter()
        .min_by_key(|(_, p)| match p.step {
            Step::Offer(i) => i,
            _ => usize::MAX,
        })?
        .1
        .clone();
    let mid = first.message_id?;
    let hints: Vec<String> = offers
        .iter()
        .filter_map(|(_, p)| p.action.cli_twin())
        .collect();
    for (k, _) in &offers {
        s.remove(k);
    }
    s.retain(|_, p| {
        !(p.alert_ref == alert_ref && matches!(p.step, Step::Confirm { .. } | Step::Cancel { .. }))
    });
    let text = expired_text(&hints, ttl_mins);
    let mut kb = labels_of(s, alert_ref);
    kb.push(add_label(s, &first, "Buttons expired", &text, now));
    Some((mid, kb))
}

/// Result labels already on an alert's message, oldest first.
fn labels_of(s: &HashMap<String, Pending>, alert_ref: &str) -> Vec<(String, String)> {
    let mut v: Vec<(DateTime<Utc>, String, String)> = s
        .iter()
        .filter(|(_, p)| p.alert_ref == alert_ref)
        .filter_map(|(id, p)| match &p.step {
            Step::Label { text, shown } if !text.starts_with("Expired") => {
                let shown = if shown.is_empty() {
                    text.lines().next().unwrap_or("").to_string()
                } else {
                    shown.clone()
                };
                Some((p.expires, format!("{}{}", PREFIX, id), shown))
            }
            _ => None,
        })
        .collect();
    v.sort();
    v.into_iter().map(|(_, d, l)| (d, l)).collect()
}

/// The host an alert's text names: its "host" line, or "... on <host>" in
/// the minimal format.
fn host_in(text: &str) -> Option<String> {
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("host ") {
            let h = rest.trim();
            if !h.is_empty() {
                return Some(h.to_string());
            }
        }
    }
    let first = text.lines().next()?;
    let (_, after) = first.rsplit_once(" alert ")?;
    let (_, host) = after.split_once(" on ")?;
    let host = host.trim();
    (!host.is_empty() && !host.contains(' ')).then(|| host.to_string())
}

/// The alert reference in a message's text, for the "details" hint.
fn alert_ref_in(text: &str) -> Option<String> {
    let i = text.find("HER-")?;
    let r: String = text[i..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect();
    (r.len() > 8).then_some(r)
}

/// A button we know nothing about: say why, and where the alert is.
fn unknown_button(cq: &Value, now: DateTime<Utc>) -> String {
    let text = cq["message"]["text"].as_str().unwrap_or("");
    // Another host's alert: two hosts are polling this bot, and this one
    // got a press meant for the other.
    let me = crate::procsrc::hostname();
    if let Some(host) = host_in(text).filter(|h| *h != me) {
        return format!(
            "This is {}'s alert, but {} answered: both read this bot's presses. Give each host              with buttons its own bot. Nothing was done.",
            host, me
        );
    }
    let hint = alert_ref_in(text)
        .map(|r| format!(" Details: sudo hermian show {}", r))
        .unwrap_or_default();
    let sent = cq["message"]["date"]
        .as_i64()
        .and_then(|t| DateTime::from_timestamp(t, 0));
    match (sent, STARTED.get()) {
        (Some(sent), Some(start)) if sent < *start => format!(
            "Hermian restarted at {}, after this alert, and this button was lost. Nothing was \
             done.{}",
            at(now, *start),
            hint
        ),
        _ => format!("This button is no longer valid. Nothing was done.{}", hint),
    }
}

fn clip(s: String) -> String {
    if s.chars().count() <= ANSWER_MAX {
        return s;
    }
    let mut t: String = s.chars().take(ANSWER_MAX - 1).collect();
    t.push('…');
    t
}

/// Decide what to do with one callback query. Returns the text to show the
/// presser and what to do next.
pub fn handle_callback(cq: &Value, cfg: &TelegramCfg, now: DateTime<Utc>) -> (String, Outcome) {
    let (text, out) = decide(cq, cfg, now);
    (clip(text), out)
}

fn decide(cq: &Value, cfg: &TelegramCfg, now: DateTime<Utc>) -> (String, Outcome) {
    let none = Outcome::default;
    let from_id = cq["from"]["id"].as_i64();
    let who = describe_user(&cq["from"]);
    let chat_ok = cq["message"]["chat"]["id"]
        .as_i64()
        .map(|id| id.to_string() == cfg.chat_id.trim())
        .unwrap_or(false);
    if !cfg.actions_enabled() {
        return (
            "Response buttons are turned off on this host.".into(),
            none(),
        );
    }
    if !chat_ok {
        return ("Not from the configured chat.".into(), none());
    }
    let allowed = from_id.is_some_and(|id| cfg.allowed_user_ids.contains(&id));
    if !allowed {
        crate::daemon::log_daemon(
            hermian_core::Severity::High,
            &format!(
                "refused a Telegram button press from {} (not in allowed_user_ids)",
                who
            ),
        );
        return ("You're not allowed to do this.".into(), none());
    }
    let Some(id) = cq["data"].as_str().and_then(|d| d.strip_prefix(PREFIX)) else {
        return ("Unknown button.".into(), none());
    };
    let Ok(mut s) = store().lock() else {
        return ("Try again.".into(), none());
    };
    let Some(p) = s.get(id).cloned() else {
        return (unknown_button(cq, now), none());
    };
    let message_id = p
        .message_id
        .or_else(|| cq["message"]["message_id"].as_i64());
    let label = p.action.label();
    match &p.step {
        Step::Used { by, note, .. } => {
            let text = if *by == who {
                format!("You did this: {}", note)
            } else {
                format!("Already handled: {}. Yours wasn't applied.", note)
            };
            return (text, none());
        }
        Step::Label { text, .. } => return (text.clone(), none()),
        _ => {}
    }
    if p.expires <= now {
        if let Step::Confirm { .. } | Step::Cancel { .. } = p.step {
            // A stale confirmation shouldn't leave the alert without buttons.
            s.retain(|_, o| {
                !(o.alert_ref == p.alert_ref
                    && matches!(o.step, Step::Confirm { .. } | Step::Cancel { .. }))
            });
            let keyboard = message_id.map(|m| (m, offers_of(&s, &p.alert_ref, now)));
            save(&s);
            return (
                "The confirmation expired; press the button again.".into(),
                Outcome {
                    request: None,
                    keyboard,
                },
            );
        }
        let keyboard = expire_alert(&mut s, &p.alert_ref, cfg.action_ttl_mins, now);
        save(&s);
        return (
            expired_text(
                &p.action.cli_twin().into_iter().collect::<Vec<_>>(),
                cfg.action_ttl_mins,
            ),
            Outcome {
                request: None,
                keyboard,
            },
        );
    }
    let offer_id = match &p.step {
        Step::Offer(_) if needs_confirmation(&p.action) => {
            // Keep the offer for Cancel, and ask.
            let until = now + chrono::Duration::seconds(CONFIRM_SECS);
            let mut step = |st: Step| {
                let nid = random_id();
                s.insert(
                    nid.clone(),
                    Pending {
                        action: p.action.clone(),
                        alert_ref: p.alert_ref.clone(),
                        expires: until,
                        message_id,
                        step: st,
                    },
                );
                format!("{}{}", PREFIX, nid)
            };
            let confirm = step(Step::Confirm {
                offer: id.to_string(),
            });
            let cancel = step(Step::Cancel {
                offer: id.to_string(),
            });
            save(&s);
            let keyboard = message_id.map(|m| {
                (
                    m,
                    vec![
                        (confirm, format!("Confirm: {}", label)),
                        (cancel, "Cancel".to_string()),
                    ],
                )
            });
            return (
                format!("{}? Press Confirm within 2 minutes.", label),
                Outcome {
                    request: None,
                    keyboard,
                },
            );
        }
        Step::Cancel { .. } => {
            s.retain(|_, o| {
                !(o.alert_ref == p.alert_ref
                    && matches!(o.step, Step::Confirm { .. } | Step::Cancel { .. }))
            });
            let keyboard = message_id.map(|m| {
                let mut kb = labels_of(&s, &p.alert_ref);
                kb.extend(offers_of(&s, &p.alert_ref, now));
                (m, kb)
            });
            save(&s);
            return (
                "Cancelled. Nothing was changed.".into(),
                Outcome {
                    request: None,
                    keyboard,
                },
            );
        }
        Step::Confirm { offer } => offer.clone(),
        _ => id.to_string(),
    };
    // An offer that needs no confirmation, or a confirmed one: it's used.
    s.retain(|_, o| {
        !(o.alert_ref == p.alert_ref
            && matches!(o.step, Step::Confirm { .. } | Step::Cancel { .. }))
    });
    let Some(offer) = s.get(&offer_id).cloned() else {
        return (unknown_button(cq, now), none());
    };
    // Someone else chose while this Confirm was up.
    if let Step::Used { note, .. } = &offer.step {
        save(&s);
        return (
            format!("Already handled: {}. Yours wasn't applied.", note),
            none(),
        );
    }
    let used = |note: String| Step::Used {
        by: who.clone(),
        at: now,
        note,
    };
    let keep_until = now + chrono::Duration::hours(KEEP_HOURS);
    let note = format!("{} chose {} at {}", short(&who), label, at(now, now));
    if let Some(o) = s.get_mut(&offer_id) {
        o.step = used(note.clone());
        o.expires = keep_until;
    }
    if p.action.settles() {
        // One choice per alert: its other buttons say who chose what.
        for o in s.values_mut() {
            if o.alert_ref == p.alert_ref && matches!(o.step, Step::Offer(_)) {
                o.step = used(note.clone());
                o.expires = keep_until;
            }
        }
    }
    // Until the result is in, the message shows what's left to press.
    let keyboard = message_id.map(|m| {
        let mut kb = labels_of(&s, &p.alert_ref);
        if !p.action.settles() {
            kb.extend(offers_of(&s, &p.alert_ref, now));
        }
        (m, kb)
    });
    save(&s);
    let req = ActionRequest {
        action: p.action.clone(),
        alert_ref: p.alert_ref.clone(),
        by: who,
        message_id,
    };
    (
        format!("On it: {} on {}", label, crate::procsrc::hostname()),
        Outcome {
            request: Some(req),
            keyboard,
        },
    )
}

/// The keyboard an alert gets once a press has its result: earlier result
/// labels, this result's label, the Undo where there is one, and the alert's
/// remaining buttons if the choice didn't settle it.
fn result_keyboard(
    s: &mut HashMap<String, Pending>,
    req: &ActionRequest,
    text: &str,
    summary: &str,
    undo: Option<(ResponseAction, u32)>,
    now: DateTime<Utc>,
) -> Vec<(String, String)> {
    // Later presses on the buttons this choice used or retired quote the
    // outcome instead of "chose ...".
    let chose = format!("{} chose {}", short(&req.by), req.action.label());
    for o in s.values_mut() {
        if o.alert_ref == req.alert_ref {
            if let Step::Used { note, .. } = &mut o.step {
                if note.starts_with(&chose) {
                    *note = summary.to_string();
                }
            }
        }
    }
    let like = Pending {
        action: req.action.clone(),
        alert_ref: req.alert_ref.clone(),
        expires: now,
        message_id: req.message_id,
        step: Step::Offer(0),
    };
    let mut kb = labels_of(s, &req.alert_ref);
    kb.push(add_label(s, &like, summary, text, now));
    if let Some((action, ttl_mins)) = undo {
        let id = random_id();
        kb.push((format!("{}{}", PREFIX, id), action.label()));
        s.insert(
            id,
            Pending {
                action,
                alert_ref: req.alert_ref.clone(),
                expires: now + chrono::Duration::minutes(i64::from(ttl_mins.max(1))),
                message_id: req.message_id,
                step: Step::Offer(1000),
            },
        );
    }
    if !req.action.settles() {
        for b in offers_of(s, &req.alert_ref, now) {
            if !kb.iter().any(|(k, _)| *k == b.0) {
                kb.push(b);
            }
        }
    }
    trim(s);
    save(s);
    kb
}

/// After the daemon carried out a press: the alert's keyboard shows the
/// outcome (see `result_keyboard`), and with `reply` the full result is
/// also posted under the alert.
pub fn finish(
    cfg: &TelegramCfg,
    req: &ActionRequest,
    text: &str,
    summary: &str,
    reply: bool,
    undo: Option<(ResponseAction, u32)>,
    now: DateTime<Utc>,
) {
    let kb = match store().lock() {
        Ok(mut s) => result_keyboard(&mut s, req, text, summary, undo, now),
        Err(_) => Vec::new(),
    };
    if reply {
        report(cfg, req.message_id, text);
    }
    if let Some(mid) = req.message_id {
        edit_keyboard(cfg, mid, &kb);
    }
}

fn keyboard_value(buttons: &[(String, String)]) -> Value {
    if buttons.is_empty() {
        json!({ "inline_keyboard": [] })
    } else {
        keyboard(buttons)
    }
}

/// Tidy messages whose buttons all expired: they get one "Buttons expired"
/// label. Returns the keyboards to apply.
fn sweep(ttl_mins: u32, now: DateTime<Utc>) -> Vec<(i64, Vec<(String, String)>)> {
    let Ok(mut s) = store().lock() else {
        return Vec::new();
    };
    let mut alerts: Vec<String> = s
        .values()
        .filter(|p| matches!(p.step, Step::Offer(_)) && p.message_id.is_some())
        .map(|p| p.alert_ref.clone())
        .collect();
    alerts.sort();
    alerts.dedup();
    let mut out = Vec::new();
    for a in alerts {
        let all_expired = s
            .values()
            .filter(|p| p.alert_ref == a && matches!(p.step, Step::Offer(_)))
            .all(|p| p.expires <= now);
        if all_expired {
            out.extend(expire_alert(&mut s, &a, ttl_mins, now));
        }
    }
    let before = s.len();
    s.retain(|_, p| keep(p, now));
    if !out.is_empty() || s.len() != before {
        save(&s);
    }
    out
}

fn describe_user(from: &Value) -> String {
    let id = from["id"].as_i64().unwrap_or(0);
    match from["username"].as_str() {
        Some(u) if !u.is_empty() => format!("@{} (id {})", u, id),
        _ => format!(
            "{} (id {})",
            from["first_name"].as_str().unwrap_or("someone"),
            id
        ),
    }
}

/// HTTP client for Telegram and webhooks. An error status comes back as a
/// response, so its body (Telegram's `description`) can be read.
pub(crate) fn agent(timeout: Duration) -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .user_agent(format!("hermian/{}", hermian_core::VERSION))
        .http_status_as_error(false)
        .build()
        .into()
}

fn call(cfg: &TelegramCfg, method: &str, body: Value, timeout: Duration) -> Result<Value, String> {
    let base = crate::channels::telegram::api_base();
    call_at(&base, cfg, method, body, timeout)
}

fn call_at(
    base: &str,
    cfg: &TelegramCfg,
    method: &str,
    body: Value,
    timeout: Duration,
) -> Result<Value, String> {
    let url = format!("{}/bot{}/{}", base, cfg.bot_token, method);
    match agent(timeout).post(&url).send_json(body) {
        Ok(mut r) if r.status().as_u16() < 400 => {
            r.body_mut().read_json::<Value>().map_err(|e| e.to_string())
        }
        Ok(mut r) => {
            let desc = r
                .body_mut()
                .read_json::<Value>()
                .ok()
                .and_then(|v| v["description"].as_str().map(str::to_string))
                .unwrap_or_default();
            Err(format!("HTTP {} {}", r.status().as_u16(), desc)
                .trim()
                .to_string())
        }
        Err(e) => Err(crate::notify::webhook::strip_url_paths(
            &e.to_string().replace(&cfg.bot_token, "<token>"),
        )),
    }
}

/// Fetch and handle button presses until shutdown. Reads the current config
/// each round, so turning actions on or off takes effect on reload.
pub fn spawn_poller(
    cfg: Arc<Mutex<TelegramCfg>>,
    tx: mpsc::Sender<ActionRequest>,
    shutdown: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    let now = Utc::now();
    let _ = STARTED.set(now);
    PERSIST.store(true, Ordering::Relaxed);
    load_saved(now);
    std::thread::Builder::new()
        .name("hermian-tgbot".to_string())
        .spawn(move || poll_loop(cfg, tx, shutdown))?;
    Ok(())
}

fn poll_loop(
    cfg: Arc<Mutex<TelegramCfg>>,
    tx: mpsc::Sender<ActionRequest>,
    shutdown: Arc<AtomicBool>,
) {
    let mut offset: i64 = 0;
    let mut backoff = Duration::from_secs(2);
    while !shutdown.load(Ordering::Relaxed) {
        let current = cfg.lock().map(|c| c.clone()).unwrap_or_default();
        if !current.actions_enabled() || current.bot_token.is_empty() {
            set_poll_error("");
            std::thread::sleep(Duration::from_secs(5));
            continue;
        }
        let body = json!({
            "offset": offset,
            "timeout": POLL_SECS,
            "allowed_updates": ["callback_query"],
        });
        match call(
            &current,
            "getUpdates",
            body,
            Duration::from_secs(POLL_SECS + 15),
        ) {
            Ok(v) => {
                set_poll_error("");
                backoff = Duration::from_secs(2);
                for u in v["result"].as_array().cloned().unwrap_or_default() {
                    if let Some(id) = u["update_id"].as_i64() {
                        offset = offset.max(id + 1);
                    }
                    let cq = &u["callback_query"];
                    if cq.is_null() {
                        continue;
                    }
                    let (text, outcome) = handle_callback(cq, &current, Utc::now());
                    if let Some(cq_id) = cq["id"].as_str() {
                        let _ = call(
                            &current,
                            "answerCallbackQuery",
                            json!({ "callback_query_id": cq_id, "text": text }),
                            Duration::from_secs(10),
                        );
                    }
                    if let Some((mid, buttons)) = &outcome.keyboard {
                        edit_keyboard(&current, *mid, buttons);
                    }
                    if let Some(req) = outcome.request {
                        if tx.blocking_send(req).is_err() {
                            return;
                        }
                    }
                }
                // Telegram is reachable: tidy expired keyboards and post
                // any result that couldn't be delivered before.
                for (mid, buttons) in sweep(current.action_ttl_mins, Utc::now()) {
                    edit_keyboard(&current, mid, &buttons);
                }
                flush_undelivered(&current);
            }
            Err(e) => {
                // 409: something else is reading this bot's updates. Either
                // another host with actions on shares the bot (each press
                // reaches only one of them), or a webhook is set.
                let conflict = e.starts_with("HTTP 409");
                if conflict {
                    CONFLICTS.fetch_add(1, Ordering::Relaxed);
                }
                let hint = if conflict {
                    " (another host with Telegram actions on may be using this bot: give each \
                     host with buttons its own bot, see docs/FLEET.md; or a webhook is set: \
                     call deleteWebhook)"
                } else {
                    ""
                };
                set_poll_error(&format!("{}{}", e, hint));
                std::thread::sleep(backoff);
                backoff = (backoff * 2).min(Duration::from_secs(120));
            }
        }
    }
}

fn edit_keyboard(cfg: &TelegramCfg, mid: i64, buttons: &[(String, String)]) {
    let _ = call(
        cfg,
        "editMessageReplyMarkup",
        json!({
            "chat_id": cfg.chat_id,
            "message_id": mid,
            "reply_markup": keyboard_value(buttons),
        }),
        Duration::from_secs(10),
    );
}

/// Delays before each try of a result message.
const REPORT_TRIES: [Duration; 3] = [
    Duration::from_secs(0),
    Duration::from_secs(1),
    Duration::from_secs(3),
];

fn send_text(cfg: &TelegramCfg, message_id: Option<i64>, text: &str) -> Result<(), String> {
    let mut body = json!({
        "chat_id": cfg.chat_id,
        "text": text,
        "disable_notification": true,
    });
    if let Some(mid) = message_id {
        body["reply_to_message_id"] = json!(mid);
        body["allow_sending_without_reply"] = json!(true);
    }
    if let Some(t) = cfg.message_thread_id {
        body["message_thread_id"] = json!(t);
    }
    call(cfg, "sendMessage", body, Duration::from_secs(15)).map(|_| ())
}

/// "N earlier action result(s) couldn't be delivered:" and their text.
fn undelivered_preface(old: &[String]) -> String {
    format!(
        "{} earlier action result(s) couldn't be delivered:\n\n{}",
        old.len(),
        old.join("\n\n")
    )
}

/// Post the result as a reply to the alert, with retries. If it still
/// doesn't go through, it's kept and posted with the next message that does.
pub fn report(cfg: &TelegramCfg, message_id: Option<i64>, text: &str) {
    let old: Vec<String> = undelivered()
        .lock()
        .map(|mut u| std::mem::take(&mut *u))
        .unwrap_or_default();
    let full = if old.is_empty() {
        text.to_string()
    } else {
        format!("{}\n\n{}", undelivered_preface(&old), text)
    };
    let mut last = String::new();
    for wait in REPORT_TRIES {
        std::thread::sleep(wait);
        match send_text(cfg, message_id, &full) {
            Ok(()) => return,
            Err(e) => last = e,
        }
    }
    crate::daemon::log_daemon(
        hermian_core::Severity::Low,
        &format!(
            "could not post the Telegram action result ({}); it goes with the next message",
            last
        ),
    );
    if let Ok(mut u) = undelivered().lock() {
        u.extend(old);
        u.push(text.to_string());
        let skip = u.len().saturating_sub(20);
        u.drain(..skip);
    }
    if let Ok(s) = store().lock() {
        save(&s);
    }
}

/// Post results that couldn't be delivered earlier, once Telegram answers.
fn flush_undelivered(cfg: &TelegramCfg) {
    let old: Vec<String> = undelivered()
        .lock()
        .map(|mut u| std::mem::take(&mut *u))
        .unwrap_or_default();
    if old.is_empty() {
        return;
    }
    if send_text(cfg, None, &undelivered_preface(&old)).is_err() {
        if let Ok(mut u) = undelivered().lock() {
            let mut back = old;
            back.append(&mut u);
            *u = back;
        }
    }
    if let Ok(s) = store().lock() {
        save(&s);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> TelegramCfg {
        TelegramCfg {
            bot_token: "1:x".into(),
            chat_id: "-1001".into(),
            actions: true,
            allowed_user_ids: vec![42],
            ..TelegramCfg::default()
        }
    }

    fn press(data: &str, from: i64, chat: i64) -> Value {
        json!({
            "id": "cb1",
            "from": { "id": from, "username": "op" },
            "message": { "message_id": 7, "chat": { "id": chat } },
            "data": data,
        })
    }

    fn ip(s: &str) -> std::net::IpAddr {
        s.parse().unwrap()
    }

    /// Press, and for a destructive action press Confirm too.
    fn press_confirmed(data: &str, now: DateTime<Utc>) -> Outcome {
        let (_, first) = handle_callback(&press(data, 42, -1001), &cfg(), now);
        if first.request.is_some() {
            return first;
        }
        let (_, buttons) = first.keyboard.expect("confirmation keyboard");
        handle_callback(&press(&buttons[0].0, 42, -1001), &cfg(), now).1
    }

    #[test]
    fn only_allowed_users_in_the_chat_can_press() {
        let now = Utc::now();
        let b = register(
            "HER-T-1",
            &[ResponseAction::Block {
                sources: vec![ip("198.51.100.7")],
            }],
            30,
            now,
        );
        let data = &b[0].0;
        let (msg, out) = handle_callback(&press(data, 99, -1001), &cfg(), now);
        assert!(out.request.is_none() && out.keyboard.is_none(), "{}", msg);
        let (_, out) = handle_callback(&press(data, 42, -2002), &cfg(), now);
        assert!(out.request.is_none(), "wrong chat");
        // The refused presses didn't use the button up.
        let out = press_confirmed(data, now);
        let req = out.request.expect("allowed user in the right chat");
        assert_eq!(req.by, "@op (id 42)");
        assert_eq!(req.message_id, Some(7));
        // One-time, and a second press says so.
        let (msg, out) = handle_callback(&press(data, 42, -1001), &cfg(), now);
        assert!(out.request.is_none(), "{}", msg);
        assert!(msg.starts_with("You did this: @op chose Block"), "{}", msg);
    }

    #[test]
    fn destructive_actions_ask_first() {
        let now = Utc::now();
        let b = register(
            "HER-T-7",
            &[
                ResponseAction::Ignore {
                    sources: vec![],
                    hours: 0,
                },
                ResponseAction::Disconnect {
                    source: ip("198.51.100.7"),
                    port: Some(1),
                    user: "root".into(),
                    block: true,
                },
            ],
            30,
            now,
        );
        // First press: nothing happens yet, the keyboard asks.
        let (msg, out) = handle_callback(&press(&b[1].0, 42, -1001), &cfg(), now);
        assert!(out.request.is_none(), "{}", msg);
        let (mid, ask) = out.keyboard.expect("asks");
        assert_eq!(mid, 7);
        assert_eq!(ask[0].1, "Confirm: Disconnect and block");
        assert_eq!(ask[1].1, "Cancel");
        // Cancel puts the alert's buttons back, in order, and acts on nothing.
        let (msg, out) = handle_callback(&press(&ask[1].0, 42, -1001), &cfg(), now);
        assert!(out.request.is_none() && msg.contains("Cancelled"));
        let (_, back) = out.keyboard.unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back[1].1, "Disconnect and block");
        // The cancelled Confirm is gone.
        assert!(handle_callback(&press(&ask[0].0, 42, -1001), &cfg(), now)
            .1
            .request
            .is_none());
        // Ask again and confirm: now it acts.
        let (_, out) = handle_callback(&press(&back[1].0, 42, -1001), &cfg(), now);
        let (_, ask) = out.keyboard.unwrap();
        let (_, out) = handle_callback(&press(&ask[0].0, 42, -1001), &cfg(), now);
        assert!(matches!(
            out.request.map(|r| r.action),
            Some(ResponseAction::Disconnect { .. })
        ));
    }

    #[test]
    fn a_confirmation_expires_after_two_minutes() {
        let now = Utc::now();
        let b = register(
            "HER-T-8",
            &[ResponseAction::Block {
                sources: vec![ip("198.51.100.7")],
            }],
            30,
            now,
        );
        let (_, out) = handle_callback(&press(&b[0].0, 42, -1001), &cfg(), now);
        let (_, ask) = out.keyboard.unwrap();
        let later = now + chrono::Duration::seconds(CONFIRM_SECS + 1);
        let (msg, out) = handle_callback(&press(&ask[0].0, 42, -1001), &cfg(), later);
        assert!(out.request.is_none() && msg.contains("expired"), "{}", msg);
        // The original button is back and still works.
        let (_, back) = out.keyboard.expect("buttons restored");
        assert_eq!(back.len(), 1);
    }

    #[test]
    fn ignore_needs_no_confirmation() {
        let now = Utc::now();
        let b = register(
            "HER-T-9",
            &[ResponseAction::Ignore {
                sources: vec![],
                hours: 0,
            }],
            30,
            now,
        );
        let (_, out) = handle_callback(&press(&b[0].0, 42, -1001), &cfg(), now);
        assert!(out.request.is_some());
        // Settled: nothing left to press while the result comes in.
        assert_eq!(out.keyboard.map(|(_, kb)| kb.len()), Some(0));
    }

    #[test]
    fn buttons_expire_and_settling_retires_the_rest() {
        let now = Utc::now();
        let b = register(
            "HER-T-2",
            &[
                ResponseAction::Ignore {
                    sources: vec![],
                    hours: 0,
                },
                ResponseAction::Disconnect {
                    source: ip("198.51.100.7"),
                    port: Some(1),
                    user: "root".into(),
                    block: true,
                },
            ],
            30,
            now,
        );
        assert!(press_confirmed(&b[1].0, now).request.is_some());
        let mut other = press(&b[0].0, 42, -1001);
        other["from"] = json!({ "id": 42, "username": "ann" });
        let (msg, out) = handle_callback(&other, &cfg(), now);
        assert!(
            out.request.is_none(),
            "the other button went with the choice"
        );
        assert!(
            msg.starts_with("Already handled: @op chose Disconnect and block"),
            "{}",
            msg
        );

        let b = register(
            "HER-T-3",
            &[ResponseAction::Ignore {
                sources: vec![],
                hours: 0,
            }],
            1,
            now,
        );
        let later = now + chrono::Duration::minutes(2);
        let (msg, out) = handle_callback(&press(&b[0].0, 42, -1001), &cfg(), later);
        assert!(out.request.is_none(), "{}", msg);
        assert_eq!(msg, "Expired (buttons last 15 min). Nothing was done.");
    }

    #[test]
    fn blocking_one_digest_source_keeps_the_others() {
        let now = Utc::now();
        let b = register(
            "HER-T-4",
            &[
                ResponseAction::Block {
                    sources: vec![ip("198.51.100.7")],
                },
                ResponseAction::Block {
                    sources: vec![ip("203.0.113.9")],
                },
            ],
            30,
            now,
        );
        let first = press_confirmed(&b[0].0, now);
        assert!(first.request.is_some());
        // The keyboard comes back with the other source's button only.
        let (_, rest) = first.keyboard.expect("remaining buttons");
        assert_eq!(rest.len(), 1);
        assert_eq!(rest[0].1, "Block 203.0.113.9");
        assert!(press_confirmed(&b[1].0, now).request.is_some());
    }

    #[test]
    fn disabled_actions_refuse_everything() {
        let now = Utc::now();
        let b = register(
            "HER-T-5",
            &[ResponseAction::Ignore {
                sources: vec![],
                hours: 0,
            }],
            30,
            now,
        );
        let mut c = cfg();
        c.actions = false;
        assert!(handle_callback(&press(&b[0].0, 42, -1001), &c, now)
            .1
            .request
            .is_none());
    }

    /// A minimal Bot API stand-in: answers by method name and records calls.
    type Calls = Arc<Mutex<Vec<(String, Value)>>>;

    fn mock_server(updates: Value) -> (String, Calls) {
        use std::io::{BufRead, BufReader, Read, Write};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let calls: Calls = Arc::default();
        let rec = calls.clone();
        std::thread::spawn(move || {
            let mut served_updates = false;
            for stream in l.incoming().flatten() {
                let mut r = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                if r.read_line(&mut line).is_err() {
                    continue;
                }
                let path = line.split_whitespace().nth(1).unwrap_or("").to_string();
                let mut len = 0usize;
                loop {
                    let mut h = String::new();
                    if r.read_line(&mut h).is_err() || h == "\r\n" || h.is_empty() {
                        break;
                    }
                    if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap_or(0);
                    }
                }
                let mut body = vec![0u8; len];
                let _ = r.read_exact(&mut body);
                let body: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                let method = path.rsplit('/').next().unwrap_or("").to_string();
                rec.lock().unwrap().push((method.clone(), body));
                let reply = match method.as_str() {
                    "getUpdates" if !served_updates => {
                        served_updates = true;
                        json!({ "ok": true, "result": updates.clone() })
                    }
                    "getUpdates" => {
                        std::thread::sleep(Duration::from_millis(200));
                        json!({ "ok": true, "result": [] })
                    }
                    "sendMessage" => json!({ "ok": true, "result": { "message_id": 555 } }),
                    _ => json!({ "ok": true, "result": true }),
                };
                let text = reply.to_string();
                let mut s = stream;
                let _ = write!(
                    s,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    text.len(),
                    text
                );
            }
        });
        (base, calls)
    }

    /// An error status still yields Telegram's description: the shared-bot
    /// alert keys on "HTTP 409", and the token never shows in an error.
    #[test]
    fn error_status_keeps_the_description() {
        use std::io::{Read, Write};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf);
            let body = r#"{"ok":false,"error_code":409,"description":"Conflict: terminated by other getUpdates request"}"#;
            let _ = write!(
                s,
                "HTTP/1.1 409 Conflict\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
        });
        let e = call_at(
            &base,
            &cfg(),
            "getUpdates",
            json!({}),
            Duration::from_secs(5),
        )
        .unwrap_err();
        assert_eq!(
            e,
            "HTTP 409 Conflict: terminated by other getUpdates request"
        );
        // Nothing listening: a transport error, with the token redacted.
        let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", dead.local_addr().unwrap());
        drop(dead);
        let e = call_at(&base, &cfg(), "getMe", json!({}), Duration::from_secs(5)).unwrap_err();
        assert!(!e.contains("1:x"), "{e}");
    }

    /// Alert with buttons -> Telegram -> a press from an allowed user ->
    /// answered and handed to the daemon; a press from someone else is
    /// answered with a refusal and goes nowhere.
    #[test]
    fn end_to_end_against_a_mock_bot_api() {
        use hermian_core::{Alert, DetectionId, Finding, Severity};
        // Step 1: sending an alert that offers actions attaches a keyboard.
        let (base, calls) = mock_server(json!([]));
        std::env::set_var("HERMIAN_TELEGRAM_API", &base);
        let f = Finding::new(
            DetectionId::D2,
            Severity::High,
            "SSH login after a failed-auth burst",
            "x",
        )
        .offer(ResponseAction::Ignore {
            sources: vec![],
            hours: 0,
        })
        .offer(ResponseAction::Disconnect {
            source: ip("198.51.100.7"),
            port: Some(4242),
            user: "deploy".into(),
            block: true,
        });
        let alert = Alert::from_finding(f, "HER-E2E-1".into(), "web-01".into(), Utc::now());
        crate::channels::telegram::send(&alert, &cfg()).unwrap();
        let sent = calls
            .lock()
            .unwrap()
            .iter()
            .find(|(m, _)| m == "sendMessage")
            .cloned()
            .unwrap();
        let kb = &sent.1["reply_markup"]["inline_keyboard"];
        assert_eq!(kb.as_array().unwrap().len(), 2, "{}", sent.1);
        assert_eq!(kb[1][0]["text"], "Disconnect and block");
        let data = kb[1][0]["callback_data"].as_str().unwrap().to_string();

        // Step 2: the poller receives two presses of that button.
        let updates = json!([
            { "update_id": 10, "callback_query": {
                "id": "q-bad", "from": { "id": 99, "username": "eve" },
                "message": { "message_id": 1, "chat": { "id": -1001 } }, "data": data } },
            { "update_id": 11, "callback_query": {
                "id": "q-ok", "from": { "id": 42, "username": "op" },
                "message": { "message_id": 1, "chat": { "id": -1001 } }, "data": data } }
        ]);
        let (base, calls) = mock_server(updates);
        std::env::set_var("HERMIAN_TELEGRAM_API", &base);
        let (tx, mut rx) = mpsc::channel(4);
        let shutdown = Arc::new(AtomicBool::new(false));
        spawn_poller(Arc::new(Mutex::new(cfg())), tx, shutdown.clone()).unwrap();
        // The allowed press asks for confirmation: the keyboard is swapped.
        let ask = {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            loop {
                let edit = calls
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|(m, _)| m == "editMessageReplyMarkup")
                    .cloned();
                if let Some((_, body)) = edit {
                    break body;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "no confirmation asked"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        };
        shutdown.store(true, Ordering::Relaxed);
        assert!(rx.try_recv().is_err(), "nothing done before Confirm");
        let kb = &ask["reply_markup"]["inline_keyboard"];
        assert_eq!(kb[0][0]["text"], "Confirm: Disconnect and block");
        let confirm = kb[0][0]["callback_data"].as_str().unwrap();
        let (_, out) = handle_callback(
            &json!({
                "id": "q-confirm", "from": { "id": 42, "username": "op" },
                "message": { "message_id": 1, "chat": { "id": -1001 } }, "data": confirm }),
            &cfg(),
            Utc::now(),
        );
        let req = out.request.expect("confirmed");
        assert_eq!(req.by, "@op (id 42)");
        assert_eq!(req.message_id, Some(555), "message id from sendMessage");
        assert!(matches!(
            req.action,
            ResponseAction::Disconnect {
                block: true,
                port: Some(4242),
                ..
            }
        ));
        assert!(rx.try_recv().is_err(), "the refused press produced nothing");
        let answers: Vec<Value> = calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(m, _)| m == "answerCallbackQuery")
            .map(|(_, b)| b.clone())
            .collect();
        assert_eq!(answers.len(), 2);
        assert_eq!(answers[0]["callback_query_id"], "q-bad");
        assert!(answers[0]["text"].as_str().unwrap().contains("not allowed"));
        assert_eq!(answers[1]["callback_query_id"], "q-ok");
        // Only callback queries are requested from Telegram.
        let poll = calls
            .lock()
            .unwrap()
            .iter()
            .find(|(m, _)| m == "getUpdates")
            .cloned()
            .unwrap();
        assert_eq!(poll.1["allowed_updates"], json!(["callback_query"]));
        std::env::remove_var("HERMIAN_TELEGRAM_API");
    }

    #[test]
    fn keyboard_has_one_button_per_row() {
        let k = keyboard(&[
            ("hm:a".into(), "Ignore".into()),
            ("hm:b".into(), "Block 1.2.3.4".into()),
        ]);
        assert_eq!(k["inline_keyboard"].as_array().unwrap().len(), 2);
        assert_eq!(k["inline_keyboard"][1][0]["callback_data"], "hm:b");
        // Callback data must fit Telegram's 64-byte limit.
        let b = register(
            "HER-T-6",
            &[ResponseAction::Ignore {
                sources: vec![],
                hours: 0,
            }],
            30,
            Utc::now(),
        );
        assert!(b[0].0.len() <= 64);
    }

    fn req_for(data: &str, now: DateTime<Utc>) -> ActionRequest {
        press_confirmed(data, now).request.expect("acted")
    }

    #[test]
    fn an_expired_button_says_how_to_do_it_now() {
        let now = Utc::now();
        let b = register(
            "HER-T-10",
            &[ResponseAction::Block {
                sources: vec![ip("198.51.100.7")],
            }],
            30,
            now,
        );
        attach_message(&b, 70);
        let later = now + chrono::Duration::minutes(31);
        let (msg, out) = handle_callback(&press(&b[0].0, 42, -1001), &cfg(), later);
        assert!(out.request.is_none());
        assert_eq!(
            msg,
            "Expired (buttons last 15 min). From the host: sudo hermian block 198.51.100.7"
        );
        let (mid, kb) = out.keyboard.expect("keyboard tidied");
        assert_eq!(mid, 70);
        assert_eq!(kb.len(), 1);
        assert_eq!(kb[0].1, "Buttons expired");
        // The label repeats the command when pressed.
        let (msg, _) = handle_callback(&press(&kb[0].0, 42, -1001), &cfg(), later);
        assert!(msg.contains("sudo hermian block 198.51.100.7"), "{}", msg);
    }

    #[test]
    fn the_sweep_tidies_keyboards_nobody_pressed() {
        let now = Utc::now();
        let b = register(
            "HER-T-11",
            &[ResponseAction::Ignore {
                sources: vec![],
                hours: 0,
            }],
            1,
            now,
        );
        attach_message(&b, 71);
        assert!(sweep(15, now).iter().all(|(m, _)| *m != 71), "still live");
        let tidied = sweep(15, now + chrono::Duration::minutes(2));
        let (_, kb) = tidied.iter().find(|(m, _)| *m == 71).expect("tidied");
        assert_eq!(kb[0].1, "Buttons expired");
        // Only once.
        assert!(sweep(15, now + chrono::Duration::minutes(3))
            .iter()
            .all(|(m, _)| *m != 71));
    }

    #[test]
    fn a_result_becomes_a_label_with_an_undo() {
        let now = Utc::now();
        let b = register(
            "HER-T-12",
            &[ResponseAction::Block {
                sources: vec![ip("198.51.100.7")],
            }],
            30,
            now,
        );
        attach_message(&b, 72);
        let req = req_for(&b[0].0, now);
        let text = "✓ Blocked 198.51.100.7 until 14:02 UTC tomorrow\nweb-01 · @op · 14:02 UTC";
        let summary = "✓ Blocked 198.51.100.7 · @op 14:02 UTC";
        let kb = {
            let mut s = store().lock().unwrap();
            result_keyboard(
                &mut s,
                &req,
                text,
                summary,
                Some((
                    ResponseAction::Unblock {
                        sources: vec![ip("198.51.100.7")],
                    },
                    60,
                )),
                now,
            )
        };
        assert_eq!(kb.len(), 2, "{:?}", kb);
        assert_eq!(kb[0].1, summary);
        assert_eq!(kb[1].1, "Undo: unblock 198.51.100.7");
        // The label shows the whole result.
        let (msg, _) = handle_callback(&press(&kb[0].0, 42, -1001), &cfg(), now);
        assert!(msg.starts_with("✓ Blocked 198.51.100.7"), "{}", msg);
        // The used button now quotes the outcome.
        let (msg, _) = handle_callback(&press(&b[0].0, 42, -1001), &cfg(), now);
        assert_eq!(msg, format!("You did this: {}", summary));
        // Undo needs no confirmation.
        let (_, out) = handle_callback(&press(&kb[1].0, 42, -1001), &cfg(), now);
        assert!(matches!(
            out.request.map(|r| r.action),
            Some(ResponseAction::Unblock { .. })
        ));
    }

    #[test]
    fn a_choice_made_while_a_confirm_was_up_wins() {
        let now = Utc::now();
        let b = register(
            "HER-T-13",
            &[
                ResponseAction::Ignore {
                    sources: vec![],
                    hours: 0,
                },
                ResponseAction::Disconnect {
                    source: ip("198.51.100.7"),
                    port: None,
                    user: "root".into(),
                    block: false,
                },
            ],
            30,
            now,
        );
        // @op asks to disconnect; @ann presses Ignore before @op confirms.
        let (_, out) = handle_callback(&press(&b[1].0, 42, -1001), &cfg(), now);
        let (_, ask) = out.keyboard.unwrap();
        let mut ann = press(&b[0].0, 42, -1001);
        ann["from"] = json!({ "id": 42, "username": "ann" });
        assert!(handle_callback(&ann, &cfg(), now).1.request.is_some());
        let (msg, out) = handle_callback(&press(&ask[0].0, 42, -1001), &cfg(), now);
        assert!(out.request.is_none(), "{}", msg);
    }

    #[test]
    fn a_lost_button_says_why_and_where_the_alert_is() {
        let cq = json!({
            "id": "q", "from": { "id": 42, "username": "op" },
            "message": { "message_id": 9, "chat": { "id": -1001 },
                         "text": "HIGH · SSH\nhermian show HER-2026-1018-009" },
            "data": "hm:000000000000000000000000",
        });
        let (msg, out) = handle_callback(&cq, &cfg(), Utc::now());
        assert!(out.request.is_none());
        assert!(
            msg.ends_with("Details: sudo hermian show HER-2026-1018-009"),
            "{}",
            msg
        );
        assert!(msg.contains("Nothing was done"), "{}", msg);
    }

    #[test]
    fn buttons_survive_a_round_trip_to_disk() {
        let now = Utc::now();
        let a = ResponseAction::Block {
            sources: vec![ip("198.51.100.7")],
        };
        let mut buttons = HashMap::new();
        for (i, step) in [
            Step::Offer(0),
            Step::Confirm { offer: "a".into() },
            Step::Cancel { offer: "a".into() },
            Step::Used {
                by: "@op (id 42)".into(),
                at: now,
                note: "x".into(),
            },
            Step::Label {
                text: "y".into(),
                shown: "z".into(),
            },
        ]
        .into_iter()
        .enumerate()
        {
            buttons.insert(
                format!("id{}", i),
                Pending {
                    action: a.clone(),
                    alert_ref: "HER-T-14".into(),
                    expires: now,
                    message_id: Some(1),
                    step,
                },
            );
        }
        let saved = Saved {
            buttons,
            undelivered: vec!["r".into()],
        };
        let back: Saved = serde_json::from_str(&serde_json::to_string(&saved).unwrap()).unwrap();
        assert_eq!(back.buttons.len(), 5);
        assert_eq!(back.buttons["id3"].step, saved.buttons["id3"].step);
        assert_eq!(back.undelivered, vec!["r".to_string()]);
    }

    #[test]
    fn answers_fit_telegrams_limit() {
        let long = "x".repeat(500);
        assert_eq!(clip(long).chars().count(), ANSWER_MAX);
        assert_eq!(clip("short".into()), "short");
    }

    #[test]
    fn a_press_for_another_hosts_alert_says_so() {
        let cq = |text: &str| {
            json!({
                "id": "q", "from": { "id": 42, "username": "op" },
                "message": { "message_id": 9, "chat": { "id": -1001 }, "text": text },
                "data": "hm:111111111111111111111111",
            })
        };
        let full = "◉◉◉○  HIGH · SSH
Root login

host   db-02-elsewhere
rule   D2 · SSH";
        let (msg, out) = handle_callback(&cq(full), &cfg(), Utc::now());
        assert!(out.request.is_none());
        assert!(
            msg.starts_with("This is db-02-elsewhere's alert, but "),
            "{}",
            msg
        );
        assert!(msg.contains("its own bot"), "{}", msg);
        assert_eq!(
            host_in(
                "HIGH alert 025 on web-01
sudo hermian show HER-1"
            ),
            Some("web-01".into())
        );
        // Our own host: the usual answer.
        let own = format!("host   {}", crate::procsrc::hostname());
        let (msg, _) = handle_callback(&cq(&own), &cfg(), Utc::now());
        assert!(msg.starts_with("This button is no longer valid"), "{}", msg);
    }
}
