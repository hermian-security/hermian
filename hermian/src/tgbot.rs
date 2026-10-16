//! Telegram response buttons.
//!
//! Alerts that offer responses get an inline keyboard. Each button carries a
//! random one-time id that points at an action kept here, in memory, until
//! it expires. Button presses are fetched by long-polling `getUpdates`
//! (outbound only, so Hermian still listens on no port, and it keeps working
//! during isolation since Telegram stays reachable). A press is only acted
//! on if it comes from the configured chat *and* from one of
//! `allowed_user_ids`; anything else is refused and logged.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use chrono::{DateTime, Utc};
use hermian_core::config::TelegramCfg;
use hermian_core::ResponseAction;
use serde_json::{json, Value};
use tokio::sync::mpsc;

/// Prefix of our callback data, so stray buttons from elsewhere are ignored.
const PREFIX: &str = "hm:";
/// Most pending actions kept (oldest dropped first).
const MAX_PENDING: usize = 2000;
/// Long-poll wait, seconds. The HTTP timeout must be longer.
const POLL_SECS: u64 = 25;

#[derive(Debug, Clone)]
pub struct Pending {
    pub action: ResponseAction,
    pub alert_ref: String,
    pub expires: DateTime<Utc>,
    pub message_id: Option<i64>,
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
    s.retain(|_, p| p.expires > now);
    let mut out = Vec::new();
    for a in actions {
        let id = random_id();
        s.insert(
            id.clone(),
            Pending {
                action: a.clone(),
                alert_ref: alert_ref.to_string(),
                expires,
                message_id: None,
            },
        );
        out.push((format!("{}{}", PREFIX, id), a.label()));
    }
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

/// Decide what to do with one callback query. Returns the text to show the
/// presser and, if every check passed, the action to carry out.
pub fn handle_callback(
    cq: &Value,
    cfg: &TelegramCfg,
    now: DateTime<Utc>,
) -> (String, Option<ActionRequest>) {
    let from_id = cq["from"]["id"].as_i64();
    let who = describe_user(&cq["from"]);
    let chat_ok = cq["message"]["chat"]["id"]
        .as_i64()
        .map(|id| id.to_string() == cfg.chat_id.trim())
        .unwrap_or(false);
    if !cfg.actions_enabled() {
        return ("Response buttons are turned off on this host.".into(), None);
    }
    if !chat_ok {
        return ("Not from the configured chat.".into(), None);
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
        return ("You're not allowed to do this.".into(), None);
    }
    let Some(id) = cq["data"].as_str().and_then(|d| d.strip_prefix(PREFIX)) else {
        return ("Unknown button.".into(), None);
    };
    let Ok(mut s) = store().lock() else {
        return ("Try again.".into(), None);
    };
    let Some(p) = s.remove(id) else {
        return ("This button has expired or was already used.".into(), None);
    };
    if p.expires <= now {
        return ("This button has expired.".into(), None);
    }
    if p.action.settles() {
        // One choice per alert: its other buttons stop working.
        s.retain(|_, other| other.alert_ref != p.alert_ref);
    }
    let req = ActionRequest {
        action: p.action.clone(),
        alert_ref: p.alert_ref.clone(),
        by: who,
        message_id: p
            .message_id
            .or_else(|| cq["message"]["message_id"].as_i64()),
    };
    (format!("{}: on it.", p.action.label()), Some(req))
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

fn agent(timeout: Duration) -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(timeout)
        .user_agent(&format!("hermian/{}", hermian_core::VERSION))
        .build()
}

fn call(cfg: &TelegramCfg, method: &str, body: Value, timeout: Duration) -> Result<Value, String> {
    let url = format!(
        "{}/bot{}/{}",
        crate::channels::telegram::api_base(),
        cfg.bot_token,
        method
    );
    match agent(timeout).post(&url).send_json(body) {
        Ok(r) => r.into_json::<Value>().map_err(|e| e.to_string()),
        Err(ureq::Error::Status(code, r)) => {
            let desc = r
                .into_json::<Value>()
                .ok()
                .and_then(|v| v["description"].as_str().map(str::to_string))
                .unwrap_or_default();
            Err(format!("HTTP {} {}", code, desc).trim().to_string())
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
                    let (text, req) = handle_callback(cq, &current, Utc::now());
                    if let Some(cq_id) = cq["id"].as_str() {
                        let _ = call(
                            &current,
                            "answerCallbackQuery",
                            json!({ "callback_query_id": cq_id, "text": text }),
                            Duration::from_secs(10),
                        );
                    }
                    if let Some(req) = req {
                        if tx.blocking_send(req).is_err() {
                            return;
                        }
                    }
                }
            }
            Err(e) => {
                // 409: something else is reading this bot's updates. Either
                // another host with actions on shares the bot (each press
                // reaches only one of them), or a webhook is set.
                let hint = if e.starts_with("HTTP 409") {
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

/// Post the outcome as a reply to the alert, and drop its buttons if the
/// choice settled it. Best effort: failures are logged, not retried.
pub fn report(cfg: &TelegramCfg, message_id: Option<i64>, text: &str, settled: bool) {
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
    if let Err(e) = call(cfg, "sendMessage", body, Duration::from_secs(15)) {
        crate::daemon::log_daemon(
            hermian_core::Severity::Low,
            &format!("could not post the Telegram action result: {}", e),
        );
    }
    if let (true, Some(mid)) = (settled, message_id) {
        let _ = call(
            cfg,
            "editMessageReplyMarkup",
            json!({
                "chat_id": cfg.chat_id,
                "message_id": mid,
                "reply_markup": { "inline_keyboard": [] },
            }),
            Duration::from_secs(15),
        );
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
        let (msg, req) = handle_callback(&press(data, 99, -1001), &cfg(), now);
        assert!(req.is_none(), "{}", msg);
        let (_, req) = handle_callback(&press(data, 42, -2002), &cfg(), now);
        assert!(req.is_none(), "wrong chat");
        // The refused presses didn't use the button up.
        let (_, req) = handle_callback(&press(data, 42, -1001), &cfg(), now);
        let req = req.expect("allowed user in the right chat");
        assert_eq!(req.by, "@op (id 42)");
        assert_eq!(req.message_id, Some(7));
        // One-time.
        let (msg, req) = handle_callback(&press(data, 42, -1001), &cfg(), now);
        assert!(req.is_none() && msg.contains("expired or was already used"));
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
        let (_, req) = handle_callback(&press(&b[1].0, 42, -1001), &cfg(), now);
        assert!(req.is_some());
        let (_, req) = handle_callback(&press(&b[0].0, 42, -1001), &cfg(), now);
        assert!(req.is_none(), "the other button went with the choice");

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
        let (msg, req) = handle_callback(&press(&b[0].0, 42, -1001), &cfg(), later);
        assert!(req.is_none() && msg.contains("expired"), "{}", msg);
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
        assert!(handle_callback(&press(&b[0].0, 42, -1001), &cfg(), now)
            .1
            .is_some());
        assert!(handle_callback(&press(&b[1].0, 42, -1001), &cfg(), now)
            .1
            .is_some());
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
        let req = {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            loop {
                if let Ok(r) = rx.try_recv() {
                    break r;
                }
                assert!(std::time::Instant::now() < deadline, "no action request");
                std::thread::sleep(Duration::from_millis(20));
            }
        };
        shutdown.store(true, Ordering::Relaxed);
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
}
