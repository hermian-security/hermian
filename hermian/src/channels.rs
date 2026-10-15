//! Outbound notification transports: Telegram and email.
//!
//! Each `send` is synchronous and returns `Err(String)` with a one-line reason
//! so the notifier can retry with backoff and surface it in `hermian status`.

use std::time::Duration;

use hermian_core::config::{EmailCfg, TelegramCfg};
use hermian_core::{render, Alert, Severity, Theme};

use crate::notify::SendError;

// ---------------------------------------------------------------------------
// Telegram
// ---------------------------------------------------------------------------

pub mod telegram {
    use super::*;

    /// Telegram caps messages at 4096 chars; keep headroom for the pre block.
    const MAX_TEXT: usize = 3800;

    /// Bot API base. Overridable for integration tests against a mock server.
    pub fn api_base() -> String {
        std::env::var("HERMIAN_TELEGRAM_API")
            .unwrap_or_else(|_| "https://api.telegram.org".to_string())
    }

    /// ureq includes the request URL (and thus the bot token) in its errors.
    fn redact(cfg: &TelegramCfg, e: impl std::fmt::Display) -> String {
        let s = e.to_string();
        // replace("") would insert "<token>" between every character.
        let s = if cfg.bot_token.is_empty() {
            s
        } else {
            s.replace(&cfg.bot_token, "<token>")
        };
        // And if the URL comes back escaped or normalised, drop its path.
        crate::notify::webhook::strip_url_paths(&s)
    }

    /// Escape for Telegram's HTML parse mode.
    fn esc(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    }

    /// Facts beyond these go to `hermian show` instead of the message.
    const MAX_FACT_ROWS: usize = 6;
    /// Lines kept from one multi-line fact.
    const MAX_FACT_LINES: usize = 4;
    /// Text width of a fact value, so a table line fits a phone screen.
    const FACT_W: usize = 30;
    /// Facts labels are clipped here; keep it above the longest label in use.
    const LABEL_W: usize = 12;
    /// Separates the incident from the explanation, as a plain rule. U+2501.
    const DIVIDER: &str = "\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\
                           \u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}";

    /// A four-cell severity meter (filled cells count up with severity).
    pub(super) fn meter(s: Severity) -> &'static str {
        match s {
            Severity::Critical => "\u{25A0}\u{25A0}\u{25A0}\u{25A0}", // â– â– â– â–
            Severity::High => "\u{25A0}\u{25A0}\u{25A0}\u{25A1}",     // â– â– â– â–¡
            Severity::Low => "\u{25A0}\u{25A0}\u{25A1}\u{25A1}",      // â– â– â–¡â–¡
            Severity::Info => "\u{25A0}\u{25A1}\u{25A1}\u{25A1}",     // â– â–¡â–¡â–¡
        }
    }

    /// Cut `s` to at most `max` chars, marking the cut. Applied before
    /// escaping so an HTML entity is never split.
    fn clip(s: &str, max: usize) -> String {
        if s.chars().count() <= max {
            return s.to_string();
        }
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('\u{2026}');
        out
    }

    /// Wrap `text` to `width`, hard-splitting words that don't fit, keeping at
    /// most `max_lines` lines. An explicit newline starts a new line. Runs on
    /// unescaped text so escaping a whole line can never split an entity.
    fn wrap_lines(text: &str, width: usize, max_lines: usize) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for para in text.split('\n') {
            let mut cur = String::new();
            for word in para.split_whitespace() {
                if word.chars().count() > width {
                    if !cur.is_empty() {
                        out.push(std::mem::take(&mut cur));
                        if out.len() >= max_lines {
                            return out;
                        }
                    }
                    let mut chunk = String::new();
                    for ch in word.chars() {
                        chunk.push(ch);
                        if chunk.chars().count() == width {
                            out.push(std::mem::take(&mut chunk));
                            if out.len() >= max_lines {
                                return out;
                            }
                        }
                    }
                    cur = chunk;
                    continue;
                }
                if !cur.is_empty() && cur.chars().count() + 1 + word.chars().count() > width {
                    out.push(std::mem::take(&mut cur));
                    if out.len() >= max_lines {
                        return out;
                    }
                }
                if !cur.is_empty() {
                    cur.push(' ');
                }
                cur.push_str(word);
            }
            out.push(std::mem::take(&mut cur));
            if out.len() >= max_lines {
                break;
            }
        }
        out.truncate(max_lines);
        out
    }

    /// The evidence facts as an aligned monospace block, HTML-escaped. `None`
    /// when there is nothing to show.
    fn fact_table(rows: &[(String, String)]) -> Option<String> {
        if rows.is_empty() {
            return None;
        }
        let labels: Vec<String> = rows
            .iter()
            .take(MAX_FACT_ROWS)
            .map(|(l, _)| esc(&clip(l, LABEL_W)))
            .collect();
        let label_w = labels.iter().map(|l| l.chars().count()).max().unwrap_or(0);
        let mut lines: Vec<String> = Vec::new();
        for ((_, value), label) in rows.iter().take(MAX_FACT_ROWS).zip(&labels) {
            for (i, l) in wrap_lines(&clip(value, 400), FACT_W, MAX_FACT_LINES)
                .iter()
                .enumerate()
            {
                let pad = if i == 0 { label.as_str() } else { "" };
                lines.push(format!("{:<w$}  {}", pad, esc(l), w = label_w));
            }
        }
        if rows.len() > MAX_FACT_ROWS {
            lines.push(format!("+{} more", rows.len() - MAX_FACT_ROWS));
        }
        Some(format!("<pre>{}</pre>", lines.join("\n")))
    }

    /// Evidence worth showing: the process chain when it has more than one
    /// step, and any fact the title or summary doesn't already state. A fact
    /// whose value is already in the sentence above it is the same thing twice;
    /// `hermian show <ref>` always has the complete list.
    fn extra_facts(alert: &Alert) -> Vec<(String, String)> {
        let stated = format!("{} {}", alert.title, alert.what).to_lowercase();
        let mut rows: Vec<(String, String)> = Vec::new();
        if alert.chain.len() > 1 {
            let chain: Vec<&str> = alert.chain.iter().map(|n| n.comm.as_str()).collect();
            rows.push(("Chain".to_string(), chain.join(" \u{2192} ")));
        }
        for f in &alert.facts {
            let v = f.value.trim();
            if v.is_empty() || stated.contains(&v.to_lowercase()) {
                continue;
            }
            rows.push((f.label.clone(), f.value.clone()));
        }
        rows
    }

    /// The explanation: a rule, why it matters, the recommended steps, a rule.
    /// Empty when there is nothing to explain.
    fn explanation(alert: &Alert) -> String {
        if alert.why.is_empty() && alert.actions.is_empty() {
            return String::new();
        }
        let mut s = format!("{}\n", DIVIDER);
        if !alert.why.is_empty() {
            s.push('\n');
            s.push_str(&esc(&clip(&alert.why, 600)));
            s.push('\n');
        }
        if !alert.actions.is_empty() {
            s.push_str("\n<b>Also</b>\n");
            for (i, a) in alert.actions.iter().take(5).enumerate() {
                s.push_str(&format!("{}. {}\n", i + 1, esc(&clip(a, 180))));
            }
        }
        s.push_str(&format!("\n{}", DIVIDER));
        s
    }

    /// Build the HTML message body. Shape:
    ///
    /// ```text
    /// â– â– â– â–¡ HERMIAN - HIGH
    /// Host : web-01
    ///
    /// - SSH login after a failed-auth burst :
    ///
    /// root logged in from 198.51.100.7 shortly after 14 failed attempts.
    ///
    /// â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”
    /// A login from an address that was just brute-forcing this host ...
    ///
    /// Also
    /// 1. ...
    /// â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”
    ///
    /// hermian show HER-...
    /// ```
    ///
    /// The CLI keeps the full alert; this is the short form. Every piece is
    /// complete HTML so skipping one never leaves a tag open, the footer is
    /// always kept, and each field is clipped to a budget so a long
    /// attacker-controlled value can't push the message past Telegram's limit.
    pub fn body(alert: &Alert) -> String {
        let footer = format!("\n<code>hermian show {}</code>", esc(&alert.ref_id));
        let mut out = format!(
            "<b>{} HERMIAN - {}</b>\nHost : {}",
            meter(alert.severity),
            alert.severity.as_str(),
            esc(&clip(&alert.host, 60))
        );
        if alert.repeats > 1 {
            out.push_str(&format!("  (seen {} times)", alert.repeats));
        }
        out.push_str(&format!(
            "\n\n- {} :\n",
            esc(&clip(alert.title.trim(), 160))
        ));

        let mut pieces: Vec<String> = Vec::new();
        if !alert.what.is_empty() {
            pieces.push(format!("\n{}\n", esc(&clip(&alert.what, 500))));
        }
        if let Some(t) = fact_table(&extra_facts(alert)) {
            pieces.push(format!("\n{}\n", t));
        }
        let tail = explanation(alert);
        if !tail.is_empty() {
            pieces.push(format!("\n{}", tail));
        }

        let footer_len = footer.chars().count();
        for p in pieces {
            if out.chars().count() + p.chars().count() + footer_len <= MAX_TEXT {
                out.push_str(&p);
            }
        }
        out.push_str(&footer);
        out
    }

    pub fn send(alert: &Alert, cfg: &TelegramCfg) -> Result<(), SendError> {
        let url = format!("{}/bot{}/sendMessage", api_base(), cfg.bot_token);
        let mut payload = serde_json::json!({
            "chat_id": cfg.chat_id,
            "text": body(alert),
            "parse_mode": "HTML",
            "disable_web_page_preview": true,
            "disable_notification": cfg.silent_below_critical && alert.severity < Severity::Critical,
        });
        if let Some(t) = cfg.message_thread_id {
            payload["message_thread_id"] = serde_json::json!(t);
        }
        // Response buttons, when enabled and the alert offers any.
        let buttons = if cfg.actions_enabled() && !alert.offers.is_empty() {
            crate::tgbot::register(
                &alert.ref_id,
                &alert.offers,
                cfg.action_ttl_mins,
                chrono::Utc::now(),
            )
        } else {
            Vec::new()
        };
        if !buttons.is_empty() {
            payload["reply_markup"] = crate::tgbot::keyboard(&buttons);
        }
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(cfg.timeout_secs.clamp(3, 60)))
            .user_agent(&format!("hermian/{}", hermian_core::VERSION))
            .build();
        match agent.post(&url).send_json(payload) {
            Ok(resp) => {
                if !buttons.is_empty() {
                    if let Some(mid) = resp
                        .into_json::<serde_json::Value>()
                        .ok()
                        .and_then(|v| v["result"]["message_id"].as_i64())
                    {
                        crate::tgbot::attach_message(&buttons, mid);
                    }
                }
                Ok(())
            }
            Err(ureq::Error::Status(code, resp)) => {
                let detail = resp
                    .into_string()
                    .ok()
                    .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
                    .and_then(|v| v["description"].as_str().map(str::to_string))
                    .unwrap_or_default();
                Err(SendError::http(
                    code,
                    format!("telegram HTTP {} {}", code, detail).trim(),
                ))
            }
            Err(e) => Err(SendError::transient(format!(
                "telegram request failed: {}",
                redact(cfg, e)
            ))),
        }
    }

    /// Verify the token and chat without sending an alert.
    pub fn probe(cfg: &TelegramCfg) -> Result<String, String> {
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(10))
            .build();
        let me: serde_json::Value = agent
            .get(&format!("{}/bot{}/getMe", api_base(), cfg.bot_token))
            .call()
            .map_err(|e| match e {
                ureq::Error::Status(401, _) => {
                    "bot_token rejected by Telegram (401); re-copy it from @BotFather".to_string()
                }
                other => format!("getMe failed: {}", redact(cfg, other)),
            })?
            .into_json()
            .map_err(|e| redact(cfg, e))?;
        let name = me["result"]["username"].as_str().unwrap_or("?").to_string();
        let chat: serde_json::Value = agent
            .post(&format!("{}/bot{}/getChat", api_base(), cfg.bot_token))
            .send_json(serde_json::json!({"chat_id": cfg.chat_id}))
            .map_err(|e| match e {
                ureq::Error::Status(400 | 403, _) => format!(
                    "chat_id {} not reachable: send a message to the bot first (or add it to the group), \
                     then read the id from /getUpdates",
                    cfg.chat_id
                ),
                other => format!("getChat failed: {}", redact(cfg, other)),
            })?
            .into_json()
            .map_err(|e| redact(cfg, e))?;
        let title = chat["result"]["title"]
            .as_str()
            .or(chat["result"]["username"].as_str())
            .or(chat["result"]["first_name"].as_str())
            .unwrap_or("?");
        Ok(format!(
            "bot @{} -> chat \"{}\" ({})",
            name, title, cfg.chat_id
        ))
    }
}

// ---------------------------------------------------------------------------
// Email
// ---------------------------------------------------------------------------

pub mod email {
    use super::*;
    use lettre::message::{header::ContentType, Mailbox, MultiPart, SinglePart};
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::transport::smtp::client::{Tls, TlsParameters};
    use lettre::{Message, SendmailTransport, SmtpTransport, Transport};

    fn colour(s: Severity) -> &'static str {
        match s {
            Severity::Critical => "#D62828",
            Severity::High => "#F77F00",
            Severity::Low => "#C9A227",
            Severity::Info => "#8D99AE",
        }
    }

    fn esc(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    }

    /// ASCII-only so the subject never needs RFC 2047 encoding (which some
    /// clients render badly in notification previews).
    pub fn subject(alert: &Alert, prefix: &str) -> String {
        let title: String = alert.title.chars().filter(|c| c.is_ascii()).collect();
        format!(
            "{} {} {} | {} | {}",
            prefix,
            alert.severity.as_str(),
            alert.detection.short(),
            alert.host,
            title
        )
        .trim()
        .to_string()
    }

    /// Minimal, mail-client-safe HTML (inline styles, no external assets).
    pub fn html(alert: &Alert) -> String {
        let mut h = String::new();
        h.push_str("<!doctype html><html><body style=\"margin:0;padding:24px;background:#f4f5f7;font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;color:#1b1f23\">");
        h.push_str("<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\"><tr><td align=\"center\">");
        h.push_str("<table role=\"presentation\" width=\"640\" cellpadding=\"0\" cellspacing=\"0\" style=\"max-width:640px;background:#fff;border-radius:8px;overflow:hidden;border:1px solid #e1e4e8\">");
        h.push_str(&format!(
            "<tr><td style=\"background:{};color:#fff;padding:14px 20px;font-size:13px;font-weight:600;letter-spacing:.08em\">HERMIAN &nbsp;{}<span style=\"float:right;font-weight:400;opacity:.85\">{}</span></td></tr>",
            colour(alert.severity),
            alert.severity.as_str(),
            alert.ref_id
        ));
        h.push_str(&format!(
            "<tr><td style=\"padding:20px 20px 6px\"><div style=\"font-size:18px;font-weight:600;line-height:1.3\">{}</div>\
             <div style=\"margin-top:6px;font-size:13px;color:#6a737d\">{} &nbsp;\u{00B7}&nbsp; {} UTC &nbsp;\u{00B7}&nbsp; {} {}</div></td></tr>",
            esc(&alert.title),
            esc(&alert.host),
            alert.ts.format("%Y-%m-%d %H:%M:%S"),
            alert.detection.short(),
            esc(alert.detection.name())
        ));
        let section = |title: &str, body: String| {
            format!(
                "<tr><td style=\"padding:14px 20px 0\"><div style=\"font-size:11px;font-weight:700;letter-spacing:.1em;color:#6a737d\">{}</div><div style=\"margin-top:6px;font-size:14px;line-height:1.5\">{}</div></td></tr>",
                title, body
            )
        };
        let mut what = esc(&alert.what);
        if !alert.chain.is_empty() {
            what.push_str("<pre style=\"margin:10px 0 0;padding:10px 12px;background:#f6f8fa;border-radius:6px;font:12px/1.5 SFMono-Regular,Menlo,Consolas,monospace\">");
            for (i, n) in alert.chain.iter().enumerate() {
                let indent = "   ".repeat(i.saturating_sub(1));
                let conn = if i == 0 { "" } else { "\u{2514}\u{2500} " };
                let user = n.user.clone().unwrap_or_else(|| format!("uid {}", n.uid));
                let name = if n.focus {
                    format!("<b>{}</b>", esc(&n.comm))
                } else {
                    esc(&n.comm)
                };
                what.push_str(&format!(
                    "{}{}{}  <span style=\"color:#6a737d\">{} \u{00B7} pid {}</span>\n",
                    indent,
                    conn,
                    name,
                    esc(&user),
                    n.pid
                ));
            }
            what.push_str("</pre>");
        }
        if !alert.facts.is_empty() {
            what.push_str("<table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" style=\"margin-top:10px;font-size:13px\">");
            for f in &alert.facts {
                what.push_str(&format!(
                    "<tr><td style=\"color:#6a737d;padding:2px 14px 2px 0;white-space:nowrap\">{}</td><td style=\"font-family:SFMono-Regular,Menlo,Consolas,monospace;word-break:break-all\">{}</td></tr>",
                    esc(&f.label),
                    esc(&f.value)
                ));
            }
            what.push_str("</table>");
        }
        h.push_str(&section("WHAT HAPPENED", what));
        if !alert.why.is_empty() {
            h.push_str(&section("WHY THIS MATTERS", esc(&alert.why)));
        }
        if !alert.actions.is_empty() {
            let mut ol = String::from("<ol style=\"margin:0;padding-left:20px\">");
            for a in &alert.actions {
                ol.push_str(&format!("<li style=\"margin:2px 0\">{}</li>", esc(a)));
            }
            ol.push_str("</ol>");
            h.push_str(&section("RECOMMENDED ACTION", ol));
        }
        h.push_str(&format!(
            "<tr><td style=\"padding:18px 20px 20px;font:12px SFMono-Regular,Menlo,Consolas,monospace;color:#6a737d;border-top:1px solid #e1e4e8;margin-top:14px\">hermian show {r} &nbsp;&nbsp;\u{00B7}&nbsp;&nbsp; hermian collect {r}</td></tr>",
            r = alert.ref_id
        ));
        h.push_str("</table></td></tr></table></body></html>");
        h
    }

    fn build(alert: &Alert, cfg: &EmailCfg) -> Result<Message, String> {
        let from: Mailbox = format!("HERMIAN <{}>", cfg.from)
            .parse()
            .map_err(|e| format!("bad from address: {}", e))?;
        let mut b = Message::builder()
            .from(from)
            .subject(subject(alert, &cfg.subject_prefix))
            .header(lettre::message::header::MessageId::from(format!(
                "<{}@{}>",
                alert.ref_id.to_lowercase(),
                cfg.from.split('@').nth(1).unwrap_or("hermian")
            )));
        for to in &cfg.to {
            let mb: Mailbox = to
                .parse()
                .map_err(|e| format!("bad to address {}: {}", to, e))?;
            b = b.to(mb);
        }
        let plain = render(alert, Theme::Plain);
        b.multipart(
            MultiPart::alternative()
                .singlepart(
                    SinglePart::builder()
                        .header(ContentType::TEXT_PLAIN)
                        .body(plain),
                )
                .singlepart(
                    SinglePart::builder()
                        .header(ContentType::TEXT_HTML)
                        .body(html(alert)),
                ),
        )
        .map_err(|e| format!("build message: {}", e))
    }

    /// Credentials over a cleartext connection to another host give the
    /// password to anyone on the path. Local relays (loopback) are fine.
    pub fn cleartext_credentials(cfg: &EmailCfg) -> bool {
        let local = matches!(cfg.smtp_host.as_str(), "localhost" | "127.0.0.1" | "::1")
            || cfg.smtp_host.starts_with("127.");
        cfg.smtp_security == "none" && !cfg.smtp_username.is_empty() && !local
    }

    fn smtp(cfg: &EmailCfg) -> Result<SmtpTransport, String> {
        if cleartext_credentials(cfg) {
            return Err(
                "refusing to send SMTP credentials without TLS; set smtp_security = \"starttls\" or \"tls\""
                    .to_string(),
            );
        }
        let timeout = Some(Duration::from_secs(cfg.timeout_secs.clamp(5, 120)));
        let mut t = match cfg.smtp_security.as_str() {
            "tls" => {
                let params =
                    TlsParameters::new(cfg.smtp_host.clone()).map_err(|e| e.to_string())?;
                SmtpTransport::builder_dangerous(&cfg.smtp_host).tls(Tls::Wrapper(params))
            }
            "none" => SmtpTransport::builder_dangerous(&cfg.smtp_host),
            _ => {
                let params =
                    TlsParameters::new(cfg.smtp_host.clone()).map_err(|e| e.to_string())?;
                SmtpTransport::builder_dangerous(&cfg.smtp_host).tls(Tls::Required(params))
            }
        }
        .port(cfg.smtp_port)
        .timeout(timeout);
        if !cfg.smtp_username.is_empty() {
            t = t.credentials(Credentials::new(
                cfg.smtp_username.clone(),
                cfg.smtp_password.clone(),
            ));
        }
        Ok(t.build())
    }

    pub fn send(alert: &Alert, cfg: &EmailCfg) -> Result<(), SendError> {
        // A message we can't build (bad address) won't build on retry either.
        let msg = build(alert, cfg).map_err(SendError::permanent)?;
        match cfg.transport.as_str() {
            "sendmail" => SendmailTransport::new_with_command(&cfg.sendmail_path)
                .send(&msg)
                .map(|_| ())
                .map_err(|e| SendError::transient(format!("sendmail failed: {}", e))),
            _ => smtp(cfg)
                .map_err(SendError::transient)?
                .send(&msg)
                .map(|_| ())
                .map_err(|e| {
                    let text = format!("smtp failed: {}", e);
                    if e.is_permanent() {
                        SendError::permanent(text)
                    } else {
                        SendError::transient(text)
                    }
                }),
        }
    }

    /// Connect and authenticate without sending.
    pub fn probe(cfg: &EmailCfg) -> Result<String, String> {
        match cfg.transport.as_str() {
            "sendmail" => {
                if std::path::Path::new(&cfg.sendmail_path).is_file() {
                    Ok(format!("sendmail at {}", cfg.sendmail_path))
                } else {
                    Err(format!("{} not found", cfg.sendmail_path))
                }
            }
            _ => {
                let t = smtp(cfg)?;
                match t.test_connection() {
                    Ok(true) => Ok(format!(
                        "smtp {}:{} ({}) authenticated={}",
                        cfg.smtp_host,
                        cfg.smtp_port,
                        cfg.smtp_security,
                        !cfg.smtp_username.is_empty()
                    )),
                    Ok(false) => Err("smtp server did not respond to NOOP".into()),
                    Err(e) => Err(format!("smtp connection failed: {}", e)),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hermian_core::{DetectionId, Finding};

    fn alert() -> Alert {
        let f = Finding::new(
            DetectionId::D3,
            Severity::Critical,
            "ld.so.preload <modified>",
            "x",
        )
        .what("A & B")
        .why("Loader injection is a common persistence trick.")
        .fact("Preloads", "/tmp/evil.so")
        .action("Remove it.");
        Alert::from_finding(
            f,
            "HER-2025-0101-007".into(),
            "web-01".into(),
            chrono::Utc::now(),
        )
    }

    #[test]
    fn telegram_body_is_escaped_and_bounded() {
        let b = telegram::body(&alert());
        assert!(b.contains("&lt;modified&gt;"));
        assert!(b.contains("A &amp; B"));
        assert!(!b.contains("<modified>"));
        assert!(b.chars().count() <= 4096);
        assert!(b.contains("<pre>"));
    }

    #[test]
    fn telegram_body_stays_under_the_limit_with_huge_facts() {
        let mut f = Finding::new(DetectionId::D3, Severity::High, "Cron job added", "x")
            .what("w".repeat(5000));
        for i in 0..30 {
            f = f.fact(format!("Line {}", i), "<&>".repeat(2000));
        }
        let a = Alert::from_finding(f, "HER-1".into(), "web-01".into(), chrono::Utc::now());
        let b = telegram::body(&a);
        assert!(b.chars().count() <= 4096, "{}", b.chars().count());
        assert!(b.ends_with("<code>hermian show HER-1</code>"));
        // Never a dangling entity or tag.
        assert_eq!(b.matches("<code>").count(), b.matches("</code>").count());
        assert!(!b.contains("&am\n") && !b.contains("&l\n"));
    }

    #[test]
    fn telegram_body_has_a_meter_and_no_emoji() {
        let b = telegram::body(&alert());
        // No emoji anywhere: severity is a word and a block meter.
        assert!(!b.chars().any(|c| c as u32 >= 0x1F000), "{}", b);
        assert!(
            b.starts_with("<b>\u{25A0}\u{25A0}\u{25A0}\u{25A0} HERMIAN - CRITICAL</b>"),
            "{}",
            b
        );
        assert!(b.contains("Host : web-01"));
        assert!(b.contains("- ld.so.preload &lt;modified&gt; :"));
        assert!(b.contains("<b>Also</b>"));
        assert!(b.contains("1. Remove it."));
        // The full alert is not repeated; the CLI keeps that.
        assert!(!b.contains("Recommended action"));
        assert!(b.ends_with("<code>hermian show HER-2025-0101-007</code>"));
    }

    #[test]
    fn meters_count_up_with_severity() {
        assert_eq!(
            telegram::meter(Severity::Critical),
            "\u{25A0}\u{25A0}\u{25A0}\u{25A0}"
        );
        assert_eq!(
            telegram::meter(Severity::High),
            "\u{25A0}\u{25A0}\u{25A0}\u{25A1}"
        );
        assert_eq!(
            telegram::meter(Severity::Low),
            "\u{25A0}\u{25A0}\u{25A1}\u{25A1}"
        );
        assert_eq!(
            telegram::meter(Severity::Info),
            "\u{25A0}\u{25A1}\u{25A1}\u{25A1}"
        );
    }

    #[test]
    fn facts_already_in_the_summary_are_not_repeated() {
        let f = Finding::new(
            DetectionId::D2,
            Severity::High,
            "SSH login after a failed-auth burst",
            "x",
        )
        .what("User 'root' authenticated from 198.51.100.7 after 14 failed attempts.")
        .fact("Source", "198.51.100.7")
        .fact("User", "root")
        .fact("Failed attempts", "14");
        let a = Alert::from_finding(f, "HER-1".into(), "web-01".into(), chrono::Utc::now());
        let b = telegram::body(&a);
        assert!(!b.contains("<pre>"), "{}", b);
        assert!(
            b.contains("User 'root' authenticated from 198.51.100.7"),
            "{}",
            b
        );
        // A fact the sentence does not carry still shows.
        let f2 = Finding::new(DetectionId::D1, Severity::Critical, "Web server chain", "x")
            .what("nginx started a shell.")
            .fact("File", "/tmp/.x");
        let a2 = Alert::from_finding(f2, "HER-2".into(), "web-01".into(), chrono::Utc::now());
        assert!(telegram::body(&a2).contains("/tmp/.x"));
    }

    #[test]
    fn telegram_fact_table_is_aligned_and_capped() {
        let mut f = Finding::new(DetectionId::D2, Severity::High, "SSH login", "x")
            .fact("Source", "198.51.100.7")
            .fact("User", "root");
        for i in 0..10 {
            f = f.fact(format!("Extra {}", i), "v");
        }
        let a = Alert::from_finding(f, "HER-1".into(), "web-01".into(), chrono::Utc::now());
        let b = telegram::body(&a);
        // Rows share one label column, and the extras collapse to a count.
        let pre = &b[b.find("<pre>").unwrap() + 5..b.find("</pre>").unwrap()];
        let src = pre.lines().find(|l| l.starts_with("Source")).unwrap();
        let usr = pre.lines().find(|l| l.starts_with("User")).unwrap();
        assert_eq!(
            src.find("198").unwrap(),
            usr.find("root").unwrap(),
            "{}",
            pre
        );
        assert!(b.contains("+6 more"), "{}", b);
    }

    #[test]
    fn smtp_credentials_need_tls_unless_local() {
        let mut c = EmailCfg {
            smtp_host: "mail.example.com".into(),
            smtp_username: "u".into(),
            smtp_security: "none".into(),
            ..EmailCfg::default()
        };
        assert!(email::cleartext_credentials(&c));
        c.smtp_security = "starttls".into();
        assert!(!email::cleartext_credentials(&c));
        c.smtp_security = "none".into();
        c.smtp_host = "127.0.0.1".into();
        assert!(!email::cleartext_credentials(&c));
        c.smtp_host = "mail.example.com".into();
        c.smtp_username.clear();
        assert!(!email::cleartext_credentials(&c));
    }

    #[test]
    fn email_subject_and_html() {
        let a = alert();
        assert_eq!(
            email::subject(&a, "[HERMIAN]"),
            "[HERMIAN] CRITICAL D3 | web-01 | ld.so.preload <modified>"
        );
        assert!(email::subject(&a, "[HERMIAN]").is_ascii());
        let h = email::html(&a);
        assert!(h.contains("&lt;modified&gt;"));
        assert!(h.contains("hermian show HER-2025-0101-007"));
        assert!(h.contains("#D62828"));
    }
}
