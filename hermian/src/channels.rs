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
    fn api_base() -> String {
        std::env::var("HERMIAN_TELEGRAM_API")
            .unwrap_or_else(|_| "https://api.telegram.org".to_string())
    }

    /// ureq includes the request URL (and thus the bot token) in its errors.
    fn redact(cfg: &TelegramCfg, e: impl std::fmt::Display) -> String {
        let s = e.to_string();
        // replace("") would insert "<token>" between every character.
        if cfg.bot_token.is_empty() {
            s
        } else {
            s.replace(&cfg.bot_token, "<token>")
        }
    }

    /// Escape for Telegram's HTML parse mode.
    fn esc(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    }

    fn glyph(s: Severity) -> &'static str {
        match s {
            Severity::Critical => "\u{1F534}", // red circle
            Severity::High => "\u{1F7E0}",     // orange circle
            Severity::Low => "\u{1F7E1}",      // yellow circle
            Severity::Info => "\u{26AA}",      // white circle
        }
    }

    /// Build the HTML message body: a bold headline, the human summary, and
    /// the full plain-theme alert in a monospace block.
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

    pub fn body(alert: &Alert) -> String {
        // Every piece is complete HTML, so skipping one never leaves an open
        // tag; the footer is always kept. Facts can quote attacker-controlled
        // file content, so without a budget one long line could push the
        // message past Telegram's limit and get it rejected on every retry.
        let footer = format!("\n<code>hermian show {}</code>", esc(&alert.ref_id));
        let mut out = format!(
            "{} <b>HERMIAN {}</b> \u{00B7} <code>{}</code>\n<b>{}</b>\n",
            glyph(alert.severity),
            alert.severity.as_str(),
            esc(&clip(&alert.host, 80)),
            esc(&clip(&alert.title, 200))
        );
        let mut pieces = Vec::new();
        if !alert.what.is_empty() {
            pieces.push(format!("{}\n", esc(&clip(&alert.what, 1200))));
        }
        if !alert.chain.is_empty() {
            let chain: Vec<String> = alert
                .chain
                .iter()
                .map(|n| format!("{}({})", n.comm, n.pid))
                .collect();
            pieces.push(format!(
                "<i>chain:</i> <code>{}</code>\n",
                esc(&clip(&chain.join(" \u{2192} "), 600))
            ));
        }
        for f in &alert.facts {
            pieces.push(format!(
                "<i>{}:</i> <code>{}</code>\n",
                esc(&clip(&f.label, 60)),
                esc(&clip(&f.value, 400))
            ));
        }
        if let Some(a) = alert.actions.first() {
            pieces.push(format!("\n<b>Next:</b> {}\n", esc(&clip(a, 400))));
        }
        let footer_len = footer.chars().count();
        for p in pieces {
            if out.chars().count() + p.chars().count() + footer_len <= MAX_TEXT {
                out.push_str(&p);
            }
        }
        out.push_str(&footer);
        // Full rendering as an expandable-ish block, if it fits.
        let full = render(alert, Theme::Plain);
        let budget = MAX_TEXT.saturating_sub(out.chars().count() + 20);
        if full.chars().count() < budget {
            out.push_str("\n\n<pre>");
            out.push_str(&esc(&full));
            out.push_str("</pre>");
        }
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
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(cfg.timeout_secs.clamp(3, 60)))
            .user_agent(&format!("hermian/{}", hermian_core::VERSION))
            .build();
        match agent.post(&url).send_json(payload) {
            Ok(_) => Ok(()),
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

    fn smtp(cfg: &EmailCfg) -> Result<SmtpTransport, String> {
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
