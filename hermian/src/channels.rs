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
    pub(super) fn clip(s: &str, max: usize) -> String {
        if s.chars().count() <= max {
            return s.to_string();
        }
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('\u{2026}');
        out
    }

    /// Build the HTML message body:
    ///
    /// ```text
    /// ■■■■ CRITICAL · web-01                 <- meter, level, host (tap to copy)
    /// Web server chain ran downloaded code   <- headline
    /// ┃ nginx started a shell that ...       <- what happened, as a quote card
    /// hermian · D1 · 03:14 UTC               <- quiet context
    /// hermian show HER-2026-1006-415         <- tap to copy
    /// ```
    ///
    /// Telegram allows no colour or fonts, so hierarchy does the work. The
    /// bot's name and avatar already say who's talking, so the header leads
    /// with the severity. Evidence, the process chain, why it matters and
    /// the recommended steps stay in the CLI; the message says what happened,
    /// nothing more.
    pub fn body(alert: &Alert) -> String {
        let mut out = format!(
            "<b>{} {}</b> \u{00B7} <code>{}</code>",
            meter(alert.severity),
            alert.severity.as_str(),
            esc(&clip(&alert.host, 60))
        );
        if alert.repeats > 1 {
            out.push_str(&format!(" \u{00B7} seen {} times", alert.repeats));
        }
        if !alert.title.trim().is_empty() {
            out.push_str(&format!("\n<b>{}</b>", esc(&clip(alert.title.trim(), 160))));
        }
        if !alert.what.is_empty() {
            out.push_str(&format!(
                "\n\n<blockquote>{}</blockquote>",
                esc(&clip(&alert.what, 500))
            ));
        }
        out.push_str(&format!(
            "\n\n<i>hermian \u{00B7} {} \u{00B7} {} UTC</i>\n<code>hermian show {}</code>",
            alert.detection.short(),
            alert.ts.format("%H:%M"),
            esc(&alert.ref_id)
        ));
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
    use lettre::message::{header::ContentType, Attachment, Mailbox, MultiPart, SinglePart};
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::transport::smtp::client::{Tls, TlsParameters};
    use lettre::{Message, SendmailTransport, SmtpTransport, Transport};

    /// The logo for the email header: the mark on its dark tile (so it reads
    /// on light and dark mail clients alike), 64 px shown at 32. It travels
    /// inside the message as an inline attachment: no remote image (those
    /// are blocked by default and would tell a server when an alert was
    /// read), no data: URI (Gmail drops them). About 0.6 KB.
    pub(super) const MARK_PNG: &[u8] = include_bytes!("../assets/mark-email.png");
    const MARK_CID: &str = "hermian-mark";

    /// Severity colours from the identity, light palette (mail is mostly
    /// read on light backgrounds; the dark-mode CSS keeps them readable).
    fn colour(s: Severity) -> &'static str {
        match s {
            Severity::Critical => "#D9344C",
            Severity::High => "#5B4FD0",
            Severity::Low => "#6B6888",
            Severity::Info => "#8D8AA8",
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

    const SANS: &str =
        "-apple-system,BlinkMacSystemFont,'Segoe UI',Manrope,Helvetica,Arial,sans-serif";
    const MONO: &str = "'JetBrains Mono',SFMono-Regular,Menlo,Consolas,'Liberation Mono',monospace";

    /// A section label in the brand accent.
    fn eyebrow(label: &str) -> String {
        format!(
            "<div class=\"hm-ac\" style=\"margin-top:26px;font:600 11px/1 {};letter-spacing:.1em;color:#5B4FD0\">{}</div>",
            MONO, label
        )
    }

    /// The alert as a branded, mail-client-safe page: tables and inline
    /// styles only (the logo is the one image, carried inline; nothing
    /// remote), a hidden preheader for the inbox preview, and a dark palette
    /// for clients that honour
    /// `prefers-color-scheme`. Only the severity and the logo's dot carry
    /// colour; the process chain is drawn like a terminal.
    pub fn html(alert: &Alert) -> String {
        let sev = colour(alert.severity);
        let mut h = String::with_capacity(8192);
        h.push_str(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
             <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
             <meta name=\"color-scheme\" content=\"light dark\">\
             <meta name=\"supported-color-schemes\" content=\"light dark\">",
        );
        h.push_str(&format!("<title>{}</title>", esc(&alert.title)));
        h.push_str(
            "<style>@media (prefers-color-scheme:dark){\
             .hm-bg{background:#0F0E17!important}\
             .hm-card{background:#14131D!important;border-color:#2A2839!important}\
             .hm-tx{color:#ECEBF7!important}.hm-dim{color:#8D8AA8!important}\
             .hm-line{border-color:#2A2839!important}.hm-ac{color:#9A8CF7!important}\
             .hm-box{background:#1A1926!important;border-color:#2A2839!important;color:#ECEBF7!important}}\
             @media (max-width:620px){.hm-pad{padding-left:20px!important;padding-right:20px!important}}\
             </style></head>",
        );
        h.push_str(&format!(
            "<body class=\"hm-bg\" style=\"margin:0;padding:0;background:#F4F4F8;font-family:{};color:#17142E\">",
            SANS
        ));
        // Inbox preview text, padded so clients don't pull body text after it.
        let preview =
            super::telegram::clip(&format!("{} \u{00B7} {}", alert.host, alert.what), 140);
        h.push_str(&format!(
            "<div style=\"display:none;max-height:0;overflow:hidden;opacity:0;mso-hide:all\">{}{}</div>",
            esc(&preview),
            "&#847;&zwnj;&nbsp;".repeat(30)
        ));
        h.push_str(
            "<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" class=\"hm-bg\" style=\"background:#F4F4F8\">\
             <tr><td align=\"center\" style=\"padding:32px 12px\">\
             <table role=\"presentation\" width=\"600\" cellpadding=\"0\" cellspacing=\"0\" style=\"width:100%;max-width:600px\">",
        );
        // Brand row: the logo (an inline attachment, see `build`), the
        // wordmark, and the reference on the right. alt is empty because the
        // wordmark right after it already says "hermian".
        h.push_str(&format!(
            "<tr><td style=\"padding:0 4px 14px\"><table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\"><tr>\
             <td class=\"hm-tx\" style=\"font:600 18px/32px {sans};color:#17142E;letter-spacing:-.02em\">\
             <img src=\"cid:{cid}\" width=\"32\" height=\"32\" alt=\"\" style=\"display:inline-block;vertical-align:middle;border:0;outline:none\">\
             &nbsp;<span style=\"vertical-align:middle\">hermian</span></td>\
             <td align=\"right\" class=\"hm-dim\" style=\"font:12px/1 {mono};color:#6B6888\">{r}</td>\
             </tr></table></td></tr>",
            sans = SANS,
            mono = MONO,
            cid = MARK_CID,
            r = esc(&alert.ref_id)
        ));
        // The card, with a severity stripe on top.
        h.push_str(
            "<tr><td class=\"hm-card\" style=\"background:#FFFFFF;border:1px solid #E3E1EF;border-radius:16px;overflow:hidden\">",
        );
        h.push_str(&format!(
            "<div style=\"height:4px;line-height:4px;font-size:0;background:{}\">&nbsp;</div>",
            sev
        ));
        h.push_str("<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\"><tr><td class=\"hm-pad\" style=\"padding:28px 32px 30px\">");
        h.push_str(&format!(
            "<div style=\"font:600 12px/1 {};letter-spacing:.08em;color:{}\">{}&nbsp; {}</div>",
            MONO,
            sev,
            super::telegram::meter(alert.severity),
            alert.severity.as_str()
        ));
        h.push_str(&format!(
            "<h1 class=\"hm-tx\" style=\"margin:14px 0 0;font:600 22px/1.3 {};letter-spacing:-.015em;color:#17142E\">{}</h1>",
            SANS,
            esc(&alert.title)
        ));
        let repeats = if alert.repeats > 1 {
            format!(" &nbsp;\u{00B7}&nbsp; seen {} times", alert.repeats)
        } else {
            String::new()
        };
        h.push_str(&format!(
            "<div class=\"hm-dim\" style=\"margin-top:8px;font-size:13px;line-height:1.5;color:#6B6888\">{} &nbsp;\u{00B7}&nbsp; {} {} &nbsp;\u{00B7}&nbsp; {} UTC{}</div>",
            esc(&alert.host),
            alert.detection.short(),
            esc(alert.detection.name()),
            alert.ts.format("%Y-%m-%d %H:%M:%S"),
            repeats
        ));
        if !alert.what.is_empty() {
            h.push_str(&format!(
                "<p class=\"hm-tx\" style=\"margin:20px 0 0;font-size:15px;line-height:1.6;color:#17142E\">{}</p>",
                esc(&alert.what)
            ));
        }
        if !alert.chain.is_empty() {
            h.push_str(&format!(
                "<div style=\"margin-top:20px;background:#0F0E17;border-radius:12px;padding:16px 18px;font:12.5px/1.75 {};color:#ECEBF7;word-break:break-all\">",
                MONO
            ));
            for (i, n) in alert.chain.iter().enumerate() {
                let indent = "&nbsp;&nbsp;&nbsp;".repeat(i.saturating_sub(1));
                let conn = if i == 0 { "" } else { "\u{2514}\u{2500} " };
                let user = n.user.clone().unwrap_or_else(|| format!("uid {}", n.uid));
                let name = if n.focus {
                    format!(
                        "<span style=\"color:#FF6B81;font-weight:600\">{}</span>",
                        esc(&n.comm)
                    )
                } else {
                    esc(&n.comm)
                };
                h.push_str(&format!(
                    "{}<span style=\"color:#4D4A6B\">{}</span>{} <span style=\"color:#8D8AA8\">{} \u{00B7} pid {}</span><br>",
                    indent,
                    conn,
                    name,
                    esc(&user),
                    n.pid
                ));
            }
            h.push_str("</div>");
        }
        if !alert.facts.is_empty() {
            h.push_str("<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" style=\"margin-top:18px\">");
            for f in &alert.facts {
                h.push_str(&format!(
                    "<tr><td class=\"hm-dim hm-line\" style=\"padding:8px 16px 8px 0;border-top:1px solid #E3E1EF;font-size:12.5px;color:#6B6888;white-space:nowrap;vertical-align:top\">{}</td>\
                     <td class=\"hm-tx hm-line\" style=\"padding:8px 0;border-top:1px solid #E3E1EF;font:12.5px/1.5 {};color:#17142E;word-break:break-all\">{}</td></tr>",
                    esc(&f.label),
                    MONO,
                    esc(&f.value)
                ));
            }
            h.push_str("</table>");
        }
        if !alert.why.is_empty() {
            h.push_str(&eyebrow("WHY IT MATTERS"));
            h.push_str(&format!(
                "<p class=\"hm-tx\" style=\"margin:10px 0 0;font-size:14.5px;line-height:1.6;color:#17142E\">{}</p>",
                esc(&alert.why)
            ));
        }
        if !alert.actions.is_empty() {
            h.push_str(&eyebrow("NEXT STEPS"));
            h.push_str("<table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" style=\"margin-top:8px\">");
            for (i, a) in alert.actions.iter().enumerate() {
                h.push_str(&format!(
                    "<tr><td class=\"hm-ac\" style=\"padding:4px 12px 4px 0;font:600 12.5px/1.6 {};color:#5B4FD0;vertical-align:top\">{}</td>\
                     <td class=\"hm-tx\" style=\"padding:4px 0;font-size:14.5px;line-height:1.6;color:#17142E\">{}</td></tr>",
                    MONO,
                    i + 1,
                    esc(a)
                ));
            }
            h.push_str("</table>");
        }
        h.push_str(&format!(
            "<div class=\"hm-box\" style=\"margin-top:26px;border:1px solid #E3E1EF;background:#F7F7FB;border-radius:10px;padding:12px 16px;font:13px/1.5 {mono};color:#17142E\">\
             <span class=\"hm-dim\" style=\"color:#8D8AA8\">$</span> hermian show {r}</div>\
             <div class=\"hm-dim\" style=\"margin-top:8px;font-size:12.5px;line-height:1.5;color:#6B6888\">Run it on {host} for the full record. \
             <span style=\"font-family:{mono}\">hermian collect {r}</span> gathers local context.</div>",
            mono = MONO,
            r = esc(&alert.ref_id),
            host = esc(&alert.host)
        ));
        h.push_str("</td></tr></table></td></tr>");
        h.push_str(&format!(
            "<tr><td align=\"center\" class=\"hm-dim\" style=\"padding:22px 12px 0;font-size:12px;line-height:1.6;color:#8D8AA8\">\
             Silent by default. Loud when it matters.<br>Sent by Hermian on {}. Who receives these is set in /etc/hermian/config.toml.</td></tr>",
            esc(&alert.host)
        ));
        h.push_str("</table></td></tr></table></body></html>");
        h
    }

    pub(super) fn build(alert: &Alert, cfg: &EmailCfg) -> Result<Message, String> {
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
        let png = ContentType::parse("image/png").map_err(|e| format!("build message: {}", e))?;
        // alternative(plain, related(html, logo)): the standard shape for
        // HTML mail with an inline image.
        b.multipart(
            MultiPart::alternative()
                .singlepart(
                    SinglePart::builder()
                        .header(ContentType::TEXT_PLAIN)
                        .body(plain),
                )
                .multipart(
                    MultiPart::related()
                        .singlepart(
                            SinglePart::builder()
                                .header(ContentType::TEXT_HTML)
                                .body(html(alert)),
                        )
                        .singlepart(
                            Attachment::new_inline(MARK_CID.to_string())
                                .body(MARK_PNG.to_vec(), png),
                        ),
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
        assert!(!b.contains("<pre>"));
        assert!(!b.contains("Loader injection"));
        assert!(!b.contains("Remove it."));
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
        assert_eq!(
            b.matches("<blockquote>").count(),
            b.matches("</blockquote>").count()
        );
        assert!(!b.contains("&am\n") && !b.contains("&l\n"));
    }

    #[test]
    fn telegram_body_has_a_meter_and_no_emoji() {
        let b = telegram::body(&alert());
        // No emoji anywhere: severity is a word and a block meter.
        assert!(!b.chars().any(|c| c as u32 >= 0x1F000), "{}", b);
        assert!(
            b.starts_with(
                "<b>\u{25A0}\u{25A0}\u{25A0}\u{25A0} CRITICAL</b> \u{00B7} <code>web-01</code>"
            ),
            "{}",
            b
        );
        assert!(b.contains("<b>ld.so.preload &lt;modified&gt;</b>"));
        assert!(b.contains("A &amp; B"));
        // The why, the steps and the facts stay in the CLI.
        assert!(!b.contains("Loader injection"));
        assert!(!b.contains("Remove it."));
        assert!(!b.contains("/tmp/evil.so"));
        assert!(b.ends_with("<code>hermian show HER-2025-0101-007</code>"));
    }

    /// Header, headline, the sentence as a quote card, a quiet context line,
    /// then the command to copy. Repeats show in the header.
    #[test]
    fn telegram_body_layout() {
        let mut a = alert();
        a.repeats = 3;
        let b = telegram::body(&a);
        let order = [
            "<b>\u{25A0}\u{25A0}\u{25A0}\u{25A0} CRITICAL</b> \u{00B7} <code>web-01</code> \u{00B7} seen 3 times\n",
            "<b>ld.so.preload &lt;modified&gt;</b>",
            "<blockquote>A &amp; B</blockquote>",
            "<i>hermian \u{00B7} D3 \u{00B7} ",
            " UTC</i>\n<code>hermian show HER-2025-0101-007</code>",
        ];
        let mut at = 0;
        for part in order {
            let i = b[at..]
                .find(part)
                .unwrap_or_else(|| panic!("{:?} not after {} in {}", part, at, b));
            at += i + part.len();
        }
        assert_eq!(at, b.len(), "{}", b);
        // The product name is quiet context now, not a shouted header.
        assert!(!b.contains("HERMIAN"), "{}", b);
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
    fn telegram_body_is_a_headline_and_a_sentence() {
        let f = Finding::new(
            DetectionId::D2,
            Severity::Low,
            "SSH login from a new source",
            "x",
        )
        .what("User 'deploy' authenticated (key) from 1.2.3.4, a source never seen before.")
        .fact("Source", "1.2.3.4")
        .why("Some explanation that stays in the CLI.")
        .action("Do something about it.");
        let a = Alert::from_finding(f, "HER-2".into(), "web-01".into(), chrono::Utc::now());
        let b = telegram::body(&a);
        assert!(b.contains("<b>SSH login from a new source</b>"), "{}", b);
        assert!(b.contains("authenticated (key) from 1.2.3.4"), "{}", b);
        assert!(!b.contains("Some explanation"), "{}", b);
        assert!(!b.contains("Do something"), "{}", b);
        assert!(b.chars().count() < 400, "{}", b);
    }

    /// The chain renders like a terminal, the flagged process in red, and
    /// everything user-controlled is escaped.
    #[test]
    fn email_html_chain_and_escaping() {
        use hermian_core::alert::ChainNode;
        let mut a = alert();
        a.chain = vec![
            ChainNode {
                pid: 1,
                uid: 0,
                user: Some("root".into()),
                comm: "systemd".into(),
                exe: String::new(),
                focus: false,
            },
            ChainNode {
                pid: 42,
                uid: 33,
                user: Some("www-data".into()),
                comm: "<sh>".into(),
                exe: String::new(),
                focus: true,
            },
        ];
        a.repeats = 4;
        let h = email::html(&a);
        assert!(
            h.contains("color:#FF6B81;font-weight:600\">&lt;sh&gt;</span>"),
            "{}",
            h
        );
        assert!(h.contains("www-data \u{00B7} pid 42"));
        assert!(h.contains("seen 4 times"));
        assert!(!h.contains("<sh>"));
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
        assert!(h.contains("#D9344C"));
        // Brand row (the logo by Content-ID), preheader, dark mode, sections.
        assert!(h.contains("<img src=\"cid:hermian-mark\""));
        assert!(h.contains(">hermian</span></td>"));
        assert!(h.contains("display:none;max-height:0"));
        assert!(h.contains("prefers-color-scheme:dark"));
        assert!(h.contains("WHY IT MATTERS") && h.contains("NEXT STEPS"));
        assert!(!h.contains("http"), "no remote assets");
        assert_eq!(h.matches("<img").count(), 1, "only the inline logo");
    }

    /// The logo travels inside the message: the HTML and the PNG share a
    /// multipart/related part, and the PNG carries the Content-ID the HTML
    /// points at. The plain-text alternative stays.
    #[test]
    fn email_carries_the_logo_inline() {
        let cfg = EmailCfg {
            from: "hermian@example.com".into(),
            to: vec!["ops@example.com".into()],
            ..EmailCfg::default()
        };
        let raw = String::from_utf8(email::build(&alert(), &cfg).unwrap().formatted()).unwrap();
        assert!(raw.contains("multipart/alternative"), "{}", raw);
        assert!(raw.contains("multipart/related"), "{}", raw);
        assert!(raw.contains("Content-ID: <hermian-mark>"), "{}", raw);
        assert!(raw.contains("Content-Disposition: inline"), "{}", raw);
        assert!(raw.contains("Content-Type: image/png"), "{}", raw);
        assert!(raw.contains("Content-Type: text/plain"), "{}", raw);
        // A real PNG, and small.
        assert_eq!(&email::MARK_PNG[..8], b"\x89PNG\r\n\x1a\n");
        assert!(email::MARK_PNG.len() < 2048);
    }
}
