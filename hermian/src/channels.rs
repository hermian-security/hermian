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

    /// The severity meter, shared with the CLI.
    pub(super) fn meter(s: Severity) -> &'static str {
        hermian_core::alert::severity_meter(s)
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

    /// Most facts on the fact sheet; the CLI has the rest.
    const SHEET_FACTS: usize = 5;

    /// Build the HTML message body:
    ///
    /// ```text
    /// ◉◉◉○  HIGH · Persistence               <- meter, level, detection family
    /// Shell profile changed with no ...      <- headline, on its own line
    /// ┃ /root/.bashrc was moved into ...     <- what happened, as a quote card
    /// host  web-01                           <- <pre> fact sheet, tap to copy
    /// path  /root/.bashrc
    /// rule  D3 · Persistence modification
    /// time  16 Oct 2026 · 12:36 UTC
    /// ┃ Risk ... Next steps 1. ... 2. ...    <- expandable quote, collapsed
    /// hermian show HER-2026-1016-163         <- tap to copy
    /// ```
    ///
    /// Telegram allows no colour or fonts, so hierarchy does the work. The
    /// bot's name and avatar already say who's talking, so there's no
    /// product name. The why and the steps sit in a collapsed quote: the
    /// push notification and the first screen stay short.
    pub fn body(alert: &Alert) -> String {
        // Escaping can triple hostile text, so shed detail until it fits
        // Telegram's 4096-character limit: first the collapsed section, then
        // the fact sheet's length.
        let levels = [
            (SHEET_FACTS, 120, true, 500),
            (SHEET_FACTS, 120, false, 500),
            (2, 40, false, 300),
        ];
        for (facts, value_max, why, what_max) in levels {
            let b = body_with(alert, facts, value_max, why, what_max);
            if b.chars().count() <= TG_LIMIT {
                return b;
            }
        }
        // Worst case, every field escaped 5x: still well under the limit.
        body_with(alert, 0, 0, false, 120)
    }

    const TG_LIMIT: usize = 4096;

    fn body_with(
        alert: &Alert,
        facts: usize,
        value_max: usize,
        why: bool,
        what_max: usize,
    ) -> String {
        let mut out = format!(
            "<b>{}  {}</b> \u{00B7} {}",
            meter(alert.severity),
            alert.severity.as_str(),
            alert.detection.family()
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
                esc(&clip(&alert.what, what_max))
            ));
        }
        out.push_str(&format!(
            "\n\n<pre>{}</pre>",
            esc(&fact_sheet(alert, facts, value_max))
        ));
        let why_steps = if why {
            why_and_steps(alert)
        } else {
            String::new()
        };
        if !why_steps.is_empty() {
            out.push_str(&format!(
                "\n\n<blockquote expandable>{}</blockquote>",
                why_steps
            ));
        }
        out.push_str(&format!(
            "\n\n<code>hermian show {}</code>",
            esc(&alert.ref_id)
        ));
        out
    }

    /// Aligned `key  value` lines: host, the first detector facts, the
    /// process chain, the rule and the time. Plain text; escaped by the
    /// caller.
    fn fact_sheet(alert: &Alert, facts: usize, value_max: usize) -> String {
        let mut rows: Vec<(String, String)> = vec![("host".into(), clip(&alert.host, 60))];
        for f in alert.facts.iter().take(facts) {
            rows.push((clip(&f.label.to_lowercase(), 16), clip(&f.value, value_max)));
        }
        if !alert.chain.is_empty() {
            let chain = alert
                .chain
                .iter()
                .map(|n| n.comm.as_str())
                .collect::<Vec<_>>()
                .join(" \u{203A} ");
            rows.push(("chain".into(), clip(&chain, value_max.max(40))));
        }
        rows.push((
            "rule".into(),
            format!(
                "{} \u{00B7} {}",
                alert.detection.short(),
                alert.detection.name()
            ),
        ));
        rows.push((
            "time".into(),
            alert.ts.format("%-d %b %Y \u{00B7} %H:%M UTC").to_string(),
        ));
        let width = rows
            .iter()
            .map(|(k, _)| k.chars().count())
            .max()
            .unwrap_or(0);
        rows.iter()
            .map(|(k, v)| format!("{:<w$}  {}", k, v, w = width))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The risk and the numbered steps, escaped, or empty.
    fn why_and_steps(alert: &Alert) -> String {
        let mut s = String::new();
        if !alert.why.is_empty() {
            s.push_str(&format!("<b>Risk</b>\n{}", esc(&clip(&alert.why, 600))));
        }
        if !alert.actions.is_empty() {
            if !s.is_empty() {
                s.push_str("\n\n");
            }
            s.push_str("<b>Next steps</b>");
            for (i, a) in alert.actions.iter().take(5).enumerate() {
                s.push_str(&format!("\n{}. {}", i + 1, esc(&clip(a, 200))));
            }
        }
        s
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
        let agent = crate::tgbot::agent(Duration::from_secs(cfg.timeout_secs.clamp(3, 60)));
        match agent.post(&url).send_json(payload) {
            Ok(mut resp) if resp.status().as_u16() < 400 => {
                if !buttons.is_empty() {
                    if let Some(mid) = resp
                        .body_mut()
                        .read_json::<serde_json::Value>()
                        .ok()
                        .and_then(|v| v["result"]["message_id"].as_i64())
                    {
                        crate::tgbot::attach_message(&buttons, mid);
                    }
                }
                Ok(())
            }
            Ok(mut resp) => {
                let code = resp.status().as_u16();
                let detail = resp
                    .body_mut()
                    .read_to_string()
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
        let agent = crate::tgbot::agent(Duration::from_secs(10));
        let mut me = agent
            .get(format!("{}/bot{}/getMe", api_base(), cfg.bot_token))
            .call()
            .map_err(|e| format!("getMe failed: {}", redact(cfg, e)))?;
        match me.status().as_u16() {
            401 => {
                return Err(
                    "bot_token rejected by Telegram (401); re-copy it from @BotFather".to_string(),
                )
            }
            code if code >= 400 => return Err(format!("getMe failed: HTTP {}", code)),
            _ => {}
        }
        let me: serde_json::Value = me.body_mut().read_json().map_err(|e| redact(cfg, e))?;
        let name = me["result"]["username"].as_str().unwrap_or("?").to_string();
        let mut chat = agent
            .post(format!("{}/bot{}/getChat", api_base(), cfg.bot_token))
            .send_json(serde_json::json!({"chat_id": cfg.chat_id}))
            .map_err(|e| format!("getChat failed: {}", redact(cfg, e)))?;
        match chat.status().as_u16() {
            400 | 403 => {
                return Err(format!(
                    "chat_id {} not reachable: send a message to the bot first (or add it to the group), \
                     then read the id from /getUpdates",
                    cfg.chat_id
                ))
            }
            code if code >= 400 => return Err(format!("getChat failed: HTTP {}", code)),
            _ => {}
        }
        let chat: serde_json::Value = chat.body_mut().read_json().map_err(|e| redact(cfg, e))?;
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

    /// The header lockup (light on the ink band, 176x44 shown at 88x22) and
    /// the company lockup for the footer (one mid-tone colour, so it reads on
    /// light and dark clients). Both travel inside the message as inline
    /// attachments: no remote image (blocked by default, and it would tell a
    /// server when an alert was read), no data: URI (Gmail drops them).
    /// About 1.1 KB each.
    pub(super) const LOCKUP_PNG: &[u8] = include_bytes!("../assets/lockup-email-dark.png");
    pub(super) const COMPANY_PNG: &[u8] = include_bytes!("../assets/company-email.png");
    const LOCKUP_CID: &str = "hermian-lockup";
    const COMPANY_CID: &str = "hermian-company";

    fn esc(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    }

    /// "[Hermian] HIGH: <title> (<host>)". Severity and title lead because
    /// inbox lists cut from the right. ASCII-only so the subject never needs
    /// RFC 2047 encoding (which some clients render badly in previews).
    pub fn subject(alert: &Alert, prefix: &str) -> String {
        let ascii = |s: &str| s.chars().filter(|c| c.is_ascii()).collect::<String>();
        format!(
            "{} {}: {} ({})",
            prefix,
            alert.severity.as_str(),
            ascii(alert.title.trim()),
            ascii(&alert.host)
        )
        .trim()
        .to_string()
    }

    const SANS: &str =
        "-apple-system,BlinkMacSystemFont,'Segoe UI',Manrope,Helvetica,Arial,sans-serif";
    const MONO: &str = "'JetBrains Mono',SFMono-Regular,Menlo,Consolas,'Liberation Mono',monospace";

    /// A section label in the brand accent.
    fn eyebrow(label: &str, top: u32) -> String {
        format!(
            "<div class=\"hm-ac\" style=\"margin-top:{}px;font:600 11px/1 {};letter-spacing:.1em;color:#5B4FD0\">{}</div>",
            top, MONO, label
        )
    }

    /// Pill colours per severity: background, text and lit dots, unlit dots.
    fn pill(s: Severity) -> (&'static str, &'static str, &'static str) {
        match s {
            Severity::Critical => ("#FCE8EB", "#D9344C", "#F0A5B1"),
            Severity::High => ("#EFEDFB", "#5B4FD0", "#B7B0EC"),
            Severity::Low => ("#EEEDF3", "#6B6888", "#C5C3D3"),
            Severity::Info => ("#F1F1F5", "#8D8AA8", "#D3D1DE"),
        }
    }

    fn lit_dots(s: Severity) -> usize {
        match s {
            Severity::Critical => 4,
            Severity::High => 3,
            Severity::Low => 2,
            Severity::Info => 1,
        }
    }

    /// One spec-grid cell: a small label over a monospace value.
    fn cell(label: &str, value: &str, td_attrs: &str, borders: &str) -> String {
        format!(
            "<td class=\"hm-line\" {} style=\"padding:14px 16px;border-color:#E3E1EF;border-style:solid;border-width:0;vertical-align:top{}\">\
             <div class=\"hm-dim\" style=\"font:600 10.5px/1 {mono};letter-spacing:.1em;color:#8D8AA8\">{}</div>\
             <div class=\"hm-tx\" style=\"margin-top:6px;font:500 13px/1.4 {mono};color:#17142E;word-break:break-all\">{}</div></td>",
            td_attrs,
            borders,
            esc(&label.to_uppercase()),
            esc(value),
            mono = MONO
        )
    }

    /// The alert as a branded, mail-client-safe page: tables and inline
    /// styles only, the two logos carried inline (nothing remote), a hidden
    /// preheader for the inbox preview, and a dark palette for clients that
    /// honour `prefers-color-scheme`. An ink header band with the lockup,
    /// the severity as a pill with a drawn four-dot meter (Unicode glyphs
    /// turn into emoji in some clients), a spec grid, the risk, numbered
    /// steps and both CLI commands in one terminal block.
    pub fn html(alert: &Alert) -> String {
        let sev = alert.severity;
        let (pill_bg, pill_fg, pill_off) = pill(sev);
        let mut h = String::with_capacity(12288);
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
             .hm-tx{color:#ECEBF7!important}.hm-tx2{color:#C9C7DA!important}.hm-dim{color:#8D8AA8!important}\
             .hm-line{border-color:#2A2839!important}.hm-ac{color:#9A8CF7!important}\
             .hm-pill{background:#221F38!important}}\
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
             <tr><td align=\"center\" style=\"padding:32px 12px 36px\">\
             <table role=\"presentation\" width=\"600\" cellpadding=\"0\" cellspacing=\"0\" style=\"width:100%;max-width:600px\">",
        );
        // Header band: the lockup (inline PNG, already on the ink colour)
        // and the reference.
        h.push_str(&format!(
            "<tr><td class=\"hm-pad\" style=\"background:#17142E;border-radius:16px 16px 0 0;padding:22px 32px\">\
             <table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\"><tr>\
             <td><img src=\"cid:{cid}\" width=\"88\" height=\"22\" alt=\"Hermian\" style=\"display:block;border:0;outline:none;color:#ECEBF7;font:600 16px {sans}\"></td>\
             <td align=\"right\" style=\"font:500 11.5px/1 {mono};letter-spacing:.04em;color:#8D8AA8\">{r}</td>\
             </tr></table></td></tr>",
            cid = LOCKUP_CID,
            sans = SANS,
            mono = MONO,
            r = esc(&alert.ref_id)
        ));
        h.push_str(
            "<tr><td class=\"hm-card hm-pad\" style=\"background:#FFFFFF;border:1px solid #E3E1EF;border-top:0;border-radius:0 0 16px 16px;padding:32px 32px 34px\">",
        );
        // Severity pill with a drawn meter, then the detection.
        let mut dots = String::new();
        for i in 0..4 {
            let style = if i < lit_dots(sev) {
                format!("background:{}", pill_fg)
            } else {
                format!("border:1.5px solid {}", pill_off)
            };
            dots.push_str(&format!(
                "<span style=\"display:inline-block;width:7px;height:7px;box-sizing:border-box;border-radius:50%;margin-right:3px;vertical-align:middle;{}\"></span>",
                style
            ));
        }
        h.push_str(&format!(
            "<table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\"><tr>\
             <td class=\"hm-pill\" style=\"background:{bg};border-radius:999px;padding:6px 12px 6px 10px;white-space:nowrap\">{dots}\
             <span style=\"font:600 11.5px/1 {mono};letter-spacing:.1em;color:{fg};vertical-align:middle;padding-left:2px\">{level}</span></td>\
             <td class=\"hm-dim\" style=\"padding-left:12px;font:500 12px/1.4 {mono};letter-spacing:.06em;color:#6B6888\">{short} \u{00B7} {name}</td>\
             </tr></table>",
            bg = pill_bg,
            fg = pill_fg,
            dots = dots,
            mono = MONO,
            level = sev.as_str(),
            short = alert.detection.short(),
            name = esc(&alert.detection.name().to_uppercase())
        ));
        h.push_str(&format!(
            "<h1 class=\"hm-tx\" style=\"margin:18px 0 0;font:600 26px/1.25 {};letter-spacing:-.022em;color:#17142E\">{}</h1>",
            SANS,
            esc(&alert.title)
        ));
        if alert.repeats > 1 {
            h.push_str(&format!(
                "<div class=\"hm-dim\" style=\"margin-top:6px;font-size:13px;color:#6B6888\">Seen {} times</div>",
                alert.repeats
            ));
        }
        if !alert.what.is_empty() {
            h.push_str(&format!(
                "<p class=\"hm-tx2\" style=\"margin:14px 0 0;font-size:15.5px;line-height:1.65;color:#3A3756\">{}</p>",
                esc(&alert.what)
            ));
        }
        // Spec grid: host and time side by side, then one row per fact.
        h.push_str(
            "<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" class=\"hm-line\" \
             style=\"margin-top:26px;border:1px solid #E3E1EF;border-radius:12px;border-collapse:separate;overflow:hidden\">",
        );
        let detected = alert.ts.format("%Y-%m-%d %H:%M:%S UTC").to_string();
        let more = !alert.facts.is_empty();
        let bottom = if more { ";border-bottom-width:1px" } else { "" };
        h.push_str(&format!(
            "<tr>{}{}</tr>",
            cell(
                "Host",
                &alert.host,
                "width=\"50%\"",
                &format!(";border-right-width:1px{}", bottom)
            ),
            cell("Detected", &detected, "width=\"50%\"", bottom)
        ));
        for (i, f) in alert.facts.iter().enumerate() {
            let last = i + 1 == alert.facts.len();
            let b = if last { "" } else { ";border-bottom-width:1px" };
            h.push_str(&format!(
                "<tr>{}</tr>",
                cell(&f.label, &f.value, "colspan=\"2\"", b)
            ));
        }
        h.push_str("</table>");
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
        if !alert.why.is_empty() {
            h.push_str(&eyebrow("RISK", 30));
            h.push_str(&format!(
                "<p class=\"hm-tx\" style=\"margin:10px 0 0;font-size:14.5px;line-height:1.65;color:#17142E\">{}</p>",
                esc(&alert.why)
            ));
        }
        if !alert.actions.is_empty() {
            h.push_str(&eyebrow("NEXT STEPS", 28));
            h.push_str(
                "<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" style=\"margin-top:12px\">",
            );
            for (i, a) in alert.actions.iter().enumerate() {
                let top = if i == 0 {
                    "border-top:1px solid #EDECF4;"
                } else {
                    ""
                };
                h.push_str(&format!(
                    "<tr><td class=\"hm-ac hm-line\" width=\"32\" style=\"{top}border-bottom:1px solid #EDECF4;padding:11px 0;font:600 12px/1.5 {mono};color:#5B4FD0;vertical-align:top\">{n:02}</td>\
                     <td class=\"hm-tx hm-line\" style=\"{top}border-bottom:1px solid #EDECF4;padding:11px 0;font-size:14.5px;line-height:1.5;color:#17142E\">{a}</td></tr>",
                    top = top,
                    mono = MONO,
                    n = i + 1,
                    a = esc(a)
                ));
            }
            h.push_str("</table>");
        }
        // Both commands in one terminal block.
        h.push_str(&format!(
            "<div style=\"margin-top:30px;background:#0F0E17;border-radius:12px;padding:16px 18px\">\
             <div style=\"font:600 10.5px/1 {mono};letter-spacing:.1em;color:#8D8AA8\">ON <span style=\"letter-spacing:0\">{host}</span></div>\
             <div style=\"margin-top:12px;font:13px/1.7 {mono};color:#ECEBF7;word-break:break-all\">\
             <span style=\"color:#9A8CF7\">$</span> hermian show {r} &nbsp;<span style=\"color:#6B6888\"># full record</span><br>\
             <span style=\"color:#9A8CF7\">$</span> hermian collect {r} &nbsp;<span style=\"color:#6B6888\"># local context</span></div></div>",
            mono = MONO,
            host = esc(&alert.host),
            r = esc(&alert.ref_id)
        ));
        h.push_str("</td></tr>");
        h.push_str(&format!(
            "<tr><td align=\"center\" style=\"padding:26px 12px 0\">\
             <img src=\"cid:{cid}\" width=\"112\" height=\"16\" alt=\"Hermian Security\" style=\"display:block;margin:0 auto;border:0;outline:none;opacity:.75\">\
             <div class=\"hm-dim\" style=\"margin-top:10px;font-size:12px;line-height:1.6;color:#8D8AA8\">Silent by default. Loud when it matters.<br>\
             Recipients are set in <span style=\"font-family:{mono}\">/etc/hermian/config.toml</span> on {host}.</div></td></tr>",
            cid = COMPANY_CID,
            mono = MONO,
            host = esc(&alert.host)
        ));
        h.push_str("</table></td></tr></table></body></html>");
        h
    }

    pub(super) fn build(alert: &Alert, cfg: &EmailCfg) -> Result<Message, String> {
        let from: Mailbox = format!("Hermian <{}>", cfg.from)
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
        // alternative(plain, related(html, logos)): the standard shape for
        // HTML mail with inline images.
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
                            Attachment::new_inline(LOCKUP_CID.to_string())
                                .body(LOCKUP_PNG.to_vec(), png.clone()),
                        )
                        .singlepart(
                            Attachment::new_inline(COMPANY_CID.to_string())
                                .body(COMPANY_PNG.to_vec(), png),
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
    }

    #[test]
    fn telegram_body_stays_under_the_limit_with_huge_facts() {
        let mut f = Finding::new(DetectionId::D3, Severity::High, "Cron job added", "x")
            .what("w".repeat(5000))
            .why("<&>".repeat(3000));
        for i in 0..30 {
            f = f.fact(format!("Line {}", i), "<&>".repeat(2000));
            f = f.action("<&>".repeat(500));
        }
        let mut a = Alert::from_finding(f, "HER-1".into(), "<&>".repeat(400), chrono::Utc::now());
        a.title = "<&>".repeat(400);
        let b = telegram::body(&a);
        assert!(b.chars().count() <= 4096, "{}", b.chars().count());
        assert!(b.ends_with("<code>hermian show HER-1</code>"));
        // Never a dangling entity or tag.
        for (open, close) in [
            ("<code>", "</code>"),
            ("<pre>", "</pre>"),
            ("<blockquote", "</blockquote>"),
            ("<b>", "</b>"),
        ] {
            assert_eq!(
                b.matches(open).count(),
                b.matches(close).count(),
                "{}",
                open
            );
        }
        assert!(!b.contains("&am\n") && !b.contains("&l\n"));
    }

    #[test]
    fn telegram_body_has_a_meter_and_no_emoji() {
        let b = telegram::body(&alert());
        // No emoji anywhere: severity is a word and a dot meter.
        assert!(!b.chars().any(|c| c as u32 >= 0x1F000), "{}", b);
        assert!(
            b.starts_with(
                "<b>\u{25C9}\u{25C9}\u{25C9}\u{25C9}  CRITICAL</b> \u{00B7} Persistence\n"
            ),
            "{}",
            b
        );
        assert!(b.ends_with("<code>hermian show HER-2025-0101-007</code>"));
    }

    /// Header (meter, level, family), headline, the sentence as a quote,
    /// the fact sheet, the risk and steps collapsed, then the command.
    #[test]
    fn telegram_body_layout() {
        let mut a = alert();
        a.repeats = 3;
        let b = telegram::body(&a);
        let order = [
            "<b>\u{25C9}\u{25C9}\u{25C9}\u{25C9}  CRITICAL</b> \u{00B7} Persistence \u{00B7} seen 3 times\n",
            "<b>ld.so.preload &lt;modified&gt;</b>",
            "<blockquote>A &amp; B</blockquote>",
            "<pre>host      web-01\npreloads  /tmp/evil.so\nrule      D3 \u{00B7} Persistence modification\ntime      ",
            " UTC</pre>",
            "<blockquote expandable><b>Risk</b>\nLoader injection is a common persistence trick.\n\n<b>Next steps</b>\n1. Remove it.</blockquote>",
            "<code>hermian show HER-2025-0101-007</code>",
        ];
        let mut at = 0;
        for part in order {
            let i = b[at..]
                .find(part)
                .unwrap_or_else(|| panic!("{:?} not after {} in {}", part, at, b));
            at += i + part.len();
        }
        assert_eq!(at, b.len(), "{}", b);
        // The bot's name says who's talking.
        assert!(
            !b.contains("HERMIAN") && !b.contains("hermian \u{00B7}"),
            "{}",
            b
        );
    }

    /// The process chain shows on the fact sheet; no risk or steps means no
    /// collapsed section.
    #[test]
    fn telegram_fact_sheet_has_the_chain() {
        use hermian_core::alert::ChainNode;
        let f = Finding::new(DetectionId::D1, Severity::High, "Web shell", "x").what("w");
        let mut a = Alert::from_finding(f, "HER-3".into(), "web-01".into(), chrono::Utc::now());
        a.chain = ["nginx", "sh", "curl"]
            .iter()
            .enumerate()
            .map(|(i, c)| ChainNode {
                pid: i as u32 + 1,
                uid: 0,
                user: None,
                comm: c.to_string(),
                exe: String::new(),
                focus: false,
            })
            .collect();
        let b = telegram::body(&a);
        assert!(
            b.contains("chain  nginx \u{203A} sh \u{203A} curl\n"),
            "{}",
            b
        );
        assert!(!b.contains("expandable"), "{}", b);
    }

    #[test]
    fn meters_count_up_with_severity() {
        assert_eq!(
            telegram::meter(Severity::Critical),
            "\u{25C9}\u{25C9}\u{25C9}\u{25C9}"
        );
        assert_eq!(
            telegram::meter(Severity::High),
            "\u{25C9}\u{25C9}\u{25C9}\u{25CB}"
        );
        assert_eq!(
            telegram::meter(Severity::Low),
            "\u{25C9}\u{25C9}\u{25CB}\u{25CB}"
        );
        assert_eq!(
            telegram::meter(Severity::Info),
            "\u{25C9}\u{25CB}\u{25CB}\u{25CB}"
        );
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
        assert!(h.contains("Seen 4 times"));
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
            email::subject(&a, "[Hermian]"),
            "[Hermian] CRITICAL: ld.so.preload <modified> (web-01)"
        );
        assert!(email::subject(&a, "[Hermian]").is_ascii());
        let h = email::html(&a);
        assert!(h.contains("&lt;modified&gt;"));
        assert!(h.contains("hermian show HER-2025-0101-007"));
        // Critical pill, four lit dots, the detection beside it.
        assert!(h.contains("background:#FCE8EB"));
        assert_eq!(
            h.matches("vertical-align:middle;background:#D9344C")
                .count(),
            4
        );
        assert!(h.contains("D3 \u{00B7} PERSISTENCE MODIFICATION"));
        // Header band and footer logos by Content-ID, the spec grid, both commands.
        assert!(h.contains("<img src=\"cid:hermian-lockup\""));
        assert!(h.contains("<img src=\"cid:hermian-company\""));
        assert!(h.contains(">HOST<") && h.contains(">DETECTED<") && h.contains(">PRELOADS<"));
        assert!(h.contains("# full record") && h.contains("hermian collect HER-2025-0101-007"));
        assert!(h.contains("display:none;max-height:0"));
        assert!(h.contains("prefers-color-scheme:dark"));
        assert!(h.contains(">RISK<") && h.contains("NEXT STEPS"));
        assert!(!h.contains("http"), "no remote assets");
        assert_eq!(h.matches("<img").count(), 2, "only the inline logos");
    }

    /// The logos travel inside the message: the HTML and the PNGs share a
    /// multipart/related part, and each PNG carries the Content-ID the HTML
    /// points at. The plain-text alternative stays.
    #[test]
    fn email_carries_the_logos_inline() {
        let cfg = EmailCfg {
            from: "hermian@example.com".into(),
            to: vec!["ops@example.com".into()],
            ..EmailCfg::default()
        };
        let raw = String::from_utf8(email::build(&alert(), &cfg).unwrap().formatted()).unwrap();
        assert!(raw.contains("multipart/alternative"), "{}", raw);
        assert!(raw.contains("multipart/related"), "{}", raw);
        assert!(raw.contains("Content-ID: <hermian-lockup>"), "{}", raw);
        assert!(raw.contains("Content-ID: <hermian-company>"), "{}", raw);
        assert!(raw.contains("Content-Disposition: inline"), "{}", raw);
        assert!(raw.contains("Content-Type: image/png"), "{}", raw);
        assert!(raw.contains("Content-Type: text/plain"), "{}", raw);
        // Real PNGs, and small.
        for png in [email::LOCKUP_PNG, email::COMPANY_PNG] {
            assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");
            assert!(png.len() < 2048);
        }
    }
}
