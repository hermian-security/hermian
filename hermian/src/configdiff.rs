//! What changed between two configs, for the runtime reload alert.
//!
//! Every field is compared, not a hand-picked list: a reload that only
//! repoints the webhook or Telegram chat is exactly what an attacker would do
//! to take over the alert path, so it mustn't read as "no functional change".
//!
//! Each change is also judged: does it loosen protection (fewer or other
//! destinations, a rule off, a wider exception)? Those page CRITICAL. Changes
//! that only tune or tighten (a timeout, a new channel, an exception removed)
//! are recorded without paging, so editing your own config doesn't page you.
//! Anything not known to be harmless counts as loosening.

use hermian_core::Config;
use serde_json::Value;

/// Fields whose values are never shown, only that they changed.
const SECRET_FIELDS: &[&str] = &[
    "token",
    "bot_token",
    "smtp_password",
    "smtp_username",
    "url",
];

/// Fields that decide *where* alerts go.
const DESTINATION_FIELDS: &[&str] = &[
    "notifications.channels",
    "notifications.min_severity",
    "notifications.webhook.url",
    "notifications.webhook.token",
    "notifications.telegram.bot_token",
    "notifications.telegram.chat_id",
    "notifications.telegram.message_thread_id",
    // Who can act on alerts from Telegram is as sensitive as where they go.
    "notifications.telegram.actions",
    "notifications.telegram.allowed_user_ids",
    "notifications.email.transport",
    "notifications.email.to",
    "notifications.email.smtp_host",
    "notifications.email.smtp_port",
    "notifications.email.sendmail_path",
];

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ConfigDiff {
    /// Dotted paths that changed, e.g. `notifications.telegram.chat_id`.
    pub changed: Vec<String>,
    /// One line for the alert, with secrets redacted.
    pub summary: String,
    /// Alerts may now go somewhere else (or nowhere).
    pub destinations_changed: bool,
    /// Something now protects less (see the module doc).
    pub weakens: bool,
}

impl ConfigDiff {
    pub fn is_functional(&self) -> bool {
        !self.changed.is_empty()
    }
}

pub fn diff(old: &Config, new: &Config) -> ConfigDiff {
    let (Ok(a), Ok(b)) = (serde_json::to_value(old), serde_json::to_value(new)) else {
        // Can't compare: assume the worst.
        return ConfigDiff {
            changed: vec!["(unknown)".into()],
            summary: "configuration changed (could not compare)".into(),
            destinations_changed: true,
            weakens: true,
        };
    };
    let mut changes = Vec::new();
    walk("", &a, &b, &mut changes);
    let destinations_changed = changes
        .iter()
        .any(|(path, _, _)| DESTINATION_FIELDS.contains(&path.as_str()));
    let weakens = changes.iter().any(|(_, _, weak)| *weak);
    let summary = if changes.is_empty() {
        "no functional change".to_string()
    } else {
        changes
            .iter()
            .map(|(_, line, _)| line.as_str())
            .collect::<Vec<_>>()
            .join("; ")
    };
    ConfigDiff {
        changed: changes.into_iter().map(|(p, _, _)| p).collect(),
        summary,
        destinations_changed,
        weakens,
    }
}

/// Fields that only tune how Hermian behaves, never what it protects.
const HARMLESS_FIELDS: &[&str] = &[
    "general.alert_retention_days",
    "general.hostname",
    "baseline.duration_hours",
    "ssh.brute_digest_hours",
    "ssh.brute_digest_days",
    "notifications.dedup_window_secs",
    "notifications.content",
    "notifications.telegram.silent_below_critical",
    "notifications.telegram.timeout_secs",
    "notifications.telegram.action_ttl_mins",
    "notifications.email.subject_prefix",
    "notifications.email.from",
    "notifications.email.timeout_secs",
    "notifications.webhook.format",
    "notifications.webhook.timeout_secs",
    "response.block_duration_hours",
    "response.auto_isolate_revert_mins",
];

fn severity_rank(v: &Value) -> u8 {
    match v.as_str().map(str::to_ascii_uppercase).as_deref() {
        Some("INFO") => 0,
        Some("LOW") => 1,
        Some("HIGH") => 2,
        Some("CRITICAL") => 3,
        _ => 4,
    }
}

/// Entries in `b` that weren't in `a`.
fn added(a: &Value, b: &Value) -> bool {
    let old = a.as_array().cloned().unwrap_or_default();
    b.as_array()
        .is_some_and(|new| new.iter().any(|x| !old.contains(x)))
}

/// Whether changing `path` from `a` to `b` loosens protection.
fn loosens(path: &str, a: &Value, b: &Value) -> bool {
    if HARMLESS_FIELDS.contains(&path) {
        return false;
    }
    let num = |v: &Value| v.as_f64().unwrap_or(0.0);
    match path {
        // Fewer channels: alerts reach fewer places. A new one is fine.
        "notifications.channels" => added(b, a),
        "notifications.min_severity" => severity_rank(b) > severity_rank(a),
        "ssh.permit_root" | "notifications.telegram.actions" => b == &Value::Bool(true),
        "baseline.enabled" | "response.auto_isolate" => b == &Value::Bool(false),
        "ssh.known_key_new_network" => b.as_str() == Some("log"),
        // More failures needed before anything shows: quieter.
        "ssh.failed_burst_count"
        | "ssh.brute_min_attempts"
        | "ssh.failed_burst_window_secs"
        | "ssh.brute_alert_count" => num(b) > num(a),
        // A shorter window needs the same failures faster: quieter.
        "ssh.brute_alert_window_secs" => num(b) < num(a),
        // More people who can press buttons, more addresses that are never
        // blocked, more exceptions: wider. Removing entries tightens.
        "notifications.telegram.allowed_user_ids" | "response.management_cidrs" => added(a, b),
        p if p.starts_with("allowlist.") => added(a, b),
        p if p.starts_with("detections.") => b == &Value::Bool(false),
        // Repointing where alerts go (a token, a chat, a URL, recipients...)
        // and anything unknown: assume the worst.
        _ => true,
    }
}

fn walk(path: &str, a: &Value, b: &Value, out: &mut Vec<(String, String, bool)>) {
    if a == b {
        return;
    }
    if let (Value::Object(ma), Value::Object(mb)) = (a, b) {
        let mut keys: Vec<&String> = ma.keys().chain(mb.keys()).collect();
        keys.sort();
        keys.dedup();
        for k in keys {
            let child = if path.is_empty() {
                k.clone()
            } else {
                format!("{}.{}", path, k)
            };
            walk(
                &child,
                ma.get(k).unwrap_or(&Value::Null),
                mb.get(k).unwrap_or(&Value::Null),
                out,
            );
        }
        return;
    }
    let field = path.rsplit('.').next().unwrap_or(path);
    let line = if SECRET_FIELDS.contains(&field) {
        format!("{} changed", path)
    } else if path.starts_with("allowlist.") {
        // Entries can be long; the count and section are what matter here.
        format!("{}: {} -> {} entries", path, len(a), len(b))
    } else {
        format!("{}: {} -> {}", path, short(a), short(b))
    };
    out.push((path.to_string(), line, loosens(path, a, b)));
}

fn len(v: &Value) -> usize {
    v.as_array().map(Vec::len).unwrap_or(0)
}

fn short(v: &Value) -> String {
    let s = match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    if s.chars().count() > 60 {
        let mut t: String = s.chars().take(59).collect();
        t.push('\u{2026}');
        t
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        Config::default()
    }

    #[test]
    fn identical_configs_are_not_functional() {
        let d = diff(&cfg(), &cfg());
        assert!(!d.is_functional());
        assert_eq!(d.summary, "no functional change");
    }

    #[test]
    fn repointing_alerts_is_a_destination_change() {
        let old = cfg();
        let mut new = cfg();
        new.notifications.telegram.chat_id = "-100999".into();
        let d = diff(&old, &new);
        assert!(d.is_functional());
        assert!(d.destinations_changed);
        assert!(
            d.summary.contains("notifications.telegram.chat_id"),
            "{}",
            d.summary
        );

        let mut new = cfg();
        new.notifications.webhook.url = "https://attacker.example/hook?secret=abc".into();
        let d = diff(&old, &new);
        assert!(d.destinations_changed);
        assert!(!d.summary.contains("attacker"), "{}", d.summary);
        assert!(d.summary.contains("notifications.webhook.url changed"));
    }

    #[test]
    fn secrets_are_never_printed() {
        let old = cfg();
        let mut new = cfg();
        new.notifications.telegram.bot_token = "123:SECRET".into();
        new.notifications.email.smtp_password = "hunter2".into();
        let d = diff(&old, &new);
        assert!(!d.summary.contains("SECRET") && !d.summary.contains("hunter2"));
        assert!(d.destinations_changed);
    }

    #[test]
    fn response_and_baseline_changes_count() {
        let old = cfg();
        let mut new = cfg();
        new.response.management_cidrs = vec!["0.0.0.0/0".into()];
        new.baseline.duration_hours = 1;
        let d = diff(&old, &new);
        assert!(d.is_functional());
        assert!(!d.destinations_changed);
        assert!(d.changed.contains(&"response.management_cidrs".to_string()));
        assert!(d.changed.contains(&"baseline.duration_hours".to_string()));
    }

    #[test]
    fn swapping_allowlist_entries_is_seen() {
        // Same count, different entry: the old count-only check missed this.
        let mut old = cfg();
        old.allowlist
            .binaries
            .push(hermian_core::allowlist::PathRule {
                path: "/usr/local/bin/backup".into(),
                reason: "nightly job".into(),
            });
        let mut new = cfg();
        new.allowlist
            .binaries
            .push(hermian_core::allowlist::PathRule {
                path: "/tmp/*".into(),
                reason: "x".into(),
            });
        let d = diff(&old, &new);
        assert!(d.is_functional(), "{:?}", d);
    }

    #[test]
    fn tuning_or_tightening_doesnt_loosen() {
        let old = cfg();
        let mut new = cfg();
        new.notifications.telegram.timeout_secs = 30;
        new.response.block_duration_hours = 48;
        new.notifications.min_severity = "LOW".into();
        new.notifications.channels.push("stdout".into());
        let d = diff(&old, &new);
        assert!(d.is_functional() && !d.weakens, "{:?}", d);
    }

    #[test]
    fn loosening_is_caught() {
        let loosened = |f: &dyn Fn(&mut Config)| {
            let mut new = cfg();
            f(&mut new);
            diff(&cfg(), &new).weakens
        };
        assert!(loosened(
            &|c| c.notifications.min_severity = "CRITICAL".into()
        ));
        assert!(loosened(&|c| c.detections.d1_process_chains = false));
        assert!(loosened(&|c| c.ssh.permit_root = true));
        assert!(loosened(&|c| c
            .notifications
            .channels
            .retain(|x| x != "file")));
        assert!(loosened(
            &|c| c.notifications.telegram.chat_id = "-100999".into()
        ));
        assert!(loosened(
            &|c| c.response.management_cidrs = vec!["0.0.0.0/1".into()]
        ));
        assert!(loosened(&|c| c.ssh.known_key_new_network = "log".into()));
        assert!(loosened(&|c| c.allowlist.ssh_sources.push(
            hermian_core::allowlist::SourceRule {
                source: "0.0.0.0/0".into(),
                reason: "x".into(),
            }
        )));
        // Removing an exception tightens.
        let mut with = cfg();
        with.allowlist
            .ssh_sources
            .push(hermian_core::allowlist::SourceRule {
                source: "10.0.0.0/8".into(),
                reason: "VPN".into(),
            });
        assert!(!diff(&with, &cfg()).weakens);
    }
}
