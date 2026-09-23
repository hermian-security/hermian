//! What changed between two configs, for the runtime reload alert.
//!
//! Every field is compared, not a hand-picked list: a reload that only
//! repoints the webhook or Telegram chat is exactly what an attacker would do
//! to take over the alert path, so it mustn't read as "no functional change".

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
        };
    };
    let mut changes = Vec::new();
    walk("", &a, &b, &mut changes);
    let destinations_changed = changes
        .iter()
        .any(|(path, _)| DESTINATION_FIELDS.contains(&path.as_str()));
    let summary = if changes.is_empty() {
        "no functional change".to_string()
    } else {
        changes
            .iter()
            .map(|(_, line)| line.as_str())
            .collect::<Vec<_>>()
            .join("; ")
    };
    ConfigDiff {
        changed: changes.into_iter().map(|(p, _)| p).collect(),
        summary,
        destinations_changed,
    }
}

fn walk(path: &str, a: &Value, b: &Value, out: &mut Vec<(String, String)>) {
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
    out.push((path.to_string(), line));
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
}
