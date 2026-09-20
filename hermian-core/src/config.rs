use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::allowlist::Allowlist;
use crate::events::Severity;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("baseline.duration_hours must be greater than 0")]
    BaselineDuration,
    #[error("ssh.failed_burst_count must be greater than 0")]
    BurstCount,
    #[error("ssh.failed_burst_window_secs must be greater than 0")]
    BurstWindow,
    #[error("notifications.dedup_window_secs must be greater than 0")]
    DedupWindow,
    #[error("unknown notification channel '{0}' (supported: journald, file, stdout, webhook)")]
    UnknownChannel(String),
    #[error("notifications.channels must not be empty")]
    NoChannels,
    #[error("notifications.min_severity must be one of INFO, LOW, HIGH, CRITICAL")]
    MinSeverity,
    #[error("notifications.webhook.url is required when the 'webhook' channel is enabled")]
    WebhookUrl,
    #[error("notifications.webhook.url must start with https:// or http://")]
    WebhookScheme,
    #[error("notifications.webhook.format must be one of generic, slack, discord, ntfy")]
    WebhookFormat,
    #[error("notifications.telegram.bot_token is required (format: 123456:ABC-DEF...)")]
    TelegramToken,
    #[error("notifications.telegram.chat_id is required")]
    TelegramChat,
    #[error("notifications.email.transport must be smtp or sendmail")]
    EmailTransport,
    #[error("notifications.email.from must be a valid address")]
    EmailFrom,
    #[error("notifications.email.to must contain at least one valid address")]
    EmailTo,
    #[error("notifications.email.smtp_host is required for the smtp transport")]
    EmailSmtpHost,
    #[error("notifications.email.smtp_security must be starttls, tls or none")]
    EmailSmtpSecurity,
    #[error("notifications.email.smtp_username and smtp_password must be set together")]
    EmailSmtpAuth,
    #[error("ssh.off_hours_start/end must be between 0 and 23")]
    OffHours,
    #[error("response.auto_isolate requires at least one entry in response.management_cidrs")]
    IsolateWithoutCidrs,
    #[error("response.management_cidrs contains an invalid CIDR: '{0}'")]
    BadCidr(String),
    #[error("allowlist.{0} entry has an empty reason")]
    EmptyReason(&'static str),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct General {
    pub hostname: String,
    pub log_level: String,
}

impl Default for General {
    fn default() -> Self {
        General {
            hostname: String::new(),
            log_level: "info".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BaselineCfg {
    pub enabled: bool,
    pub duration_hours: u32,
}

impl Default for BaselineCfg {
    fn default() -> Self {
        BaselineCfg {
            enabled: true,
            duration_hours: 24,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SshCfg {
    /// Treat root SSH logins as expected (suppresses the root-login alert
    /// entirely). When `false` (default) a root login is HIGH the first time it
    /// is seen from a given source and INFO for repeats from that source; new
    /// sources are covered by the baseline novelty rule.
    pub permit_root: bool,
    pub failed_burst_count: u32,
    pub failed_burst_window_secs: u64,
    /// Off-hours window in UTC. Set start == end to disable.
    pub off_hours_start: u32,
    pub off_hours_end: u32,
}

impl Default for SshCfg {
    fn default() -> Self {
        SshCfg {
            permit_root: false,
            failed_burst_count: 5,
            failed_burst_window_secs: 60,
            off_hours_start: 22,
            off_hours_end: 6,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DetectionsCfg {
    pub d1_process_chains: bool,
    pub d2_auth: bool,
    pub d3_persistence: bool,
    pub d4_priv_esc: bool,
    pub d5_network: bool,
}

impl Default for DetectionsCfg {
    fn default() -> Self {
        DetectionsCfg {
            d1_process_chains: true,
            d2_auth: true,
            d3_persistence: true,
            d4_priv_esc: true,
            d5_network: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WebhookCfg {
    pub url: String,
    /// generic | slack | discord | ntfy
    pub format: String,
    /// Optional bearer token / ntfy access token sent as `Authorization`.
    pub token: String,
    pub timeout_secs: u64,
}

impl Default for WebhookCfg {
    fn default() -> Self {
        WebhookCfg {
            url: String::new(),
            format: "generic".to_string(),
            token: String::new(),
            timeout_secs: 10,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TelegramCfg {
    /// Bot token from @BotFather, e.g. "123456789:AAH...".
    pub bot_token: String,
    /// Chat, group or channel id (negative for groups). Get it from
    /// https://api.telegram.org/bot<token>/getUpdates after messaging the bot.
    pub chat_id: String,
    /// Optional topic id for forum-style supergroups.
    pub message_thread_id: Option<i64>,
    /// Send CRITICAL alerts with notification sound (others are silent).
    pub silent_below_critical: bool,
    pub timeout_secs: u64,
}

impl Default for TelegramCfg {
    fn default() -> Self {
        TelegramCfg {
            bot_token: String::new(),
            chat_id: String::new(),
            message_thread_id: None,
            silent_below_critical: true,
            timeout_secs: 10,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EmailCfg {
    /// smtp | sendmail
    pub transport: String,
    pub from: String,
    pub to: Vec<String>,
    /// Prefix for the subject line, e.g. "[HERMIAN]".
    pub subject_prefix: String,
    // --- smtp transport ---
    pub smtp_host: String,
    pub smtp_port: u16,
    /// starttls | tls | none
    pub smtp_security: String,
    pub smtp_username: String,
    pub smtp_password: String,
    pub timeout_secs: u64,
    // --- sendmail transport ---
    pub sendmail_path: String,
}

impl Default for EmailCfg {
    fn default() -> Self {
        EmailCfg {
            transport: "smtp".to_string(),
            from: String::new(),
            to: Vec::new(),
            subject_prefix: "[HERMIAN]".to_string(),
            smtp_host: String::new(),
            smtp_port: 587,
            smtp_security: "starttls".to_string(),
            smtp_username: String::new(),
            smtp_password: String::new(),
            timeout_secs: 20,
            sendmail_path: "/usr/sbin/sendmail".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NotificationsCfg {
    pub channels: Vec<String>,
    pub dedup_window_secs: u64,
    /// Minimum severity that is *notified* (sent to webhook/telegram/email/
    /// stdout). Everything is always written to journald/file regardless.
    pub min_severity: String,
    pub webhook: WebhookCfg,
    pub telegram: TelegramCfg,
    pub email: EmailCfg,
}

impl Default for NotificationsCfg {
    fn default() -> Self {
        NotificationsCfg {
            channels: vec!["journald".to_string(), "file".to_string()],
            dedup_window_secs: 300,
            min_severity: "HIGH".to_string(),
            webhook: WebhookCfg::default(),
            telegram: TelegramCfg::default(),
            email: EmailCfg::default(),
        }
    }
}

impl NotificationsCfg {
    pub fn min_severity(&self) -> Severity {
        self.min_severity.parse().unwrap_or(Severity::High)
    }

    pub fn has_channel(&self, name: &str) -> bool {
        self.channels.iter().any(|c| c == name)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct ResponseCfg {
    pub auto_isolate: bool,
    pub management_cidrs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub general: General,
    pub baseline: BaselineCfg,
    pub ssh: SshCfg,
    pub detections: DetectionsCfg,
    pub notifications: NotificationsCfg,
    pub response: ResponseCfg,
    pub allowlist: Allowlist,
}

pub const SUPPORTED_CHANNELS: &[&str] =
    &["journald", "file", "stdout", "webhook", "telegram", "email"];
pub const SUPPORTED_EMAIL_TRANSPORTS: &[&str] = &["smtp", "sendmail"];
pub const SUPPORTED_SMTP_SECURITY: &[&str] = &["starttls", "tls", "none"];
pub const SUPPORTED_WEBHOOK_FORMATS: &[&str] = &["generic", "slack", "discord", "ntfy"];

impl Config {
    pub fn parse(toml_text: &str) -> Result<Config, toml::de::Error> {
        toml::from_str(toml_text)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.baseline.duration_hours == 0 {
            return Err(ConfigError::BaselineDuration);
        }
        if self.ssh.failed_burst_count == 0 {
            return Err(ConfigError::BurstCount);
        }
        if self.ssh.failed_burst_window_secs == 0 {
            return Err(ConfigError::BurstWindow);
        }
        if self.notifications.dedup_window_secs == 0 {
            return Err(ConfigError::DedupWindow);
        }
        if self.ssh.off_hours_start > 23 || self.ssh.off_hours_end > 23 {
            return Err(ConfigError::OffHours);
        }
        if self.notifications.channels.is_empty() {
            return Err(ConfigError::NoChannels);
        }
        for ch in &self.notifications.channels {
            if !SUPPORTED_CHANNELS.contains(&ch.as_str()) {
                return Err(ConfigError::UnknownChannel(ch.clone()));
            }
        }
        if self.notifications.min_severity.parse::<Severity>().is_err() {
            return Err(ConfigError::MinSeverity);
        }
        if self.notifications.has_channel("webhook") {
            let w = &self.notifications.webhook;
            if w.url.is_empty() {
                return Err(ConfigError::WebhookUrl);
            }
            if !w.url.starts_with("https://") && !w.url.starts_with("http://") {
                return Err(ConfigError::WebhookScheme);
            }
            if !SUPPORTED_WEBHOOK_FORMATS.contains(&w.format.as_str()) {
                return Err(ConfigError::WebhookFormat);
            }
        }
        if self.notifications.has_channel("telegram") {
            let t = &self.notifications.telegram;
            if t.bot_token.is_empty() || !t.bot_token.contains(':') {
                return Err(ConfigError::TelegramToken);
            }
            if t.chat_id.is_empty() {
                return Err(ConfigError::TelegramChat);
            }
        }
        if self.notifications.has_channel("email") {
            let e = &self.notifications.email;
            if !SUPPORTED_EMAIL_TRANSPORTS.contains(&e.transport.as_str()) {
                return Err(ConfigError::EmailTransport);
            }
            if e.from.is_empty() || !e.from.contains('@') {
                return Err(ConfigError::EmailFrom);
            }
            if e.to.is_empty() || e.to.iter().any(|a| !a.contains('@')) {
                return Err(ConfigError::EmailTo);
            }
            if e.transport == "smtp" {
                if e.smtp_host.is_empty() {
                    return Err(ConfigError::EmailSmtpHost);
                }
                if !SUPPORTED_SMTP_SECURITY.contains(&e.smtp_security.as_str()) {
                    return Err(ConfigError::EmailSmtpSecurity);
                }
                if e.smtp_username.is_empty() != e.smtp_password.is_empty() {
                    return Err(ConfigError::EmailSmtpAuth);
                }
            }
        }
        if self.response.auto_isolate && self.response.management_cidrs.is_empty() {
            return Err(ConfigError::IsolateWithoutCidrs);
        }
        for cidr in &self.response.management_cidrs {
            if crate::allowlist::parse_cidr(cidr).is_none() {
                return Err(ConfigError::BadCidr(cidr.clone()));
            }
        }
        self.allowlist.validate()?;
        Ok(())
    }
}

pub const DEFAULT_CONFIG_TOML: &str = r#"# HERMIAN configuration
#
# This file is monitored while the daemon runs. Any change triggers validation,
# a reload, and a CRITICAL self-protection alert so tampering is never silent.
# Every allowlist entry requires a 'reason' - it is your audit trail.

[general]
hostname = ""           # empty = use the system hostname

[baseline]
enabled = true          # learn SSH sources / network peers before alerting on novelty
duration_hours = 24

[ssh]
permit_root = false     # true suppresses the "root login over SSH" alert
failed_burst_count = 5
failed_burst_window_secs = 60
off_hours_start = 22    # UTC; set start == end to disable off-hours weighting
off_hours_end = 6

[detections]
d1_process_chains = true
d2_auth = true
d3_persistence = true
d4_priv_esc = true
d5_network = true

[notifications]
# journald and file receive every alert. The other channels receive alerts at
# or above min_severity. Enable a channel by adding it to this list:
#   "telegram", "email", "webhook", "stdout"
channels = ["journald", "file"]
dedup_window_secs = 300
min_severity = "HIGH"

[notifications.telegram]
# 1. Message @BotFather, /newbot, copy the token.
# 2. Send any message to your new bot (or add it to a group).
# 3. curl https://api.telegram.org/bot<TOKEN>/getUpdates  -> "chat":{"id":...}
bot_token = ""
chat_id = ""
silent_below_critical = true   # only CRITICAL makes a sound
timeout_secs = 10

[notifications.email]
transport = "smtp"             # smtp | sendmail (use the host's MTA)
from = ""                      # e.g. "hermian@example.com"
to = []                        # e.g. ["ops@example.com"]
subject_prefix = "[HERMIAN]"
smtp_host = ""                 # e.g. "smtp.gmail.com" (use an app password)
smtp_port = 587
smtp_security = "starttls"     # starttls (587) | tls (465) | none (25, local relay)
smtp_username = ""
smtp_password = ""
timeout_secs = 20
sendmail_path = "/usr/sbin/sendmail"

[notifications.webhook]
url = ""
format = "generic"      # generic | slack | discord | ntfy
token = ""
timeout_secs = 10

[response]
auto_isolate = false    # on CRITICAL, drop all traffic except management_cidrs
management_cidrs = []   # e.g. ["203.0.113.0/24"]

[allowlist]
# [[allowlist.process_chains]]
# parent = "deploy-agent"
# child  = "bash"
# user   = "deploy"
# reason = "CI/CD deployment pipeline"
#
# [[allowlist.persistence]]
# path   = "/var/spool/cron/crontabs/deploy"
# reason = "Managed by Ansible"
#
# [[allowlist.ssh_sources]]
# source = "10.0.0.0/8"
# reason = "Corporate VPN range"
#
# [[allowlist.destinations]]
# destination = "203.0.113.10/32"
# reason = "Payment provider API"
#
# [[allowlist.binaries]]
# path   = "/opt/app/bin/updater"
# reason = "Internal auto-updater runs from /tmp staging"
#
# [[allowlist.debuggers]]
# comm   = "my-profiler"
# reason = "In-house APM agent uses ptrace"
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_toml_parses_and_validates() {
        let cfg = Config::parse(DEFAULT_CONFIG_TOML).expect("default config must parse");
        cfg.validate().expect("default config must validate");
        assert!(cfg.detections.d1_process_chains);
        assert!(cfg.baseline.enabled);
        assert_eq!(cfg.notifications.min_severity(), Severity::High);
    }

    #[test]
    fn allowlist_reason_is_required() {
        let toml_text = r#"
[[allowlist.process_chains]]
parent = "x"
child = "y"
"#;
        assert!(Config::parse(toml_text).is_err());
        let toml_text = r#"
[[allowlist.process_chains]]
parent = "x"
child = "y"
reason = ""
"#;
        let cfg = Config::parse(toml_text).unwrap();
        assert!(matches!(cfg.validate(), Err(ConfigError::EmptyReason(_))));
    }

    #[test]
    fn documented_singular_aliases_work() {
        let toml_text = r#"
[[allowlist.process_chain]]
parent = "deploy-agent"
child = "bash"
reason = "ci"

[[allowlist.ssh_source]]
source = "10.0.0.5"
reason = "ansible"
"#;
        let cfg = Config::parse(toml_text).expect("aliases parse");
        assert_eq!(cfg.allowlist.process_chains.len(), 1);
        assert_eq!(cfg.allowlist.ssh_sources.len(), 1);
    }

    #[test]
    fn invalid_thresholds_rejected() {
        let cfg = Config::parse("[ssh]\nfailed_burst_count = 0\n").unwrap();
        assert!(matches!(cfg.validate(), Err(ConfigError::BurstCount)));
    }

    #[test]
    fn webhook_requires_url_and_scheme() {
        let cfg = Config::parse("[notifications]\nchannels = [\"webhook\"]\n").unwrap();
        assert!(matches!(cfg.validate(), Err(ConfigError::WebhookUrl)));
        let cfg = Config::parse(
            "[notifications]\nchannels = [\"webhook\"]\n[notifications.webhook]\nurl = \"ftp://x\"\n",
        )
        .unwrap();
        assert!(matches!(cfg.validate(), Err(ConfigError::WebhookScheme)));
        let cfg = Config::parse(
            "[notifications]\nchannels = [\"journald\", \"webhook\"]\n[notifications.webhook]\nurl = \"https://hooks.example/x\"\nformat = \"slack\"\n",
        )
        .unwrap();
        cfg.validate().unwrap();
    }

    #[test]
    fn telegram_and_email_validation() {
        let cfg = Config::parse("[notifications]\nchannels = [\"telegram\"]\n").unwrap();
        assert!(matches!(cfg.validate(), Err(ConfigError::TelegramToken)));
        let cfg = Config::parse(
            "[notifications]\nchannels = [\"telegram\"]\n[notifications.telegram]\nbot_token = \"1:x\"\n",
        )
        .unwrap();
        assert!(matches!(cfg.validate(), Err(ConfigError::TelegramChat)));
        let cfg = Config::parse(
            "[notifications]\nchannels = [\"telegram\"]\n[notifications.telegram]\nbot_token = \"1:x\"\nchat_id = \"-100\"\n",
        )
        .unwrap();
        cfg.validate().unwrap();

        let cfg = Config::parse("[notifications]\nchannels = [\"email\"]\n").unwrap();
        assert!(matches!(cfg.validate(), Err(ConfigError::EmailFrom)));
        let cfg = Config::parse(
            "[notifications]\nchannels = [\"email\"]\n[notifications.email]\nfrom = \"a@b\"\nto = [\"c@d\"]\n",
        )
        .unwrap();
        assert!(matches!(cfg.validate(), Err(ConfigError::EmailSmtpHost)));
        let cfg = Config::parse(
            "[notifications]\nchannels = [\"email\"]\n[notifications.email]\nfrom = \"a@b\"\nto = [\"c@d\"]\nsmtp_host = \"h\"\nsmtp_username = \"u\"\n",
        )
        .unwrap();
        assert!(matches!(cfg.validate(), Err(ConfigError::EmailSmtpAuth)));
        let cfg = Config::parse(
            "[notifications]\nchannels = [\"email\"]\n[notifications.email]\ntransport = \"sendmail\"\nfrom = \"a@b\"\nto = [\"c@d\"]\n",
        )
        .unwrap();
        cfg.validate().unwrap();
    }

    #[test]
    fn auto_isolate_requires_cidrs() {
        let cfg = Config::parse("[response]\nauto_isolate = true\n").unwrap();
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::IsolateWithoutCidrs)
        ));
        let cfg = Config::parse("[response]\nmanagement_cidrs = [\"not-a-cidr\"]\n").unwrap();
        assert!(matches!(cfg.validate(), Err(ConfigError::BadCidr(_))));
    }

    #[test]
    fn unknown_keys_rejected() {
        assert!(Config::parse("[ssh]\npermit_rooot = true\n").is_err());
    }
}
