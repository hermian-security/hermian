use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::allowlist::Allowlist;
use crate::events::Severity;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("baseline.duration_hours must be between 1 and 8760 (one year)")]
    BaselineDuration,
    #[error("ssh.failed_burst_count must be between 1 and 10000")]
    BurstCount,
    #[error("ssh.failed_burst_window_secs must be between 1 and 86400 (one day)")]
    BurstWindow,
    #[error("notifications.dedup_window_secs must be between 1 and 86400 (one day)")]
    DedupWindow,
    #[error(
        "unknown notification channel '{0}' (supported: journald, file, stdout, webhook, telegram, email)"
    )]
    UnknownChannel(String),
    #[error("notifications.{0}.timeout_secs must be between 1 and 300")]
    Timeout(&'static str),
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
    #[error("response.management_cidrs entry '{0}' matches every address, so isolation would do nothing")]
    CatchAllCidr(String),
    #[error("response.auto_isolate_revert_mins must be at most 10080 (one week)")]
    RevertMins,
    #[error("allowlist.{0} entry has an empty reason")]
    EmptyReason(&'static str),
    #[error("general.alert_retention_days must be at most 3650 (0 keeps alerts forever)")]
    RetentionDays,
    #[error("ssh.brute_digest_hours must be between 1 and 24")]
    DigestHours,
    #[error("ssh.brute_min_attempts must be between 1 and 10000")]
    DigestMinAttempts,
    #[error("notifications.telegram.actions needs the telegram channel and at least one entry in allowed_user_ids")]
    TelegramActions,
    #[error("notifications.telegram.action_ttl_mins must be between 1 and 1440")]
    ActionTtl,
    #[error("response.block_duration_hours must be between 1 and 8760")]
    BlockHours,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct General {
    pub hostname: String,
    pub log_level: String,
    /// Stored alert records and collect bundles older than this are deleted
    /// (0 keeps them forever). `alerts.log` is rotated by size regardless.
    pub alert_retention_days: u32,
}

impl Default for General {
    fn default() -> Self {
        General {
            hostname: String::new(),
            log_level: "info".to_string(),
            alert_retention_days: 90,
        }
    }
}

/// Upper bound for `general.alert_retention_days` (ten years).
pub const MAX_RETENTION_DAYS: u32 = 3650;

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
    /// Off-hours window in local time. Set start == end to disable.
    pub off_hours_start: u32,
    pub off_hours_end: u32,
    /// Failed logins against *existing* accounts are summed up in a digest
    /// every this many hours, sent only if there were any.
    pub brute_digest_hours: u32,
    /// A source needs at least this many failures against existing accounts
    /// in a digest period to be listed.
    pub brute_min_attempts: u32,
}

impl Default for SshCfg {
    fn default() -> Self {
        SshCfg {
            permit_root: false,
            failed_burst_count: 5,
            failed_burst_window_secs: 60,
            off_hours_start: 22,
            off_hours_end: 6,
            brute_digest_hours: 2,
            brute_min_attempts: 10,
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
    /// Show response buttons (Block IP, Disconnect...) under alerts that
    /// offer them. Off by default: it turns the bot into a remote control.
    pub actions: bool,
    /// Telegram user ids allowed to press those buttons. Required when
    /// `actions` is on; presses from anyone else are refused and logged.
    pub allowed_user_ids: Vec<i64>,
    /// Buttons stop working after this many minutes.
    pub action_ttl_mins: u32,
}

impl Default for TelegramCfg {
    fn default() -> Self {
        TelegramCfg {
            bot_token: String::new(),
            chat_id: String::new(),
            message_thread_id: None,
            silent_below_critical: true,
            timeout_secs: 10,
            actions: false,
            allowed_user_ids: Vec::new(),
            action_ttl_mins: 30,
        }
    }
}

impl TelegramCfg {
    /// Whether response buttons are in use.
    pub fn actions_enabled(&self) -> bool {
        self.actions && !self.allowed_user_ids.is_empty()
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ResponseCfg {
    pub auto_isolate: bool,
    pub management_cidrs: Vec<String>,
    /// Lift an automatic isolation after this many minutes (0 = stay
    /// isolated until `hermian unisolate`). A dead-man switch in case the
    /// management CIDRs turn out to be wrong.
    pub auto_isolate_revert_mins: u32,
    /// How long a "Block IP" lasts, in hours.
    pub block_duration_hours: u32,
}

impl Default for ResponseCfg {
    fn default() -> Self {
        ResponseCfg {
            auto_isolate: false,
            management_cidrs: Vec::new(),
            auto_isolate_revert_mins: 0,
            block_duration_hours: 24,
        }
    }
}

/// Upper bound for `block_duration_hours` (one year).
pub const MAX_BLOCK_HOURS: u32 = 24 * 365;

/// Upper bound for `auto_isolate_revert_mins` (one week).
pub const MAX_REVERT_MINS: u32 = 7 * 24 * 60;

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

pub const MAX_BASELINE_HOURS: u32 = 24 * 365;
pub const MAX_WINDOW_SECS: u64 = 86_400;

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
        // Upper bounds too: chrono panics on out-of-range durations, so a
        // typo like duration_hours = 99999999999 used to crash the daemon on
        // (re)load instead of being rejected.
        if !(1..=MAX_BASELINE_HOURS).contains(&self.baseline.duration_hours) {
            return Err(ConfigError::BaselineDuration);
        }
        if self.general.alert_retention_days > MAX_RETENTION_DAYS {
            return Err(ConfigError::RetentionDays);
        }
        if !(1..=24).contains(&self.ssh.brute_digest_hours) {
            return Err(ConfigError::DigestHours);
        }
        if !(1..=10_000).contains(&self.ssh.brute_min_attempts) {
            return Err(ConfigError::DigestMinAttempts);
        }
        let tg = &self.notifications.telegram;
        if tg.actions
            && (tg.allowed_user_ids.is_empty() || !self.notifications.has_channel("telegram"))
        {
            return Err(ConfigError::TelegramActions);
        }
        if !(1..=1440).contains(&tg.action_ttl_mins) {
            return Err(ConfigError::ActionTtl);
        }
        if !(1..=MAX_BLOCK_HOURS).contains(&self.response.block_duration_hours) {
            return Err(ConfigError::BlockHours);
        }
        if !(1..=10_000).contains(&self.ssh.failed_burst_count) {
            return Err(ConfigError::BurstCount);
        }
        if !(1..=MAX_WINDOW_SECS).contains(&self.ssh.failed_burst_window_secs) {
            return Err(ConfigError::BurstWindow);
        }
        if !(1..=MAX_WINDOW_SECS).contains(&self.notifications.dedup_window_secs) {
            return Err(ConfigError::DedupWindow);
        }
        for (name, t) in [
            ("webhook", self.notifications.webhook.timeout_secs),
            ("telegram", self.notifications.telegram.timeout_secs),
            ("email", self.notifications.email.timeout_secs),
        ] {
            if !(1..=300).contains(&t) {
                return Err(ConfigError::Timeout(name));
            }
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
            match crate::allowlist::parse_cidr(cidr) {
                None => return Err(ConfigError::BadCidr(cidr.clone())),
                // 0.0.0.0/0 or ::/0 keeps everything reachable: isolation
                // would silently do nothing.
                Some((_, 0)) => return Err(ConfigError::CatchAllCidr(cidr.clone())),
                Some(_) => {}
            }
        }
        if self.response.auto_isolate_revert_mins > MAX_REVERT_MINS {
            return Err(ConfigError::RevertMins);
        }
        self.allowlist.validate()?;
        Ok(())
    }
}

pub const DEFAULT_CONFIG_TOML: &str = r#"# HERMIAN configuration
#
# This file is monitored while the daemon runs. A real change that validates
# reloads and pages CRITICAL. Invalid TOML stays on the last good config and
# is logged, not paged. Every allowlist entry requires a 'reason'.
#
# Lines starting with '#' are inactive: remove the '#' to use a setting.
# 'hermian enable' (run on every upgrade) adds settings new in that version
# to this file, commented out, without changing anything you've set.

[general]
hostname = ""           # empty = use the system hostname
alert_retention_days = 90  # delete stored alerts/collect bundles older than this; 0 = keep

[baseline]
enabled = true          # learn SSH sources / network peers before alerting on novelty
duration_hours = 24

[ssh]
permit_root = false     # true suppresses the "root login over SSH" alert
failed_burst_count = 5          # failures in the window; INFO until a login follows
failed_burst_window_secs = 60
off_hours_start = 22    # host local time; set start == end to disable off-hours weighting
off_hours_end = 6
brute_digest_hours = 2  # failed logins against existing accounts, summed up this often
brute_min_attempts = 10 # failures a source needs in that period to be listed

[detections]
d1_process_chains = true   # web/db shells, download-and-run, /tmp and fileless execution
d2_auth = true             # SSH brute force, suspicious logins, account changes
d3_persistence = true      # cron, systemd, SSH keys, shell profiles, PAM, loader config
d4_priv_esc = true         # setuid files, sudoers/shadow edits, ptrace, LD_PRELOAD
d5_network = true          # connections from flagged chains, new destinations, listeners

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
#    A private chat's id is your own user id; a group's is negative.
# 4. Add "telegram" to channels above, then: sudo hermian notify-test
bot_token = ""                 # e.g. "123456789:AAH..."
chat_id = ""                   # in quotes, e.g. "123456789" or "-1001234567890"
silent_below_critical = true   # only CRITICAL makes a sound
timeout_secs = 10
# message_thread_id = 12345    # topic id, for forum-style supergroups
# Response buttons (Block IP, Disconnect session...) under alerts that offer them.
# Only the Telegram user ids listed here can press them. Your id: message
# @userinfobot. Re-run 'hermian enable' after turning this on (it grants the
# daemon the firewall and kill capabilities these need).
actions = false
allowed_user_ids = []          # numbers, no quotes, e.g. [123456789]
action_ttl_mins = 30           # buttons expire after this

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
# management_cidrs: the addresses YOU manage this host from (home, office,
# VPN, bastion). They're never blocked by a button and stay reachable during
# isolation. Set them before turning on auto_isolate or Telegram actions.
auto_isolate = false    # on CRITICAL, drop all traffic except management_cidrs
management_cidrs = []   # e.g. ["203.0.113.0/24", "198.51.100.7/32"]
auto_isolate_revert_mins = 0  # >0 lifts an automatic isolation after this long
block_duration_hours = 24     # how long a "Block IP" button blocks a source

[allowlist]
# Exceptions. Each needs a reason. Prefer fixing a noisy rule over a broad
# exception. Uncomment a block (all its lines) and edit it; repeat a block
# to add more entries.
#
# Your own SSH sources, so your logins don't alert:
# [[allowlist.ssh_sources]]
# source = "198.51.100.7/32"
# reason = "My home connection"
#
# [[allowlist.process_chains]]
# parent = "deploy-agent"
# child  = "bash"
# user   = "deploy"
# reason = "CI/CD deployment pipeline"
#
# PHP's mail() runs `sh -c sendmail ...`, which looks like a web shell:
# [[allowlist.process_chains]]
# parent = "php-fpm8.2"
# child  = "sh"
# user   = "www-data"
# reason = "PHP mail() via sendmail"
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
    fn telegram_actions_need_the_channel_and_allowed_users() {
        let base = "[notifications]\nchannels = [\"journald\", \"telegram\"]\n\
                    [notifications.telegram]\nbot_token = \"1:x\"\nchat_id = \"-1\"\n";
        let no_users = Config::parse(&format!("{}actions = true\n", base)).unwrap();
        assert!(matches!(
            no_users.validate(),
            Err(ConfigError::TelegramActions)
        ));
        let ok = Config::parse(&format!(
            "{}actions = true\nallowed_user_ids = [42]\n",
            base
        ))
        .unwrap();
        ok.validate().unwrap();
        assert!(ok.notifications.telegram.actions_enabled());
        let no_channel =
            Config::parse("[notifications.telegram]\nactions = true\nallowed_user_ids = [42]\n")
                .unwrap();
        assert!(matches!(
            no_channel.validate(),
            Err(ConfigError::TelegramActions)
        ));
        let block = Config::parse("[response]\nblock_duration_hours = 0\n").unwrap();
        assert!(matches!(block.validate(), Err(ConfigError::BlockHours)));
        let digest = Config::parse("[ssh]\nbrute_digest_hours = 48\n").unwrap();
        assert!(matches!(digest.validate(), Err(ConfigError::DigestHours)));
        // Defaults: off, 24 h blocks, 2 h digest, 10 attempts.
        let d = Config::default();
        assert!(!d.notifications.telegram.actions_enabled());
        assert_eq!(d.response.block_duration_hours, 24);
        assert_eq!(d.ssh.brute_digest_hours, 2);
        assert_eq!(d.ssh.brute_min_attempts, 10);
    }

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
    fn huge_values_are_rejected_not_crashed_on() {
        for (toml_text, want) in [
            ("[baseline]\nduration_hours = 4000000000\n", "baseline"),
            (
                "[notifications]\ndedup_window_secs = 9223372036854775807\n",
                "dedup",
            ),
            ("[ssh]\nfailed_burst_window_secs = 9999999999999\n", "burst"),
            ("[notifications.telegram]\ntimeout_secs = 0\n", "timeout"),
        ] {
            let cfg = Config::parse(toml_text).unwrap();
            let err = cfg.validate().expect_err(want);
            assert!(!err.to_string().is_empty());
        }
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
        for all in ["0.0.0.0/0", "::/0"] {
            let cfg =
                Config::parse(&format!("[response]\nmanagement_cidrs = [\"{}\"]\n", all)).unwrap();
            assert!(
                matches!(cfg.validate(), Err(ConfigError::CatchAllCidr(_))),
                "{}",
                all
            );
        }
        let cfg = Config::parse(
            "[response]\nmanagement_cidrs = [\"203.0.113.0/24\"]\nauto_isolate_revert_mins = 99999\n",
        )
        .unwrap();
        assert!(matches!(cfg.validate(), Err(ConfigError::RevertMins)));
    }

    #[test]
    fn unknown_keys_rejected() {
        assert!(Config::parse("[ssh]\npermit_rooot = true\n").is_err());
    }
}
