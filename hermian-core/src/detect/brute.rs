//! Brute force against existing accounts, summed up in a periodic digest.
//!
//! Failed logins for usernames that don't exist (admin, test, oracle...) are
//! the internet's background noise and stay out of it. A digest is only
//! produced when a period saw real attempts against accounts that can log in,
//! and only lists sources with enough of them to matter.

use chrono::{DateTime, Duration, Utc};
use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;

use crate::alert::Finding;
use crate::events::{DetectionId, Severity};
use crate::response::ResponseAction;

/// Most sources tracked per period (rotating IPv6 scanners mustn't grow it).
const MAX_SOURCES: usize = 20_000;
/// Usernames remembered per source.
const MAX_USERS: usize = 8;
/// Sources listed, and offered a "Block" button each.
const TOP_LISTED: usize = 5;
/// Sources a "Block all" covers.
const BLOCK_ALL_MAX: usize = 50;
/// How long "Remind me later" silences the root-password warning.
pub const ROOT_WARNING_SNOOZE_DAYS: u32 = 7;

#[derive(Debug, Clone, Default)]
pub struct SourceStats {
    pub failures: u32,
    pub users: BTreeSet<String>,
    pub last: Option<DateTime<Utc>>,
}

/// A finished period: when it started, and its sources, busiest first.
pub type DigestPeriod = (DateTime<Utc>, Vec<(IpAddr, SourceStats)>);

#[derive(Debug, Default)]
pub struct BruteDigest {
    started: Option<DateTime<Utc>>,
    sources: HashMap<IpAddr, SourceStats>,
}

impl BruteDigest {
    /// One failed login against an existing account.
    pub fn record(&mut self, ip: IpAddr, user: &str, now: DateTime<Utc>) {
        self.started.get_or_insert(now);
        if !self.sources.contains_key(&ip) && self.sources.len() >= MAX_SOURCES {
            return;
        }
        let s = self.sources.entry(ip).or_default();
        s.failures = s.failures.saturating_add(1);
        s.last = Some(now);
        if s.users.len() < MAX_USERS {
            s.users.insert(user.to_string());
        }
    }

    /// Forget a source (it was ignored or blocked).
    pub fn forget(&mut self, ip: &IpAddr) {
        self.sources.remove(ip);
    }

    /// The period's data, if `period` has passed since its first failure.
    /// Resets for the next period either way.
    pub fn take_if_due(&mut self, now: DateTime<Utc>, period: Duration) -> Option<DigestPeriod> {
        let started = self.started?;
        if now - started < period {
            return None;
        }
        self.started = None;
        let mut all: Vec<(IpAddr, SourceStats)> = self.sources.drain().collect();
        all.sort_by(|a, b| b.1.failures.cmp(&a.1.failures).then(a.0.cmp(&b.0)));
        Some((started, all))
    }

    pub fn len(&self) -> usize {
        self.sources.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }
}

/// Build the digest alert, or nothing if no source reached `min_attempts`.
pub fn digest_finding(
    started: DateTime<Utc>,
    sources: Vec<(IpAddr, SourceStats)>,
    min_attempts: u32,
    period_hours: u32,
    root_password_login: bool,
) -> Option<Finding> {
    let listed: Vec<(IpAddr, SourceStats)> = sources
        .into_iter()
        .filter(|(_, s)| s.failures >= min_attempts)
        .collect();
    if listed.is_empty() {
        return None;
    }
    let total: u32 = listed.iter().map(|(_, s)| s.failures).sum();
    let mut accounts: BTreeSet<&str> = BTreeSet::new();
    for (_, s) in &listed {
        accounts.extend(s.users.iter().map(String::as_str));
    }
    let root_targeted = accounts.contains("root");
    let top: Vec<String> = listed
        .iter()
        .take(TOP_LISTED)
        .map(|(ip, s)| {
            let users: Vec<&str> = s.users.iter().map(String::as_str).collect();
            format!("{} ({} tries: {})", ip, s.failures, users.join(", "))
        })
        .collect();
    let mut why = String::from(
        "These attempts named accounts that exist on this host and can log in, which is \
         different from the constant scanning for 'admin' or 'test'. A strong password or \
         key-only login stops them; blocking the sources stops the noise.",
    );
    // Only worth saying while someone is actually trying.
    let warn_root = root_password_login;
    if warn_root {
        why.push_str(
            " Root can log in over SSH with a password on this host, so a guessed root \
             password is a full compromise.",
        );
    }
    let mut f = Finding::new(
        DetectionId::D2,
        Severity::High,
        "SSH brute force against existing accounts",
        &format!("d2|brute-digest|{}", started.timestamp()),
    )
    .what(format!(
        "{} failed logins from {} source{} against existing accounts in the last {} hour{} \
         (since {} UTC).",
        total,
        listed.len(),
        if listed.len() == 1 { "" } else { "s" },
        period_hours,
        if period_hours == 1 { "" } else { "s" },
        started.format("%H:%M"),
    ))
    .fact("Top sources", top.join("; "))
    .fact(
        "Accounts",
        accounts.iter().copied().collect::<Vec<_>>().join(", "),
    )
    .fact(
        "Root login",
        if warn_root {
            if root_targeted {
                "ENABLED, and root is being tried"
            } else {
                "ENABLED"
            }
        } else {
            ""
        },
    )
    .why(why);
    if warn_root {
        f = f.action(
            "Disable root password login: set 'PermitRootLogin prohibit-password' in \
             sshd_config (keys still work), then reload sshd.",
        );
    }
    f = f.actions([
        "Check that the accounts listed use keys or strong passwords.",
        "Block the sources if they keep coming back.",
    ]);
    for (ip, _) in listed.iter().take(TOP_LISTED) {
        f = f.offer(ResponseAction::Block { sources: vec![*ip] });
    }
    if listed.len() > 1 {
        f = f.offer(ResponseAction::Block {
            sources: listed
                .iter()
                .take(BLOCK_ALL_MAX)
                .map(|(ip, _)| *ip)
                .collect(),
        });
    }
    f = f.offer(ResponseAction::Ignore {
        sources: listed.iter().map(|(ip, _)| *ip).collect(),
        hours: period_hours,
    });
    if warn_root {
        f = f.offer(ResponseAction::SnoozeRootPasswordWarning {
            days: ROOT_WARNING_SNOOZE_DAYS,
        });
    }
    Some(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    mod engine_level {
        use crate::alert::Alert;
        use crate::baseline::Baseline;
        use crate::config::Config;
        use crate::engine::Engine;
        use crate::events::*;
        use crate::response::ResponseAction;
        use chrono::{DateTime, Duration, Utc};
        use std::net::IpAddr;

        const PASSWD: &str = "root:x:0:0:root:/root:/bin/bash\n\
                              deploy:x:1000:1000::/home/deploy:/bin/bash\n\
                              www-data:x:33:33::/var/www:/usr/sbin/nologin\n";

        fn engine() -> Engine {
            let mut cfg = Config::default();
            cfg.ssh.off_hours_start = 0;
            cfg.ssh.off_hours_end = 0;
            let allow = cfg.allowlist.clone();
            let mut b = Baseline::new(true, 24, Utc::now());
            b.complete = true;
            let mut e = Engine::new(cfg, allow, b, "t".into());
            e.seed_file_snapshot("/etc/passwd", PASSWD.into());
            e
        }

        fn auth(t: DateTime<Utc>, result: AuthResult, user: &str, ip: &str) -> Event {
            Event::Auth(AuthEvent {
                ts: t,
                result,
                user: user.into(),
                rhost: Some(ip.parse().unwrap()),
                service: "sshd".into(),
                tty: "ssh".into(),
                port: Some(50_000),
            })
        }

        fn hammer(e: &mut Engine, t: DateTime<Utc>, user: &str, ip: &str, n: i64) {
            for i in 0..n {
                let ev = auth(t + Duration::seconds(i), AuthResult::Failure, user, ip);
                e.process_at(ev, t + Duration::seconds(i));
            }
        }

        fn digest(alerts: &[Alert]) -> Option<&Alert> {
            alerts
                .iter()
                .find(|a| a.title == "SSH brute force against existing accounts")
        }

        #[test]
        fn only_existing_login_accounts_count() {
            let mut e = engine();
            let t = Utc::now();
            hammer(&mut e, t, "admin", "198.51.100.1", 50); // doesn't exist
            hammer(&mut e, t, "www-data", "198.51.100.2", 50); // no login shell
            hammer(&mut e, t, "deploy", "198.51.100.3", 12);
            let a = e.tick(t + Duration::hours(2) + Duration::minutes(1));
            let d = digest(&a).unwrap_or_else(|| panic!("{:?}", a));
            let top = &d
                .facts
                .iter()
                .find(|f| f.label == "Top sources")
                .unwrap()
                .value;
            assert!(top.contains("198.51.100.3"), "{}", top);
            assert!(!top.contains("198.51.100.1") && !top.contains("198.51.100.2"));
        }

        #[test]
        fn no_attacks_no_digest_and_root_warning_rides_along() {
            let mut e = engine();
            e.set_root_password_login(true);
            let t = Utc::now();
            assert!(digest(&e.tick(t + Duration::hours(3))).is_none());
            hammer(&mut e, t, "root", "198.51.100.7", 15);
            let a = e.tick(t + Duration::hours(2) + Duration::minutes(1));
            let d = digest(&a).unwrap();
            assert!(d.why.contains("Root can log in"));
            // Snoozed: the next digest has no warning.
            e.snooze_root_warning(t + Duration::days(7));
            let t2 = t + Duration::hours(3);
            hammer(&mut e, t2, "root", "198.51.100.7", 15);
            let a = e.tick(t2 + Duration::hours(2) + Duration::minutes(1));
            assert!(!digest(&a).unwrap().why.contains("Root can log in"));
        }

        #[test]
        fn ignored_sources_drop_out_until_the_time_is_up() {
            let mut e = engine();
            let t = Utc::now();
            let ip: IpAddr = "198.51.100.7".parse().unwrap();
            e.ignore_sources(&[ip], t + Duration::hours(2));
            hammer(&mut e, t, "root", "198.51.100.7", 30);
            assert!(digest(&e.tick(t + Duration::hours(2) + Duration::minutes(1))).is_none());
            let t2 = t + Duration::hours(3);
            hammer(&mut e, t2, "root", "198.51.100.7", 30);
            assert!(digest(&e.tick(t2 + Duration::hours(2) + Duration::minutes(1))).is_some());
        }

        #[test]
        fn suspicious_logins_offer_disconnect_buttons() {
            let mut e = engine();
            let t = Utc::now();
            hammer(&mut e, t, "deploy", "198.51.100.7", 6);
            let a = e.process_at(
                auth(
                    t + Duration::seconds(10),
                    AuthResult::Success,
                    "deploy",
                    "198.51.100.7",
                ),
                t + Duration::seconds(10),
            );
            let hit = a
                .iter()
                .find(|a| a.title == "SSH login after a failed-auth burst")
                .unwrap_or_else(|| panic!("{:?}", a));
            let labels: Vec<String> = hit.offers.iter().map(|o| o.label()).collect();
            assert_eq!(
                labels,
                vec!["Ignore", "Disconnect session", "Disconnect and block"]
            );
            assert!(matches!(
                hit.offers[2],
                ResponseAction::Disconnect {
                    port: Some(50_000),
                    block: true,
                    ..
                }
            ));
        }
    }

    #[test]
    fn digest_waits_for_the_period_and_resets() {
        let mut d = BruteDigest::default();
        let t = Utc::now();
        assert!(d.take_if_due(t, Duration::hours(2)).is_none());
        d.record(ip("198.51.100.7"), "root", t);
        assert!(d
            .take_if_due(t + Duration::minutes(119), Duration::hours(2))
            .is_none());
        let (started, rows) = d
            .take_if_due(t + Duration::hours(2), Duration::hours(2))
            .unwrap();
        assert_eq!(started, t);
        assert_eq!(rows.len(), 1);
        assert!(d
            .take_if_due(t + Duration::hours(5), Duration::hours(2))
            .is_none());
    }

    #[test]
    fn quiet_sources_are_left_out_and_nothing_means_no_alert() {
        let t = Utc::now();
        let mut d = BruteDigest::default();
        for _ in 0..3 {
            d.record(ip("198.51.100.7"), "deploy", t);
        }
        let (s, rows) = d
            .take_if_due(t + Duration::hours(2), Duration::hours(2))
            .unwrap();
        assert!(digest_finding(s, rows, 10, 2, true).is_none());
    }

    #[test]
    fn digest_lists_sources_offers_buttons_and_warns_about_root() {
        let t = Utc::now();
        let mut d = BruteDigest::default();
        for _ in 0..30 {
            d.record(ip("198.51.100.7"), "root", t);
        }
        for _ in 0..12 {
            d.record(ip("203.0.113.9"), "deploy", t);
        }
        let (s, rows) = d
            .take_if_due(t + Duration::hours(2), Duration::hours(2))
            .unwrap();
        let f = digest_finding(s, rows, 10, 2, true).unwrap();
        assert_eq!(f.severity, Severity::High);
        let top = &f
            .facts
            .iter()
            .find(|x| x.label == "Top sources")
            .unwrap()
            .value;
        assert!(top.starts_with("198.51.100.7 (30 tries: root)"), "{}", top);
        assert!(f.why.contains("Root can log in"));
        let labels: Vec<String> = f.offers.iter().map(|o| o.label()).collect();
        assert_eq!(
            labels,
            vec![
                "Block 198.51.100.7",
                "Block 203.0.113.9",
                "Block all (2)",
                "Ignore 2h",
                "Remind me in 7 days"
            ]
        );
        // Without the root-password setting, no warning and no snooze button.
        let mut d = BruteDigest::default();
        for _ in 0..30 {
            d.record(ip("198.51.100.7"), "root", t);
        }
        let (s, rows) = d
            .take_if_due(t + Duration::hours(2), Duration::hours(2))
            .unwrap();
        let f = digest_finding(s, rows, 10, 2, false).unwrap();
        assert!(!f.why.contains("Root can log in"));
        assert!(!f
            .offers
            .iter()
            .any(|o| matches!(o, ResponseAction::SnoozeRootPasswordWarning { .. })));
    }
}
