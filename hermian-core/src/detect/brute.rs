//! Brute force against existing accounts: a weekly digest, and one alert
//! when a single source is hammering an account that accepts a password.
//!
//! Failed logins for usernames that don't exist (admin, test, oracle...) are
//! the internet's background noise and stay out of both. The digest is only
//! produced when a period saw real attempts against accounts that can log in,
//! lists sources with enough of them to matter, and is only *sent* when one
//! of those accounts accepts a password: otherwise the attempts can't
//! succeed and it's recorded, not sent. The fast alert is for the attack in
//! progress, against an account a password could open.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;

use crate::alert::Finding;
use crate::events::{DetectionId, Severity};
use crate::response::ResponseAction;

/// Most sources tracked per period (rotating IPv6 scanners mustn't grow it).
const MAX_SOURCES: usize = 20_000;
/// Usernames remembered per source.
const MAX_USERS: usize = 8;
/// Accounts counted per period (only existing login accounts get here).
const MAX_ACCOUNTS: usize = 64;
/// Sources listed in the digest's text.
const TOP_LISTED: usize = 5;
/// Sources its one "Block" button covers.
const BLOCK_ALL_MAX: usize = 50;
/// How long "Remind me later" silences the root-password warning.
pub const ROOT_WARNING_SNOOZE_DAYS: u32 = 7;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SourceStats {
    pub failures: u32,
    pub users: BTreeSet<String>,
    pub last: Option<DateTime<Utc>>,
}

/// A finished period: when it started, its sources (busiest first), and the
/// attempts per account (busiest first).
pub struct DigestPeriod {
    pub started: DateTime<Utc>,
    pub sources: Vec<(IpAddr, SourceStats)>,
    pub accounts: Vec<(String, u32)>,
}

/// The digest's running period. Saved by the daemon, so a week survives
/// restarts.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct BruteDigest {
    started: Option<DateTime<Utc>>,
    sources: HashMap<IpAddr, SourceStats>,
    #[serde(default)]
    accounts: HashMap<String, u32>,
}

impl BruteDigest {
    /// One failed login against an existing account.
    pub fn record(&mut self, ip: IpAddr, user: &str, now: DateTime<Utc>) {
        self.started.get_or_insert(now);
        if self.accounts.contains_key(user) || self.accounts.len() < MAX_ACCOUNTS {
            *self.accounts.entry(user.to_string()).or_default() += 1;
        }
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
        let mut sources: Vec<(IpAddr, SourceStats)> = self.sources.drain().collect();
        sources.sort_by(|a, b| b.1.failures.cmp(&a.1.failures).then(a.0.cmp(&b.0)));
        let mut accounts: Vec<(String, u32)> = self.accounts.drain().collect();
        accounts.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        Some(DigestPeriod {
            started,
            sources,
            accounts,
        })
    }

    pub fn len(&self) -> usize {
        self.sources.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }
}

/// Whether a password could open `user`'s account, from `sshd -T`
/// (`(root, others)`; `None` until sshd answered, which counts as yes).
pub fn password_could_work(user: &str, password_guessable: Option<(bool, bool)>) -> bool {
    match password_guessable {
        None => true,
        Some((root, others)) => {
            if user == "root" {
                root
            } else {
                others
            }
        }
    }
}

/// "1 240" style thousands, for counts in alert text.
fn count(n: u32) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(' ');
        }
        out.push(c);
    }
    out
}

/// Build the digest alert, or nothing if no source reached `min_attempts`.
pub fn digest_finding(
    period: DigestPeriod,
    min_attempts: u32,
    period_days: u32,
    root_password_login: bool,
    password_guessable: Option<(bool, bool)>,
) -> Option<Finding> {
    let listed: Vec<(IpAddr, SourceStats)> = period
        .sources
        .into_iter()
        .filter(|(_, s)| s.failures >= min_attempts)
        .collect();
    if listed.is_empty() {
        return None;
    }
    let total: u32 = listed.iter().map(|(_, s)| s.failures).sum();
    let mut tried: BTreeSet<&str> = BTreeSet::new();
    for (_, s) in &listed {
        tried.extend(s.users.iter().map(String::as_str));
    }
    let root_targeted = tried.contains("root");
    // Sent only if a password could open one of the accounts tried.
    let guessable: Vec<&str> = tried
        .iter()
        .copied()
        .filter(|a| password_could_work(a, password_guessable))
        .collect();
    let hopeless = guessable.is_empty();
    let per_account: Vec<String> = period
        .accounts
        .iter()
        .filter(|(a, _)| tried.contains(a.as_str()))
        .map(|(a, n)| {
            format!(
                "{} ({} tries{})",
                a,
                count(*n),
                if password_could_work(a, password_guessable) {
                    ", accepts a password"
                } else {
                    ", keys only"
                }
            )
        })
        .collect();
    let top: Vec<String> = listed
        .iter()
        .take(TOP_LISTED)
        .map(|(ip, s)| format!("{} ({})", ip, count(s.failures)))
        .collect();
    let mut why = String::from(if hopeless {
        "None of the accounts tried accepts a password here (sshd only takes keys for them), \
         so these attempts can't succeed. Recorded for the volume and the sources, not sent."
    } else {
        "These attempts named accounts that exist on this host and accept a password, which \
         is different from the constant scanning for 'admin' or 'test'. A strong password or \
         key-only login stops them; blocking the sources stops the noise."
    });
    // Only worth saying while someone is actually trying.
    let warn_root = root_password_login && root_targeted;
    if warn_root {
        why.push_str(
            " Root can log in over SSH with a password on this host, so a single guessed \
             password is enough to log in as root.",
        );
    }
    let mut f = Finding::new(
        DetectionId::D2,
        if hopeless {
            Severity::Low
        } else {
            Severity::High
        },
        "SSH brute force against existing accounts",
        &format!("d2|brute-digest|{}", period.started.timestamp()),
    )
    .what(format!(
        "{} failed logins against existing accounts over the last {} day{}, from {} \
         source{}.",
        count(total),
        period_days,
        if period_days == 1 { "" } else { "s" },
        count(listed.len() as u32),
        if listed.len() == 1 { "" } else { "s" },
    ))
    .fact("Accounts", per_account.join("; "))
    .fact("Top sources", top.join("; "))
    .why(why);
    if warn_root {
        f = f.action(
            "Disable root password login: set 'PermitRootLogin prohibit-password' in \
             sshd_config (keys still work), then reload sshd.",
        );
    }
    f = if hopeless {
        f.action("Nothing to do. Block the sources if the noise bothers you.")
    } else {
        f.actions([
            "Switch the accounts listed to keys (PasswordAuthentication no), or make sure \
             their passwords are long and unique.",
            "Block the sources if they keep coming back.",
        ])
    };
    // One button: blocking them all. One per source made a wall of buttons.
    f = f.offer(ResponseAction::Block {
        sources: listed
            .iter()
            .take(BLOCK_ALL_MAX)
            .map(|(ip, _)| *ip)
            .collect(),
    });
    Some(f)
}

/// Signature prefix of the fast alert, one per source.
pub const LIVE_SIG: &str = "d2|brute-live|";

/// A source hammering accounts that accept a password, right now.
pub fn live_finding(ip: IpAddr, users: &[String], failures: usize, window_secs: u64) -> Finding {
    Finding::new(
        DetectionId::D2,
        Severity::High,
        "SSH brute force in progress",
        &format!("{}{}", LIVE_SIG, ip),
    )
    .what(format!(
        "{} failed to log in {} times in {} seconds, against {}: an account that accepts a \
         password.",
        ip,
        failures,
        window_secs,
        users.join(", ")
    ))
    .fact("Source", ip.to_string())
    .fact("Accounts", users.join(", "))
    .fact("Failures", format!("{} in {} s", failures, window_secs))
    .why(
        "One address guessing passwords this fast, against an account a password can open. \
         Hermian pages separately if one of those attempts logs in.",
    )
    .actions([
        "Block the source.",
        "Switch the account to keys, or make sure its password is long and unique.",
    ])
    .offer(ResponseAction::Block { sources: vec![ip] })
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
            let cfg = Config::default();
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
                method: AuthMethod::Unknown,
                port: Some(50_000),
                key: None,
            })
        }

        /// `n` failures, `gap` seconds apart; returns every alert raised.
        fn hammer_at(
            e: &mut Engine,
            t: DateTime<Utc>,
            user: &str,
            ip: &str,
            n: i64,
            gap: i64,
        ) -> Vec<Alert> {
            let mut out = Vec::new();
            for i in 0..n {
                let at = t + Duration::seconds(i * gap);
                out.extend(e.process_at(auth(at, AuthResult::Failure, user, ip), at));
            }
            out
        }

        /// Slow enough never to trip the fast alert.
        fn hammer(e: &mut Engine, t: DateTime<Utc>, user: &str, ip: &str, n: i64) {
            hammer_at(e, t, user, ip, n, 30);
        }

        fn digest(alerts: &[Alert]) -> Option<&Alert> {
            alerts
                .iter()
                .find(|a| a.title == "SSH brute force against existing accounts")
        }

        fn week() -> Duration {
            Duration::days(7) + Duration::minutes(1)
        }

        #[test]
        fn the_digest_is_weekly_and_counts_per_account() {
            let mut e = engine();
            let t = Utc::now();
            hammer(&mut e, t, "admin", "198.51.100.1", 50); // doesn't exist
            hammer(&mut e, t, "www-data", "198.51.100.2", 50); // no login shell
            hammer(&mut e, t, "deploy", "198.51.100.3", 12);
            hammer(&mut e, t, "root", "198.51.100.4", 30);
            assert!(
                digest(&e.tick(t + Duration::hours(3))).is_none(),
                "not after hours"
            );
            let a = e.tick(t + week());
            let d = digest(&a).unwrap_or_else(|| panic!("{:?}", a));
            assert!(d.what.contains("over the last 7 days"), "{}", d.what);
            let fact = |l: &str| d.facts.iter().find(|f| f.label == l).unwrap().value.clone();
            let accounts = fact("Accounts");
            assert!(accounts.starts_with("root (30 tries"), "{}", accounts);
            assert!(accounts.contains("deploy (12 tries"), "{}", accounts);
            assert!(!accounts.contains("admin") && !accounts.contains("www-data"));
            // One button: block them all.
            let labels: Vec<String> = d.offers.iter().map(|o| o.label()).collect();
            assert_eq!(labels, vec!["Block all (2)"]);
        }

        #[test]
        fn the_week_survives_a_restart() {
            let mut e = engine();
            let t = Utc::now();
            hammer(&mut e, t, "root", "198.51.100.7", 15);
            let saved = serde_json::to_string(&e.brute).unwrap();
            let mut restarted = engine();
            restarted.brute = serde_json::from_str(&saved).unwrap();
            assert!(digest(&restarted.tick(t + week())).is_some());
        }

        #[test]
        fn root_warning_rides_along_only_when_root_is_tried() {
            let mut e = engine();
            e.set_sshd_auth(true, true, false);
            let t = Utc::now();
            hammer(&mut e, t, "root", "198.51.100.7", 15);
            assert!(digest(&e.tick(t + week()))
                .unwrap()
                .why
                .contains("Root can log in"));
            let t2 = t + Duration::days(8);
            hammer(&mut e, t2, "deploy", "198.51.100.7", 15);
            let a = e.tick(t2 + week());
            assert!(!digest(&a).unwrap().why.contains("Root can log in"));
        }

        #[test]
        fn ignored_sources_drop_out_until_the_time_is_up() {
            let mut e = engine();
            let t = Utc::now();
            let ip: IpAddr = "198.51.100.7".parse().unwrap();
            e.ignore_sources(&[ip], t + Duration::days(8));
            hammer(&mut e, t, "root", "198.51.100.7", 30);
            assert!(digest(&e.tick(t + week())).is_none());
            let t2 = t + Duration::days(9);
            hammer(&mut e, t2, "root", "198.51.100.7", 30);
            assert!(digest(&e.tick(t2 + week())).is_some());
        }

        #[test]
        fn hammering_a_password_account_pages_at_once() {
            let mut e = engine();
            e.set_sshd_auth(false, true, false); // deploy accepts passwords
            let t = Utc::now();
            let a = hammer_at(&mut e, t, "deploy", "198.51.100.9", 20, 2);
            let live: Vec<&Alert> = a
                .iter()
                .filter(|a| a.title == "SSH brute force in progress")
                .collect();
            assert_eq!(live.len(), 1, "once, at the threshold: {:?}", a);
            assert_eq!(live[0].severity, Severity::High);
            assert!(
                live[0].what.contains("20 times in 60 seconds"),
                "{}",
                live[0].what
            );
            let labels: Vec<String> = live[0].offers.iter().map(|o| o.label()).collect();
            assert_eq!(labels, vec!["Block 198.51.100.9"]);
            // Slower than the threshold: nothing.
            let slow = hammer_at(&mut e, t, "deploy", "198.51.100.10", 20, 5);
            assert!(!slow
                .iter()
                .any(|a| a.title == "SSH brute force in progress"));
        }

        #[test]
        fn hammering_a_keys_only_account_doesnt_page() {
            let mut e = engine();
            e.set_sshd_auth(false, false, false); // keys only
            let t = Utc::now();
            let a = hammer_at(&mut e, t, "root", "198.51.100.9", 40, 1);
            assert!(!a.iter().any(|a| a.title == "SSH brute force in progress"));
            let a = hammer_at(&mut e, t, "nobody-here", "198.51.100.8", 40, 1);
            assert!(!a.iter().any(|a| a.title == "SSH brute force in progress"));
        }

        #[test]
        fn suspicious_logins_offer_disconnect_buttons() {
            let mut e = engine();
            let t = Utc::now();
            hammer_at(&mut e, t, "deploy", "198.51.100.7", 6, 1);
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
        assert!(d.take_if_due(t, Duration::days(7)).is_none());
        d.record(ip("198.51.100.7"), "root", t);
        assert!(d
            .take_if_due(t + Duration::days(6), Duration::days(7))
            .is_none());
        let p = d
            .take_if_due(t + Duration::days(7), Duration::days(7))
            .unwrap();
        assert_eq!(p.started, t);
        assert_eq!(p.sources.len(), 1);
        assert_eq!(p.accounts, vec![("root".to_string(), 1)]);
        assert!(d
            .take_if_due(t + Duration::days(20), Duration::days(7))
            .is_none());
    }

    #[test]
    fn quiet_sources_are_left_out_and_nothing_means_no_alert() {
        let t = Utc::now();
        let mut d = BruteDigest::default();
        for _ in 0..3 {
            d.record(ip("198.51.100.7"), "deploy", t);
        }
        let p = d
            .take_if_due(t + Duration::days(7), Duration::days(7))
            .unwrap();
        assert!(digest_finding(p, 10, 7, true, None).is_none());
    }

    /// On a key-only host the same attempts are recorded, not sent: they
    /// can't succeed. Unknown, or a Match block, keeps the page.
    #[test]
    fn attempts_that_cant_succeed_are_not_sent() {
        let period = |users: &[&str]| {
            let t = Utc::now();
            let mut d = BruteDigest::default();
            for u in users {
                for _ in 0..12 {
                    d.record(ip("198.51.100.7"), u, t);
                }
            }
            d.take_if_due(t + Duration::days(8), Duration::days(7))
                .unwrap()
        };
        let sev = |users: &[&str], guessable: Option<(bool, bool)>| {
            digest_finding(period(users), 10, 7, false, guessable)
                .unwrap()
                .severity
        };
        assert_eq!(
            sev(&["root", "deploy"], Some((false, false))),
            Severity::Low
        );
        assert_eq!(sev(&["root"], Some((false, true))), Severity::Low);
        assert_eq!(
            sev(&["root", "deploy"], Some((false, true))),
            Severity::High
        );
        assert_eq!(sev(&["root"], None), Severity::High);
        let f = digest_finding(period(&["deploy"]), 10, 7, false, Some((false, false))).unwrap();
        assert!(f.why.contains("can't succeed"), "{}", f.why);
        let accounts = &f
            .facts
            .iter()
            .find(|x| x.label == "Accounts")
            .unwrap()
            .value;
        assert!(accounts.contains("keys only"), "{}", accounts);
    }

    #[test]
    fn big_counts_are_readable() {
        assert_eq!(count(7), "7");
        assert_eq!(count(1240), "1 240");
        assert_eq!(count(1_234_567), "1 234 567");
    }
}
