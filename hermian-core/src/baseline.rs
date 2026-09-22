use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Baseline {
    pub enabled: bool,
    pub started_at: Option<DateTime<Utc>>,
    pub duration_hours: u32,
    pub complete: bool,
    pub known_ssh_sources: HashSet<IpAddr>,
    pub known_dests: HashSet<IpAddr>,
    pub known_connectors: HashSet<String>,
    /// Sources that have successfully logged in as root. Unlike the sets above
    /// this is recorded for the lifetime of the install, not just during the
    /// learning window: it answers "has this happened before", not "is normal".
    #[serde(default)]
    pub root_sources: HashSet<IpAddr>,
    /// How `known_connectors` keys were built. Baselines written before the
    /// scheme existed (0) keyed on the chain's root, which was nearly always
    /// systemd, so they're relearned rather than trusted.
    #[serde(default)]
    pub connector_scheme: u8,
    /// While set, connectors are being relearned after a scheme change and
    /// connector novelty isn't judged.
    #[serde(default)]
    pub connectors_relearn_until: Option<DateTime<Utc>>,
}

/// Current `known_connectors` key scheme: the connecting process's own exe.
pub const CONNECTOR_SCHEME: u8 = 1;

impl Default for Baseline {
    fn default() -> Self {
        Baseline {
            enabled: false,
            started_at: None,
            duration_hours: 24,
            complete: true,
            known_ssh_sources: HashSet::new(),
            known_dests: HashSet::new(),
            known_connectors: HashSet::new(),
            root_sources: HashSet::new(),
            connector_scheme: 0,
            connectors_relearn_until: None,
        }
    }
}

impl Baseline {
    pub fn new(enabled: bool, duration_hours: u32, now: DateTime<Utc>) -> Self {
        Baseline {
            enabled,
            started_at: if enabled { Some(now) } else { None },
            duration_hours,
            complete: !enabled,
            known_ssh_sources: HashSet::new(),
            known_dests: HashSet::new(),
            known_connectors: HashSet::new(),
            root_sources: HashSet::new(),
            connector_scheme: CONNECTOR_SCHEME,
            connectors_relearn_until: None,
        }
    }

    /// Drop connector keys built with an older scheme. A finished baseline
    /// relearns connectors for another `duration_hours` instead of flagging
    /// every program as new.
    pub fn migrate_connectors(&mut self, now: DateTime<Utc>) {
        if self.connector_scheme >= CONNECTOR_SCHEME {
            return;
        }
        self.known_connectors.clear();
        self.connector_scheme = CONNECTOR_SCHEME;
        if self.enabled && self.complete {
            self.connectors_relearn_until =
                Some(now + Duration::hours(self.duration_hours.min(24 * 365) as i64));
        }
    }

    fn relearning_connectors(&self, now: DateTime<Utc>) -> bool {
        self.connectors_relearn_until
            .map(|until| now < until)
            .unwrap_or(false)
    }

    /// Record a successful root login; returns true if the source was new.
    pub fn observe_root_source(&mut self, ip: IpAddr) -> bool {
        self.root_sources.insert(ip)
    }

    pub fn root_source_is_known(&self, ip: IpAddr) -> bool {
        self.root_sources.contains(&ip)
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// True once the baseline has finished learning and novelty judgements are
    /// meaningful. A disabled baseline never learned anything, so treating all
    /// traffic as "novel" would be pure noise; it returns `false` here.
    pub fn can_judge_novelty(&self) -> bool {
        self.enabled && self.complete
    }

    pub fn remaining(&self, now: DateTime<Utc>) -> Option<Duration> {
        if self.complete {
            return None;
        }
        let started = self.started_at?;
        let deadline = started + Duration::hours(self.duration_hours as i64);
        let rem = deadline - now;
        if rem.num_seconds() > 0 {
            Some(rem)
        } else {
            None
        }
    }

    pub fn check_completion(&mut self, now: DateTime<Utc>) -> bool {
        if self.complete {
            return false;
        }
        if self.remaining(now).is_none() {
            self.complete = true;
            return true;
        }
        false
    }

    pub fn observe_ssh_source(&mut self, ip: IpAddr, now: DateTime<Utc>) {
        self.check_completion(now);
        if !self.complete {
            self.known_ssh_sources.insert(ip);
        }
    }

    pub fn observe_dest(&mut self, ip: IpAddr, now: DateTime<Utc>) {
        self.check_completion(now);
        if !self.complete {
            self.known_dests.insert(ip);
        }
    }

    pub fn observe_connector(&mut self, key: &str, now: DateTime<Utc>) {
        self.check_completion(now);
        if !self.complete || self.relearning_connectors(now) {
            self.known_connectors.insert(key.to_string());
        }
    }

    /// Whether connector novelty can be judged at `now`.
    pub fn can_judge_connectors(&self, now: DateTime<Utc>) -> bool {
        self.can_judge_novelty() && !self.relearning_connectors(now)
    }

    pub fn ssh_source_is_known(&self, ip: IpAddr) -> bool {
        self.known_ssh_sources.contains(&ip)
    }

    pub fn dest_is_known(&self, ip: IpAddr) -> bool {
        self.known_dests.contains(&ip)
    }

    pub fn connector_is_known(&self, key: &str) -> bool {
        self.known_connectors.contains(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> DateTime<Utc> {
        Utc::now()
    }

    #[test]
    fn disabled_baseline_is_complete_immediately() {
        let b = Baseline::new(false, 24, now());
        assert!(b.is_complete());
    }

    #[test]
    fn enabled_baseline_learns_and_completes() {
        let t0 = now();
        let mut b = Baseline::new(true, 24, t0);
        assert!(!b.is_complete());
        let ip: IpAddr = "192.0.2.10".parse().unwrap();
        b.observe_ssh_source(ip, t0);
        assert!(b.ssh_source_is_known(ip));
        b.observe_dest(ip, t0);
        b.observe_connector("nginx|33", t0);
        let later = t0 + Duration::hours(25);
        assert!(b.check_completion(later));
        assert!(b.is_complete());
        let ip2: IpAddr = "192.0.2.11".parse().unwrap();
        assert!(!b.ssh_source_is_known(ip2));
    }

    #[test]
    fn legacy_connector_keys_are_relearned() {
        let t0 = now();
        // A pre-scheme baseline.json: finished, keyed on "systemd|uid".
        let mut b: Baseline = serde_json::from_str(
            r#"{"enabled":true,"complete":true,"duration_hours":24,
                "known_connectors":["/usr/lib/systemd/systemd|0"]}"#,
        )
        .unwrap();
        assert_eq!(b.connector_scheme, 0);
        b.migrate_connectors(t0);
        assert_eq!(b.connector_scheme, CONNECTOR_SCHEME);
        assert!(b.known_connectors.is_empty());
        assert!(!b.can_judge_connectors(t0));
        b.observe_connector("/usr/sbin/nginx|33", t0);
        let later = t0 + Duration::hours(25);
        assert!(b.can_judge_connectors(later));
        assert!(b.connector_is_known("/usr/sbin/nginx|33"));
        b.observe_connector("/tmp/x|33", later);
        assert!(!b.connector_is_known("/tmp/x|33"));
        // Idempotent for current-scheme baselines.
        b.migrate_connectors(later);
        assert!(b.connector_is_known("/usr/sbin/nginx|33"));
    }
}
