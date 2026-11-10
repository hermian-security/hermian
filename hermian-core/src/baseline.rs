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
    #[serde(skip)]
    pub known_dest_nets: HashSet<IpAddr>,
    pub known_connectors: HashSet<String>,
    #[serde(default)]
    pub root_sources: HashSet<IpAddr>,
    #[serde(default)]
    pub connector_scheme: u8,
    #[serde(default)]
    pub connectors_relearn_until: Option<DateTime<Utc>>,
    #[serde(default)]
    pub known_keys: HashSet<String>,
    #[serde(default)]
    pub reported_sshd_key_sources: HashSet<String>,
}

pub const CONNECTOR_SCHEME: u8 = 1;

pub const MAX_LEARNED: usize = 50_000;

pub fn source_net(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4((u32::from(v4) & 0xffff_0000).into()),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => source_net(IpAddr::V4(v4)),
            None => IpAddr::V6((u128::from(v6) & (u128::MAX << 96)).into()),
        },
    }
}

pub fn dest_net(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4((u32::from(v4) & 0xffff_ff00).into()),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => dest_net(IpAddr::V4(v4)),
            None => IpAddr::V6((u128::from(v6) & (u128::MAX << 64)).into()),
        },
    }
}

impl Default for Baseline {
    fn default() -> Self {
        Baseline {
            enabled: false,
            started_at: None,
            duration_hours: 24,
            complete: true,
            known_ssh_sources: HashSet::new(),
            known_dests: HashSet::new(),
            known_dest_nets: HashSet::new(),
            known_connectors: HashSet::new(),
            root_sources: HashSet::new(),
            connector_scheme: 0,
            connectors_relearn_until: None,
            known_keys: HashSet::new(),
            reported_sshd_key_sources: HashSet::new(),
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
            known_dest_nets: HashSet::new(),
            known_connectors: HashSet::new(),
            root_sources: HashSet::new(),
            connector_scheme: CONNECTOR_SCHEME,
            connectors_relearn_until: None,
            known_keys: HashSet::new(),
            reported_sshd_key_sources: HashSet::new(),
        }
    }

    pub fn judging_from(now: DateTime<Utc>, duration_hours: u32) -> Self {
        let mut b = Baseline::new(true, duration_hours, now);
        b.complete = true;
        b
    }

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

    pub fn observe_root_source(&mut self, ip: IpAddr) -> bool {
        if self.root_sources.len() >= MAX_LEARNED {
            return false;
        }
        self.root_sources.insert(ip)
    }

    pub fn root_source_is_known(&self, ip: IpAddr) -> bool {
        self.root_sources.contains(&ip)
    }

    pub fn root_net_is_known(&self, ip: IpAddr) -> bool {
        let net = source_net(ip);
        self.root_sources.iter().any(|s| source_net(*s) == net)
    }

    pub fn ssh_net_is_known(&self, ip: IpAddr) -> bool {
        let net = source_net(ip);
        self.known_ssh_sources.iter().any(|s| source_net(*s) == net)
    }

    pub fn observe_key(&mut self, user: &str, fingerprint: &str) {
        if self.known_keys.len() < MAX_LEARNED {
            self.known_keys.insert(format!("{} {}", user, fingerprint));
        }
    }

    pub fn observe_sshd_key_source(&mut self, setting: &str, path: &str) -> bool {
        if self.reported_sshd_key_sources.len() >= MAX_LEARNED {
            return false;
        }
        self.reported_sshd_key_sources
            .insert(format!("{} {}", setting, path))
    }

    pub fn key_is_known(&self, user: &str, fingerprint: &str) -> bool {
        self.known_keys
            .contains(&format!("{} {}", user, fingerprint))
    }

    pub fn can_judge_novelty(&self) -> bool {
        self.enabled && self.complete
    }

    pub fn remaining(&self, now: DateTime<Utc>) -> Option<Duration> {
        if self.complete {
            return None;
        }
        let started = self.started_at?;
        let hours = self.duration_hours.min(crate::config::MAX_BASELINE_HOURS) as i64;
        let deadline = started.checked_add_signed(Duration::hours(hours))?;
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
        if self.known_ssh_sources.len() < MAX_LEARNED {
            self.known_ssh_sources.insert(ip);
        }
    }

    pub fn observe_dest(&mut self, ip: IpAddr, now: DateTime<Utc>) {
        self.check_completion(now);
        if ip.is_unspecified() || ip.is_loopback() {
            return;
        }
        if self.known_dests.len() < MAX_LEARNED {
            self.known_dests.insert(ip);
        }
        if self.known_dest_nets.len() < MAX_LEARNED {
            self.known_dest_nets.insert(dest_net(ip));
        }
    }

    pub fn index_dests(&mut self) {
        let nets: Vec<IpAddr> = self.known_dests.iter().map(|ip| dest_net(*ip)).collect();
        for net in nets {
            if self.known_dest_nets.len() >= MAX_LEARNED {
                break;
            }
            self.known_dest_nets.insert(net);
        }
    }

    pub fn observe_connector(&mut self, key: &str, now: DateTime<Utc>) {
        self.check_completion(now);
        if self.known_connectors.len() < MAX_LEARNED {
            self.known_connectors.insert(key.to_string());
        }
    }

    pub fn can_judge_connectors(&self, now: DateTime<Utc>) -> bool {
        self.can_judge_novelty() && !self.relearning_connectors(now)
    }

    pub fn ssh_source_is_known(&self, ip: IpAddr) -> bool {
        self.known_ssh_sources.contains(&ip)
    }

    pub fn dest_is_known(&self, ip: IpAddr) -> bool {
        self.known_dests.contains(&ip) || self.known_dest_nets.contains(&dest_net(ip))
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
        assert!(b.complete);
    }

    #[test]
    fn destinations_are_judged_by_network() {
        let t0 = now();
        let mut b = Baseline::new(true, 24, t0);
        b.observe_dest("198.51.100.7".parse().unwrap(), t0);
        b.observe_dest("2001:db8:1:2::5".parse().unwrap(), t0);
        assert!(b.dest_is_known("198.51.100.200".parse().unwrap()));
        assert!(b.dest_is_known("::ffff:198.51.100.9".parse().unwrap()));
        assert!(b.dest_is_known("2001:db8:1:2:ffff::1".parse().unwrap()));
        assert!(!b.dest_is_known("198.51.101.7".parse().unwrap()));
        assert!(!b.dest_is_known("2001:db8:1:3::5".parse().unwrap()));
    }

    #[test]
    fn dest_networks_are_rebuilt_after_loading() {
        let mut b: Baseline = serde_json::from_str(
            r#"{"enabled":true,"complete":true,"known_dests":["203.0.113.5"]}"#,
        )
        .unwrap();
        assert!(!b.dest_is_known("203.0.113.6".parse().unwrap()));
        b.index_dests();
        assert!(b.dest_is_known("203.0.113.6".parse().unwrap()));
        let text = serde_json::to_string(&b).unwrap();
        assert!(!text.contains("known_dest_nets"), "{}", text);
    }

    #[test]
    fn huge_duration_from_disk_does_not_panic() {
        let mut b: Baseline = serde_json::from_str(
            r#"{"enabled":true,"complete":false,"duration_hours":4294967295,
                "started_at":"2026-01-01T00:00:00Z"}"#,
        )
        .unwrap();
        let t = "2026-06-01T00:00:00Z".parse().unwrap();
        assert!(b.remaining(t).is_some());
        assert!(!b.check_completion(t));
    }

    #[test]
    fn enabled_baseline_learns_and_completes() {
        let t0 = now();
        let mut b = Baseline::new(true, 24, t0);
        assert!(!b.complete);
        let ip: IpAddr = "192.0.2.10".parse().unwrap();
        b.observe_ssh_source(ip, t0);
        assert!(b.ssh_source_is_known(ip));
        b.observe_dest(ip, t0);
        b.observe_connector("nginx|33", t0);
        let later = t0 + Duration::hours(25);
        assert!(b.check_completion(later));
        assert!(b.complete);
        let ip2: IpAddr = "192.0.2.11".parse().unwrap();
        assert!(!b.ssh_source_is_known(ip2));
    }

    #[test]
    fn legacy_connector_keys_are_relearned() {
        let t0 = now();
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
        assert!(b.connector_is_known("/tmp/x|33"));
        b.migrate_connectors(later);
        assert!(b.connector_is_known("/usr/sbin/nginx|33"));
    }

    #[test]
    fn known_sets_keep_learning_after_the_window() {
        let t0 = now();
        let mut b = Baseline::new(true, 24, t0);
        let later = t0 + Duration::hours(25);
        assert!(b.check_completion(later));
        let src: IpAddr = "192.0.2.11".parse().unwrap();
        let dst: IpAddr = "198.51.100.7".parse().unwrap();
        assert!(!b.ssh_source_is_known(src));
        assert!(!b.dest_is_known(dst));
        assert!(!b.connector_is_known("/usr/bin/curl|0"));
        b.observe_ssh_source(src, later);
        b.observe_dest(dst, later);
        b.observe_connector("/usr/bin/curl|0", later);
        assert!(b.ssh_source_is_known(src));
        assert!(b.dest_is_known(dst));
        assert!(b.connector_is_known("/usr/bin/curl|0"));
        assert!(!b.ssh_source_is_known("192.0.2.99".parse().unwrap()));
    }

    #[test]
    fn judging_from_now_keeps_novelty_on() {
        let b = Baseline::judging_from(now(), 24);
        assert!(b.can_judge_novelty());
        assert!(b.can_judge_connectors(now()));
        assert!(!Baseline::new(false, 24, now()).can_judge_novelty());
    }

    #[test]
    fn unspecified_and_loopback_destinations_are_not_learned() {
        let mut b = Baseline::new(true, 24, now());
        for ip in ["0.0.0.0", "::", "127.0.0.1", "::1"] {
            b.observe_dest(ip.parse().unwrap(), now());
        }
        assert!(b.known_dests.is_empty());
        assert!(b.known_dest_nets.is_empty());
    }
}
