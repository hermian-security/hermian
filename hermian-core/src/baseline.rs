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
    /// Successful SSH login sources, recorded for the lifetime of the install.
    /// The learning window only gates when novelty is judged; learning keeps
    /// going afterwards so a source is "new" exactly once, not every time it
    /// appears after the window closed.
    pub known_ssh_sources: HashSet<IpAddr>,
    /// Destinations of outbound connections, recorded lifetime-wide like
    /// `known_ssh_sources`.
    pub known_dests: HashSet<IpAddr>,
    /// The networks of `known_dests` (see [`dest_net`]). Derived, not saved:
    /// rebuilt by [`Baseline::index_dests`] when a baseline is loaded.
    #[serde(skip)]
    pub known_dest_nets: HashSet<IpAddr>,
    /// Connecting programs (see `connector_key`), recorded lifetime-wide.
    pub known_connectors: HashSet<String>,
    /// Sources that have successfully logged in as root. Separate from
    /// `known_ssh_sources` so the root rule can ask "has this source ever
    /// logged in as root", not just "is this source normal".
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
    /// Keys that have logged in, as "<user> SHA256:<fingerprint>",
    /// lifetime-wide. A login with one of these from a new address on a
    /// network the account already logs in from is routine (dynamic IPs).
    #[serde(default)]
    pub known_keys: HashSet<String>,
}

/// Current `known_connectors` key scheme: the connecting process's own exe.
pub const CONNECTOR_SCHEME: u8 = 1;

/// Most entries learned per set. A busy host (or a hostile one, during the
/// learning window) could otherwise grow these, and baseline.json, without
/// limit. Past the cap, unseen values are simply novel.
pub const MAX_LEARNED: usize = 50_000;

/// The network a login source is judged by when the key is already known:
/// its /16 (IPv4, including v4-mapped IPv6) or /32 (IPv6). Home and mobile
/// connections change address inside their provider's block; a different
/// provider or country is a different network.
pub fn source_net(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4((u32::from(v4) & 0xffff_0000).into()),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => source_net(IpAddr::V4(v4)),
            None => IpAddr::V6((u128::from(v6) & (u128::MAX << 96)).into()),
        },
    }
}

/// The network a destination is judged by: its /24 (IPv4, including
/// v4-mapped IPv6) or /64 (IPv6). APIs and CDNs rotate addresses inside a
/// block, and each new address used to page "new external destination".
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
        if self.root_sources.len() >= MAX_LEARNED {
            return false;
        }
        self.root_sources.insert(ip)
    }

    pub fn root_source_is_known(&self, ip: IpAddr) -> bool {
        self.root_sources.contains(&ip)
    }

    /// Whether root has logged in from `ip`'s network (see [`source_net`]).
    pub fn root_net_is_known(&self, ip: IpAddr) -> bool {
        let net = source_net(ip);
        self.root_sources.iter().any(|s| source_net(*s) == net)
    }

    /// Whether anyone has logged in from `ip`'s network.
    pub fn ssh_net_is_known(&self, ip: IpAddr) -> bool {
        let net = source_net(ip);
        self.known_ssh_sources.iter().any(|s| source_net(*s) == net)
    }

    pub fn observe_key(&mut self, user: &str, fingerprint: &str) {
        if self.known_keys.len() < MAX_LEARNED {
            self.known_keys.insert(format!("{} {}", user, fingerprint));
        }
    }

    pub fn key_is_known(&self, user: &str, fingerprint: &str) -> bool {
        self.known_keys
            .contains(&format!("{} {}", user, fingerprint))
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
        // duration_hours comes from baseline.json too, which isn't validated:
        // clamp it rather than let chrono panic on overflow.
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
        if self.known_dests.len() < MAX_LEARNED {
            self.known_dests.insert(ip);
        }
        if self.known_dest_nets.len() < MAX_LEARNED {
            self.known_dest_nets.insert(dest_net(ip));
        }
    }

    /// Rebuild the derived network set after loading from disk.
    pub fn index_dests(&mut self) {
        let nets: Vec<IpAddr> = self.known_dests.iter().map(|ip| dest_net(*ip)).collect();
        for net in nets {
            if self.known_dest_nets.len() >= MAX_LEARNED {
                break;
            }
            self.known_dest_nets.insert(net);
        }
    }

    /// The relearn window only suppresses judging (see `can_judge_connectors`);
    /// observation itself is lifetime-wide like the other sets.
    pub fn observe_connector(&mut self, key: &str, now: DateTime<Utc>) {
        self.check_completion(now);
        if self.known_connectors.len() < MAX_LEARNED {
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

    /// Known if this address, or another in its network, was seen before.
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
        assert!(b.is_complete());
    }

    #[test]
    fn destinations_are_judged_by_network() {
        let t0 = now();
        let mut b = Baseline::new(true, 24, t0);
        b.observe_dest("198.51.100.7".parse().unwrap(), t0);
        b.observe_dest("2001:db8:1:2::5".parse().unwrap(), t0);
        // Same /24 or /64: a rotated address isn't new.
        assert!(b.dest_is_known("198.51.100.200".parse().unwrap()));
        assert!(b.dest_is_known("::ffff:198.51.100.9".parse().unwrap()));
        assert!(b.dest_is_known("2001:db8:1:2:ffff::1".parse().unwrap()));
        // Next block over is.
        assert!(!b.dest_is_known("198.51.101.7".parse().unwrap()));
        assert!(!b.dest_is_known("2001:db8:1:3::5".parse().unwrap()));
    }

    #[test]
    fn dest_networks_are_rebuilt_after_loading() {
        // baseline.json keeps plain addresses; the network set isn't saved.
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
        // Observation keeps recording after the window, so a reconnect from
        // this program is known and won't be judged novel again.
        assert!(b.connector_is_known("/tmp/x|33"));
        // Idempotent for current-scheme baselines.
        b.migrate_connectors(later);
        assert!(b.connector_is_known("/usr/sbin/nginx|33"));
    }

    /// The sets used to freeze when the learning window closed, so anything
    /// first seen afterwards re-alerted on every later occurrence (a login
    /// from one IP paged "new source" indefinitely). They now learn for the
    /// lifetime of the install; only judgement waits for the window.
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
        // A value never observed is still novel.
        assert!(!b.ssh_source_is_known("192.0.2.99".parse().unwrap()));
    }
}
