pub mod d1;
pub mod d2;
pub mod d3;
pub mod d4;
pub mod d5;

use chrono::{DateTime, Duration, Timelike, Utc};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

use crate::alert::{chain_from_procs, ChainNode};
use crate::allowlist::Allowlist;
use crate::baseline::Baseline;
use crate::config::Config;
use crate::events::{DetectionId, FileEvent, Severity, WriterInfo};
use crate::proctree::ProcessTree;

/// A process chain that a prior detection flagged; later detections use this to
/// escalate related activity (e.g. a connect from a flagged web-shell chain).
#[derive(Debug, Clone)]
pub struct FlaggedChain {
    pub pids: Vec<u32>,
    pub detection: DetectionId,
    pub severity: Severity,
    pub ts: DateTime<Utc>,
    pub reason: String,
}

/// Read-only view of engine state handed to every detection rule.
#[derive(Debug)]
pub struct Ctx<'a> {
    pub tree: &'a ProcessTree,
    pub baseline: &'a Baseline,
    pub allowlist: &'a Allowlist,
    pub cfg: &'a Config,
    pub flags: &'a VecDeque<FlaggedChain>,
    pub user_names: &'a HashMap<u32, String>,
    pub now: DateTime<Utc>,
}

/// How confident we are that a file change was made by an operator sitting at a
/// session, as opposed to by an unattended process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attribution {
    /// Writer identified and it descends from an interactive session.
    Interactive,
    /// Writer identified and it does NOT descend from any session.
    Unattended,
    /// Writer unknown, but an interactive session was active on the host.
    LikelyInteractive,
    /// Writer unknown and no interactive session was active anywhere.
    LikelyUnattended,
}

impl Attribution {
    pub fn is_interactive(self) -> bool {
        matches!(
            self,
            Attribution::Interactive | Attribution::LikelyInteractive
        )
    }
}

impl<'a> Ctx<'a> {
    pub fn is_off_hours(&self, now: DateTime<Utc>) -> bool {
        let hour = now.hour();
        let start = self.cfg.ssh.off_hours_start;
        let end = self.cfg.ssh.off_hours_end;
        if start == end {
            return false;
        }
        if start < end {
            hour >= start && hour < end
        } else {
            hour >= start || hour < end
        }
    }

    pub fn has_recent_flag(
        &self,
        pid: u32,
        window_secs: i64,
        detection: Option<DetectionId>,
    ) -> bool {
        let chain_pids: Vec<u32> = self.tree.chain_of(pid).iter().map(|p| p.pid).collect();
        self.flags.iter().any(|f| {
            if detection.map(|d| f.detection != d).unwrap_or(false) {
                return false;
            }
            if self.now - f.ts > Duration::seconds(window_secs) {
                return false;
            }
            f.pids.iter().any(|p| *p == pid || chain_pids.contains(p))
        })
    }

    /// Structured process chain for `pid`, focus on the last node.
    pub fn chain_nodes(&self, pid: u32) -> Vec<ChainNode> {
        chain_from_procs(&self.tree.chain_of(pid), self.user_names)
    }

    pub fn user_name(&self, uid: u32) -> Option<&str> {
        self.user_names.get(&uid).map(|s| s.as_str())
    }

    /// Decide whether a file change looks operator-driven.
    pub fn attribute(&self, ev: &FileEvent) -> Attribution {
        match &ev.writer {
            Some(w) => {
                if self.tree.has_interactive_session(w.pid, w.tty_nr) {
                    Attribution::Interactive
                } else {
                    Attribution::Unattended
                }
            }
            None => {
                if ev.session_present {
                    Attribution::LikelyInteractive
                } else {
                    Attribution::LikelyUnattended
                }
            }
        }
    }
}

pub fn writer_label(writer: Option<&WriterInfo>) -> String {
    match writer {
        Some(w) => format!("{} (pid {})", w.comm, w.pid),
        None => "an unidentified process".to_string(),
    }
}

/// Sliding-window counter keyed by source address.
#[derive(Debug, Default)]
pub struct BurstTracker {
    counts: HashMap<IpAddr, VecDeque<DateTime<Utc>>>,
}

impl BurstTracker {
    pub fn record(&mut self, ip: IpAddr, now: DateTime<Utc>, window_secs: i64) -> usize {
        let q = self.counts.entry(ip).or_default();
        q.push_back(now);
        let cutoff = now - Duration::seconds(window_secs);
        while q.front().map(|t| *t < cutoff).unwrap_or(false) {
            q.pop_front();
        }
        q.len()
    }

    /// Drop sources with no activity since `cutoff`.
    pub fn prune(&mut self, cutoff: DateTime<Utc>) {
        self.counts
            .retain(|_, q| q.back().map(|t| *t >= cutoff).unwrap_or(false));
    }

    pub fn len(&self) -> usize {
        self.counts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.counts.is_empty()
    }
}

/// Last-seen content of a few account files, used to diff on change.
#[derive(Debug, Default)]
pub struct FileSnapshots {
    pub content: HashMap<String, String>,
}

impl FileSnapshots {
    pub fn update(&mut self, path: &str, content: String) -> Option<String> {
        self.content.insert(path.to_string(), content)
    }

    pub fn get(&self, path: &str) -> Option<&String> {
        self.content.get(path)
    }
}

pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_broadcast()
                || (o[0] == 100 && (64..=127).contains(&o[1])) // 100.64/10 CGNAT
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            (s[0] & 0xfe00) == 0xfc00 // fc00::/7 unique local
                || (s[0] & 0xffc0) == 0xfe80 // fe80::/10 link local
                || v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || v6.to_ipv4_mapped().map(|v4| is_private_ip(IpAddr::V4(v4))).unwrap_or(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx<'a>(
        cfg: &'a Config,
        tree: &'a ProcessTree,
        baseline: &'a Baseline,
        allowlist: &'a Allowlist,
        flags: &'a VecDeque<FlaggedChain>,
        users: &'a HashMap<u32, String>,
        now: DateTime<Utc>,
    ) -> Ctx<'a> {
        Ctx {
            tree,
            baseline,
            allowlist,
            cfg,
            flags,
            user_names: users,
            now,
        }
    }

    #[test]
    fn off_hours_window() {
        let cfg = Config::default();
        let tree = ProcessTree::new();
        let baseline = Baseline::default();
        let allowlist = Allowlist::default();
        let flags = VecDeque::new();
        let users = HashMap::new();
        let t = Utc::now().with_hour(23).unwrap().with_minute(30).unwrap();
        let c = ctx(&cfg, &tree, &baseline, &allowlist, &flags, &users, t);
        assert!(c.is_off_hours(t));
        assert!(!c.is_off_hours(Utc::now().with_hour(12).unwrap()));

        let mut disabled = Config::default();
        disabled.ssh.off_hours_start = 0;
        disabled.ssh.off_hours_end = 0;
        let c = ctx(&disabled, &tree, &baseline, &allowlist, &flags, &users, t);
        assert!(!c.is_off_hours(t));
    }

    #[test]
    fn private_ips() {
        assert!(is_private_ip("10.1.2.3".parse().unwrap()));
        assert!(is_private_ip("192.168.0.1".parse().unwrap()));
        assert!(is_private_ip("127.0.0.1".parse().unwrap()));
        assert!(is_private_ip("100.100.1.1".parse().unwrap()));
        assert!(is_private_ip("fd00::1".parse().unwrap()));
        assert!(is_private_ip("fe80::1".parse().unwrap()));
        assert!(is_private_ip("::ffff:10.0.0.1".parse().unwrap()));
        assert!(!is_private_ip("198.51.100.42".parse().unwrap()));
        assert!(!is_private_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_private_ip("2606:4700::1111".parse().unwrap()));
    }

    #[test]
    fn burst_tracking_and_prune() {
        let mut b = BurstTracker::default();
        let ip: IpAddr = "192.0.2.9".parse().unwrap();
        let t = Utc::now();
        assert_eq!(b.record(ip, t, 60), 1);
        assert_eq!(b.record(ip, t + Duration::seconds(10), 60), 2);
        assert_eq!(b.record(ip, t + Duration::seconds(61), 60), 2);
        assert_eq!(b.record(ip, t + Duration::seconds(120), 60), 2);
        b.prune(t + Duration::seconds(121));
        assert!(b.is_empty());
    }
}
