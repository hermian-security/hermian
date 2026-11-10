pub mod brute;
pub mod d1;
pub mod d2;
pub mod d3;
pub mod d4;
pub mod d5;

use chrono::{DateTime, Duration, Utc};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

use crate::alert::{chain_from_procs, ChainNode};
use crate::allowlist::Allowlist;
use crate::baseline::Baseline;
use crate::config::Config;
use crate::events::{DetectionId, FileEvent, Severity, WriterInfo};
use crate::proctree::ProcessTree;

pub const FLAG_WINDOW_SECS: i64 = 600;

#[derive(Debug, Clone)]
pub struct FlaggedChain {
    pub pids: Vec<u32>,
    pub detection: DetectionId,
    pub severity: Severity,
    pub ts: DateTime<Utc>,
    pub reason: String,
}

#[derive(Debug)]
pub struct Ctx<'a> {
    pub tree: &'a ProcessTree,
    pub baseline: &'a Baseline,
    pub allowlist: &'a Allowlist,
    pub cfg: &'a Config,
    pub flags: &'a VecDeque<FlaggedChain>,
    pub user_names: &'a HashMap<u32, String>,
    pub self_pid: u32,
    pub now: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attribution {
    Interactive,
    Unattended,
    LikelyInteractive,
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

    pub fn tool_exemption_applies(&self, pid: u32) -> bool {
        let service_origin = self.tree.chain_of(pid).iter().any(|p| {
            matches!(
                crate::proctree::role_of(&p.comm, &p.exe),
                crate::proctree::Role::WebServer | crate::proctree::Role::Database
            )
        });
        !service_origin && !self.has_recent_flag(pid, 600, Some(DetectionId::D1))
    }

    pub fn incident_root(&self, pid: u32) -> String {
        let chain = self.tree.chain_of(pid);
        chain
            .iter()
            .find(|p| {
                p.pid > 1
                    && !matches!(
                        crate::proctree::role_of(&p.comm, &p.exe),
                        crate::proctree::Role::System
                            | crate::proctree::Role::Sshd
                            | crate::proctree::Role::Cron
                    )
            })
            .or(chain.last())
            .map(|p| {
                if p.exe.is_empty() {
                    p.comm.clone()
                } else {
                    p.exe.clone()
                }
            })
            .unwrap_or_else(|| pid.to_string())
    }

    pub fn chain_nodes(&self, pid: u32) -> Vec<ChainNode> {
        chain_from_procs(&self.tree.chain_of(pid), self.user_names)
    }

    pub fn user_name(&self, uid: u32) -> Option<&str> {
        self.user_names.get(&uid).map(|s| s.as_str())
    }

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

pub fn content_tag(content: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in content.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{:016x}", h)
}

pub fn writer_label(writer: Option<&WriterInfo>) -> String {
    match writer {
        Some(w) => format!("{} (pid {})", w.comm, w.pid),
        None => "an unidentified process".to_string(),
    }
}

pub const MAX_BURST_SOURCES: usize = 20_000;
const MAX_ATTEMPTS_PER_SOURCE: usize = 10_001;

#[derive(Debug, Default)]
pub struct BurstTracker {
    counts: HashMap<IpAddr, VecDeque<DateTime<Utc>>>,
    users: HashMap<IpAddr, Vec<String>>,
}

impl BurstTracker {
    pub fn record(&mut self, ip: IpAddr, now: DateTime<Utc>, window_secs: i64) -> usize {
        self.record_failure(ip, now, window_secs, "")
    }

    pub fn record_failure(
        &mut self,
        ip: IpAddr,
        now: DateTime<Utc>,
        window_secs: i64,
        user: &str,
    ) -> usize {
        if !self.counts.contains_key(&ip) && self.counts.len() >= MAX_BURST_SOURCES {
            let oldest = self
                .counts
                .iter()
                .min_by_key(|(_, q)| q.back().copied())
                .map(|(k, _)| *k);
            if let Some(k) = oldest {
                self.counts.remove(&k);
                self.users.remove(&k);
            }
        }
        let q = self.counts.entry(ip).or_default();
        q.push_back(now);
        let cutoff = now - Duration::seconds(window_secs);
        while q.front().map(|t| *t < cutoff).unwrap_or(false) {
            q.pop_front();
        }
        while q.len() > MAX_ATTEMPTS_PER_SOURCE {
            q.pop_front();
        }
        if !user.is_empty() {
            let users = self.users.entry(ip).or_default();
            if users.last().map(String::as_str) != Some(user) {
                users.push(user.to_string());
                if users.len() > 8 {
                    users.remove(0);
                }
            }
        }
        q.len()
    }

    pub fn recent_failures(&self, ip: IpAddr, now: DateTime<Utc>, window_secs: i64) -> usize {
        let Some(q) = self.counts.get(&ip) else {
            return 0;
        };
        let cutoff = now - Duration::seconds(window_secs);
        q.iter().filter(|t| **t >= cutoff).count()
    }

    pub fn recent_users(&self, ip: IpAddr) -> &[String] {
        self.users.get(&ip).map(Vec::as_slice).unwrap_or(&[])
    }

    pub fn prune(&mut self, cutoff: DateTime<Utc>) {
        self.counts
            .retain(|_, q| q.back().map(|t| *t >= cutoff).unwrap_or(false));
        self.users.retain(|ip, _| self.counts.contains_key(ip));
    }

    pub fn len(&self) -> usize {
        self.counts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.counts.is_empty()
    }
}

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
                || (o[0] == 100 && (64..=127).contains(&o[1]))
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || v6
                    .to_ipv4_mapped()
                    .map(|v4| is_private_ip(IpAddr::V4(v4)))
                    .unwrap_or(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_tags_differ_by_content() {
        assert_eq!(content_tag("a"), content_tag("a"));
        assert_ne!(
            content_tag("eve ALL=(ALL) ALL"),
            content_tag("eve ALL=(ALL) NOPASSWD: ALL")
        );
    }

    #[test]
    fn burst_sources_are_bounded() {
        let mut b = BurstTracker::default();
        let t = Utc::now();
        for i in 0..(MAX_BURST_SOURCES as u32 + 10) {
            let ip = IpAddr::from(std::net::Ipv4Addr::from(i));
            b.record(ip, t + Duration::milliseconds(i64::from(i)), 60);
        }
        assert_eq!(b.len(), MAX_BURST_SOURCES);
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
        assert_eq!(b.recent_failures(ip, t + Duration::seconds(10), 60), 0);
    }
}
