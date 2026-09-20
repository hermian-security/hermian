use serde::{Deserialize, Serialize};
use std::net::IpAddr;

use crate::config::ConfigError;

/// Operator-declared exceptions. Every rule carries a mandatory `reason` so the
/// config file doubles as the audit trail of suppression decisions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Allowlist {
    #[serde(alias = "process_chain")]
    pub process_chains: Vec<ProcessChainRule>,
    pub persistence: Vec<PathRule>,
    #[serde(alias = "ssh_source")]
    pub ssh_sources: Vec<SourceRule>,
    #[serde(alias = "binary")]
    pub binaries: Vec<PathRule>,
    #[serde(alias = "destination")]
    pub destinations: Vec<DestinationRule>,
    #[serde(alias = "debugger")]
    pub debuggers: Vec<DebuggerRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessChainRule {
    pub parent: String,
    pub child: String,
    #[serde(default)]
    pub user: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathRule {
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRule {
    pub source: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationRule {
    pub destination: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebuggerRule {
    pub comm: String,
    pub reason: String,
}

/// Parse `a.b.c.d`, `a.b.c.d/nn`, or an IPv6 equivalent. A bare address is a
/// host route (/32 or /128).
pub fn parse_cidr(s: &str) -> Option<(IpAddr, u32)> {
    let (ip, prefix) = match s.split_once('/') {
        Some((ip, p)) => (ip.trim(), Some(p.trim().parse::<u32>().ok()?)),
        None => (s.trim(), None),
    };
    let ip: IpAddr = ip.parse().ok()?;
    let max = match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    let prefix = prefix.unwrap_or(max);
    if prefix > max {
        return None;
    }
    Some((ip, prefix))
}

fn ip_matches(ip: IpAddr, (net, prefix): (IpAddr, u32)) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            if prefix == 0 {
                return true;
            }
            let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
            u32::from(a) & mask == u32::from(n) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            if prefix == 0 {
                return true;
            }
            let mask = u128::MAX.checked_shl(128 - prefix).unwrap_or(0);
            u128::from(a) & mask == u128::from(n) & mask
        }
        // Allow a v4 rule to match a v4-mapped v6 address.
        (IpAddr::V6(a), IpAddr::V4(_)) => a
            .to_ipv4_mapped()
            .map(|v4| ip_matches(IpAddr::V4(v4), (net, prefix)))
            .unwrap_or(false),
        _ => false,
    }
}

fn path_matches(path: &str, rule: &str) -> bool {
    let rule = rule.trim_end_matches('/');
    if rule.is_empty() {
        return false;
    }
    if let Some(prefix) = rule.strip_suffix('*') {
        return path.starts_with(prefix);
    }
    path == rule || path.starts_with(&format!("{}/", rule))
}

impl Allowlist {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self
            .process_chains
            .iter()
            .any(|r| r.reason.trim().is_empty())
        {
            return Err(ConfigError::EmptyReason("process_chains"));
        }
        if self.persistence.iter().any(|r| r.reason.trim().is_empty()) {
            return Err(ConfigError::EmptyReason("persistence"));
        }
        if self.ssh_sources.iter().any(|r| r.reason.trim().is_empty()) {
            return Err(ConfigError::EmptyReason("ssh_sources"));
        }
        if self.binaries.iter().any(|r| r.reason.trim().is_empty()) {
            return Err(ConfigError::EmptyReason("binaries"));
        }
        if self.destinations.iter().any(|r| r.reason.trim().is_empty()) {
            return Err(ConfigError::EmptyReason("destinations"));
        }
        if self.debuggers.iter().any(|r| r.reason.trim().is_empty()) {
            return Err(ConfigError::EmptyReason("debuggers"));
        }
        for r in &self.ssh_sources {
            if parse_cidr(&r.source).is_none() {
                return Err(ConfigError::BadCidr(r.source.clone()));
            }
        }
        for r in &self.destinations {
            if parse_cidr(&r.destination).is_none() {
                return Err(ConfigError::BadCidr(r.destination.clone()));
            }
        }
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.process_chains.is_empty()
            && self.persistence.is_empty()
            && self.ssh_sources.is_empty()
            && self.binaries.is_empty()
            && self.destinations.is_empty()
            && self.debuggers.is_empty()
    }

    pub fn chain_allowed(
        &self,
        parent: &str,
        child: &str,
        uid: Option<u32>,
        user_name: Option<&str>,
    ) -> bool {
        self.process_chains.iter().any(|r| {
            if r.parent != parent || r.child != child {
                return false;
            }
            match &r.user {
                None => true,
                Some(want) => {
                    user_name.map(|n| n == want).unwrap_or(false)
                        || want
                            .parse::<u32>()
                            .ok()
                            .zip(uid)
                            .map(|(w, u)| w == u)
                            .unwrap_or(false)
                }
            }
        })
    }

    pub fn path_allowed(&self, path: &str) -> bool {
        self.persistence.iter().any(|r| path_matches(path, &r.path))
    }

    pub fn binary_allowed(&self, path: &str) -> bool {
        let clean = path.trim_end_matches(" (deleted)");
        self.binaries.iter().any(|r| path_matches(clean, &r.path))
    }

    pub fn source_allowed(&self, ip: IpAddr) -> bool {
        self.ssh_sources
            .iter()
            .filter_map(|r| parse_cidr(&r.source))
            .any(|net| ip_matches(ip, net))
    }

    pub fn destination_allowed(&self, ip: IpAddr) -> bool {
        self.destinations
            .iter()
            .filter_map(|r| parse_cidr(&r.destination))
            .any(|net| ip_matches(ip, net))
    }

    pub fn debugger_allowed(&self, comm: &str) -> bool {
        self.debuggers.iter().any(|r| r.comm == comm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Allowlist {
        Allowlist {
            process_chains: vec![ProcessChainRule {
                parent: "deploy-agent".into(),
                child: "bash".into(),
                user: Some("deploy".into()),
                reason: "CI/CD deployment pipeline".into(),
            }],
            persistence: vec![
                PathRule {
                    path: "/var/spool/cron/crontabs/deploy".into(),
                    reason: "Managed by Ansible".into(),
                },
                PathRule {
                    path: "/etc/cron.d/app-*".into(),
                    reason: "App-managed schedules".into(),
                },
            ],
            ssh_sources: vec![SourceRule {
                source: "10.0.0.5".into(),
                reason: "Ansible control node".into(),
            }],
            binaries: vec![PathRule {
                path: "/opt/app/bin/updater".into(),
                reason: "Internal auto-updater".into(),
            }],
            destinations: vec![DestinationRule {
                destination: "10.0.1.0/24".into(),
                reason: "Internal network".into(),
            }],
            debuggers: vec![DebuggerRule {
                comm: "my-profiler".into(),
                reason: "In-house profiler".into(),
            }],
        }
    }

    #[test]
    fn chain_matching() {
        let a = sample();
        assert!(a.chain_allowed("deploy-agent", "bash", Some(1001), Some("deploy")));
        assert!(!a.chain_allowed("deploy-agent", "bash", Some(0), Some("root")));
        assert!(!a.chain_allowed("other", "bash", Some(1001), Some("deploy")));
        // Numeric user rule.
        let mut b = sample();
        b.process_chains[0].user = Some("1001".into());
        assert!(b.chain_allowed("deploy-agent", "bash", Some(1001), None));
    }

    #[test]
    fn path_matching() {
        let a = sample();
        assert!(a.path_allowed("/var/spool/cron/crontabs/deploy"));
        assert!(a.path_allowed("/var/spool/cron/crontabs/deploy/backup"));
        assert!(!a.path_allowed("/var/spool/cron/crontabs/root"));
        assert!(a.path_allowed("/etc/cron.d/app-nightly"));
        assert!(!a.path_allowed("/etc/cron.d/other"));
    }

    #[test]
    fn source_matching() {
        let a = sample();
        assert!(a.source_allowed("10.0.0.5".parse().unwrap()));
        assert!(!a.source_allowed("10.0.0.6".parse().unwrap()));
        assert!(a.source_allowed("::ffff:10.0.0.5".parse().unwrap()));
    }

    #[test]
    fn destination_matching() {
        let a = sample();
        assert!(a.destination_allowed("10.0.1.42".parse().unwrap()));
        assert!(!a.destination_allowed("198.51.100.42".parse().unwrap()));
    }

    #[test]
    fn cidr_parsing() {
        assert_eq!(parse_cidr("10.0.0.1").unwrap().1, 32);
        assert_eq!(parse_cidr("10.0.0.0/8").unwrap().1, 8);
        assert_eq!(parse_cidr("fd00::/8").unwrap().1, 8);
        assert!(parse_cidr("10.0.0.0/33").is_none());
        assert!(parse_cidr("nope").is_none());
    }

    #[test]
    fn validation_catches_bad_entries() {
        let mut a = sample();
        assert!(a.validate().is_ok());
        a.ssh_sources[0].source = "bad".into();
        assert!(matches!(a.validate(), Err(ConfigError::BadCidr(_))));
        let mut b = sample();
        b.binaries[0].reason = "  ".into();
        assert!(matches!(
            b.validate(),
            Err(ConfigError::EmptyReason("binaries"))
        ));
    }
}
