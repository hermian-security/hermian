//! Response actions an alert can offer (as Telegram buttons, for now).
//!
//! The engine only *describes* what could be done; it never does it. The
//! daemon decides whether actions are enabled, who may trigger them, and
//! carries them out.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResponseAction {
    /// Do nothing. With sources and hours set (brute-force digest), stop
    /// reporting those sources for that long. Successful logins from them
    /// still alert.
    Ignore { sources: Vec<IpAddr>, hours: u32 },
    /// Block these sources in the firewall for `response.block_duration_hours`.
    Block { sources: Vec<IpAddr> },
    /// End the SSH session from `source` (and `port`, when known), blocking
    /// the source first if `block` is set.
    Disconnect {
        source: IpAddr,
        port: Option<u16>,
        user: String,
        block: bool,
    },
    /// Stop adding the "root can log in with a password" warning to digests
    /// for this many days.
    SnoozeRootPasswordWarning { days: u32 },
    /// Lift blocks made from an alert's buttons (the Undo on a Block result).
    /// Offered by the daemon after a block, never by the engine.
    Unblock { sources: Vec<IpAddr> },
}

impl ResponseAction {
    /// Button label.
    pub fn label(&self) -> String {
        match self {
            ResponseAction::Ignore { sources, hours } if !sources.is_empty() && *hours > 0 => {
                format!("Ignore {}h", hours)
            }
            ResponseAction::Ignore { .. } => "Ignore".to_string(),
            ResponseAction::Block { sources } if sources.len() == 1 => {
                format!("Block {}", sources[0])
            }
            ResponseAction::Block { sources } => format!("Block all ({})", sources.len()),
            ResponseAction::Disconnect { block: false, .. } => "Disconnect session".to_string(),
            ResponseAction::Disconnect { block: true, .. } => "Disconnect and block".to_string(),
            ResponseAction::SnoozeRootPasswordWarning { days } => {
                format!("Remind me in {} days", days)
            }
            ResponseAction::Unblock { sources } if sources.len() == 1 => {
                format!("Undo: unblock {}", sources[0])
            }
            ResponseAction::Unblock { sources } => format!("Undo: unblock all ({})", sources.len()),
        }
    }

    /// The same thing from a root shell, for when the button can't be used
    /// any more (expired, or the daemon restarted). None for choices that
    /// only matter while the alert is fresh.
    pub fn cli_twin(&self) -> Option<String> {
        let each = |verb: &str, ips: &[IpAddr]| {
            ips.iter()
                .map(|ip| format!("sudo hermian {} {}", verb, ip))
                .collect::<Vec<_>>()
                .join(" && ")
        };
        match self {
            ResponseAction::Block { sources } if !sources.is_empty() => Some(format!(
                "sudo hermian block {}",
                sources
                    .iter()
                    .map(|ip| ip.to_string())
                    .collect::<Vec<_>>()
                    .join(" ")
            )),
            ResponseAction::Unblock { sources } if !sources.is_empty() => {
                Some(each("unblock", sources))
            }
            ResponseAction::Disconnect {
                source,
                block: true,
                ..
            } => Some(format!(
                "sudo hermian block {0} && sudo hermian disconnect {0}",
                source
            )),
            ResponseAction::Disconnect { source, .. } => {
                Some(format!("sudo hermian disconnect {}", source))
            }
            _ => None,
        }
    }

    /// Whether choosing this settles the alert, so its other buttons go away.
    /// Blocking one source of a digest leaves the rest open.
    pub fn settles(&self) -> bool {
        !matches!(self, ResponseAction::Block { sources } if sources.len() == 1)
            && !matches!(
                self,
                ResponseAction::SnoozeRootPasswordWarning { .. } | ResponseAction::Unblock { .. }
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_and_settling() {
        let ip: IpAddr = "198.51.100.7".parse().unwrap();
        let one = ResponseAction::Block { sources: vec![ip] };
        assert_eq!(one.label(), "Block 198.51.100.7");
        assert!(!one.settles());
        let all = ResponseAction::Block {
            sources: vec![ip, "203.0.113.9".parse().unwrap()],
        };
        assert_eq!(all.label(), "Block all (2)");
        assert!(all.settles());
        let d = ResponseAction::Disconnect {
            source: ip,
            port: Some(4),
            user: "root".into(),
            block: true,
        };
        assert_eq!(d.label(), "Disconnect and block");
        let i = ResponseAction::Ignore {
            sources: vec![],
            hours: 0,
        };
        assert_eq!(i.label(), "Ignore");
        // Round-trips through JSON (alerts are stored as JSON).
        let back: ResponseAction =
            serde_json::from_str(&serde_json::to_string(&d).unwrap()).unwrap();
        assert_eq!(back, d);
        let u = ResponseAction::Unblock { sources: vec![ip] };
        assert_eq!(u.label(), "Undo: unblock 198.51.100.7");
        assert!(!u.settles());
    }

    #[test]
    fn every_host_changing_action_has_a_cli_twin() {
        let ip: IpAddr = "198.51.100.7".parse().unwrap();
        let ip2: IpAddr = "203.0.113.9".parse().unwrap();
        let twin = |a: ResponseAction| a.cli_twin().unwrap_or_default();
        assert_eq!(
            twin(ResponseAction::Block {
                sources: vec![ip, ip2]
            }),
            "sudo hermian block 198.51.100.7 203.0.113.9"
        );
        assert_eq!(
            twin(ResponseAction::Unblock { sources: vec![ip] }),
            "sudo hermian unblock 198.51.100.7"
        );
        assert_eq!(
            twin(ResponseAction::Disconnect {
                source: ip,
                port: None,
                user: "root".into(),
                block: true
            }),
            "sudo hermian block 198.51.100.7 && sudo hermian disconnect 198.51.100.7"
        );
        assert!(ResponseAction::Ignore {
            sources: vec![],
            hours: 0
        }
        .cli_twin()
        .is_none());
    }
}
