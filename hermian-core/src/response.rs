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
        }
    }

    /// Whether choosing this settles the alert, so its other buttons go away.
    /// Blocking one source of a digest leaves the rest open.
    pub fn settles(&self) -> bool {
        !matches!(self, ResponseAction::Block { sources } if sources.len() == 1)
            && !matches!(self, ResponseAction::SnoozeRootPasswordWarning { .. })
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
    }
}
