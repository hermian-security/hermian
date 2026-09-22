//! Network isolation via an nftables table owned by HERMIAN.
//!
//! Isolation is never automatic unless `response.auto_isolate = true` *and*
//! `response.management_cidrs` is non-empty; those CIDRs (plus loopback and
//! established flows) remain reachable so the operator can still get in.
//! DHCP, IPv6 neighbour discovery, the configured DNS resolvers and the
//! notification endpoints stay open too, so the link survives and alerts
//! still go out.

use std::net::IpAddr;

use anyhow::{Context, Result};
use hermian_core::config::NotificationsCfg;

use crate::config;
use crate::ui::Style;

const TABLE: &str = "hermian";

fn run_nft(args: &[&str]) -> Result<()> {
    let out = std::process::Command::new("nft")
        .args(args)
        .output()
        .context("failed to run nft (install nftables)")?;
    if out.status.success() {
        Ok(())
    } else {
        anyhow::bail!(
            "nft {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )
    }
}

pub fn is_isolated() -> bool {
    std::process::Command::new("nft")
        .args(["list", "table", "inet", TABLE])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// What an isolated host may still reach besides the management CIDRs.
#[derive(Debug, Default, Clone)]
pub struct Egress {
    /// Configured DNS resolvers (not "any host on port 53": that's an
    /// exfiltration and C2 channel).
    pub resolvers: Vec<IpAddr>,
    /// Notification endpoints, so the alert that triggered isolation (and
    /// any after it) can still be delivered.
    pub notify: Vec<(IpAddr, u16)>,
}

fn fam(ip: &IpAddr) -> &'static str {
    if ip.is_ipv4() {
        "ip"
    } else {
        "ip6"
    }
}

/// Build the complete ruleset as one `nft -f -` script. It creates, deletes
/// and recreates the table in a single transaction, so there's no window
/// with the old rules gone and the new ones not yet loaded.
fn ruleset(management_cidrs: &[String], egress: &Egress) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "add table inet {t}\ndelete table inet {t}\n",
        t = TABLE
    ));
    s.push_str(&format!("table inet {t} {{\n", t = TABLE));
    for (chain, hook, iface, dir) in [
        ("input", "input", "iif", "saddr"),
        ("output", "output", "oif", "daddr"),
    ] {
        s.push_str(&format!("  chain {} {{\n", chain));
        s.push_str(&format!(
            "    type filter hook {} priority -10; policy drop;\n",
            hook
        ));
        s.push_str(&format!("    {} lo accept\n", iface));
        s.push_str("    ct state established,related accept\n");
        for cidr in management_cidrs {
            let fam = if cidr.contains(':') { "ip6" } else { "ip" };
            s.push_str(&format!("    {} {} {} accept\n", fam, dir, cidr));
        }
        // Keep the link itself alive: IPv6 neighbour/router discovery and
        // DHCP lease renewal. Without them IPv6 management access breaks at
        // once and an IPv4 lease eventually expires, locking the operator out.
        s.push_str(
            "    icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, \
             nd-router-advert } accept\n",
        );
        if chain == "input" {
            s.push_str("    udp sport 67 udp dport 68 accept\n");
            s.push_str("    udp sport 547 udp dport 546 accept\n");
        } else {
            s.push_str("    udp sport 68 udp dport 67 accept\n");
            s.push_str("    udp sport 546 udp dport 547 accept\n");
            for r in &egress.resolvers {
                s.push_str(&format!("    {} daddr {} udp dport 53 accept\n", fam(r), r));
                s.push_str(&format!("    {} daddr {} tcp dport 53 accept\n", fam(r), r));
            }
            for (ip, port) in &egress.notify {
                s.push_str(&format!(
                    "    {} daddr {} tcp dport {} accept\n",
                    fam(ip),
                    ip,
                    port
                ));
            }
        }
        s.push_str("  }\n");
    }
    s.push_str("}\n");
    s
}

/// Non-loopback nameservers from resolv.conf. With systemd-resolved the stub
/// (127.0.0.53) is loopback, so its real upstreams are read too.
fn resolvers() -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = ["/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"]
        .iter()
        .filter_map(|p| std::fs::read_to_string(p).ok())
        .flat_map(|c| parse_resolv_conf(&c))
        .collect();
    out.sort();
    out.dedup();
    out
}

fn parse_resolv_conf(content: &str) -> Vec<IpAddr> {
    content
        .lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver"))
        .filter_map(|v| v.split_whitespace().next())
        // Drop a zone suffix such as fe80::1%eth0.
        .filter_map(|v| v.split('%').next()?.parse::<IpAddr>().ok())
        .filter(|ip| !ip.is_loopback())
        .collect()
}

/// `host:port` pairs the enabled notifying channels connect to.
fn notify_targets(n: &NotificationsCfg) -> Vec<(String, u16)> {
    let mut out = Vec::new();
    if n.has_channel("telegram") {
        let base = std::env::var("HERMIAN_TELEGRAM_API")
            .unwrap_or_else(|_| "https://api.telegram.org".to_string());
        out.extend(url_host_port(&base));
    }
    if n.has_channel("webhook") {
        out.extend(url_host_port(&n.webhook.url));
    }
    if n.has_channel("email") && n.email.transport != "sendmail" && !n.email.smtp_host.is_empty() {
        out.push((n.email.smtp_host.clone(), n.email.smtp_port));
    }
    out
}

fn url_host_port(url: &str) -> Option<(String, u16)> {
    let (scheme, rest) = url.split_once("://")?;
    let default = match scheme {
        "https" => 443,
        "http" => 80,
        _ => return None,
    };
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit('@').next()?;
    if let Some(v6) = authority.strip_prefix('[') {
        let (host, after) = v6.split_once(']')?;
        let port = after
            .strip_prefix(':')
            .and_then(|p| p.parse().ok())
            .unwrap_or(default);
        return Some((host.to_string(), port));
    }
    match authority.rsplit_once(':') {
        Some((h, p)) => Some((h.to_string(), p.parse().ok()?)),
        None => Some((authority.to_string(), default)),
    }
}

/// Resolve what isolation must keep reachable. Runs before the ruleset is
/// applied, while DNS still works.
pub fn egress_for(n: &NotificationsCfg) -> Egress {
    use std::net::ToSocketAddrs;
    let mut notify: Vec<(IpAddr, u16)> = notify_targets(n)
        .into_iter()
        .flat_map(|(host, port)| {
            (host.as_str(), port)
                .to_socket_addrs()
                .map(|it| it.map(|a| (a.ip(), port)).collect::<Vec<_>>())
                .unwrap_or_default()
        })
        .collect();
    notify.sort();
    notify.dedup();
    Egress {
        resolvers: resolvers(),
        notify,
    }
}

/// Whether this process can change nftables (CAP_NET_ADMIN, bit 12).
fn has_net_admin() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("CapEff:"))
                .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
        })
        .map(|caps| caps & (1 << 12) != 0)
        .unwrap_or(false)
}

pub fn apply_isolation(management_cidrs: &[String], egress: &Egress) -> Result<()> {
    if management_cidrs.is_empty() {
        anyhow::bail!("isolation requires response.management_cidrs in /etc/hermian/config.toml");
    }
    let script = ruleset(management_cidrs, egress);
    let mut child = std::process::Command::new("nft")
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("failed to run nft")?;
    {
        use std::io::Write;
        let mut stdin = child.stdin.take().context("nft stdin")?;
        stdin.write_all(script.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        anyhow::bail!(
            "nft rejected ruleset: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

pub fn remove_isolation() -> Result<()> {
    if !is_isolated() {
        return Ok(());
    }
    run_nft(&["delete", "table", "inet", TABLE])
}

pub fn cmd_isolate() -> Result<()> {
    config::require_root()?;
    let st = Style::detect();
    let cfg = config::load_config()?;
    let egress = egress_for(&cfg.notifications);
    apply_isolation(&cfg.response.management_cidrs, &egress)?;
    println!("{}", st.warn("Host isolated."));
    println!(
        "  Reachable: loopback, established flows, {}",
        cfg.response.management_cidrs.join(", ")
    );
    println!(
        "  Also:      {} DNS resolver(s), {} notification endpoint(s), DHCP, IPv6 ND",
        egress.resolvers.len(),
        egress.notify.len()
    );
    println!("  Recover:   sudo hermian unisolate");
    Ok(())
}

pub fn cmd_unisolate() -> Result<()> {
    config::require_root()?;
    let st = Style::detect();
    remove_isolation()?;
    println!("{}", st.ok("Isolation removed."));
    Ok(())
}

pub fn auto_isolate_if_enabled(cfg: &hermian_core::Config) {
    if !(cfg.response.auto_isolate && !cfg.response.management_cidrs.is_empty()) {
        return;
    }
    let cidrs = cfg.response.management_cidrs.clone();
    let notifications = cfg.notifications.clone();
    // Everything here shells out or resolves names: keep it off the event loop.
    tokio::task::spawn_blocking(move || {
        if is_isolated() {
            return;
        }
        if !has_net_admin() {
            crate::daemon::log_daemon(
                hermian_core::Severity::High,
                "auto-isolate is enabled but the daemon lacks CAP_NET_ADMIN; \
                 re-run 'hermian enable' to grant it",
            );
            return;
        }
        let egress = egress_for(&notifications);
        isolate_now(&cidrs, &egress)
    });
}

fn isolate_now(cidrs: &[String], egress: &Egress) {
    match apply_isolation(cidrs, egress) {
        Ok(()) => crate::daemon::log_daemon(
            hermian_core::Severity::Critical,
            "auto-isolate triggered; host isolated (recover with: sudo hermian unisolate)",
        ),
        Err(e) => crate::daemon::log_daemon(
            hermian_core::Severity::High,
            &format!("auto-isolate failed: {:#}", e),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn egress() -> Egress {
        Egress {
            resolvers: vec!["192.0.2.53".parse().unwrap()],
            notify: vec![("149.154.167.220".parse().unwrap(), 443)],
        }
    }

    #[test]
    fn ruleset_contains_cidrs_and_v6() {
        let s = ruleset(
            &["203.0.113.0/24".into(), "2001:db8::/32".into()],
            &egress(),
        );
        assert!(s.contains("ip saddr 203.0.113.0/24 accept"));
        assert!(s.contains("ip6 daddr 2001:db8::/32 accept"));
        assert!(s.contains("policy drop"));
    }

    #[test]
    fn ruleset_replaces_the_table_in_one_transaction() {
        let s = ruleset(&["203.0.113.0/24".into()], &egress());
        let add = s.find("add table inet hermian").unwrap();
        let del = s.find("delete table inet hermian").unwrap();
        let new = s.find("table inet hermian {").unwrap();
        assert!(add < del && del < new);
    }

    #[test]
    fn dns_is_limited_to_resolvers_and_outbound() {
        let s = ruleset(&["203.0.113.0/24".into()], &egress());
        assert!(!s.contains("\n    udp dport 53 accept"), "{}", s);
        assert!(s.contains("ip daddr 192.0.2.53 udp dport 53 accept"));
        let input = &s[s.find("chain input").unwrap()..s.find("chain output").unwrap()];
        assert!(!input.contains("dport 53"), "{}", input);
    }

    #[test]
    fn ruleset_keeps_the_link_and_alert_path_alive() {
        let s = ruleset(&["2001:db8::/32".into()], &egress());
        assert!(s.contains("nd-neighbor-solicit"));
        assert!(s.contains("udp sport 68 udp dport 67 accept"));
        assert!(s.contains("ip daddr 149.154.167.220 tcp dport 443 accept"));
    }

    /// `nft -c` parses and validates without applying. Needs root and nft;
    /// CI runs it with sudo.
    #[test]
    #[ignore]
    fn nft_accepts_the_ruleset() {
        use std::io::Write;
        let e = Egress {
            resolvers: vec![
                "192.0.2.53".parse().unwrap(),
                "2001:db8::53".parse().unwrap(),
            ],
            notify: vec![
                ("149.154.167.220".parse().unwrap(), 443),
                ("2001:db8::443".parse().unwrap(), 8443),
            ],
        };
        let script = ruleset(&["203.0.113.0/24".into(), "2001:db8::/32".into()], &e);
        let mut child = std::process::Command::new("nft")
            .args(["-c", "-f", "-"])
            .stdin(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("nft must be installed");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(script.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&out.stderr),
            script
        );
    }

    #[test]
    fn resolv_conf_parsing() {
        let ips = parse_resolv_conf(
            "# comment\nnameserver 127.0.0.53\nnameserver 192.0.2.1\nnameserver fe80::1%eth0\noptions edns0\n",
        );
        assert_eq!(
            ips,
            vec![
                "192.0.2.1".parse::<IpAddr>().unwrap(),
                "fe80::1".parse().unwrap()
            ]
        );
    }

    #[test]
    fn notification_urls_are_parsed() {
        assert_eq!(
            url_host_port("https://hooks.slack.com/services/x"),
            Some(("hooks.slack.com".into(), 443))
        );
        assert_eq!(
            url_host_port("http://user:pw@10.0.0.5:8080/h?x=1"),
            Some(("10.0.0.5".into(), 8080))
        );
        assert_eq!(
            url_host_port("https://[2001:db8::1]:8443/"),
            Some(("2001:db8::1".into(), 8443))
        );
        assert_eq!(url_host_port("ftp://x"), None);
    }
}
