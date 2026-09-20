//! Network isolation via an nftables table owned by HERMIAN.
//!
//! Isolation is never automatic unless `response.auto_isolate = true` *and*
//! `response.management_cidrs` is non-empty; those CIDRs (plus loopback and
//! established flows) remain reachable so the operator can still get in.

use anyhow::{Context, Result};

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

/// Build the complete ruleset as one atomic `nft -f -` script.
fn ruleset(management_cidrs: &[String]) -> String {
    let mut s = String::new();
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
        // Allow the operator's DNS so `hermian` itself and admin tooling keep working.
        s.push_str("    udp dport 53 accept\n");
        s.push_str("  }\n");
    }
    s.push_str("}\n");
    s
}

pub fn apply_isolation(management_cidrs: &[String]) -> Result<()> {
    if management_cidrs.is_empty() {
        anyhow::bail!("isolation requires response.management_cidrs in /etc/hermian/config.toml");
    }
    // Replace atomically: delete (ignore missing) then load the new table.
    let _ = run_nft(&["delete", "table", "inet", TABLE]);
    let script = ruleset(management_cidrs);
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
    apply_isolation(&cfg.response.management_cidrs)?;
    println!("{}", st.warn("Host isolated."));
    println!(
        "  Reachable: loopback, established flows, DNS, and {}",
        cfg.response.management_cidrs.join(", ")
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
    if is_isolated() {
        return;
    }
    let cidrs = cfg.response.management_cidrs.clone();
    tokio::task::spawn_blocking(move || match apply_isolation(&cidrs) {
        Ok(()) => crate::daemon::log_daemon(
            hermian_core::Severity::Critical,
            "auto-isolate triggered; host isolated (recover with: sudo hermian unisolate)",
        ),
        Err(e) => crate::daemon::log_daemon(
            hermian_core::Severity::High,
            &format!("auto-isolate failed: {:#}", e),
        ),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ruleset_contains_cidrs_and_v6() {
        let s = ruleset(&["203.0.113.0/24".into(), "2001:db8::/32".into()]);
        assert!(s.contains("ip saddr 203.0.113.0/24 accept"));
        assert!(s.contains("ip6 daddr 2001:db8::/32 accept"));
        assert!(s.contains("policy drop"));
    }
}
