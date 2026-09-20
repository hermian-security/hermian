//! `hermian uninstall`: remove the unit, state, logs, PAM hook and binary.

use std::fs;
use std::io::Write;

use anyhow::{Context, Result};

use crate::cli::UninstallArgs;
use crate::ui::Style;
use crate::{config, isolate, paths, procsrc};

pub fn run(args: &UninstallArgs) -> Result<()> {
    config::require_root()?;
    let st = Style::detect();

    if !args.yes {
        print!("Remove HERMIAN completely (daemon, unit, config, alerts, logs, binary)? [y/N] ");
        std::io::stdout().flush()?;
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        let a = answer.trim();
        if !a.eq_ignore_ascii_case("y") && !a.eq_ignore_ascii_case("yes") {
            println!("Aborted.");
            return Ok(());
        }
    }

    // Never leave a host isolated by a tool that is about to disappear.
    let _ = isolate::remove_isolation();

    let _ = std::process::Command::new("systemctl")
        .args(["disable", "--now", "hermian"])
        .output();

    for path in [
        paths::UNIT_PATH.to_string(),
        "/etc/sysctl.d/60-hermian.conf".to_string(),
        paths::config_path().to_string_lossy().into_owned(),
        paths::state_dir().to_string_lossy().into_owned(),
        paths::log_dir().to_string_lossy().into_owned(),
        paths::run_dir().to_string_lossy().into_owned(),
    ] {
        let p = std::path::Path::new(&path);
        if p.is_dir() {
            fs::remove_dir_all(p).ok();
        } else if p.exists() {
            fs::remove_file(p).ok();
        }
    }
    if let Some(cfg_dir) = paths::config_path().parent() {
        let _ = fs::remove_dir(cfg_dir); // only if empty
    }
    let _ = std::process::Command::new("systemctl")
        .args(["daemon-reload"])
        .output();

    remove_pam_line()?;
    let _ = fs::remove_file(paths::PAM_MODULE_PATH);

    if let Ok(exe) = procsrc::current_exe_path() {
        let _ = fs::remove_file(exe);
    }

    println!("{}", st.ok("HERMIAN removed."));
    println!(
        "  {}",
        st.dim("No unit, state, logs, PAM hook, or privileged process remains.")
    );
    Ok(())
}

fn remove_pam_line() -> Result<()> {
    let sshd_pam = std::path::Path::new("/etc/pam.d/sshd");
    if !sshd_pam.exists() {
        return Ok(());
    }
    let content = fs::read_to_string(sshd_pam).context("failed to read /etc/pam.d/sshd")?;
    let filtered: Vec<&str> = content
        .lines()
        .filter(|l| !l.contains("pam_hermian.so") && !l.contains("# HERMIAN:"))
        .collect();
    let new_content = format!("{}\n", filtered.join("\n"));
    if new_content != content {
        fs::write(sshd_pam, new_content)?;
    }
    let _ = fs::remove_file("/etc/pam.d/sshd.hermian-bak");
    Ok(())
}
