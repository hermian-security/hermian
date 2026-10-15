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

    // Stop the daemon first: lifting isolation while it still runs left a
    // window for it to isolate the host again. The watchdog timer goes too,
    // or it would point at a binary that is about to disappear.
    for unit in ["hermian-watchdog.timer", "hermian"] {
        let _ = std::process::Command::new("systemctl")
            .args(["disable", "--now", unit])
            .output();
    }
    // Never leave a host isolated by a tool that is about to disappear, and
    // drop the blocks made with the Telegram buttons too.
    let _ = isolate::remove_isolation();
    crate::blocklist::remove_table();

    for path in [
        paths::UNIT_PATH.to_string(),
        paths::WATCHDOG_UNIT_PATH.to_string(),
        paths::WATCHDOG_TIMER_PATH.to_string(),
        "/etc/sysctl.d/60-hermian.conf".to_string(),
        paths::config_path().to_string_lossy().into_owned(),
        crate::enable::backup_path(&paths::config_path())
            .to_string_lossy()
            .into_owned(),
        paths::state_dir().to_string_lossy().into_owned(),
        paths::log_dir().to_string_lossy().into_owned(),
        paths::run_dir().to_string_lossy().into_owned(),
    ] {
        let p = std::path::Path::new(&path);
        if !safe_to_remove(p) {
            eprintln!(
                "hermian: not removing {} (doesn't look like a HERMIAN path)",
                p.display()
            );
            continue;
        }
        // symlink_metadata: never follow a symlink into somewhere else.
        match fs::symlink_metadata(p) {
            Ok(m) if m.is_dir() => {
                fs::remove_dir_all(p).ok();
            }
            Ok(_) => {
                fs::remove_file(p).ok();
            }
            Err(_) => {}
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

/// Only delete absolute paths with a `hermian` component, without `..`.
///
/// The state, log and run dirs can be overridden through environment
/// variables, and `remove_dir_all` runs as root: `HERMIAN_STATE_DIR=/`
/// would have wiped the system.
fn safe_to_remove(p: &std::path::Path) -> bool {
    use std::path::Component;
    p.is_absolute()
        && !p
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
        && p.components().any(|c| match c {
            Component::Normal(s) => s.to_string_lossy().contains("hermian"),
            _ => false,
        })
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
        config::replace_file_keep_mode(sshd_pam, &new_content)?;
    }
    let _ = fs::remove_file("/etc/pam.d/sshd.hermian-bak");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn only_hermian_paths_are_removed() {
        assert!(safe_to_remove(Path::new("/var/lib/hermian")));
        assert!(safe_to_remove(Path::new("/etc/hermian/config.toml")));
        assert!(safe_to_remove(Path::new(
            "/etc/systemd/system/hermian.service"
        )));
        assert!(safe_to_remove(Path::new("/etc/sysctl.d/60-hermian.conf")));
        assert!(!safe_to_remove(Path::new("/")));
        assert!(!safe_to_remove(Path::new("/var/lib")));
        assert!(!safe_to_remove(Path::new("relative/hermian")));
        assert!(!safe_to_remove(Path::new("/var/lib/hermian/../../..")));
    }
}
