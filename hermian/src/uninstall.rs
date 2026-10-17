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
        print!("Remove Hermian completely (daemon, unit, config, alerts, logs, binary)? [y/N] ");
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
        let _ = crate::procsrc::system_command("systemctl")
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
                "hermian: not removing {} (doesn't look like a Hermian path)",
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
    let _ = crate::procsrc::system_command("systemctl")
        .args(["daemon-reload"])
        .output();

    // The empty mount point systemd made for the unit's preload bind mount.
    // Only if it's still empty: content would be someone else's (or a
    // rootkit's, which is evidence).
    if fs::metadata("/etc/ld.so.preload").is_ok_and(|m| m.is_file() && m.len() == 0) {
        let _ = fs::remove_file("/etc/ld.so.preload");
    }

    remove_pam_line()?;
    let _ = fs::remove_file(paths::PAM_MODULE_PATH);
    let _ = fs::remove_file(paths::APT_SOURCES_PATH);
    let _ = fs::remove_file(paths::APT_KEYRING_PATH);

    // Installed from the .deb: let dpkg remove its own files and forget the
    // package. Deleting the binary by hand left `dpkg -l` showing
    // "ii hermian", so apt still thought it was installed.
    let purged = package_installed() && purge_package();
    if !purged {
        if package_installed() {
            eprintln!(
                "hermian: dpkg --purge hermian failed; the files are gone but run it \
                 yourself so apt forgets the package"
            );
        }
        if let Ok(exe) = procsrc::current_exe_path() {
            let _ = fs::remove_file(exe);
        }
    }

    println!("{}", st.ok("Hermian removed."));
    println!(
        "  {}",
        st.dim("No unit, state, logs, PAM hook, or privileged process remains.")
    );
    Ok(())
}

/// Whether dpkg has the hermian package installed.
fn package_installed() -> bool {
    crate::procsrc::system_command("dpkg-query")
        .args(["-W", "-f=${Status}", "hermian"])
        .output()
        .map(|o| o.status.success() && dpkg_status_installed(&String::from_utf8_lossy(&o.stdout)))
        .unwrap_or(false)
}

/// "install ok installed" is installed; "half-installed", "config-files"
/// and "not-installed" aren't, nor is a missing status.
fn dpkg_status_installed(status: &str) -> bool {
    status.split_whitespace().last() == Some("installed")
}

/// `dpkg --purge hermian`. The maintainer scripts only redo what uninstall
/// already did (units, PAM lines, state), so missing files are fine.
fn purge_package() -> bool {
    crate::procsrc::system_command("dpkg")
        .args(["--purge", "hermian"])
        .env("DEBIAN_FRONTEND", "noninteractive")
        .stdout(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
        && !package_installed()
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

    #[test]
    fn only_a_fully_installed_package_counts() {
        assert!(dpkg_status_installed("install ok installed"));
        assert!(!dpkg_status_installed("install ok half-installed"));
        assert!(!dpkg_status_installed("deinstall ok config-files"));
        assert!(!dpkg_status_installed("unknown ok not-installed"));
        assert!(!dpkg_status_installed(""));
    }
}
