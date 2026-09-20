//! `hermian enable`: idempotent install/upgrade of the systemd unit, state
//! directories, integrity hashes and baseline, then start the daemon.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use chrono::Utc;
use hermian_core::Baseline;

use crate::cli::EnableArgs;
use crate::ui::Style;
use crate::{config, paths, procsrc, selfprotect, status};

const UNIT_TEMPLATE: &str = include_str!("../../packaging/systemd/hermian.service");
const SYSCTL_TEMPLATE: &str = include_str!("../../packaging/sysctl/60-hermian.conf");
const SYSCTL_PATH: &str = "/etc/sysctl.d/60-hermian.conf";

/// Raise inotify limits if they are below what reliable monitoring needs.
/// Never lowers a value the operator has already set higher.
fn ensure_inotify_limits() -> Result<()> {
    let read = |k: &str| -> u64 {
        fs::read_to_string(format!("/proc/sys/fs/inotify/{}", k))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0)
    };
    let want_watches = 524_288u64;
    let want_instances = 512u64;
    let cur_w = read("max_user_watches");
    let cur_i = read("max_user_instances");
    if cur_w >= want_watches && cur_i >= want_instances {
        return Ok(());
    }
    fs::write(SYSCTL_PATH, SYSCTL_TEMPLATE)?;
    if cur_w < want_watches {
        let _ = fs::write(
            "/proc/sys/fs/inotify/max_user_watches",
            want_watches.to_string(),
        );
    }
    if cur_i < want_instances {
        let _ = fs::write(
            "/proc/sys/fs/inotify/max_user_instances",
            want_instances.to_string(),
        );
    }
    Ok(())
}

fn render_unit(exec_path: &str, isolation_enabled: bool) -> String {
    let caps_common = "CAP_SYS_ADMIN CAP_BPF CAP_PERFMON CAP_NET_RAW CAP_SYS_PTRACE CAP_DAC_READ_SEARCH CAP_AUDIT_CONTROL CAP_AUDIT_READ";
    let caps = if isolation_enabled {
        format!("{} CAP_NET_ADMIN", caps_common)
    } else {
        caps_common.to_string()
    };
    UNIT_TEMPLATE
        .replace("%EXEC%", exec_path)
        .replace("%CAP_BOUNDING%", &format!("CapabilityBoundingSet={}", caps))
        .replace("%CAP_AMBIENT%", &format!("AmbientCapabilities={}", caps))
}

pub fn run(args: &EnableArgs) -> Result<()> {
    config::require_root()?;
    let st = Style::detect();
    let cfg = config::load_config()?;

    for dir in [paths::state_dir(), paths::log_dir(), paths::run_dir()] {
        fs::create_dir_all(&dir)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    }
    if let Some(parent) = paths::config_path().parent() {
        let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
    }
    let _ = fs::set_permissions(paths::config_path(), fs::Permissions::from_mode(0o600));

    selfprotect::init_hashes().context("failed to initialise integrity hashes")?;
    init_baseline(&cfg, args.no_baseline)?;
    if let Err(e) = ensure_inotify_limits() {
        eprintln!(
            "hermian: could not raise inotify limits ({}); file watchers may be degraded",
            e
        );
    }

    let exe = procsrc::current_exe_path()?;
    let exe_s = exe.to_string_lossy().into_owned();
    let isolation = cfg.response.auto_isolate || !cfg.response.management_cidrs.is_empty();
    let unit = render_unit(&exe_s, isolation);
    let unit_changed = fs::read_to_string(paths::UNIT_PATH)
        .map(|c| c != unit)
        .unwrap_or(true);
    if unit_changed {
        fs::write(paths::UNIT_PATH, &unit)?;
        fs::set_permissions(paths::UNIT_PATH, fs::Permissions::from_mode(0o644))?;
    }

    if args.with_pam {
        enable_pam_module()?;
    }

    run_systemctl(&["daemon-reload"])?;
    let running = status::read_state()
        .map(|s| status::pid_alive(s.pid))
        .unwrap_or(false);
    if running {
        // Upgrade path: pick up the new binary/unit.
        run_systemctl(&["enable", "hermian"])?;
        run_systemctl(&["restart", "hermian"])?;
    } else if run_systemctl(&["enable", "--now", "hermian"]).is_err() {
        run_systemctl(&["start", "hermian"])?;
    }

    wait_for_startup()?;
    if !args.quiet {
        println!("{}", st.ok("HERMIAN enabled."));
        println!();
        status::cmd_status(false)?;
    }
    Ok(())
}

fn init_baseline(cfg: &hermian_core::Config, no_baseline: bool) -> Result<()> {
    if paths::baseline_file().exists() {
        return Ok(());
    }
    let baseline = Baseline::new(
        cfg.baseline.enabled && !no_baseline,
        cfg.baseline.duration_hours,
        Utc::now(),
    );
    config::save_baseline(&baseline)
}

fn wait_for_startup() -> Result<()> {
    let started = Instant::now();
    let deadline = started + Duration::from_secs(30);
    while Instant::now() < deadline {
        if let Some(state) = status::read_state() {
            let fresh = (Utc::now() - state.updated_at).num_seconds() < 60;
            if fresh
                && status::pid_alive(state.pid)
                && state.started_at.timestamp() >= (Utc::now().timestamp() - 90)
            {
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_millis(400));
    }
    anyhow::bail!("daemon did not become ready within 30s; see: journalctl -u hermian -n 50")
}

fn enable_pam_module() -> Result<()> {
    let pam_path = std::path::Path::new(paths::PAM_MODULE_PATH);
    if !pam_path.exists() {
        anyhow::bail!(
            "PAM module not found at {}. Install it from the package before using --with-pam.",
            paths::PAM_MODULE_PATH
        );
    }
    let sshd_pam = std::path::Path::new("/etc/pam.d/sshd");
    if !sshd_pam.exists() {
        eprintln!("hermian: /etc/pam.d/sshd not found; skipping PAM hook");
        return Ok(());
    }
    let content = fs::read_to_string(sshd_pam)?;
    if content.contains("pam_hermian.so") {
        return Ok(());
    }
    let mut new_content = content.clone();
    if !new_content.ends_with('\n') {
        new_content.push('\n');
    }
    new_content.push_str("# HERMIAN: passive auth telemetry (never affects the auth decision)\n");
    new_content
        .push_str("auth    optional    pam_hermian.so\nsession optional    pam_hermian.so\n");
    // Keep a backup; PAM edits deserve one.
    let _ = fs::copy(sshd_pam, "/etc/pam.d/sshd.hermian-bak");
    fs::write(sshd_pam, new_content)?;
    Ok(())
}

fn run_systemctl(args: &[&str]) -> Result<()> {
    let out = std::process::Command::new("systemctl")
        .args(args)
        .output()
        .context("failed to run systemctl (is this a systemd host?)")?;
    if out.status.success() {
        Ok(())
    } else {
        anyhow::bail!(
            "systemctl {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )
    }
}
