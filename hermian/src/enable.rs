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
const WATCHDOG_UNIT_TEMPLATE: &str =
    include_str!("../../packaging/systemd/hermian-watchdog.service");
const WATCHDOG_TIMER_TEMPLATE: &str =
    include_str!("../../packaging/systemd/hermian-watchdog.timer");
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

/// The unit for this binary. Isolation and the Telegram responses need
/// nftables (`CAP_NET_ADMIN`); disconnecting a session needs `CAP_KILL`.
/// Neither is granted unless configured.
fn render_unit(exec_path: &str, isolation_enabled: bool, actions_enabled: bool) -> String {
    let mut caps = "CAP_SYS_ADMIN CAP_BPF CAP_PERFMON CAP_NET_RAW CAP_SYS_PTRACE CAP_DAC_READ_SEARCH CAP_AUDIT_CONTROL CAP_AUDIT_READ".to_string();
    if isolation_enabled || actions_enabled {
        caps.push_str(" CAP_NET_ADMIN");
    }
    if actions_enabled {
        caps.push_str(" CAP_KILL");
    }
    UNIT_TEMPLATE
        .replace("%EXEC%", exec_path)
        .replace("%CAP_BOUNDING%", &format!("CapabilityBoundingSet={}", caps))
        .replace("%CAP_AMBIENT%", &format!("AmbientCapabilities={}", caps))
}

/// The watchdog runs as a plain root oneshot via a timer: it pages and
/// restarts the daemon when the heartbeat goes stale, so it must not share
/// the daemon's fate (crash, capabilities, memory limits).
fn render_watchdog_units(exec_path: &str) -> (String, String) {
    (
        WATCHDOG_UNIT_TEMPLATE.replace("%EXEC%", exec_path),
        WATCHDOG_TIMER_TEMPLATE.to_string(),
    )
}

pub fn run(args: &EnableArgs) -> Result<()> {
    config::require_root()?;
    let st = Style::detect();
    if !args.quiet {
        println!("\n{}\n", st.brand(hermian_core::VERSION));
    }
    let cfg = config::load_config()?;

    for dir in [paths::state_dir(), paths::log_dir(), paths::run_dir()] {
        fs::create_dir_all(&dir)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    }
    if let Some(parent) = paths::config_path().parent() {
        let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
    }
    let _ = fs::set_permissions(paths::config_path(), fs::Permissions::from_mode(0o600));

    // Show settings new in this version in the existing file, commented
    // out. Before the hashes are recorded, so the integrity check matches.
    match document_new_settings() {
        Ok(Some(n)) if !args.quiet => println!(
            "{}",
            st.dim(&format!(
                "Updated {}: {} line(s) of new settings, commented out; settings no longer used \
                 are commented out too (backup: config.toml.bak).",
                paths::config_path().display(),
                n
            ))
        ),
        Ok(_) => {}
        Err(e) => eprintln!("hermian: left the config as it was: {:#}", e),
    }
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
    let unit = render_unit(
        &exe_s,
        isolation,
        cfg.notifications.telegram.actions_enabled(),
    );
    let unit_changed = fs::read_to_string(paths::UNIT_PATH)
        .map(|c| c != unit)
        .unwrap_or(true);
    if unit_changed {
        fs::write(paths::UNIT_PATH, &unit)?;
        fs::set_permissions(paths::UNIT_PATH, fs::Permissions::from_mode(0o644))?;
    }

    let (watchdog_unit, watchdog_timer) = render_watchdog_units(&exe_s);
    for (path, content) in [
        (paths::WATCHDOG_UNIT_PATH, &watchdog_unit),
        (paths::WATCHDOG_TIMER_PATH, &watchdog_timer),
    ] {
        if fs::read_to_string(path)
            .map(|c| c != *content)
            .unwrap_or(true)
        {
            fs::write(path, content)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o644))?;
        }
    }

    // An existing hook is refreshed too, so upgrades (the package's postinst
    // runs `enable` without --with-pam) pick up placement fixes.
    if args.with_pam
        || (pam_hook_configured() && std::path::Path::new(paths::PAM_MODULE_PATH).exists())
    {
        enable_pam_module()?;
    }

    run_systemctl(&["daemon-reload"])?;
    let running = status::read_state()
        .map(|s| status::pid_alive(s.pid))
        .unwrap_or(false);
    if running {
        // Upgrade path: pick up the new binary/unit. The marker tells the
        // stopping daemon this restart is ours, so it isn't paged as an
        // unexplained stop.
        run_systemctl(&["enable", "hermian"])?;
        let _ = crate::config::write_secure(
            &paths::planned_restart_file(),
            &chrono::Utc::now().timestamp().to_string(),
        );
        run_systemctl(&["restart", "hermian"])?;
    } else if run_systemctl(&["enable", "--now", "hermian"]).is_err() {
        run_systemctl(&["start", "hermian"])?;
    }
    // The dead-man switch: a timer, not part of the daemon, so it still runs
    // when the daemon can't. Failure to enable it shouldn't abort an
    // otherwise finished install.
    if let Err(e) = run_systemctl(&["enable", "--now", "hermian-watchdog.timer"]) {
        eprintln!("hermian: could not enable the watchdog timer: {:#}", e);
    }

    wait_for_startup()?;
    if !args.quiet {
        println!("{}", st.ok("Hermian enabled."));
        println!();
        status::cmd_status(false)?;
    }
    Ok(())
}

/// Add template settings the config lacks, commented out (see confmerge).
/// Returns how many lines were added, if any.
fn document_new_settings() -> Result<Option<usize>> {
    let path = paths::config_path();
    let current = fs::read_to_string(&path)?;
    // Retired settings first (commented out, see confmerge::RETIRED), then
    // the new ones; one backup of the original either way.
    let retired = crate::confmerge::retire(&current);
    let base = retired.as_deref().unwrap_or(&current);
    let merged = crate::confmerge::merge(
        base,
        hermian_core::DEFAULT_CONFIG_TOML,
        hermian_core::VERSION,
    );
    let Some(merged) = merged.or(retired) else {
        return Ok(None);
    };
    let added = merged
        .lines()
        .count()
        .saturating_sub(current.lines().count());
    config::write_secure(&backup_path(&path), &current)?;
    config::replace_file_keep_mode(&path, &merged)?;
    Ok(Some(added))
}

pub fn backup_path(config: &std::path::Path) -> std::path::PathBuf {
    let mut s = config.as_os_str().to_owned();
    s.push(".bak");
    std::path::PathBuf::from(s)
}

fn init_baseline(cfg: &hermian_core::Config, no_baseline: bool) -> Result<()> {
    if paths::baseline_file().exists() {
        return Ok(());
    }
    // --no-baseline skips the learning period, it doesn't switch novelty off:
    // it used to write a disabled baseline, and every novelty rule went quiet
    // for good.
    let baseline = if no_baseline && cfg.baseline.enabled {
        Baseline::judging_from(Utc::now(), cfg.baseline.duration_hours)
    } else {
        Baseline::new(
            cfg.baseline.enabled,
            cfg.baseline.duration_hours,
            Utc::now(),
        )
    };
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
    let Some(new_content) = pam_config_with_hook(&content) else {
        return Ok(());
    };
    // Keep a backup; PAM edits deserve one.
    if !content.contains("pam_hermian.so") {
        let _ = fs::copy(sshd_pam, "/etc/pam.d/sshd.hermian-bak");
    }
    config::replace_file_keep_mode(sshd_pam, &new_content)?;
    Ok(())
}

/// Whether `/etc/pam.d/sshd` already loads the Hermian module.
pub fn pam_hook_configured() -> bool {
    fs::read_to_string("/etc/pam.d/sshd")
        .map(|c| {
            c.lines()
                .any(|l| l.contains("pam_hermian.so") && !l.trim_start().starts_with('#'))
        })
        .unwrap_or(false)
}

/// `content` with Hermian's PAM lines, or `None` if nothing needs to change.
///
/// The module is referenced by absolute path. A bare `pam_hermian.so` is
/// looked up in libpam's own directory, which is `/lib/<triplet>/security`
/// on Debian/Ubuntu and `/usr/lib64/security` on RHEL, not the
/// `/usr/lib/security` we install to, so the hook silently never loaded.
/// Older lines (bare name, or `auth` at the end) are rewritten.
///
/// The `auth` line goes *before* the first auth rule. Appended at the end it
/// never ran on a failed login: Debian's common-auth ends failures with
/// `pam_deny requisite`, which stops the stack. The `session` line can stay
/// last, since session stacks don't stop early on success.
fn pam_config_with_hook(content: &str) -> Option<String> {
    let comment = "# HERMIAN: passive auth telemetry (never affects the auth decision)";
    let auth = format!("auth    optional    {}", paths::PAM_MODULE_PATH);
    let session = format!("session optional    {}", paths::PAM_MODULE_PATH);
    let kept: Vec<&str> = content
        .lines()
        .filter(|l| !l.contains("pam_hermian.so") && !l.contains("# HERMIAN:"))
        .collect();
    let is_auth_rule = |l: &str| {
        let t = l.trim_start();
        t.starts_with("auth")
            || t.starts_with("-auth")
            || t == "@include common-auth"
            || t.starts_with("@include common-auth ")
            || t.starts_with("@include password-auth")
            || t.starts_with("@include system-auth")
            || t.starts_with("substack")
    };
    let first_auth = kept.iter().position(|l| is_auth_rule(l));
    let mut lines: Vec<String> = kept.iter().map(|l| l.to_string()).collect();
    match first_auth {
        Some(i) => {
            lines.insert(i, auth);
            lines.insert(i, comment.to_string());
            lines.push(session);
        }
        None => {
            lines.push(comment.to_string());
            lines.push(auth);
            lines.push(session);
        }
    }
    let out = format!("{}\n", lines.join("\n"));
    (out != content).then_some(out)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_capabilities_only_when_configured() {
        let plain = render_unit("/usr/bin/hermian", false, false);
        assert!(!plain.contains("CAP_NET_ADMIN") && !plain.contains("CAP_KILL"));
        let iso = render_unit("/usr/bin/hermian", true, false);
        assert!(iso.contains("CAP_NET_ADMIN") && !iso.contains("CAP_KILL"));
        let actions = render_unit("/usr/bin/hermian", false, true);
        assert!(actions.contains("CAP_NET_ADMIN") && actions.contains("CAP_KILL"));
        assert!(actions.contains("ExecStart=/usr/bin/hermian run"));
    }

    #[test]
    fn watchdog_units_watch_this_binary() {
        let (unit, timer) = render_watchdog_units("/usr/bin/hermian");
        assert!(unit.contains("ExecStart=/usr/bin/hermian watchdog"));
        assert!(unit.contains("Type=oneshot"));
        assert!(timer.contains("Unit=hermian-watchdog.service"));
        assert!(timer.contains("OnUnitActiveSec=60s"));
    }

    #[test]
    fn pam_hook_uses_the_absolute_module_path() {
        let base = "# PAM configuration for sshd\n@include common-auth\nsession required pam_loginuid.so\n";
        let out = pam_config_with_hook(base).unwrap();
        let auth = format!("auth    optional    {}", paths::PAM_MODULE_PATH);
        let lines: Vec<&str> = out.lines().collect();
        // The auth hook runs before common-auth, so failed logins reach it.
        let hook_at = lines.iter().position(|l| *l == auth).unwrap();
        let common_at = lines
            .iter()
            .position(|l| *l == "@include common-auth")
            .unwrap();
        assert!(hook_at < common_at, "{}", out);
        assert_eq!(lines[0], "# PAM configuration for sshd");
        assert!(lines.last().unwrap().starts_with("session optional"));
        // Idempotent.
        assert!(pam_config_with_hook(&out).is_none());
        // Old bare-name lines are replaced, not duplicated.
        let old = format!(
            "{}# HERMIAN: passive auth telemetry\nauth    optional    pam_hermian.so\nsession optional    pam_hermian.so\n",
            base
        );
        let fixed = pam_config_with_hook(&old).unwrap();
        assert_eq!(fixed, out);
    }
}
