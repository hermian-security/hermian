//! `hermian watchdog`: the dead-man switch.
//!
//! A systemd timer runs this every minute. It checks the daemon's heartbeat
//! and the unit state; if the daemon is wedged it pages, restarts it and
//! leaves a note so the next start can explain the gap. If the unit failed
//! (or is crash-looping) it pages and tries to start it. This is the one
//! thing that still works when the daemon doesn't: it closes the "kill -9
//! the security daemon and the host looks clean" hole.
//!
//! Alerts go straight out (persist + channels) because there is no daemon to
//! hand them to, and repeats are rate-limited through a small state file.

use std::fs;
use std::time::{Duration, SystemTime};

use anyhow::Result;
use chrono::{DateTime, Utc};
use hermian_core::alert::Finding;
use hermian_core::config::NotificationsCfg;
use hermian_core::{Alert, DetectionId, Severity};

use crate::status;
use crate::{config, daemon, heartbeat, notify, paths, procsrc};

/// Re-page at most this often while the problem persists.
const REMIND_AFTER: Duration = Duration::from_secs(3600);
/// A unit in `activating` this many times without a heartbeat is crash-looping.
const CRASH_LOOP_RESTARTS: u64 = 5;

#[derive(Debug, PartialEq)]
pub enum Verdict {
    /// The daemon is fine, or intentionally stopped.
    Ok,
    /// Unit is active but the heartbeat stopped; `age` is None when it never
    /// appeared.
    Wedged { age: Option<Duration> },
    /// systemd reports a failure or a crash loop.
    Failed,
}

pub fn judge(
    unit: &str,
    heartbeat_age: Option<Duration>,
    active_for: Option<Duration>,
    restarts: u64,
) -> Verdict {
    match unit {
        "active" => match heartbeat_age {
            Some(age) if age > heartbeat::STALE => Verdict::Wedged { age: Some(age) },
            Some(_) => Verdict::Ok,
            None => match active_for {
                Some(up) if up <= heartbeat::START_GRACE => Verdict::Ok,
                _ => Verdict::Wedged { age: None },
            },
        },
        "failed" => Verdict::Failed,
        // Inactive is an intentional stop (systemctl stop, or uninstall in
        // progress). Activating is systemd restarting the unit; only a
        // sustained loop without a heartbeat is treated as a failure.
        "activating" if heartbeat_age.is_none() && restarts >= CRASH_LOOP_RESTARTS => {
            Verdict::Failed
        }
        _ => Verdict::Ok,
    }
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct WatchdogState {
    /// Heartbeat epoch-second stamp of the last alert (0: no heartbeat).
    #[serde(default)]
    last_stamp: u64,
    #[serde(default)]
    last_alert_at: Option<DateTime<Utc>>,
}

/// Page when the situation changed, or an hour has passed.
fn should_alert(stamp: u64, prev: &WatchdogState, now: DateTime<Utc>) -> bool {
    if prev.last_stamp != stamp {
        return true;
    }
    match prev.last_alert_at {
        Some(t) => (now - t)
            .to_std()
            .map(|d| d >= REMIND_AFTER)
            .unwrap_or(true),
        None => true,
    }
}

pub fn run() -> Result<()> {
    config::require_root()?;
    let cfg = config::load_config()?;
    let age = heartbeat::age(&paths::heartbeat_file(), SystemTime::now());
    let verdict = judge(
        &status::unit_state(),
        age,
        unit_active_for(),
        unit_restarts(),
    );
    match verdict {
        Verdict::Ok => Ok(()),
        verdict => respond(&cfg.notifications, age, verdict),
    }
}

fn respond(cfg: &NotificationsCfg, age: Option<Duration>, verdict: Verdict) -> Result<()> {
    let restarts = unit_restarts();
    let (severity, title, what) = match &verdict {
        Verdict::Wedged { age: Some(d) } => (
            Severity::High,
            "Hermian daemon is not responding",
            format!(
                "The daemon's heartbeat has not updated for {}. The process is still running but no longer doing its job.",
                duration_text(*d)
            ),
        ),
        Verdict::Wedged { age: None } => (
            Severity::High,
            "Hermian daemon is not responding",
            "The unit is running but no heartbeat has ever been written: the daemon isn't reaching its event loop (or can't write to the run directory).".to_string(),
        ),
        _ => (
            Severity::Critical,
            "Hermian daemon is down",
            format!(
                "systemd reports the unit as failed after {} restart(s); the daemon is not running and nothing is monitored.",
                restarts
            ),
        ),
    };

    let verb = if matches!(verdict, Verdict::Wedged { .. }) {
        "restart"
    } else {
        "start"
    };
    let mut st = load_state();
    if should_alert(heartbeat_stamp(), &st, Utc::now()) {
        let actions: &[&str] = &[
            "Check the journal: journalctl -u hermian -n 100.",
            "If it keeps happening, look for a crash or a config error in /etc/hermian/config.toml.",
        ];
        let why = "This is the dead-man switch: it runs from a systemd timer, not from the daemon, so a hung or killed daemon can't silence it.";
        let finding = Finding::new(DetectionId::Self_, severity, title, "selfprotect|watchdog")
            .what(&what)
            .why(why)
            .actions(actions.iter().copied())
            .fact("Last heartbeat", heartbeat_text(age))
            .fact("Unit", unit_text(&status::unit_state(), restarts))
            .fact(
                "Action",
                format!(
                    "{}ing the daemon",
                    if verb == "start" { "start" } else { "restart" }
                ),
            );
        let alert = Alert::from_finding(
            finding,
            format!("HER-WD-{}", Utc::now().format("%Y%m%d-%H%M%S")),
            procsrc::hostname(),
            Utc::now(),
        );
        let errors = notify::store_and_send(&alert, cfg);
        for (channel, e) in &errors {
            daemon::log_daemon(
                Severity::High,
                &format!("watchdog: could not reach {}: {}", channel, e),
            );
        }
        st.last_stamp = heartbeat_stamp();
        st.last_alert_at = Some(Utc::now());
        save_state(&st);
    }

    // Restart even when the page was rate-limited; a wedged daemon that
    // recovers must not wait out the reminder window.
    if matches!(verdict, Verdict::Wedged { .. }) {
        heartbeat::note_restart(&paths::watchdog_note_file(), &heartbeat_text(age));
    }
    match systemctl(&[verb, "hermian"]) {
        Ok(()) => {
            daemon::log_daemon(
                Severity::High,
                &format!("watchdog: {}ed hermian after: {}", verb, what),
            );
            Ok(())
        }
        Err(e) => {
            daemon::log_daemon(
                Severity::High,
                &format!("watchdog: could not {} hermian: {}", verb, e),
            );
            anyhow::bail!("systemctl {} hermian failed: {}", verb, e)
        }
    }
}

fn duration_text(d: Duration) -> String {
    let s = d.as_secs();
    if s < 60 {
        format!("{}s", s)
    } else {
        format!("{}m {:02}s", s / 60, s % 60)
    }
}

fn heartbeat_text(age: Option<Duration>) -> String {
    match age {
        Some(d) => format!("{} ago", duration_text(d)),
        None => "never".to_string(),
    }
}

fn unit_text(state: &str, restarts: u64) -> String {
    if restarts > 0 {
        format!(
            "{} ({} restart{})",
            state,
            restarts,
            if restarts == 1 { "" } else { "s" }
        )
    } else {
        state.to_string()
    }
}

fn heartbeat_stamp() -> u64 {
    fs::metadata(paths::heartbeat_file())
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn load_state() -> WatchdogState {
    fs::read_to_string(paths::watchdog_state_file())
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

fn save_state(st: &WatchdogState) {
    if let Ok(text) = serde_json::to_string(st) {
        let _ = config::write_secure(&paths::watchdog_state_file(), &text);
    }
}

fn unit_restarts() -> u64 {
    systemctl_show("NRestarts")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

/// How long the unit has been active, from systemd's monotonic timestamp.
fn unit_active_for() -> Option<Duration> {
    let micros: u64 = systemctl_show("ActiveEnterTimestampMonotonic")?
        .parse()
        .ok()?;
    if micros == 0 {
        return None;
    }
    let uptime = fs::read_to_string("/proc/uptime").ok()?;
    let up_secs: f64 = uptime.split_whitespace().next()?.parse().ok()?;
    let active = up_secs - micros as f64 / 1_000_000.0;
    Some(Duration::from_secs_f64(active.max(0.0)))
}

fn systemctl_show(prop: &str) -> Option<String> {
    let out = crate::procsrc::system_command("systemctl")
        .args(["show", "hermian", "-p", prop])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    Some(text.trim().strip_prefix(&format!("{}=", prop))?.to_string())
}

fn systemctl(args: &[&str]) -> Result<(), String> {
    let out = crate::procsrc::system_command("systemctl")
        .args(args)
        .output()
        .map_err(|e| format!("failed to run systemctl: {}", e))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(n: u64) -> Option<Duration> {
        Some(Duration::from_secs(n))
    }

    #[test]
    fn judge_covers_the_unit_states() {
        // Healthy: fresh heartbeat.
        assert_eq!(judge("active", secs(10), None, 0), Verdict::Ok);
        // Wedged: heartbeat went quiet.
        assert_eq!(
            judge("active", secs(400), None, 0),
            Verdict::Wedged { age: secs(400) }
        );
        // Just started: no heartbeat yet, still inside the grace period.
        assert_eq!(judge("active", None, secs(30), 0), Verdict::Ok);
        // Started long ago but never wrote one.
        assert_eq!(
            judge("active", None, secs(600), 0),
            Verdict::Wedged { age: None }
        );
        // If the start time can't be read, alert rather than stay quiet.
        assert_eq!(
            judge("active", None, None, 0),
            Verdict::Wedged { age: None }
        );
        // Failed, and crash-looping without a heartbeat.
        assert_eq!(judge("failed", secs(5), None, 0), Verdict::Failed);
        assert_eq!(judge("activating", None, None, 12), Verdict::Failed);
        // A normal restart cycle: activating, but not for long.
        assert_eq!(judge("activating", None, None, 1), Verdict::Ok);
        // Intentional stops and unknown units stay silent.
        assert_eq!(judge("inactive", secs(9999), None, 0), Verdict::Ok);
        assert_eq!(judge("deactivating", None, None, 0), Verdict::Ok);
        assert_eq!(judge("unknown", None, None, 0), Verdict::Ok);
    }

    #[test]
    fn alerts_change_with_the_situation_and_otherwise_remind_hourly() {
        let now = Utc::now();
        let mut st = WatchdogState::default();
        // Never alerted: page.
        assert!(should_alert(100, &st, now));
        st.last_stamp = 100;
        st.last_alert_at = Some(now);
        // Same situation again: quiet.
        assert!(!should_alert(100, &st, now + chrono::Duration::minutes(10)));
        // A new heartbeat stamp means the situation changed: page.
        assert!(should_alert(200, &st, now + chrono::Duration::minutes(10)));
        // Same situation after an hour: remind.
        assert!(should_alert(100, &st, now + chrono::Duration::minutes(61)));
    }
}
