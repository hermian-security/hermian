use std::path::PathBuf;

pub const DEFAULT_CONFIG_PATH: &str = "/etc/hermian/config.toml";
pub const DEFAULT_STATE_DIR: &str = "/var/lib/hermian";
pub const DEFAULT_LOG_DIR: &str = "/var/log/hermian";
pub const DEFAULT_RUN_DIR: &str = "/run/hermian";
pub const UNIT_PATH: &str = "/etc/systemd/system/hermian.service";
pub const WATCHDOG_UNIT_PATH: &str = "/etc/systemd/system/hermian-watchdog.service";
pub const WATCHDOG_TIMER_PATH: &str = "/etc/systemd/system/hermian-watchdog.timer";
pub const PAM_MODULE_PATH: &str = "/usr/lib/security/pam_hermian.so";

fn env_path(var: &str, default: &str) -> PathBuf {
    std::env::var_os(var)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(default))
}

pub fn config_path() -> PathBuf {
    env_path("HERMIAN_CONFIG", DEFAULT_CONFIG_PATH)
}

pub fn state_dir() -> PathBuf {
    env_path("HERMIAN_STATE_DIR", DEFAULT_STATE_DIR)
}

pub fn log_dir() -> PathBuf {
    env_path("HERMIAN_LOG_DIR", DEFAULT_LOG_DIR)
}

pub fn run_dir() -> PathBuf {
    env_path("HERMIAN_RUN_DIR", DEFAULT_RUN_DIR)
}

pub fn state_file() -> PathBuf {
    state_dir().join("state.json")
}

pub fn baseline_file() -> PathBuf {
    state_dir().join("baseline.json")
}

/// Persisted per-day engine state (ref counter, counters).
pub fn engine_state_file() -> PathBuf {
    state_dir().join("engine.json")
}

pub fn alerts_dir() -> PathBuf {
    state_dir().join("alerts")
}

pub fn collections_dir() -> PathBuf {
    state_dir().join("collections")
}

pub fn binary_hash_file() -> PathBuf {
    state_dir().join("binary.sha256")
}

pub fn config_hash_file() -> PathBuf {
    state_dir().join("config.sha256")
}

/// The daemon's heartbeat (run dir: it dies with the boot, by design).
pub fn heartbeat_file() -> PathBuf {
    run_dir().join("heartbeat")
}

/// Marker recording the current run; a leftover means the last stop was dirty.
pub fn run_marker_file() -> PathBuf {
    state_dir().join("running")
}

/// Note the watchdog leaves before restarting a wedged daemon.
pub fn watchdog_note_file() -> PathBuf {
    state_dir().join("watchdog-note")
}

/// Rate-limit state for the watchdog's alerts.
pub fn watchdog_state_file() -> PathBuf {
    state_dir().join("watchdog.json")
}

/// Alerts a channel still owes the last time it queued them, one directory
/// per channel.
pub fn pending_dir() -> PathBuf {
    state_dir().join("pending")
}

pub fn pending_dir_channel(name: &str) -> PathBuf {
    pending_dir().join(name)
}

pub fn alerts_log() -> PathBuf {
    log_dir().join("alerts.log")
}

pub fn pam_socket() -> PathBuf {
    run_dir().join("pam.sock")
}
