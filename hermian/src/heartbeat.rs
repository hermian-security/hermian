//! Support files for the dead-man switch: the daemon's heartbeat, the marker
//! that tells a clean stop from a crash, and the note the watchdog leaves
//! behind when it restarts a wedged daemon.
//!
//! The heartbeat lives in the run directory (tmpfs): it only means anything
//! for the current boot, and a reboot is not a wedge. The marker lives in the
//! state directory so it survives a crash; a marker still present at startup
//! means the previous run never got to clean up.

use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime};

/// The daemon refreshes the heartbeat every tick (30 s).
pub const INTERVAL: Duration = Duration::from_secs(30);
/// A heartbeat this old means the daemon is wedged, not just busy.
pub const STALE: Duration = Duration::from_secs(180);
/// No heartbeat this long after the unit started means the same.
pub const START_GRACE: Duration = Duration::from_secs(180);

pub fn touch(path: &Path) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let stamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Write-then-rename: the watchdog must never read a half-written file.
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, format!("{} {}\n", std::process::id(), stamp))?;
    fs::rename(&tmp, path)
}

/// How long ago the heartbeat was written, or `None` if there is none.
pub fn age(path: &Path, now: SystemTime) -> Option<Duration> {
    let modified = fs::metadata(path).ok()?.modified().ok()?;
    Some(now.duration_since(modified).unwrap_or_default())
}

/// Record this run in the marker, returning the previous run's contents if it
/// didn't stop cleanly.
pub fn start(marker: &Path) -> Option<String> {
    let previous = fs::read_to_string(marker)
        .ok()
        .filter(|s| !s.trim().is_empty());
    if let Some(dir) = marker.parent() {
        let _ = fs::create_dir_all(dir);
    }
    let body = format!(
        "{} {}\n",
        std::process::id(),
        chrono::Utc::now().to_rfc3339()
    );
    let _ = fs::write(marker, body);
    previous
}

/// Called when the daemon stops through SIGTERM/SIGINT.
pub fn clean_stop(marker: &Path) {
    let _ = fs::remove_file(marker);
}

/// The watchdog writes this before restarting a wedged daemon, so the next
/// start can say why the previous run died.
pub fn note_restart(path: &Path, reason: &str) {
    if let Some(dir) = path.parent() {
        let _ = fs::create_dir_all(dir);
    }
    let _ = fs::write(
        path,
        format!("{} {}\n", chrono::Utc::now().to_rfc3339(), reason),
    );
}

/// Read and delete the watchdog's restart note.
pub fn take_restart_note(path: &Path) -> Option<String> {
    let text = fs::read_to_string(path).ok()?;
    let _ = fs::remove_file(path);
    Some(text.trim().to_string()).filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("hermian-hb-{}-{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn heartbeat_is_written_and_fresh() {
        let root = scratch("touch");
        let p = root.join("run/heartbeat");
        assert!(age(&p, SystemTime::now()).is_none());
        touch(&p).unwrap();
        let age = age(&p, SystemTime::now()).expect("heartbeat exists");
        assert!(age < Duration::from_secs(5), "{:?}", age);
        let body = fs::read_to_string(&p).unwrap();
        assert!(
            body.starts_with(&std::process::id().to_string()),
            "{}",
            body
        );
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn marker_separates_clean_stops_from_crashes() {
        let d = scratch("marker");
        fs::create_dir_all(&d).unwrap();
        let marker = d.join("running");
        // First run: nothing before it.
        assert!(start(&marker).is_none());
        // A clean stop clears the marker; the next start stays quiet.
        clean_stop(&marker);
        assert!(start(&marker).is_none());
        // A run that dies leaves it behind; the next start reports it.
        let prev = start(&marker).expect("previous run recorded");
        assert!(prev.contains(&std::process::id().to_string()), "{}", prev);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn restart_note_is_consumed_once() {
        let d = scratch("note");
        fs::create_dir_all(&d).unwrap();
        let p = d.join("watchdog-note");
        assert!(take_restart_note(&p).is_none());
        note_restart(&p, "no heartbeat for 400s");
        let note = take_restart_note(&p).unwrap();
        assert!(note.ends_with("no heartbeat for 400s"), "{}", note);
        assert!(take_restart_note(&p).is_none());
        fs::remove_dir_all(&d).unwrap();
    }
}
