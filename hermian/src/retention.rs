//! Keep the alert store and logs from growing without bound.
//!
//! - `alerts/*.json` and `collections/*` older than
//!   `general.alert_retention_days` are deleted (0 keeps them).
//! - `alerts.log` is rotated by size: `alerts.log` -> `.1` -> ... -> `.N`.
//!
//! Runs from the daemon about once an hour, on a blocking thread.

use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime};

/// Rotate `alerts.log` once it passes this size.
pub const MAX_LOG_BYTES: u64 = 50 * 1024 * 1024;
/// Rotated copies kept (`alerts.log.1` .. `.3`).
pub const KEEP_ROTATED: u32 = 3;

/// Delete regular files (and directories, for collect bundles) directly in
/// `dir` last modified before `now - max_age`. Symlinks are removed, never
/// followed. Returns how many entries were deleted.
pub fn prune_older_than(dir: &Path, max_age: Duration, now: SystemTime) -> usize {
    let Some(cutoff) = now.checked_sub(max_age) else {
        return 0;
    };
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    let mut removed = 0;
    for e in entries.flatten() {
        let Ok(meta) = e.path().symlink_metadata() else {
            continue;
        };
        let old = meta.modified().map(|m| m < cutoff).unwrap_or(false);
        if !old {
            continue;
        }
        let ok = if meta.is_dir() {
            fs::remove_dir_all(e.path()).is_ok()
        } else {
            fs::remove_file(e.path()).is_ok()
        };
        if ok {
            removed += 1;
        }
    }
    removed
}

/// Rotate `path` if it's larger than `max_bytes`. Returns true if it did.
pub fn rotate_if_large(path: &Path, max_bytes: u64, keep: u32) -> bool {
    let big = fs::symlink_metadata(path)
        .map(|m| m.is_file() && m.len() > max_bytes)
        .unwrap_or(false);
    if !big || keep == 0 {
        return false;
    }
    let numbered = |n: u32| {
        let mut s = path.as_os_str().to_owned();
        s.push(format!(".{}", n));
        std::path::PathBuf::from(s)
    };
    let _ = fs::remove_file(numbered(keep));
    for n in (1..keep).rev() {
        let _ = fs::rename(numbered(n), numbered(n + 1));
    }
    // The next append creates a fresh file (mode 0600, see write_secure_append).
    fs::rename(path, numbered(1)).is_ok()
}

/// One retention pass over the daemon's directories.
pub fn run(retention_days: u32) {
    let now = SystemTime::now();
    let mut removed = 0;
    if retention_days > 0 {
        let age = Duration::from_secs(u64::from(retention_days) * 86_400);
        removed += prune_older_than(&crate::paths::alerts_dir(), age, now);
        removed += prune_older_than(&crate::paths::collections_dir(), age, now);
        // Undelivered queue copies: a channel that has been broken for the
        // whole retention window shouldn't grow the disk without bound.
        removed += prune_older_than(&crate::paths::pending_dir(), age, now);
    }
    let rotated = rotate_if_large(&crate::paths::alerts_log(), MAX_LOG_BYTES, KEEP_ROTATED);
    if removed > 0 || rotated {
        crate::daemon::log_daemon(
            hermian_core::Severity::Info,
            &format!(
                "retention: removed {} stored alert(s)/bundle(s) older than {} days{}",
                removed,
                retention_days,
                if rotated { "; rotated alerts.log" } else { "" }
            ),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("hermian-ret-{}-{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn old_records_go_and_new_ones_stay() {
        let d = scratch("prune");
        fs::write(d.join("a.json"), "{}").unwrap();
        fs::create_dir(d.join("bundle")).unwrap();
        fs::write(d.join("bundle/x"), "x").unwrap();
        // Everything was just written: "now" a year later makes all of it old.
        let later = SystemTime::now() + Duration::from_secs(365 * 86_400);
        assert_eq!(
            prune_older_than(&d, Duration::from_secs(90 * 86_400), SystemTime::now()),
            0
        );
        assert_eq!(
            prune_older_than(&d, Duration::from_secs(90 * 86_400), later),
            2
        );
        assert_eq!(fs::read_dir(&d).unwrap().count(), 0);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn logs_rotate_by_size_and_keep_a_few() {
        let d = scratch("rotate");
        let log = d.join("alerts.log");
        for round in 0..5 {
            fs::write(&log, vec![b'x'; 20]).unwrap();
            assert!(rotate_if_large(&log, 10, 3), "round {}", round);
        }
        assert!(!log.exists());
        assert!(d.join("alerts.log.1").exists());
        assert!(d.join("alerts.log.3").exists());
        assert!(!d.join("alerts.log.4").exists());
        fs::write(&log, "small").unwrap();
        assert!(!rotate_if_large(&log, 10, 3));
        fs::remove_dir_all(&d).unwrap();
    }
}
