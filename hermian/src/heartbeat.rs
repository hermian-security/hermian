use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime};

pub const INTERVAL: Duration = Duration::from_secs(30);
pub const STALE: Duration = Duration::from_secs(180);
pub const START_GRACE: Duration = Duration::from_secs(180);

pub fn touch(path: &Path) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let stamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, format!("{} {}\n", std::process::id(), stamp))?;
    fs::rename(&tmp, path)
}

pub fn age(path: &Path, now: SystemTime) -> Option<Duration> {
    let modified = fs::metadata(path).ok()?.modified().ok()?;
    Some(now.duration_since(modified).unwrap_or_default())
}

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

pub fn clean_stop(marker: &Path) {
    let _ = fs::remove_file(marker);
}

pub fn note_restart(path: &Path, reason: &str) {
    if let Some(dir) = path.parent() {
        let _ = fs::create_dir_all(dir);
    }
    let _ = fs::write(
        path,
        format!("{} {}\n", chrono::Utc::now().to_rfc3339(), reason),
    );
}

pub fn install_panic_note(path: std::path::PathBuf) {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let thread = std::thread::current();
        let note = panic_note(thread.name().unwrap_or("unnamed"), &info.to_string());
        let _ = fs::write(&path, note);
        default(info);
    }));
}

fn panic_note(thread: &str, info: &str) -> String {
    format!(
        "panic in thread '{}': {}\n",
        thread,
        info.replace('\n', " ")
    )
}

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
        assert!(start(&marker).is_none());
        clean_stop(&marker);
        assert!(start(&marker).is_none());
        let prev = start(&marker).expect("previous run recorded");
        assert!(prev.contains(&std::process::id().to_string()), "{}", prev);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_panic_note_is_one_line_naming_the_thread() {
        let d = scratch("panic");
        fs::create_dir_all(&d).unwrap();
        let p = d.join("panic-note");
        let note = panic_note(
            "hermian-authlog",
            "panicked at hermian/src/authlog.rs:1:2:\nboom",
        );
        fs::write(&p, note).unwrap();
        let read = take_restart_note(&p).expect("note read back");
        assert_eq!(
            read,
            "panic in thread 'hermian-authlog': panicked at hermian/src/authlog.rs:1:2: boom"
        );
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
