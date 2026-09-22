//! inotify-based file watchers for persistence and account surfaces.
//!
//! Design notes:
//! * Editors and atomic-write tools generate a burst of events per save
//!   (CREATE tmp, MODIFY, MOVED_TO, ATTRIB...). Events are debounced per path
//!   and a single [`FileEvent`] is emitted after the burst settles.
//! * Writer attribution is attempted at the *first* event of a burst (while
//!   the writer likely still holds the fd) and remembered; content and
//!   metadata are read at the *last* event so they reflect the final state.
//! * The daemon's own config file is watched so tampering is reported.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use hermian_core::{Event, FileEvent, FileKind, WriterInfo};
use inotify::{EventMask, Inotify, WatchDescriptor, WatchMask};
use tokio::sync::mpsc;

use crate::procsrc;

const WATCH_FILES: &[&str] = &[
    "/etc/crontab",
    "/etc/anacrontab",
    "/etc/profile",
    "/etc/bash.bashrc",
    "/etc/zsh/zshrc",
    "/etc/ld.so.preload",
    "/etc/sudoers",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/gshadow",
    "/etc/ssh/sshd_config",
    "/etc/ssh/ssh_config",
];

const WATCH_DIRS: &[&str] = &[
    "/etc",
    "/etc/cron.d",
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/var/spool/cron",
    "/var/spool/cron/crontabs",
    "/etc/profile.d",
    "/etc/systemd/system",
    "/etc/ld.so.conf.d",
    "/etc/sudoers.d",
    "/etc/ssh",
    "/etc/ssh/sshd_config.d",
    "/etc/ssh/ssh_config.d",
    "/root",
    "/root/.ssh",
];

/// Files under a watched directory that we care about. Anything else in e.g.
/// `/etc` is ignored so the daemon does not react to every package upgrade.
fn is_interesting(path: &str) -> bool {
    if WATCH_FILES.contains(&path) {
        return true;
    }
    let name = path.rsplit('/').next().unwrap_or("");
    let parent = path.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
    match parent {
        "/etc" => WATCH_FILES.contains(&path),
        "/etc/ssh" => name == "sshd_config" || name == "ssh_config",
        "/root" => matches!(
            name,
            ".bashrc"
                | ".profile"
                | ".bash_profile"
                | ".bash_login"
                | ".zshrc"
                | ".zprofile"
                | ".zshenv"
                | ".zlogin"
        ),
        p if p.ends_with("/.ssh") => {
            name == "authorized_keys" || name == "authorized_keys2" || name == "config"
        }
        p if p.starts_with("/home/") => {
            // /home/<user>/<dotfile>
            p.matches('/').count() == 2
                && matches!(
                    name,
                    ".bashrc"
                        | ".profile"
                        | ".bash_profile"
                        | ".bash_login"
                        | ".zshrc"
                        | ".zprofile"
                        | ".zshenv"
                        | ".zlogin"
                )
        }
        _ => WATCH_DIRS
            .iter()
            .any(|d| *d != "/etc" && *d != "/root" && *d != "/etc/ssh" && parent == *d),
    }
}

const MASK: WatchMask = WatchMask::MODIFY
    .union(WatchMask::ATTRIB)
    .union(WatchMask::CREATE)
    .union(WatchMask::DELETE)
    .union(WatchMask::DELETE_SELF)
    .union(WatchMask::MOVED_FROM)
    .union(WatchMask::MOVED_TO)
    .union(WatchMask::CLOSE_WRITE)
    .union(WatchMask::MOVE_SELF);

/// How long a path must be quiet before its burst is emitted.
const SETTLE: Duration = Duration::from_millis(400);
/// Hard cap so a continuously-written file still produces an event.
const MAX_HOLD: Duration = Duration::from_millis(2500);

pub fn spawn_watchers(
    tx: mpsc::Sender<Event>,
    config_path: PathBuf,
    shutdown: Arc<AtomicBool>,
) -> Result<SharedWatchHealth> {
    let health: SharedWatchHealth = Arc::default();
    let h = health.clone();
    std::thread::Builder::new()
        .name("hermian-inotify".to_string())
        .spawn(move || watcher_loop(tx, config_path, shutdown, h))?;
    Ok(health)
}

/// Shared with the daemon so `status` can report watcher health.
#[derive(Debug, Default, Clone)]
pub struct WatchHealth {
    pub active: usize,
    pub failed: usize,
    pub last_error: String,
}

pub type SharedWatchHealth = Arc<std::sync::Mutex<WatchHealth>>;

struct Watches {
    inotify: Inotify,
    paths: HashMap<WatchDescriptor, PathBuf>,
    config_path: PathBuf,
    health: SharedWatchHealth,
    failed: usize,
    last_error: String,
}

impl Watches {
    fn add(&mut self, p: &Path) {
        if !p.exists() {
            return;
        }
        match self.inotify.watches().add(p, MASK) {
            Ok(wd) => {
                self.paths.insert(wd, p.to_path_buf());
            }
            Err(e) => {
                self.failed += 1;
                self.last_error = format!("{}: {}", p.display(), e);
            }
        }
    }

    fn publish(&mut self) {
        if let Ok(mut h) = self.health.lock() {
            h.active = self.paths.len();
            h.failed = self.failed;
            h.last_error = self.last_error.clone();
        }
        self.failed = 0;
    }

    fn refresh(&mut self) {
        for p in WATCH_FILES.iter().chain(WATCH_DIRS.iter()) {
            self.add(Path::new(p));
        }
        for p in systemd_target_dirs() {
            self.add(&p);
        }
        // /home itself, so a new home directory is noticed right away.
        self.add(Path::new("/home"));
        for p in user_home_watches() {
            self.add(&p);
        }
        // Watch the config's directory so atomic replaces are seen too.
        let config_path = self.config_path.clone();
        if let Some(dir) = config_path.parent() {
            self.add(dir);
        }
        self.add(&config_path);
    }
}

/// Enough of a file's metadata to tell that it changed: inode, mtime, size.
type Fingerprint = (u64, i64, i64, u64);

fn fingerprint(path: &Path) -> Option<Fingerprint> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::symlink_metadata(path).ok()?;
    Some((m.ino(), m.mtime(), m.mtime_nsec(), m.len()))
}

/// Fingerprints of every interesting file under the current watches. Kept up
/// to date as events are emitted, so after an inotify queue overflow the
/// lost changes can be found by comparing against a fresh one.
fn snapshot(w: &Watches) -> HashMap<String, Fingerprint> {
    let mut out = HashMap::new();
    let mut consider = |p: &Path| {
        let s = p.to_string_lossy().into_owned();
        if p == w.config_path || is_interesting(&s) {
            if let Some(fp) = fingerprint(p) {
                out.insert(s, fp);
            }
        }
    };
    for p in w.paths.values() {
        let is_dir = std::fs::symlink_metadata(p)
            .map(|m| m.is_dir())
            .unwrap_or(false);
        if !is_dir {
            consider(p);
            continue;
        }
        let Ok(entries) = std::fs::read_dir(p) else {
            continue;
        };
        for e in entries.flatten() {
            if e.file_type().map(|t| !t.is_dir()).unwrap_or(false) {
                consider(&e.path());
            }
        }
    }
    out
}

/// What changed between two snapshots.
fn snapshot_changes(
    old: &HashMap<String, Fingerprint>,
    new: &HashMap<String, Fingerprint>,
) -> Vec<(String, FileKind)> {
    let mut out: Vec<(String, FileKind)> = new
        .iter()
        .filter_map(|(p, fp)| match old.get(p) {
            None => Some((p.clone(), FileKind::Created)),
            Some(prev) if prev != fp => Some((p.clone(), FileKind::Modified)),
            _ => None,
        })
        .collect();
    out.extend(
        old.keys()
            .filter(|p| !new.contains_key(*p))
            .map(|p| (p.clone(), FileKind::Removed)),
    );
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn systemd_target_dirs() -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir("/etc/systemd/system") else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter(|e| {
            let name = e.file_name();
            let name = name.to_string_lossy();
            (name.ends_with(".wants") || name.ends_with(".requires")) && e.path().is_dir()
        })
        .map(|e| e.path())
        .collect()
}

fn user_home_watches() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir("/home") else {
        return out;
    };
    for e in entries.flatten() {
        let home = e.path();
        if !home.is_dir() {
            continue;
        }
        out.push(home.clone());
        let ssh_dir = home.join(".ssh");
        if ssh_dir.is_dir() {
            out.push(ssh_dir);
        }
    }
    out
}

struct Pending {
    first: Instant,
    last: Instant,
    kind: FileKind,
    writer: Option<WriterInfo>,
    is_config: bool,
}

fn watcher_loop(
    tx: mpsc::Sender<Event>,
    config_path: PathBuf,
    shutdown: Arc<AtomicBool>,
    health: SharedWatchHealth,
) {
    let inotify = match Inotify::init() {
        Ok(i) => i,
        Err(e) => {
            let msg = format!(
                "inotify unavailable ({}); persistence watchers disabled. \
                 If this is EMFILE/ENOSPC, raise fs.inotify.max_user_instances / max_user_watches.",
                e
            );
            eprintln!("hermian: {}", msg);
            if let Ok(mut h) = health.lock() {
                h.last_error = msg;
                h.failed = 1;
            }
            return;
        }
    };
    let mut w = Watches {
        inotify,
        paths: HashMap::new(),
        config_path: config_path.clone(),
        health,
        failed: 0,
        last_error: String::new(),
    };
    w.refresh();
    w.publish();

    let mut buffer = [0u8; 16384];
    let mut last_rescan = Instant::now();
    let mut pending: HashMap<String, Pending> = HashMap::new();
    let mut known = snapshot(&w);
    let mut overflows: u64 = 0;

    loop {
        if shutdown.load(Ordering::Relaxed) {
            return;
        }
        let mut overflowed = false;
        // Non-blocking read; inotify's fd is nonblocking by default in this crate.
        match w.inotify.read_events(&mut buffer) {
            Ok(events) => {
                for event in events {
                    if event.mask.contains(EventMask::Q_OVERFLOW) {
                        overflowed = true;
                        continue;
                    }
                    if event.mask.contains(EventMask::IGNORED) {
                        w.paths.remove(&event.wd);
                        continue;
                    }
                    let Some(base) = w.paths.get(&event.wd).cloned() else {
                        continue;
                    };
                    if event.mask.contains(EventMask::ISDIR) {
                        // A new ~/.ssh, home or cron dir: watch it now, not at
                        // the next 60s rescan, and pick up whatever was already
                        // written into it (mkdir ~/.ssh && echo key > ...).
                        if event
                            .mask
                            .intersects(EventMask::CREATE | EventMask::MOVED_TO)
                        {
                            if let Some(name) = &event.name {
                                let dir = base.join(name);
                                adopt_new_dir(&mut w, &dir, &config_path, &mut pending, 0);
                            }
                        }
                        continue;
                    }
                    let full = match &event.name {
                        Some(name) => base.join(name),
                        None => base.clone(),
                    };
                    let full_s = full.to_string_lossy().into_owned();
                    let is_config = full == config_path;
                    if !is_config && !is_interesting(&full_s) {
                        continue;
                    }
                    let kind = classify(event.mask);
                    let now = Instant::now();
                    let entry = pending.entry(full_s.clone()).or_insert_with(|| Pending {
                        first: now,
                        last: now,
                        kind,
                        // Attribute at first sight while the fd is likely open.
                        writer: lookup_writer(&full_s),
                        is_config,
                    });
                    entry.last = now;
                    entry.kind = merge_kind(entry.kind, kind);
                    if entry.writer.is_none()
                        && !matches!(kind, FileKind::Removed | FileKind::MovedFrom)
                    {
                        entry.writer = lookup_writer(&full_s);
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => std::thread::sleep(Duration::from_millis(150)),
        }

        // The kernel dropped events. Find what changed since the last
        // snapshot and queue those, rather than silently missing them.
        if overflowed {
            overflows += 1;
            let fresh = snapshot(&w);
            let changes = snapshot_changes(&known, &fresh);
            let now = Instant::now();
            for (path, kind) in &changes {
                let is_config = Path::new(path) == config_path;
                let writer = if *kind == FileKind::Removed {
                    None
                } else {
                    lookup_writer(path)
                };
                pending.entry(path.clone()).or_insert(Pending {
                    first: now,
                    last: now,
                    kind: *kind,
                    writer,
                    is_config,
                });
            }
            known = fresh;
            w.last_error = format!(
                "inotify queue overflowed {} time(s); rescanned, {} change(s) recovered",
                overflows,
                changes.len()
            );
            eprintln!("hermian: {}", w.last_error);
            w.publish();
        }

        // Flush settled bursts.
        let now = Instant::now();
        let ready: Vec<String> = pending
            .iter()
            .filter(|(_, p)| now - p.last >= SETTLE || now - p.first >= MAX_HOLD)
            .map(|(k, _)| k.clone())
            .collect();
        for key in ready {
            if let Some(p) = pending.remove(&key) {
                match fingerprint(Path::new(&key)) {
                    Some(fp) => known.insert(key.clone(), fp),
                    None => known.remove(&key),
                };
                let ev = build_file_event(&key, p);
                if tx.blocking_send(Event::File(ev)).is_err() {
                    return;
                }
            }
        }

        if last_rescan.elapsed() > Duration::from_secs(60) {
            w.refresh();
            w.publish();
            // Pick up newly watched files without reporting them as changes.
            for (path, fp) in snapshot(&w) {
                known.entry(path).or_insert(fp);
            }
            last_rescan = Instant::now();
        }
        std::thread::sleep(Duration::from_millis(60));
    }
}

/// Directories the watcher keeps a watch on (besides the fixed lists, which
/// `refresh` re-adds anyway).
fn is_wanted_dir(path: &str) -> bool {
    if WATCH_DIRS.contains(&path) {
        return true;
    }
    let parent = path.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
    let name = path.rsplit('/').next().unwrap_or("");
    // /home/<user>
    if parent == "/home" && !name.is_empty() {
        return true;
    }
    // /root/.ssh, /home/<user>/.ssh
    if name == ".ssh"
        && (parent == "/root" || parent.starts_with("/home/") && parent.matches('/').count() == 2)
    {
        return true;
    }
    // systemctl enable targets
    parent == "/etc/systemd/system" && (name.ends_with(".wants") || name.ends_with(".requires"))
}

/// Watch a directory that just appeared and queue what's already inside.
/// Depth-limited so a new home with a `.ssh` is covered in one go.
fn adopt_new_dir(
    w: &mut Watches,
    dir: &Path,
    config_path: &Path,
    pending: &mut HashMap<String, Pending>,
    depth: u8,
) {
    let dir_s = dir.to_string_lossy().into_owned();
    if depth > 1 || !is_wanted_dir(&dir_s) {
        return;
    }
    // Only real directories: a symlinked ~/.ssh would point the watch elsewhere.
    if !std::fs::symlink_metadata(dir)
        .map(|m| m.is_dir())
        .unwrap_or(false)
    {
        return;
    }
    w.add(dir);
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let now = Instant::now();
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_dir() {
            adopt_new_dir(w, &path, config_path, pending, depth + 1);
            continue;
        }
        let path_s = path.to_string_lossy().into_owned();
        let is_config = path == config_path;
        if !is_config && !is_interesting(&path_s) {
            continue;
        }
        pending.entry(path_s.clone()).or_insert_with(|| Pending {
            first: now,
            last: now,
            kind: FileKind::Created,
            writer: lookup_writer(&path_s),
            is_config,
        });
    }
}

fn classify(mask: EventMask) -> FileKind {
    if mask.contains(EventMask::CREATE) {
        FileKind::Created
    } else if mask.contains(EventMask::MOVED_TO) {
        FileKind::MovedTo
    } else if mask.contains(EventMask::MOVED_FROM) {
        FileKind::MovedFrom
    } else if mask.contains(EventMask::DELETE) || mask.contains(EventMask::DELETE_SELF) {
        FileKind::Removed
    } else {
        FileKind::Modified
    }
}

/// Collapse a burst into the most meaningful single kind.
fn merge_kind(prev: FileKind, next: FileKind) -> FileKind {
    use FileKind::*;
    match (prev, next) {
        (_, Removed) => Removed,
        (Removed, k) => k, // deleted then recreated = the new thing
        (Created, _) => Created,
        (MovedTo, Modified) | (MovedTo, MovedTo) => MovedTo,
        (_, MovedTo) => MovedTo,
        (k, Modified) => k,
        (_, k) => k,
    }
}

fn lookup_writer(path: &str) -> Option<WriterInfo> {
    let (pid, comm, exe, uid, tty_nr) = procsrc::pid_for_path(path)?;
    if pid == std::process::id() {
        return None;
    }
    Some(WriterInfo {
        pid,
        uid,
        comm,
        exe,
        tty_nr,
    })
}

fn build_file_event(path: &str, p: Pending) -> FileEvent {
    let gone = matches!(p.kind, FileKind::Removed | FileKind::MovedFrom);
    let (is_suid, has_file_caps, content, managed_by_package) = if gone {
        (false, false, None, None)
    } else {
        let managed = if path.starts_with("/etc/systemd/system/") && !p.is_config {
            procsrc::file_in_package_database(path)
        } else {
            None
        };
        (
            procsrc::is_suid_or_sgid(path),
            procsrc::has_file_capabilities(path),
            content_for(path, p.is_config),
            managed,
        )
    };
    let container = p
        .writer
        .as_ref()
        .map(|w| procsrc::container_info(w.pid).0)
        .unwrap_or(false);
    FileEvent {
        ts: chrono::Utc::now(),
        path: path.to_string(),
        kind: p.kind,
        dev: 0,
        ino: 0,
        writer: p.writer,
        // Left false here; the engine derives it from its process tree when the
        // writer is unknown.
        session_present: false,
        is_suid,
        has_file_caps,
        content,
        container,
        managed_by_package,
    }
}

fn content_for(path: &str, is_config: bool) -> Option<String> {
    if is_config {
        return None;
    }
    let name = path.rsplit('/').next().unwrap_or("");
    let tracked = path.starts_with("/etc/cron")
        || path.starts_with("/var/spool/cron")
        || path == "/etc/crontab"
        || path == "/etc/anacrontab"
        || path.starts_with("/etc/ld.so.conf.d/")
        || path == "/etc/ld.so.preload"
        || path == "/etc/passwd"
        || path == "/etc/group"
        || path == "/etc/sudoers"
        || path.starts_with("/etc/sudoers.d/")
        || name == "authorized_keys"
        || name == "authorized_keys2"
        || path.starts_with("/etc/systemd/system/")
        || name.starts_with(".bash")
        || name.starts_with(".z")
        || name == ".profile";
    if tracked {
        procsrc::read_file(path)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interesting_paths() {
        assert!(is_interesting("/etc/cron.d/job"));
        assert!(is_interesting("/etc/passwd"));
        assert!(is_interesting("/etc/ssh/sshd_config"));
        assert!(is_interesting("/root/.bashrc"));
        assert!(is_interesting("/root/.ssh/authorized_keys"));
        assert!(is_interesting("/home/dev/.zshrc"));
        assert!(is_interesting("/home/dev/.ssh/authorized_keys"));
        assert!(is_interesting("/etc/systemd/system/x.service"));
        assert!(!is_interesting("/etc/hosts"));
        assert!(!is_interesting("/etc/ssh/moduli"));
        assert!(!is_interesting("/root/notes.txt"));
        assert!(!is_interesting("/home/dev/project/.bashrc"));
    }

    #[test]
    fn new_dirs_worth_watching() {
        assert!(is_wanted_dir("/root/.ssh"));
        assert!(is_wanted_dir("/home/mallory"));
        assert!(is_wanted_dir("/home/mallory/.ssh"));
        assert!(is_wanted_dir("/etc/cron.d"));
        assert!(is_wanted_dir("/etc/systemd/system/multi-user.target.wants"));
        assert!(!is_wanted_dir("/home/mallory/project"));
        assert!(!is_wanted_dir("/home/mallory/project/.ssh"));
        assert!(!is_wanted_dir("/etc/nginx"));
        assert!(!is_wanted_dir("/tmp/.ssh"));
    }

    #[test]
    fn overflow_rescan_finds_lost_changes() {
        let fp = |ino, size| (ino, 1_700_000_000, 0, size);
        let mut old = HashMap::new();
        old.insert("/etc/cron.d/keep".to_string(), fp(1, 10));
        old.insert("/etc/cron.d/edited".to_string(), fp(2, 10));
        old.insert("/etc/cron.d/gone".to_string(), fp(3, 10));
        let mut new = old.clone();
        new.insert("/etc/cron.d/edited".to_string(), fp(2, 99));
        new.remove("/etc/cron.d/gone");
        new.insert("/root/.ssh/authorized_keys".to_string(), fp(4, 80));
        let changes = snapshot_changes(&old, &new);
        assert_eq!(
            changes,
            vec![
                ("/etc/cron.d/edited".to_string(), FileKind::Modified),
                ("/etc/cron.d/gone".to_string(), FileKind::Removed),
                ("/root/.ssh/authorized_keys".to_string(), FileKind::Created),
            ]
        );
        assert!(snapshot_changes(&new, &new).is_empty());
    }

    #[test]
    fn fingerprint_changes_on_rewrite() {
        let dir = std::env::temp_dir().join(format!("hermian-fp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("x");
        std::fs::write(&f, "a").unwrap();
        let before = fingerprint(&f).unwrap();
        std::fs::write(&f, "abc").unwrap();
        assert_ne!(before, fingerprint(&f).unwrap());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn kind_merging() {
        use FileKind::*;
        assert_eq!(merge_kind(Created, Modified), Created);
        assert_eq!(merge_kind(Modified, MovedTo), MovedTo);
        assert_eq!(merge_kind(Created, Removed), Removed);
        assert_eq!(merge_kind(Removed, Created), Created);
    }
}
