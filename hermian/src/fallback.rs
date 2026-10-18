//! Polling sources used when eBPF is unavailable, plus pollers that are always
//! on because no event source covers them well:
//! * listeners: `/proc/net/tcp*` is the authoritative view of bound ports;
//! * setuid/capability sweep: inotify cannot watch every user-writable tree
//!   and `chmod` leaves no exec trace, so transient and home directories are
//!   swept for newly privileged executables.

use std::collections::{HashMap, HashSet};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use hermian_core::{Event, ExecEvent, FileEvent, FileKind, ListenerEvent};
use tokio::sync::mpsc;

use crate::procsrc;

/// Directories swept for setuid/setgid/capability executables, with how many
/// sweeps go by between two walks of each, without and with the eBPF chmod
/// and setxattr hooks. Without them, transient directories, where a dropped
/// binary usually lands, every sweep; homes and service trees, which can
/// hold tens of thousands of entries, every third. With them, a chmod or
/// setcap is reported as it happens and the sweep is only the safety net
/// for files created with those bits. Depth-limited so a large home
/// directory cannot turn the sweep into a filesystem crawl.
const SUID_SWEEP_ROOTS: &[(&[&str], u32, u32)] = &[
    (&["/tmp", "/var/tmp", "/dev/shm"], 1, 3),
    (&["/home", "/root", "/var/www", "/srv", "/opt"], 3, 15),
];
const SUID_SWEEP_DEPTH: usize = 4;
const SUID_SWEEP_INTERVAL: Duration = Duration::from_secs(20);

/// Set once the eBPF chmod/setxattr hooks are attached.
pub static PRIV_HOOKED: AtomicBool = AtomicBool::new(false);

/// Files the hooks already reported, so the sweep doesn't report them again.
static PRIV_REPORTED: Mutex<Option<HashSet<(u64, u64)>>> = Mutex::new(None);

/// A setuid/setgid or capability file at `path`, as a file event, if `path`
/// is a regular file that really has them. `None` otherwise (a chmod that
/// failed, a directory given setgid).
pub fn privileged_file_event(
    path: String,
    kind: FileKind,
    writer: Option<hermian_core::WriterInfo>,
) -> Option<FileEvent> {
    let md = std::fs::symlink_metadata(&path).ok()?;
    if !md.is_file() {
        return None;
    }
    let is_suid = md.permissions().mode() & (libc::S_ISUID | libc::S_ISGID) != 0;
    let has_file_caps = procsrc::has_file_capabilities(&path);
    if !is_suid && !has_file_caps {
        return None;
    }
    Some(FileEvent {
        ts: chrono::Utc::now(),
        kind,
        dev: md.dev(),
        ino: md.ino(),
        writer,
        session_present: false,
        is_suid,
        has_file_caps,
        content: None,
        container: false,
        managed_by_package: None,
        path,
    })
}

/// Note a file the hooks reported. Bounded: past the cap the oldest
/// knowledge goes, and the sweep may report one of those again.
pub fn note_priv_reported(dev: u64, ino: u64) {
    if let Ok(mut g) = PRIV_REPORTED.lock() {
        let set = g.get_or_insert_with(HashSet::new);
        if set.len() >= 4096 {
            set.clear();
        }
        set.insert((dev, ino));
    }
}

/// The kernel's dev_t (12-bit major, 20-bit minor) as stat's st_dev.
pub fn st_dev_of_kernel(dev: u32) -> u64 {
    libc::makedev(dev >> 20, dev & 0xf_ffff)
}

/// When the last inode search ran, for [`find_inode`]'s rate limit.
static LAST_INODE_SEARCH: Mutex<Option<std::time::Instant>> = Mutex::new(None);

/// Where `(st_dev, ino)` is under the swept roots, as deep as the sweep goes.
/// For a chmod or setcap whose caller is gone before /proc can say what its
/// fd or working directory was. Only those roots: elsewhere the rules don't
/// page. Inode numbers come with the directory listing, so only a match is
/// stat'ed. At most once a second, so a flood can't stall the event thread;
/// past that the sweep is the safety net.
pub fn find_inode(st_dev: u64, ino: u64) -> Option<String> {
    if ino == 0 {
        return None;
    }
    if let Ok(mut last) = LAST_INODE_SEARCH.lock() {
        if last.is_some_and(|t| t.elapsed() < Duration::from_secs(1)) {
            return None;
        }
        *last = Some(std::time::Instant::now());
    }
    SUID_SWEEP_ROOTS
        .iter()
        .flat_map(|(roots, _, _)| roots.iter())
        .find_map(|root| find_inode_under(Path::new(root), st_dev, ino, SUID_SWEEP_DEPTH + 1))
}

fn find_inode_under(dir: &Path, st_dev: u64, ino: u64, depth: usize) -> Option<String> {
    use std::os::unix::fs::DirEntryExt;
    let md = std::fs::symlink_metadata(dir).ok()?;
    if md.ino() == ino && md.dev() == st_dev {
        return Some(dir.to_string_lossy().into_owned());
    }
    if depth == 0 || !md.is_dir() {
        return None;
    }
    let mut subdirs = Vec::new();
    for e in std::fs::read_dir(dir).ok()?.flatten() {
        let Ok(ft) = e.file_type() else { continue };
        if ft.is_symlink() {
            continue;
        }
        if e.ino() == ino {
            if let Ok(m) = e.metadata() {
                if m.dev() == st_dev {
                    return Some(e.path().to_string_lossy().into_owned());
                }
            }
        }
        if ft.is_dir() {
            subdirs.push(e.path());
        }
    }
    subdirs
        .iter()
        .find_map(|d| find_inode_under(d, st_dev, ino, depth - 1))
}

fn priv_reported(dev: u64, ino: u64) -> bool {
    PRIV_REPORTED
        .lock()
        .map(|g| g.as_ref().is_some_and(|s| s.contains(&(dev, ino))))
        .unwrap_or(false)
}

pub fn spawn_suid_sweeper(tx: mpsc::Sender<Event>, shutdown: Arc<AtomicBool>) -> Result<()> {
    std::thread::Builder::new()
        .name("hermian-suid".to_string())
        .spawn(move || suid_sweep_loop(tx, shutdown))?;
    Ok(())
}

fn walk(dir: &Path, depth: usize, out: &mut Vec<(String, u64, u64)>) {
    if depth == 0 {
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        // The entry's type comes with the directory listing: only regular
        // files need a stat for their mode.
        let Ok(ft) = e.file_type() else {
            continue;
        };
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            // Skip huge/noisy trees that never legitimately hold setuid files.
            let name = e.file_name();
            let name = name.to_string_lossy();
            if matches!(
                name.as_ref(),
                "node_modules"
                    | ".git"
                    | ".cache"
                    | "target"
                    | "__pycache__"
                    | ".cargo"
                    | ".rustup"
                    | "snap"
            ) {
                continue;
            }
            walk(&e.path(), depth - 1, out);
        } else if ft.is_file() {
            let Ok(md) = e.metadata() else {
                continue;
            };
            if md.permissions().mode() & (libc::S_ISUID | libc::S_ISGID) != 0 {
                out.push((e.path().to_string_lossy().into_owned(), md.dev(), md.ino()));
            }
        }
    }
}

fn scan_roots(roots: &[&str]) -> Vec<(String, u64, u64)> {
    let mut out = Vec::new();
    for root in roots {
        walk(Path::new(root), SUID_SWEEP_DEPTH, &mut out);
    }
    out
}

/// Setuid files in `current` that `known` hasn't seen; `known` becomes `current`.
fn newly_privileged(
    known: &mut HashSet<(u64, u64)>,
    current: Vec<(String, u64, u64)>,
) -> Vec<(String, u64, u64)> {
    let now_known: HashSet<(u64, u64)> = current.iter().map(|(_, d, i)| (*d, *i)).collect();
    let new = current
        .into_iter()
        .filter(|(_, d, i)| !known.contains(&(*d, *i)))
        .collect();
    *known = now_known;
    new
}

pub fn writer_from(
    (pid, comm, exe, uid, tty_nr): (u32, String, String, u32, i64),
) -> hermian_core::WriterInfo {
    hermian_core::WriterInfo {
        pid,
        uid,
        comm,
        exe,
        tty_nr,
    }
}

fn suid_sweep_loop(tx: mpsc::Sender<Event>, shutdown: Arc<AtomicBool>) {
    // Whatever exists at start is pre-existing; only new appearances alert.
    // Each group keeps its own: a group not walked this round keeps what it knew.
    let mut known: Vec<HashSet<(u64, u64)>> = SUID_SWEEP_ROOTS
        .iter()
        .map(|(roots, _, _)| {
            scan_roots(roots)
                .into_iter()
                .map(|(_, d, i)| (d, i))
                .collect()
        })
        .collect();
    let mut round: u32 = 0;
    while !shutdown.load(Ordering::Relaxed) {
        std::thread::sleep(SUID_SWEEP_INTERVAL);
        round = round.wrapping_add(1);
        let hooked = PRIV_HOOKED.load(Ordering::Relaxed);
        for (g, (roots, every, every_hooked)) in SUID_SWEEP_ROOTS.iter().enumerate() {
            if !round.is_multiple_of(if hooked { *every_hooked } else { *every }) {
                continue;
            }
            for (path, dev, ino) in newly_privileged(&mut known[g], scan_roots(roots)) {
                if priv_reported(dev, ino) {
                    continue;
                }
                let writer = procsrc::pid_for_path(&path).map(writer_from);
                let Some(ev) = privileged_file_event(path, FileKind::Created, writer) else {
                    continue;
                };
                if tx.blocking_send(Event::File(ev)).is_err() {
                    return;
                }
            }
        }
    }
}

pub fn spawn_proc_poller(tx: mpsc::Sender<Event>, shutdown: Arc<AtomicBool>) -> Result<()> {
    std::thread::Builder::new()
        .name("hermian-proc".to_string())
        .spawn(move || proc_poller_loop(tx, shutdown))?;
    Ok(())
}

pub fn spawn_listener_poller(
    tx: mpsc::Sender<Event>,
    closed_tx: mpsc::Sender<ListenerKey>,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    std::thread::Builder::new()
        .name("hermian-listener".to_string())
        .spawn(move || listener_poller_loop(tx, closed_tx, shutdown))?;
    Ok(())
}

/// Emits an Exec event for every process that appears between polls. Uses
/// `(pid, starttime)` as identity so PID reuse is not mistaken for "already seen".
fn proc_poller_loop(tx: mpsc::Sender<Event>, shutdown: Arc<AtomicBool>) {
    let mut seen: HashMap<u32, u64> = procsrc::scan_processes()
        .into_iter()
        .map(|p| (p.pid, p.start))
        .collect();
    let self_pid = std::process::id();
    while !shutdown.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(1000));
        let procs = procsrc::scan_processes();
        let mut live: HashMap<u32, u64> = HashMap::with_capacity(procs.len());
        for info in procs {
            live.insert(info.pid, info.start);
            if info.pid == self_pid || seen.get(&info.pid) == Some(&info.start) {
                continue;
            }
            let deleted = info.exe.ends_with("(deleted)");
            let ev = ExecEvent {
                ts: chrono::Utc::now(),
                pid: info.pid,
                ppid: info.ppid,
                uid: info.uid,
                gid: procsrc::gid_of(info.pid).unwrap_or(info.uid),
                comm: info.comm,
                argv0: procsrc::cmdline_of(info.pid).unwrap_or_else(|| info.exe.clone()),
                exe: info.exe,
                ld_preload: false,
                deleted_exe: deleted,
                tty_nr: info.tty_nr,
                container: info.container,
                container_id: info.container_id,
            };
            if tx.blocking_send(Event::Exec(ev)).is_err() {
                return;
            }
        }
        seen = live;
    }
}

/// `(proto, local address, port)`. The address is part of it: a second bind
/// of a known port on another address (`127.0.0.1:8080`, then
/// `0.0.0.0:8080`) is a new exposure.
pub type ListenerKey = (String, std::net::IpAddr, u16);

fn listener_poller_loop(
    tx: mpsc::Sender<Event>,
    closed_tx: mpsc::Sender<ListenerKey>,
    shutdown: Arc<AtomicBool>,
) {
    let snapshot = || -> HashSet<ListenerKey> {
        procsrc::read_tcp_tables()
            .into_iter()
            .filter(|e| e.state == procsrc::TCP_LISTEN)
            .map(|e| (e.proto.to_string(), e.local_addr, e.local_port))
            .collect()
    };
    let mut known = snapshot();
    while !shutdown.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_secs(5));
        let entries: Vec<_> = procsrc::read_tcp_tables()
            .into_iter()
            .filter(|e| e.state == procsrc::TCP_LISTEN)
            .collect();
        let current: HashSet<ListenerKey> = entries
            .iter()
            .map(|e| (e.proto.to_string(), e.local_addr, e.local_port))
            .collect();

        let new_entries: Vec<_> = entries
            .iter()
            .filter(|e| !known.contains(&(e.proto.to_string(), e.local_addr, e.local_port)))
            .collect();
        if !new_entries.is_empty() {
            let inodes: Vec<u64> = new_entries.iter().map(|e| e.inode).collect();
            let owners = procsrc::pids_for_inodes(&inodes);
            for entry in new_entries {
                let pid = owners.get(&entry.inode).copied().unwrap_or(0);
                let comm = if pid != 0 {
                    procsrc::comm_of(pid).unwrap_or_else(|| "unknown".to_string())
                } else {
                    "unknown".to_string()
                };
                let ev = ListenerEvent {
                    ts: chrono::Utc::now(),
                    proto: entry.proto.to_string(),
                    addr: entry.local_addr,
                    port: entry.local_port,
                    pid,
                    comm,
                };
                if tx.blocking_send(Event::Listener(ev)).is_err() {
                    return;
                }
            }
        }
        for gone in known.difference(&current) {
            let _ = closed_tx.blocking_send(gone.clone());
        }
        known = current;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sweep_finds_setuid_files_and_skips_symlinks_and_caches() {
        let d = std::env::temp_dir().join(format!("hermian-suid-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("a/b")).unwrap();
        std::fs::create_dir_all(d.join("node_modules")).unwrap();
        let set_uid = |p: &Path| {
            std::fs::write(p, b"x").unwrap();
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o4755)).unwrap();
        };
        set_uid(&d.join("a/b/sh"));
        set_uid(&d.join("node_modules/sh"));
        std::fs::write(d.join("plain"), b"x").unwrap();
        std::os::unix::fs::symlink(d.join("a"), d.join("link")).unwrap();

        let found = scan_roots(&[d.to_str().unwrap()]);
        let paths: Vec<&str> = found.iter().map(|(p, _, _)| p.as_str()).collect();
        assert_eq!(paths, vec![d.join("a/b/sh").to_str().unwrap()]);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn only_new_setuid_files_are_reported() {
        let f = |n: u64| (format!("/tmp/{}", n), 1, n);
        let mut known: HashSet<(u64, u64)> = [(1, 1)].into_iter().collect();
        let new = newly_privileged(&mut known, vec![f(1), f(2)]);
        assert_eq!(new, vec![f(2)]);
        assert!(newly_privileged(&mut known, vec![f(1), f(2)]).is_empty());
        // Removed, then back: reported again.
        assert!(newly_privileged(&mut known, vec![f(1)]).is_empty());
        assert_eq!(newly_privileged(&mut known, vec![f(1), f(2)]), vec![f(2)]);
    }

    #[test]
    fn transient_directories_are_swept_every_round() {
        let tmp = SUID_SWEEP_ROOTS
            .iter()
            .find(|(roots, _, _)| roots.contains(&"/tmp"))
            .unwrap();
        assert_eq!(tmp.1, 1);
        for root in ["/dev/shm", "/var/tmp", "/home", "/root"] {
            assert!(
                SUID_SWEEP_ROOTS.iter().any(|(r, _, _)| r.contains(&root)),
                "{}",
                root
            );
        }
        // Without the hooks, homes at least once a minute; with them, the
        // safety net still comes by every few minutes.
        for (_, every, every_hooked) in SUID_SWEEP_ROOTS {
            assert!(SUID_SWEEP_INTERVAL * *every <= Duration::from_secs(60));
            assert!(SUID_SWEEP_INTERVAL * *every_hooked <= Duration::from_secs(300));
            assert!(every_hooked >= every);
        }
    }

    #[test]
    fn a_file_or_directory_is_found_by_its_inode() {
        let d = std::env::temp_dir().join(format!("hermian-ino-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("a/b")).unwrap();
        std::fs::write(d.join("a/b/f"), b"x").unwrap();
        std::os::unix::fs::symlink(d.join("a"), d.join("link")).unwrap();
        for p in [d.join("a/b/f"), d.join("a/b")] {
            let md = std::fs::metadata(&p).unwrap();
            let found = find_inode_under(&d, md.dev(), md.ino(), 4);
            assert_eq!(found.as_deref(), p.to_str(), "{}", p.display());
        }
        // Too deep, or not there.
        let md = std::fs::metadata(d.join("a/b/f")).unwrap();
        assert_eq!(find_inode_under(&d, md.dev(), md.ino(), 1), None);
        assert_eq!(find_inode_under(&d, md.dev(), u64::MAX, 4), None);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn kernel_dev_t_becomes_st_dev() {
        // 8:1 is /dev/sda1; 259:65536 needs the wide minor.
        assert_eq!(st_dev_of_kernel((8 << 20) | 1), libc::makedev(8, 1));
        assert_eq!(
            st_dev_of_kernel((259 << 20) | 65536),
            libc::makedev(259, 65536)
        );
    }

    #[test]
    fn only_files_that_really_got_the_bits_are_reported() {
        let d = std::env::temp_dir().join(format!("hermian-priv-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("sh");
        std::fs::write(&f, b"x").unwrap();
        let p = f.to_str().unwrap().to_string();
        // A chmod that didn't happen (or failed): nothing.
        assert!(privileged_file_event(p.clone(), FileKind::Modified, None).is_none());
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o4755)).unwrap();
        let ev = privileged_file_event(p.clone(), FileKind::Modified, None).unwrap();
        assert!(ev.is_suid && ev.path == p);
        // A directory given setgid (shared folders) isn't a privileged file.
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o2755)).unwrap();
        assert!(
            privileged_file_event(d.to_str().unwrap().into(), FileKind::Modified, None).is_none()
        );
        // Reported by a hook: the sweep leaves it alone.
        assert!(!priv_reported(ev.dev, ev.ino));
        note_priv_reported(ev.dev, ev.ino);
        assert!(priv_reported(ev.dev, ev.ino));
        let _ = std::fs::remove_dir_all(&d);
    }
}
