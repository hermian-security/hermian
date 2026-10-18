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
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use hermian_core::{Event, ExecEvent, FileEvent, FileKind, ListenerEvent};
use tokio::sync::mpsc;

use crate::procsrc;

/// Directories swept for setuid/setgid/capability executables, with how many
/// sweeps go by between two walks of each. Transient directories, where a
/// dropped binary usually lands, every sweep; homes and service trees, which
/// can hold tens of thousands of entries, every third. Depth-limited so a
/// large home directory cannot turn the sweep into a filesystem crawl.
const SUID_SWEEP_ROOTS: &[(&[&str], u32)] = &[
    (&["/tmp", "/var/tmp", "/dev/shm"], 1),
    (&["/home", "/root", "/var/www", "/srv", "/opt"], 3),
];
const SUID_SWEEP_DEPTH: usize = 4;
const SUID_SWEEP_INTERVAL: Duration = Duration::from_secs(20);

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

fn suid_sweep_loop(tx: mpsc::Sender<Event>, shutdown: Arc<AtomicBool>) {
    // Whatever exists at start is pre-existing; only new appearances alert.
    // Each group keeps its own: a group not walked this round keeps what it knew.
    let mut known: Vec<HashSet<(u64, u64)>> = SUID_SWEEP_ROOTS
        .iter()
        .map(|(roots, _)| {
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
        for (g, (roots, every)) in SUID_SWEEP_ROOTS.iter().enumerate() {
            if !round.is_multiple_of(*every) {
                continue;
            }
            for (path, dev, ino) in newly_privileged(&mut known[g], scan_roots(roots)) {
                let writer = procsrc::pid_for_path(&path).map(|(pid, comm, exe, uid, tty_nr)| {
                    hermian_core::WriterInfo {
                        pid,
                        uid,
                        comm,
                        exe,
                        tty_nr,
                    }
                });
                let ev = FileEvent {
                    ts: chrono::Utc::now(),
                    kind: FileKind::Created,
                    dev,
                    ino,
                    writer,
                    session_present: false,
                    is_suid: true,
                    has_file_caps: procsrc::has_file_capabilities(&path),
                    content: None,
                    container: false,
                    managed_by_package: None,
                    path,
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
            .find(|(roots, _)| roots.contains(&"/tmp"))
            .unwrap();
        assert_eq!(tmp.1, 1);
        for root in ["/dev/shm", "/var/tmp", "/home", "/root"] {
            assert!(
                SUID_SWEEP_ROOTS.iter().any(|(r, _)| r.contains(&root)),
                "{}",
                root
            );
        }
        // Homes at least once a minute.
        assert!(SUID_SWEEP_ROOTS
            .iter()
            .all(|(_, every)| SUID_SWEEP_INTERVAL * *every <= Duration::from_secs(60)));
    }
}
