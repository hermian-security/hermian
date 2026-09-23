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

/// Directories swept for setuid/setgid/capability executables. Depth-limited
/// so a large home directory cannot turn the sweep into a filesystem crawl.
const SUID_SWEEP_ROOTS: &[&str] = &[
    "/tmp", "/var/tmp", "/dev/shm", "/home", "/root", "/var/www", "/srv", "/opt",
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
        let Ok(md) = e.metadata() else {
            continue;
        };
        let p = e.path();
        if md.file_type().is_symlink() {
            continue;
        }
        if md.is_dir() {
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
            walk(&p, depth - 1, out);
        } else if md.is_file() && md.permissions().mode() & (libc::S_ISUID | libc::S_ISGID) != 0 {
            out.push((p.to_string_lossy().into_owned(), md.dev(), md.ino()));
        }
    }
}

fn suid_sweep_loop(tx: mpsc::Sender<Event>, shutdown: Arc<AtomicBool>) {
    let scan = || {
        let mut out = Vec::new();
        for root in SUID_SWEEP_ROOTS {
            walk(Path::new(root), SUID_SWEEP_DEPTH, &mut out);
        }
        out
    };
    // Whatever exists at start is pre-existing; only new appearances alert.
    let mut known: HashSet<(u64, u64)> = scan().into_iter().map(|(_, d, i)| (d, i)).collect();
    while !shutdown.load(Ordering::Relaxed) {
        std::thread::sleep(SUID_SWEEP_INTERVAL);
        let current = scan();
        let mut now_known = HashSet::with_capacity(current.len());
        for (path, dev, ino) in current {
            now_known.insert((dev, ino));
            if known.contains(&(dev, ino)) {
                continue;
            }
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
        known = now_known;
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
    closed_tx: mpsc::Sender<(String, u16)>,
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

fn listener_poller_loop(
    tx: mpsc::Sender<Event>,
    closed_tx: mpsc::Sender<(String, u16)>,
    shutdown: Arc<AtomicBool>,
) {
    let snapshot = || -> HashSet<(String, u16)> {
        procsrc::read_tcp_tables()
            .into_iter()
            .filter(|e| e.state == procsrc::TCP_LISTEN)
            .map(|e| (e.proto.to_string(), e.local_port))
            .collect()
    };
    let mut known = snapshot();
    while !shutdown.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_secs(5));
        let entries: Vec<_> = procsrc::read_tcp_tables()
            .into_iter()
            .filter(|e| e.state == procsrc::TCP_LISTEN)
            .collect();
        let current: HashSet<(String, u16)> = entries
            .iter()
            .map(|e| (e.proto.to_string(), e.local_port))
            .collect();

        let new_entries: Vec<_> = entries
            .iter()
            .filter(|e| !known.contains(&(e.proto.to_string(), e.local_port)))
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
