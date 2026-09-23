//! `/proc` and libc-backed host introspection. Everything here is best-effort:
//! processes vanish mid-scan, so every per-pid read tolerates failure and a
//! failure for one pid never aborts a scan of the others.

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use hermian_core::ProcInfo;
use libc::{sysconf, uname, utsname, _SC_CLK_TCK, _SC_PAGESIZE};

pub fn kernel_release() -> String {
    // SAFETY: utsname is a plain C struct; uname fills it in.
    let mut uts: utsname = unsafe { std::mem::zeroed() };
    // SAFETY: valid pointer to a utsname.
    unsafe {
        uname(&mut uts);
    }
    let bytes: Vec<u8> = uts
        .release
        .iter()
        .take_while(|c| **c != 0)
        .map(|c| *c as u8)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

pub fn kernel_major_minor() -> (u32, u32) {
    let release = kernel_release();
    let mut it = release.split(['.', '-']);
    let major = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    (major, minor)
}

pub fn kernel_supports_ebpf() -> bool {
    let (major, minor) = kernel_major_minor();
    major > 5 || (major == 5 && minor >= 8)
}

pub fn page_size() -> u64 {
    // SAFETY: sysconf with a valid name.
    unsafe { sysconf(_SC_PAGESIZE) as u64 }
}

pub fn clock_ticks() -> u64 {
    // SAFETY: sysconf with a valid name.
    let t = unsafe { sysconf(_SC_CLK_TCK) };
    if t <= 0 {
        100
    } else {
        t as u64
    }
}

pub fn hostname() -> String {
    hostname::get()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Read up to 1 MiB of a file as UTF-8 (lossy).
pub fn read_file(path: &str) -> Option<String> {
    let f = fs::File::open(path).ok()?;
    let mut buf = Vec::new();
    f.take(1024 * 1024).read_to_end(&mut buf).ok()?;
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// Largest file [`read_regular_file`] will return.
const MAX_WATCHED_READ: u64 = 1024 * 1024;

/// Read a watched file that an unprivileged user may control (dotfiles,
/// `authorized_keys`, spool files) without letting them steer a root read.
///
/// Refuses symlinks (final component and parent directories), FIFOs, devices
/// and sockets. `O_NONBLOCK` keeps a FIFO swapped in after the check from
/// hanging the caller.
pub fn read_regular_file(path: &str) -> Option<String> {
    let (f, _) = open_regular(path)?;
    let mut buf = Vec::new();
    f.take(MAX_WATCHED_READ).read_to_end(&mut buf).ok()?;
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// Open `path` read-only if, and only if, it's a regular file reached without
/// following any symlink. See [`read_regular_file`].
pub fn open_regular(path: &str) -> Option<(fs::File, fs::Metadata)> {
    use std::os::unix::fs::OpenOptionsExt;
    let p = std::path::Path::new(path);
    // A symlinked parent (e.g. ~/.ssh -> /root/.ssh) would redirect the read.
    let parent = p.parent()?;
    if fs::canonicalize(parent).ok()? != parent {
        return None;
    }
    let f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOCTTY)
        .open(p)
        .ok()?;
    let meta = f.metadata().ok()?;
    if !meta.file_type().is_file() {
        return None;
    }
    Some((f, meta))
}

pub fn exe_of(pid: u32) -> Option<(String, bool)> {
    let link = fs::read_link(format!("/proc/{}/exe", pid)).ok()?;
    let raw = link.to_string_lossy().into_owned();
    match raw.strip_suffix(" (deleted)") {
        Some(stripped) => Some((stripped.to_string(), true)),
        None => Some((raw, false)),
    }
}

pub fn cmdline_of(pid: u32) -> Option<String> {
    let mut f = fs::File::open(format!("/proc/{}/cmdline", pid)).ok()?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).ok()?;
    let args: Vec<String> = buf
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect();
    if args.is_empty() {
        None
    } else {
        Some(args.join(" "))
    }
}

pub fn comm_of(pid: u32) -> Option<String> {
    let mut f = fs::File::open(format!("/proc/{}/comm", pid)).ok()?;
    let mut buf = [0u8; 64];
    let n = f.read(&mut buf).ok()?;
    if n == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&buf[..n]).trim().to_string())
}

/// `(ppid, tty_nr, starttime)` from `/proc/<pid>/stat`.
pub fn stat_of(pid: u32) -> Option<(u32, i64, u64)> {
    let content = read_file(&format!("/proc/{}/stat", pid))?;
    let comm_end = content.rfind(')')?;
    let rest = content.get(comm_end + 2..)?;
    let mut it = rest.split_whitespace();
    it.next()?; // state
    let ppid: u32 = it.next()?.parse().ok()?;
    it.next()?; // pgrp
    it.next()?; // session
    let tty_nr: i64 = it.next()?.parse().ok()?;
    for _ in 0..14 {
        it.next()?;
    }
    let start: u64 = it.next()?.parse().ok()?;
    Some((ppid, tty_nr, start))
}

pub fn uid_of(pid: u32) -> Option<u32> {
    let content = read_file(&format!("/proc/{}/status", pid))?;
    content.lines().find_map(|l| {
        l.strip_prefix("Uid:")
            .and_then(|v| v.split_whitespace().next())
            .and_then(|s| s.parse::<u32>().ok())
    })
}

pub fn container_info(pid: u32) -> (bool, Option<String>) {
    let host_ns = fs::read_link("/proc/1/ns/pid").ok();
    let pid_ns = fs::read_link(format!("/proc/{}/ns/pid", pid)).ok();
    let in_other_ns = matches!((&host_ns, &pid_ns), (Some(h), Some(p)) if h != p);
    let cgroup = read_file(&format!("/proc/{}/cgroup", pid)).unwrap_or_default();
    let lower = cgroup.to_lowercase();
    let runtime = ["docker", "containerd", "kubepods", "libpod", "lxc", "crio"]
        .iter()
        .any(|k| lower.contains(k));
    if !(in_other_ns || runtime) {
        return (false, None);
    }
    (true, extract_container_id(&cgroup))
}

fn extract_container_id(cgroup: &str) -> Option<String> {
    for marker in [
        "docker-",
        "crio-",
        "libpod-",
        "cri-containerd-",
        "lxc.payload.",
    ] {
        if let Some(pos) = cgroup.find(marker) {
            let id: String = cgroup[pos + marker.len()..]
                .chars()
                .take_while(|c| c.is_ascii_hexdigit())
                .collect();
            if id.len() >= 12 {
                return Some(id);
            }
        }
    }
    cgroup
        .split(['/', '.'])
        .map(str::trim)
        .filter(|s| s.len() >= 12 && s.chars().all(|c| c.is_ascii_hexdigit()))
        .max_by_key(|s| s.len())
        .map(str::to_string)
}

fn proc_pids() -> Vec<u32> {
    let Ok(entries) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|e| e.file_name().to_string_lossy().parse::<u32>().ok())
        .collect()
}

/// Every pid that exists right now.
pub fn live_pids() -> std::collections::HashSet<u32> {
    proc_pids().into_iter().collect()
}

pub fn proc_info(pid: u32, now: chrono::DateTime<chrono::Utc>) -> Option<ProcInfo> {
    let (ppid, tty_nr, start) = stat_of(pid)?;
    let comm = comm_of(pid).unwrap_or_default();
    let (exe, deleted) = exe_of(pid).unwrap_or_default();
    let uid = uid_of(pid).unwrap_or(0);
    let (container, container_id) = container_info(pid);
    Some(ProcInfo {
        pid,
        ppid,
        uid,
        comm,
        exe: if deleted {
            format!("{} (deleted)", exe)
        } else {
            exe
        },
        start,
        tty_nr,
        container,
        container_id,
        seen_at: now,
        previous: Vec::new(),
    })
}

pub fn scan_processes() -> Vec<ProcInfo> {
    let now = chrono::Utc::now();
    proc_pids()
        .into_iter()
        .filter_map(|pid| proc_info(pid, now))
        .collect()
}

/// Identify a process that currently has `path` open for writing.
pub fn pid_for_path(path: &str) -> Option<(u32, String, String, u32, i64)> {
    for pid in proc_pids() {
        let Ok(fds) = fs::read_dir(format!("/proc/{}/fd", pid)) else {
            continue;
        };
        for fd in fds.flatten() {
            let Ok(link) = fs::read_link(fd.path()) else {
                continue;
            };
            let target = link.to_string_lossy();
            let target = target.strip_suffix(" (deleted)").unwrap_or(&target);
            if target == path {
                let comm = comm_of(pid).unwrap_or_default();
                let (exe, _) = exe_of(pid).unwrap_or_default();
                let uid = uid_of(pid).unwrap_or(0);
                let (_ppid, tty_nr, _start) = stat_of(pid).unwrap_or((0, 0, 0));
                return Some((pid, comm, exe, uid, tty_nr));
            }
        }
    }
    None
}

#[derive(Debug, Clone)]
pub struct TcpEntry {
    pub proto: &'static str,
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub state: u8,
    pub uid: u32,
    pub inode: u64,
}

pub const TCP_LISTEN: u8 = 0x0A;

fn parse_hex_addr(hex: &str, port_hex: &str) -> Option<(IpAddr, u16)> {
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    if hex.len() == 8 {
        let v = u32::from_str_radix(hex, 16).ok()?;
        Some((IpAddr::V4(Ipv4Addr::from(v.swap_bytes())), port))
    } else if hex.len() == 32 {
        let mut bytes = [0u8; 16];
        for i in 0..4 {
            let v = u32::from_str_radix(&hex[i * 8..(i + 1) * 8], 16).ok()?;
            bytes[i * 4..(i + 1) * 4].copy_from_slice(&v.swap_bytes().to_be_bytes());
        }
        Some((IpAddr::V6(Ipv6Addr::from(bytes)), port))
    } else {
        None
    }
}

fn parse_tcp_file(path: &str, proto: &'static str) -> Vec<TcpEntry> {
    let Some(content) = read_file(path) else {
        return Vec::new();
    };
    content
        .lines()
        .skip(1)
        .filter_map(|line| {
            let mut it = line.split_whitespace();
            let _sl = it.next()?;
            let local = it.next()?;
            let _remote = it.next()?;
            let state = u8::from_str_radix(it.next()?, 16).ok()?;
            for _ in 0..4 {
                it.next()?;
            }
            let uid = it.next()?.parse().unwrap_or(0);
            let _timeout = it.next()?;
            let inode = it.next()?.parse().unwrap_or(0);
            let (local_addr, local_port) = local
                .split_once(':')
                .and_then(|(h, p)| parse_hex_addr(h, p))?;
            Some(TcpEntry {
                proto,
                local_addr,
                local_port,
                state,
                uid,
                inode,
            })
        })
        .collect()
}

pub fn read_tcp_tables() -> Vec<TcpEntry> {
    let mut out = parse_tcp_file("/proc/net/tcp", "tcp");
    out.extend(parse_tcp_file("/proc/net/tcp6", "tcp6"));
    out
}

/// Map many socket inodes to owning pids in one pass over `/proc/*/fd`.
pub fn pids_for_inodes(inodes: &[u64]) -> HashMap<u64, u32> {
    let mut out = HashMap::new();
    if inodes.is_empty() {
        return out;
    }
    for pid in proc_pids() {
        let Ok(fds) = fs::read_dir(format!("/proc/{}/fd", pid)) else {
            continue;
        };
        for fd in fds.flatten() {
            let Ok(link) = fs::read_link(fd.path()) else {
                continue;
            };
            let target = link.to_string_lossy();
            let Some(inode) = target
                .strip_prefix("socket:[")
                .and_then(|s| s.strip_suffix(']'))
                .and_then(|s| s.parse::<u64>().ok())
            else {
                continue;
            };
            if inodes.contains(&inode) {
                out.entry(inode).or_insert(pid);
                if out.len() == inodes.len() {
                    return out;
                }
            }
        }
    }
    out
}

/// `(cpu ticks consumed, wall clock seconds)` for this process.
pub fn self_cpu_sample() -> (u64, f64) {
    let wall = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    let Some(content) = read_file("/proc/self/stat") else {
        return (0, wall);
    };
    let Some(comm_end) = content.rfind(')') else {
        return (0, wall);
    };
    let fields: Vec<&str> = content[comm_end + 2..].split_whitespace().collect();
    let utime: u64 = fields.get(11).and_then(|s| s.parse().ok()).unwrap_or(0);
    let stime: u64 = fields.get(12).and_then(|s| s.parse().ok()).unwrap_or(0);
    (utime + stime, wall)
}

pub fn self_rss_kb() -> u64 {
    let Some(content) = read_file("/proc/self/statm") else {
        return 0;
    };
    let resident_pages: u64 = content
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    resident_pages * page_size() / 1024
}

pub fn load_user_names() -> HashMap<u32, String> {
    read_file("/etc/passwd")
        .map(|c| hermian_core::engine::parse_user_names(&c))
        .unwrap_or_default()
}

pub fn has_file_capabilities(path: &str) -> bool {
    let Ok(cpath) = std::ffi::CString::new(path) else {
        return false;
    };
    // lgetxattr: don't follow a user-planted symlink to some capability binary.
    // SAFETY: valid C strings; null buffer with size 0 queries the attribute length.
    let rc = unsafe {
        libc::lgetxattr(
            cpath.as_ptr(),
            c"security.capability".as_ptr(),
            std::ptr::null_mut(),
            0,
        )
    };
    rc > 0
}

pub fn is_suid_or_sgid(path: &str) -> bool {
    use std::os::unix::fs::PermissionsExt;
    // symlink_metadata: a symlink to /usr/bin/sudo isn't a new setuid file.
    fs::symlink_metadata(path)
        .map(|m| m.is_file() && m.permissions().mode() & (libc::S_ISUID | libc::S_ISGID) != 0)
        .unwrap_or(false)
}

/// Whether `path` is owned by an installed package. `None` when no package
/// manager could answer.
pub fn file_in_package_database(path: &str) -> Option<bool> {
    for (cmd, args) in [
        ("dpkg-query", vec!["-S"]),
        ("rpm", vec!["-qf"]),
        ("pacman", vec!["-Qo"]),
    ] {
        let out = std::process::Command::new(cmd)
            .args(&args)
            .arg(path)
            .stdin(std::process::Stdio::null())
            .output();
        match out {
            Ok(o) if o.status.success() => return Some(true),
            Ok(o) if o.status.code() == Some(1) => return Some(false),
            _ => {}
        }
    }
    None
}

pub fn current_exe_path() -> Result<PathBuf> {
    fs::read_link("/proc/self/exe").context("failed to resolve own binary path")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("hermian-{}-{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        // temp_dir itself may be a symlink (macOS-style setups); use the real path.
        fs::canonicalize(&dir).unwrap()
    }

    #[test]
    fn regular_file_is_read() {
        let dir = scratch("regular");
        let f = dir.join(".bashrc");
        fs::write(&f, "export A=1\n").unwrap();
        assert_eq!(
            read_regular_file(f.to_str().unwrap()).as_deref(),
            Some("export A=1\n")
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn fifo_does_not_block_or_read() {
        let dir = scratch("fifo");
        let f = dir.join(".bashrc");
        let c = std::ffi::CString::new(f.to_str().unwrap()).unwrap();
        // SAFETY: valid C string.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
        // A blocking open would hang this test forever.
        assert!(read_regular_file(f.to_str().unwrap()).is_none());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn symlinks_are_not_followed() {
        let dir = scratch("symlink");
        let secret = dir.join("secret");
        fs::write(&secret, "root:$6$hash:::\n").unwrap();
        let link = dir.join(".bashrc");
        symlink(&secret, &link).unwrap();
        assert!(read_regular_file(link.to_str().unwrap()).is_none());
        assert!(!is_suid_or_sgid(link.to_str().unwrap()));

        // Symlinked parent directory: ~/.ssh -> somewhere else.
        let real = dir.join("real");
        fs::create_dir(&real).unwrap();
        fs::write(real.join("authorized_keys"), "ssh-ed25519 AAAA\n").unwrap();
        let ssh = dir.join(".ssh");
        symlink(&real, &ssh).unwrap();
        assert!(read_regular_file(ssh.join("authorized_keys").to_str().unwrap()).is_none());
        fs::remove_dir_all(dir).unwrap();
    }
}
