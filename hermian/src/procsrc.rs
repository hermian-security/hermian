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
        // c_char is i8 on x86_64 and u8 on aarch64; this reads the byte either way.
        .map(|c| c.to_ne_bytes()[0])
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
    let f = match open_no_symlinks(path) {
        Ok(f) => f,
        // Kernels before 5.6 (or a seccomp filter) lack openat2: fall back
        // to checking the parent, then O_NOFOLLOW on the last component.
        // That leaves a small race (the parent can be swapped for a symlink
        // in between), which openat2 closes.
        Err(e) if matches!(e.raw_os_error(), Some(libc::ENOSYS) | Some(libc::EPERM)) => {
            // A symlinked parent (e.g. ~/.ssh -> /root/.ssh) would redirect the read.
            let parent = p.parent()?;
            if fs::canonicalize(parent).ok()? != parent {
                return None;
            }
            fs::OpenOptions::new()
                .read(true)
                .custom_flags(
                    libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOCTTY,
                )
                .open(p)
                .ok()?
        }
        Err(_) => return None,
    };
    let meta = f.metadata().ok()?;
    if !meta.file_type().is_file() {
        return None;
    }
    Some((f, meta))
}

/// Open read-only with no symlink anywhere in the path, atomically
/// (`openat2` with `RESOLVE_NO_SYMLINKS`, Linux 5.6+).
fn open_no_symlinks(path: &str) -> std::io::Result<fs::File> {
    use std::os::fd::FromRawFd;
    let c = std::ffi::CString::new(path)
        .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
    // SAFETY: open_how is plain data; zeroed is a valid value.
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags =
        (libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOCTTY)
            as u64;
    how.resolve = libc::RESOLVE_NO_SYMLINKS;
    // SAFETY: valid C string and open_how of the size passed.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            c.as_ptr(),
            &how as *const libc::open_how,
            std::mem::size_of::<libc::open_how>(),
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the kernel just returned this fd and nothing else owns it.
    Ok(unsafe { fs::File::from_raw_fd(fd as libc::c_int) })
}

/// PATH for the system tools Hermian runs.
const SAFE_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

/// A system tool (journalctl, nft, systemctl, dpkg...) by absolute path and
/// with a clean environment, so an LD_PRELOAD, LD_LIBRARY_PATH or PATH that
/// reached Hermian's environment never reaches the tool, and a planted
/// `nft` earlier in PATH is never the one that runs.
pub fn system_command(name: &str) -> std::process::Command {
    let path = SAFE_PATH
        .split(':')
        .map(|d| format!("{}/{}", d, name))
        .find(|p| std::path::Path::new(p).is_file())
        .unwrap_or_else(|| name.to_string());
    let mut c = std::process::Command::new(path);
    c.env_clear().env("PATH", SAFE_PATH).env("LC_ALL", "C");
    c
}

/// Files the unit hides from the daemon's own mount namespace
/// (`InaccessiblePaths=` in hermian.service), so a preload rootkit can't
/// hook the daemon or the tools it runs. Hermian still has to judge them, so
/// it reads the host's copies, through PID 1's root.
pub const HIDDEN_FROM_DAEMON: &[&str] = &["/etc/ld.so.preload"];

/// Where to look at `path` from inside the daemon: the host's view for the
/// files above, the path itself otherwise.
pub fn host_view(path: &str) -> std::borrow::Cow<'_, str> {
    if HIDDEN_FROM_DAEMON.contains(&path) {
        std::borrow::Cow::Owned(format!("/proc/1/root{}", path))
    } else {
        std::borrow::Cow::Borrowed(path)
    }
}

/// [`read_regular_file`], but for the host's copy of a file hidden from the
/// daemon. /proc/1/root is a link we pick ourselves; the file itself is
/// opened without following a symlink and must be a regular file.
pub fn read_host_view(path: &str) -> Option<String> {
    if !HIDDEN_FROM_DAEMON.contains(&path) {
        return read_regular_file(path);
    }
    use std::os::unix::fs::OpenOptionsExt;
    let f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOCTTY)
        .open(&*host_view(path))
        .ok()?;
    if !f.metadata().ok()?.file_type().is_file() {
        return None;
    }
    let mut buf = Vec::new();
    f.take(MAX_WATCHED_READ).read_to_end(&mut buf).ok()?;
    Some(String::from_utf8_lossy(&buf).into_owned())
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

/// The raw argument vector from `/proc/<pid>/cmdline` (at most 64 args).
pub fn argv_of(pid: u32) -> Vec<String> {
    let Ok(f) = fs::File::open(format!("/proc/{}/cmdline", pid)) else {
        return Vec::new();
    };
    let mut buf = Vec::new();
    if f.take(64 * 1024).read_to_end(&mut buf).is_err() {
        return Vec::new();
    }
    buf.split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .take(64)
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect()
}

/// The exe the engine's trust checks should see for `pid`. Normally `exe`
/// unchanged; for a script tool (`dnf`, `adduser`...) the script's own path,
/// so a shell script at `/tmp/dnf` isn't trusted as the package manager.
/// See [`hermian_core::proctree::script_tool_exe`].
pub fn judged_exe(pid: u32, comm: &str, exe: &str) -> String {
    mark_unowned(script_exe(pid, comm, exe), root_owned_cached)
}

/// Prefix put on an exe the engine would trust by path but that root doesn't
/// actually own. No trusted-dir check accepts it.
pub const NOT_ROOT_OWNED: &str = "(not root-owned) ";

/// The engine trusts install dirs (`/usr/bin/`, `/opt/`...) by path alone.
/// `/opt/<app>` is often a deploy user's, so `/opt/app/bin/apt` passed as
/// the package manager. Only paths root really owns keep that trust.
fn mark_unowned(exe: String, root_owned: impl Fn(&str) -> bool) -> String {
    if hermian_core::proctree::is_trusted_exe(&exe) && !root_owned(&exe) {
        format!("{}{}", NOT_ROOT_OWNED, exe)
    } else {
        exe
    }
}

/// `path` and every directory above it are owned by root, and nobody else
/// can replace them: no group (other than root) or world write, except on
/// sticky directories like `/nix/store` (1775 root:nixbld), where others
/// can't rename or delete root's entries.
pub fn root_owned_path(path: &str) -> bool {
    use std::os::unix::fs::MetadataExt;
    let mut p = Some(std::path::Path::new(path));
    while let Some(cur) = p {
        if cur.as_os_str().is_empty() {
            break;
        }
        let Ok(m) = fs::metadata(cur) else {
            return false;
        };
        let mode = m.mode();
        let others_write = mode & 0o002 != 0 || (mode & 0o020 != 0 && m.gid() != 0);
        let sticky_dir = m.is_dir() && mode & 0o1000 != 0;
        if m.uid() != 0 || (others_write && !sticky_dir) {
            return false;
        }
        p = cur.parent();
    }
    true
}

/// [`root_owned_path`] with a short cache: it runs on every exec.
fn root_owned_cached(path: &str) -> bool {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    use std::time::{Duration, Instant};
    const TTL: Duration = Duration::from_secs(60);
    const MAX: usize = 4096;
    static CACHE: OnceLock<Mutex<HashMap<String, (bool, Instant)>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(c) = cache.lock() {
        if let Some((owned, at)) = c.get(path) {
            if at.elapsed() < TTL {
                return *owned;
            }
        }
    }
    let owned = root_owned_path(path);
    if let Ok(mut c) = cache.lock() {
        if c.len() >= MAX {
            c.clear();
        }
        c.insert(path.to_string(), (owned, Instant::now()));
    }
    owned
}

fn script_exe(pid: u32, comm: &str, exe: &str) -> String {
    let unchanged = hermian_core::proctree::script_tool_exe(comm, exe, &[]);
    if unchanged == exe {
        // Not a script tool under an interpreter: no need to read cmdline.
        return unchanged;
    }
    // Mid-exec, comm is already the new one while the argument area isn't
    // set up yet and cmdline reads empty. Give it a moment.
    let mut argv = argv_of(pid);
    for _ in 0..5 {
        if !argv.is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
        argv = argv_of(pid);
    }
    let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
    hermian_core::proctree::script_tool_exe(comm, exe, &refs)
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
    status_id(pid, "Uid:")
}

pub fn gid_of(pid: u32) -> Option<u32> {
    status_id(pid, "Gid:")
}

/// The real id from a `Uid:`/`Gid:` line of /proc/<pid>/status.
fn status_id(pid: u32, key: &str) -> Option<u32> {
    let content = read_file(&format!("/proc/{}/status", pid))?;
    content.lines().find_map(|l| {
        l.strip_prefix(key)
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
        exe: if deleted {
            format!("{} (deleted)", exe)
        } else {
            judged_exe(pid, &comm, &exe)
        },
        comm,
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
                let exe = judged_exe(pid, &comm, &exe);
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
    pub remote_addr: IpAddr,
    pub remote_port: u16,
    pub state: u8,
    pub uid: u32,
    pub inode: u64,
}

pub const TCP_LISTEN: u8 = 0x0A;
pub const TCP_ESTABLISHED: u8 = 0x01;

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
    parse_tcp_table(&content, proto)
}

fn parse_tcp_table(content: &str, proto: &'static str) -> Vec<TcpEntry> {
    content
        .lines()
        .skip(1)
        .filter_map(|line| {
            let mut it = line.split_whitespace();
            let _sl = it.next()?;
            let local = it.next()?;
            let remote = it.next()?;
            let state = u8::from_str_radix(it.next()?, 16).ok()?;
            // tx_queue:rx_queue, tr:tm->when, retrnsmt. Skipping four here
            // used to read the timeout as uid and the refcount as the inode,
            // so socket owners (listener pids) were never found.
            for _ in 0..3 {
                it.next()?;
            }
            let uid = it.next()?.parse().unwrap_or(0);
            let _timeout = it.next()?;
            let inode = it.next()?.parse().unwrap_or(0);
            let (local_addr, local_port) = local
                .split_once(':')
                .and_then(|(h, p)| parse_hex_addr(h, p))?;
            let (remote_addr, remote_port) = remote
                .split_once(':')
                .and_then(|(h, p)| parse_hex_addr(h, p))?;
            Some(TcpEntry {
                proto,
                local_addr,
                local_port,
                remote_addr,
                remote_port,
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

/// Every pid holding any of these socket inodes (a forked sshd and its
/// monitor share the connection's socket), in one pass over `/proc/*/fd`.
pub fn all_pids_for_inodes(inodes: &[u64]) -> Vec<u32> {
    let mut out = Vec::new();
    if inodes.is_empty() {
        return out;
    }
    for pid in proc_pids() {
        let Ok(fds) = fs::read_dir(format!("/proc/{}/fd", pid)) else {
            continue;
        };
        let holds = fds.flatten().any(|fd| {
            fs::read_link(fd.path())
                .ok()
                .and_then(|l| {
                    l.to_string_lossy()
                        .strip_prefix("socket:[")
                        .and_then(|s| s.strip_suffix(']'))
                        .and_then(|s| s.parse::<u64>().ok())
                })
                .is_some_and(|ino| inodes.contains(&ino))
        });
        if holds {
            out.push(pid);
        }
    }
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
    // `dpkg-query -S` takes a glob: a file named `x*` or `[a]` could match
    // some packaged file and pass as package-owned. Don't ask about those.
    if path.contains(['*', '?', '[', ']', '\\']) {
        return None;
    }
    for (cmd, args) in [
        ("dpkg-query", vec!["-S"]),
        ("rpm", vec!["-qf"]),
        ("pacman", vec!["-Qo"]),
    ] {
        let out = system_command(cmd)
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

/// Whether `path` is a 32-bit ELF on a 64-bit x86 host. Such programs make
/// compat (int 0x80 / ia32) syscalls, which the `sys_enter_*` tracepoints
/// don't see, so their connects and ptrace calls are invisible to eBPF.
pub fn is_compat_binary(path: &str) -> bool {
    if !cfg!(target_arch = "x86_64") || path.is_empty() {
        return false;
    }
    let Ok(f) = fs::File::open(path) else {
        return false;
    };
    let mut hdr = [0u8; 5];
    if f.take(5).read_exact(&mut hdr).is_err() {
        return false;
    }
    is_elf32(&hdr)
}

fn is_elf32(hdr: &[u8; 5]) -> bool {
    hdr[..4] == *b"\x7fELF" && hdr[4] == 1
}

pub fn current_exe_path() -> Result<PathBuf> {
    fs::read_link("/proc/self/exe").context("failed to resolve own binary path")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn system_tools_run_by_absolute_path_with_a_clean_environment() {
        // Any variable proves the environment is cleared; LD_PRELOAD itself
        // would leak into tests running alongside.
        std::env::set_var("HERMIAN_TEST_LEAK", "leaked");
        let c = system_command("sh");
        let prog = c.get_program().to_string_lossy().into_owned();
        assert!(prog.starts_with('/') && prog.ends_with("/sh"), "{}", prog);
        let out = system_command("sh")
            .args(["-c", "echo \"${HERMIAN_TEST_LEAK:-unset} $PATH\""])
            .output()
            .unwrap();
        std::env::remove_var("HERMIAN_TEST_LEAK");
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            format!("unset {}", SAFE_PATH)
        );
    }

    #[test]
    fn hidden_files_are_read_from_the_host_view() {
        assert_eq!(
            host_view("/etc/ld.so.preload"),
            "/proc/1/root/etc/ld.so.preload"
        );
        assert_eq!(host_view("/etc/crontab"), "/etc/crontab");
    }

    #[test]
    fn trusted_paths_root_does_not_own_lose_their_trust() {
        let unowned = mark_unowned("/opt/app/bin/apt".into(), |_| false);
        assert_eq!(unowned, "(not root-owned) /opt/app/bin/apt");
        assert!(!hermian_core::proctree::is_trusted_exe(&unowned));
        assert_eq!(
            mark_unowned("/usr/bin/apt".into(), |_| true),
            "/usr/bin/apt"
        );
        // Untrusted paths stay as they are; nothing to downgrade.
        assert_eq!(mark_unowned("/tmp/apt".into(), |_| false), "/tmp/apt");
    }

    #[test]
    fn ownership_walks_every_parent() {
        use std::os::unix::fs::PermissionsExt;
        assert!(root_owned_path("/usr/bin/env"));
        let dir = scratch("owned");
        let f = dir.join("tool");
        fs::write(&f, "x").unwrap();
        if unsafe { libc::geteuid() } != 0 {
            // Our own file and directory: not root's.
            assert!(!root_owned_path(f.to_str().unwrap()));
        }
        // A binary anyone can rewrite never counts, whoever owns it.
        fs::set_permissions(&f, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(!root_owned_path(f.to_str().unwrap()));
        assert!(!root_owned_path("/nonexistent/hermian/tool"));
        fs::remove_dir_all(&dir).unwrap();
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("hermian-{}-{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        // temp_dir itself may be a symlink (macOS-style setups); use the real path.
        fs::canonicalize(&dir).unwrap()
    }

    #[test]
    fn tcp_table_rows_carry_both_ends() {
        // Copied from a real /proc/net/tcp (uid 991, inode 4242).
        let t = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:0016 0764A8C6:C350 01 00000000:00000000 00:00000000 00000000   991        0 4242 1 0000000000000000 20 4 30 10 -1\n";
        let rows = parse_tcp_table(t, "tcp");
        assert_eq!(rows.len(), 1);
        let r = &rows[0];
        assert_eq!(r.local_addr, "127.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(r.local_port, 22);
        assert_eq!(r.remote_addr, "198.168.100.7".parse::<IpAddr>().unwrap());
        assert_eq!(r.remote_port, 50000);
        assert_eq!(r.state, TCP_ESTABLISHED);
        assert_eq!(r.uid, 991);
        assert_eq!(r.inode, 4242);
    }

    #[test]
    fn elf_class_is_read_from_the_header() {
        assert!(is_elf32(b"\x7fELF\x01"));
        assert!(!is_elf32(b"\x7fELF\x02"));
        assert!(!is_elf32(b"#!/bi"));
        // Our own binary is 64-bit.
        let me = current_exe_path().unwrap();
        assert!(!is_compat_binary(me.to_str().unwrap()));
        assert!(!is_compat_binary("/nonexistent"));
    }

    #[test]
    fn script_named_like_a_tool_is_judged_by_its_path() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("scripttool");
        let script = dir.join("dnf");
        fs::write(&script, "#!/bin/sh\nsleep 5\n").unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        let mut child = std::process::Command::new(&script).spawn().unwrap();
        let pid = child.id();
        // Wait for the exec to land: comm switches to "dnf", then the new
        // argument area appears.
        let mut comm = String::new();
        for _ in 0..200 {
            comm = comm_of(pid).unwrap_or_default();
            if comm == "dnf" && argv_of(pid).len() >= 2 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let (exe, _) = exe_of(pid).unwrap();
        let judged = judged_exe(pid, &comm, &exe);
        let _ = child.kill();
        let _ = child.wait();
        fs::remove_dir_all(dir).unwrap();
        assert_eq!(comm, "dnf");
        assert_eq!(judged, script.to_str().unwrap(), "exe was {}", exe);
        assert_ne!(
            hermian_core::role_of(&comm, &judged),
            hermian_core::Role::PackageManager
        );
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
