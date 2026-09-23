//! Linux audit (NETLINK_AUDIT) exec source, used when eBPF is unavailable.
//!
//! Registers this process as the audit daemon, installs an `execve`/`execveat`
//! exit rule, and parses the resulting text records. Refuses to run when a
//! real auditd is present because the kernel supports exactly one listener.
//!
//! Record format (kernel, `AUDIT_SYSCALL` = 1300):
//! `audit(1700000000.123:456): arch=c000003e syscall=59 success=yes exit=0 ... ppid=1 pid=1234 ... uid=0 ... comm="sh" exe="/usr/bin/dash" ...`

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use hermian_core::{Event, ExecEvent};
use tokio::sync::mpsc;

use crate::procsrc;

const NETLINK_AUDIT: libc::c_int = 9;

const AUDIT_SET: u16 = 1001;
const AUDIT_ADD_RULE: u16 = 1011;
const AUDIT_DEL_RULE: u16 = 1012;
const AUDIT_SYSCALL: u16 = 1300;
const AUDIT_EXECVE: u16 = 1309;
const AUDIT_EOE: u16 = 1320;
const NLMSG_ERROR: u16 = 2;

const AUDIT_STATUS_ENABLED: u32 = 0x0001;
const AUDIT_STATUS_PID: u32 = 0x0004;
const AUDIT_FILTER_EXIT: u32 = 0x04;
const AUDIT_ALWAYS: u32 = 2;
const AUDIT_ARCH: u32 = 11;
const AUDIT_EQUAL: u32 = 0x4000_0000;
const AUDIT_BITMASK_SIZE: usize = 64;

const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_ACK: u16 = 0x0004;

#[repr(C)]
#[derive(Clone, Copy)]
struct NlMsgHdr {
    len: u32,
    kind: u16,
    flags: u16,
    seq: u32,
    pid: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct AuditStatus {
    mask: u32,
    enabled: u32,
    failure: u32,
    pid: u32,
    rate_limit: u32,
    backlog_limit: u32,
    lost: u32,
    backlog: u32,
    feature_bitmap: u32,
    backlog_wait_time: u32,
    backlog_wait_time_actual: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct AuditRuleData {
    flags: u32,
    action: u32,
    field_count: u32,
    mask: [u32; AUDIT_BITMASK_SIZE],
    fields: [u32; AUDIT_BITMASK_SIZE],
    values: [u32; AUDIT_BITMASK_SIZE],
    fieldflags: [u32; AUDIT_BITMASK_SIZE],
    buflen: u32,
}

impl AuditRuleData {
    fn zeroed() -> Self {
        AuditRuleData {
            flags: 0,
            action: 0,
            field_count: 0,
            mask: [0; AUDIT_BITMASK_SIZE],
            fields: [0; AUDIT_BITMASK_SIZE],
            values: [0; AUDIT_BITMASK_SIZE],
            fieldflags: [0; AUDIT_BITMASK_SIZE],
            buflen: 0,
        }
    }

    fn add_syscall(&mut self, nr: u32) {
        let word = (nr / 32) as usize;
        if word < AUDIT_BITMASK_SIZE {
            self.mask[word] |= 1 << (nr % 32);
        }
    }

    fn add_field(&mut self, field: u32, value: u32, op: u32) {
        let i = self.field_count as usize;
        if i < AUDIT_BITMASK_SIZE {
            self.fields[i] = field;
            self.values[i] = value;
            self.fieldflags[i] = op;
            self.field_count += 1;
        }
    }
}

/// (audit arch constant, execve nr, execveat nr) for the build target.
fn arch_syscalls() -> (u32, u32, u32) {
    match std::env::consts::ARCH {
        "x86_64" => (0xC000_003E, 59, 322),
        "aarch64" => (0xC000_00B7, 221, 281),
        "x86" => (0x4000_0003, 11, 358),
        _ => (0xC000_003E, 59, 322),
    }
}

pub fn auditd_running() -> bool {
    ["/run/auditd.pid", "/var/run/auditd.pid"]
        .iter()
        .any(|p| std::path::Path::new(p).exists())
}

/// The kernel accepts a single audit listener; never fight a real auditd.
pub fn audit_usable() -> bool {
    !auditd_running()
}

pub struct AuditSource {
    fd: libc::c_int,
    rule: AuditRuleData,
}

impl Drop for AuditSource {
    fn drop(&mut self) {
        // Best-effort cleanup so the rule does not outlive us.
        let _ = send_msg(self.fd, AUDIT_DEL_RULE, self.rule);
        // SAFETY: fd was returned by socket().
        unsafe {
            libc::close(self.fd);
        }
    }
}

pub fn spawn_audit_reader(tx: mpsc::Sender<Event>, shutdown: Arc<AtomicBool>) -> Result<()> {
    let source = open_audit_socket()?;
    std::thread::Builder::new()
        .name("hermian-audit".to_string())
        .spawn(move || audit_loop(source, tx, shutdown))?;
    Ok(())
}

fn open_audit_socket() -> Result<AuditSource> {
    // SAFETY: standard socket/bind sequence with correctly sized structs.
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            NETLINK_AUDIT,
        )
    };
    if fd < 0 {
        return Err(anyhow!("failed to open NETLINK_AUDIT socket"));
    }
    // SAFETY: sockaddr_nl is plain data.
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    // SAFETY: valid fd and sockaddr.
    let rc = unsafe {
        libc::bind(
            fd,
            &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        // SAFETY: fd is ours.
        unsafe {
            libc::close(fd);
        }
        return Err(anyhow!("failed to bind NETLINK_AUDIT socket"));
    }

    let status = AuditStatus {
        mask: AUDIT_STATUS_ENABLED | AUDIT_STATUS_PID,
        enabled: 1,
        failure: 1,
        // SAFETY: getpid has no preconditions.
        pid: unsafe { libc::getpid() } as u32,
        rate_limit: 0,
        backlog_limit: 8192,
        lost: 0,
        backlog: 0,
        feature_bitmap: 0,
        backlog_wait_time: 0,
        backlog_wait_time_actual: 0,
    };
    send_msg(fd, AUDIT_SET, status)?;
    expect_ack(fd)?;

    let (arch, execve, execveat) = arch_syscalls();
    let mut rule = AuditRuleData::zeroed();
    rule.flags = AUDIT_FILTER_EXIT;
    rule.action = AUDIT_ALWAYS;
    rule.add_syscall(execve);
    rule.add_syscall(execveat);
    rule.add_field(AUDIT_ARCH, arch, AUDIT_EQUAL);
    send_msg(fd, AUDIT_ADD_RULE, rule)?;
    // EEXIST is fine (rule already present from a previous unclean exit).
    if let Err(e) = expect_ack(fd) {
        if !e.to_string().contains("EEXIST") {
            // SAFETY: fd is ours.
            unsafe {
                libc::close(fd);
            }
            return Err(e);
        }
    }
    Ok(AuditSource { fd, rule })
}

fn send_msg<T: Copy>(fd: libc::c_int, kind: u16, payload: T) -> Result<()> {
    let payload_size = std::mem::size_of::<T>();
    let total = std::mem::size_of::<NlMsgHdr>() + payload_size;
    let mut buf = vec![0u8; total];
    let hdr = NlMsgHdr {
        len: total as u32,
        kind,
        flags: NLM_F_REQUEST | NLM_F_ACK,
        seq: 1,
        pid: 0,
    };
    // SAFETY: buf is exactly hdr + payload bytes; both types are repr(C) POD.
    unsafe {
        std::ptr::copy_nonoverlapping(
            &hdr as *const NlMsgHdr as *const u8,
            buf.as_mut_ptr(),
            std::mem::size_of::<NlMsgHdr>(),
        );
        std::ptr::copy_nonoverlapping(
            &payload as *const T as *const u8,
            buf.as_mut_ptr().add(std::mem::size_of::<NlMsgHdr>()),
            payload_size,
        );
        if libc::send(fd, buf.as_ptr() as *const libc::c_void, total, 0) < 0 {
            return Err(anyhow!("failed to send netlink message type {}", kind));
        }
    }
    Ok(())
}

fn set_rcv_timeout(fd: libc::c_int, secs: i64) {
    let tv = libc::timeval {
        tv_sec: secs as libc::time_t,
        tv_usec: 0,
    };
    // SAFETY: valid fd and timeval.
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const libc::timeval as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }
}

/// Wait for the NLMSG_ERROR ack that follows a request; error 0 means success.
fn expect_ack(fd: libc::c_int) -> Result<()> {
    set_rcv_timeout(fd, 2);
    let mut buf = [0u8; 8192];
    for _ in 0..8 {
        // SAFETY: valid fd and buffer.
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n <= 0 {
            return Err(anyhow!("no ack from audit subsystem (is auditd running?)"));
        }
        let n = n as usize;
        let mut offset = 0;
        while offset + std::mem::size_of::<NlMsgHdr>() <= n {
            // SAFETY: bounds checked above.
            let hdr =
                unsafe { std::ptr::read_unaligned(buf[offset..].as_ptr() as *const NlMsgHdr) };
            let msg_len = hdr.len as usize;
            if msg_len < std::mem::size_of::<NlMsgHdr>() || offset + msg_len > n {
                break;
            }
            if hdr.kind == NLMSG_ERROR {
                let err_off = offset + std::mem::size_of::<NlMsgHdr>();
                let errno = read_i32(&buf, err_off).unwrap_or(0);
                return if errno == 0 {
                    Ok(())
                } else if errno == -libc::EEXIST {
                    Err(anyhow!("EEXIST"))
                } else {
                    Err(anyhow!("audit request rejected: errno {}", -errno))
                };
            }
            offset += nlmsg_align(hdr.len);
        }
    }
    Err(anyhow!("audit ack not received"))
}

fn read_i32(buf: &[u8], offset: usize) -> Option<i32> {
    buf.get(offset..offset + 4)
        .map(|b| i32::from_ne_bytes([b[0], b[1], b[2], b[3]]))
}

fn nlmsg_align(len: u32) -> usize {
    ((len as usize) + 3) & !3
}

/// Fields collected from the SYSCALL record while waiting for EOE.
struct PendingExec {
    ppid: u32,
    uid: u32,
    gid: u32,
    comm: String,
    exe: String,
    argv0: Option<String>,
    success: bool,
    seen: Instant,
}

fn audit_loop(source: AuditSource, tx: mpsc::Sender<Event>, shutdown: Arc<AtomicBool>) {
    let fd = source.fd;
    set_rcv_timeout(fd, 1);
    let mut buf = [0u8; 65536];
    // Keyed by audit serial number, which ties SYSCALL/EXECVE/EOE records together.
    let mut pending: HashMap<u64, (u32, PendingExec)> = HashMap::new();
    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        // SAFETY: valid fd and buffer.
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n <= 0 {
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                // Timeout or signal: the normal idle path.
                Some(libc::EAGAIN) | Some(libc::EINTR) => {}
                // The kernel dropped audit records for us.
                Some(libc::ENOBUFS) => {
                    crate::daemon::log_daemon(
                        hermian_core::Severity::High,
                        "audit receive buffer overflowed; exec events were lost",
                    );
                }
                // Anything else would repeat immediately: don't spin.
                _ if n < 0 => std::thread::sleep(Duration::from_millis(200)),
                _ => {}
            }
            pending.retain(|_, (_, p)| p.seen.elapsed() < Duration::from_secs(5));
            continue;
        }
        let n = n as usize;
        let mut offset = 0;
        while offset + std::mem::size_of::<NlMsgHdr>() <= n {
            // SAFETY: bounds checked.
            let hdr =
                unsafe { std::ptr::read_unaligned(buf[offset..].as_ptr() as *const NlMsgHdr) };
            let msg_len = hdr.len as usize;
            if msg_len < std::mem::size_of::<NlMsgHdr>() || offset + msg_len > n {
                break;
            }
            let payload = &buf[offset + std::mem::size_of::<NlMsgHdr>()..offset + msg_len];
            let text = String::from_utf8_lossy(payload);
            handle_record(hdr.kind, &text, &mut pending, &tx);
            offset += nlmsg_align(hdr.len);
        }
        pending.retain(|_, (_, p)| p.seen.elapsed() < Duration::from_secs(5));
    }
    drop(source);
}

/// Parse `audit(1700000000.123:456): ...` -> (serial, rest).
fn split_header(text: &str) -> Option<(u64, &str)> {
    let rest = text.strip_prefix("audit(")?;
    let close = rest.find("):")?;
    let stamp = &rest[..close];
    let serial: u64 = stamp.rsplit(':').next()?.parse().ok()?;
    Some((serial, rest[close + 2..].trim_start()))
}

/// Extract `key=value` where value may be quoted or hex-encoded.
fn field<'a>(body: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!(" {}=", key);
    let start = if let Some(s) = body.strip_prefix(&needle[1..]) {
        Some(s)
    } else {
        body.find(&needle).map(|i| &body[i + needle.len()..])
    }?;
    if let Some(q) = start.strip_prefix('"') {
        q.split('"').next()
    } else {
        start.split_whitespace().next()
    }
}

/// A string field (`comm`, `exe`, `a0`...). The kernel writes a value in
/// quotes when it's plain, and as bare hex when it contains spaces or
/// control characters. Only the bare form may be hex-decoded: `field` strips
/// the quotes, so decoding its output mangled any quoted name that happened
/// to look like hex (a binary called `cafe` or `deadbeef` became garbage).
fn text_field(body: &str, key: &str) -> Option<String> {
    let needle = format!(" {}=", key);
    let start = if let Some(s) = body.strip_prefix(&needle[1..]) {
        s
    } else {
        body.find(&needle).map(|i| &body[i + needle.len()..])?
    };
    if let Some(q) = start.strip_prefix('"') {
        return q.split('"').next().map(str::to_string);
    }
    start.split_whitespace().next().map(decode_value)
}

/// Decode a bare audit value, which is hex when it isn't `(null)`/`(none)`.
fn decode_value(v: &str) -> String {
    let odd_len = v.len() & 1 == 1;
    if v.is_empty() || v.starts_with('"') || odd_len || !v.chars().all(|c| c.is_ascii_hexdigit()) {
        return v.trim_matches('"').to_string();
    }
    let bytes: Vec<u8> = (0..v.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&v[i..i + 2], 16).ok())
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn handle_record(
    kind: u16,
    text: &str,
    pending: &mut HashMap<u64, (u32, PendingExec)>,
    tx: &mpsc::Sender<Event>,
) {
    let Some((serial, body)) = split_header(text) else {
        return;
    };
    match kind {
        AUDIT_SYSCALL => {
            let (_, execve, execveat) = arch_syscalls();
            let syscall: u32 = field(body, "syscall")
                .and_then(|v| v.parse().ok())
                .unwrap_or(u32::MAX);
            if syscall != execve && syscall != execveat {
                return;
            }
            let pid: u32 = field(body, "pid").and_then(|v| v.parse().ok()).unwrap_or(0);
            if pid == 0 || pid == std::process::id() {
                return;
            }
            pending.insert(
                serial,
                (
                    pid,
                    PendingExec {
                        ppid: field(body, "ppid")
                            .and_then(|v| v.parse().ok())
                            .unwrap_or(0),
                        uid: field(body, "uid").and_then(|v| v.parse().ok()).unwrap_or(0),
                        gid: field(body, "gid").and_then(|v| v.parse().ok()).unwrap_or(0),
                        comm: text_field(body, "comm").unwrap_or_default(),
                        exe: text_field(body, "exe").unwrap_or_default(),
                        argv0: None,
                        success: field(body, "success").map(|v| v == "yes").unwrap_or(true),
                        seen: Instant::now(),
                    },
                ),
            );
        }
        AUDIT_EXECVE => {
            if let Some((_, p)) = pending.get_mut(&serial) {
                if let Some(a0) = text_field(body, "a0") {
                    p.argv0 = Some(a0);
                }
            }
        }
        AUDIT_EOE => {
            if let Some((pid, p)) = pending.remove(&serial) {
                if p.success {
                    emit_exec(p, pid, tx);
                }
            }
        }
        _ => {}
    }
}

fn emit_exec(p: PendingExec, pid: u32, tx: &mpsc::Sender<Event>) {
    let (exe_now, deleted) = procsrc::exe_of(pid).unwrap_or((p.exe.clone(), false));
    let exe = if exe_now.is_empty() { p.exe } else { exe_now };
    let (_ppid, tty_nr, _start) = procsrc::stat_of(pid).unwrap_or((0, 0, 0));
    let (container, container_id) = procsrc::container_info(pid);
    let comm = if p.comm.is_empty() {
        procsrc::comm_of(pid).unwrap_or_default()
    } else {
        p.comm
    };
    let ev = ExecEvent {
        ts: chrono::Utc::now(),
        pid,
        ppid: p.ppid,
        uid: p.uid,
        gid: p.gid,
        comm,
        argv0: p.argv0.unwrap_or_else(|| exe.clone()),
        deleted_exe: deleted || exe.contains("memfd:"),
        exe,
        ld_preload: false,
        tty_nr,
        container,
        container_id,
    };
    let _ = tx.blocking_send(Event::Exec(ev));
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYSCALL_REC: &str = "audit(1700000000.123:456): arch=c000003e syscall=59 success=yes exit=0 a0=55d2 a1=55d3 a2=55d4 a3=8 items=2 ppid=1 pid=1234 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm=\"sh\" exe=\"/usr/bin/dash\" key=(null)";

    #[test]
    fn header_and_fields() {
        let (serial, body) = split_header(SYSCALL_REC).unwrap();
        assert_eq!(serial, 456);
        assert_eq!(field(body, "syscall"), Some("59"));
        assert_eq!(field(body, "pid"), Some("1234"));
        assert_eq!(field(body, "ppid"), Some("1"));
        assert_eq!(field(body, "uid"), Some("0"));
        assert_eq!(field(body, "comm"), Some("sh"));
        assert_eq!(field(body, "exe"), Some("/usr/bin/dash"));
        // `uid` must not match `auid`/`euid`.
        assert_eq!(field("auid=5 uid=7 euid=9", "uid"), Some("7"));
    }

    #[test]
    fn hex_values_decode() {
        assert_eq!(decode_value("2F746D702F61206220"), "/tmp/a b ");
        assert_eq!(decode_value("\"plain\""), "plain");
        assert_eq!(decode_value("bash"), "bash");
    }

    #[test]
    fn quoted_hex_looking_names_are_not_decoded() {
        // A binary really named "cafe" is logged quoted; it must stay "cafe".
        let body = "pid=1 comm=\"cafe\" exe=\"/tmp/deadbeef\" a0=2F746D702F61206220";
        assert_eq!(text_field(body, "comm").as_deref(), Some("cafe"));
        assert_eq!(text_field(body, "exe").as_deref(), Some("/tmp/deadbeef"));
        // Bare values are hex and do get decoded.
        assert_eq!(text_field(body, "a0").as_deref(), Some("/tmp/a b "));
    }

    #[test]
    fn gid_is_parsed_not_copied_from_uid() {
        let (_, body) = split_header(SYSCALL_REC).unwrap();
        assert_eq!(field(body, "gid"), Some("0"));
        assert_eq!(field("uid=1000 gid=27 egid=27", "gid"), Some("27"));
    }

    #[test]
    fn rule_bitmask() {
        let mut r = AuditRuleData::zeroed();
        r.add_syscall(59);
        r.add_syscall(322);
        assert_eq!(r.mask[1], 1 << 27);
        assert_eq!(r.mask[10], 1 << 2);
    }
}
