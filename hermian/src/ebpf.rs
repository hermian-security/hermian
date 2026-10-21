//! eBPF loader and perf-buffer readers.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use aya::maps::perf::AsyncPerfEventArray;
use aya::programs::{KProbe, TracePoint};
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Ebpf};
use bytes::BytesMut;
use tokio::sync::mpsc;

/// Must match `hermian_ebpf::ExecEvent`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawExec {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub ld_preload: u8,
    pub via_execveat: u8,
    pub _pad: [u8; 6],
    pub filename: [u8; 256],
    pub argv0: [u8; 128],
    pub comm: [u8; 16],
}

/// Must match `hermian_ebpf::ConnectEvent`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawConnect {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub family: u16,
    pub dport: u16,
    pub daddr6: [u8; 16],
}

/// Must match `hermian_ebpf::PtraceEvent`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawPtrace {
    pub pid: u32,
    pub uid: u32,
    pub target_pid: u32,
    pub _pad: [u8; 4],
    pub request: u64,
}

/// Must match `hermian_ebpf::PrivEvent`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawPriv {
    pub pid: u32,
    pub uid: u32,
    pub fd: i32,
    pub mode: u32,
    pub kind: u8,
    pub _pad: [u8; 3],
    /// Kernel dev_t and inode of what `fd` stands for; 0 if unknown.
    pub dev: u32,
    pub ino: u64,
    pub comm: [u8; 16],
    pub path: [u8; 256],
}

/// `RawPriv::kind`: setuid/setgid bits, or the security.capability xattr.
pub const PRIV_SETID: u8 = 1;
pub const PRIV_CAPS: u8 = 2;

pub enum RawEvent {
    Exec(Box<RawExec>),
    Connect(RawConnect),
    Ptrace(RawPtrace),
    Priv(Box<RawPriv>),
}

pub fn to_str(arr: &[u8]) -> String {
    let end = arr.iter().position(|b| *b == 0).unwrap_or(arr.len());
    String::from_utf8_lossy(&arr[..end]).into_owned()
}

pub fn connect_to_ip(raw: &RawConnect) -> Option<IpAddr> {
    match raw.family {
        2 => Some(IpAddr::V4(Ipv4Addr::new(
            raw.daddr6[0],
            raw.daddr6[1],
            raw.daddr6[2],
            raw.daddr6[3],
        ))),
        10 => Some(IpAddr::V6(Ipv6Addr::from(raw.daddr6))),
        _ => None,
    }
}

/// Keeps the loaded programs alive; dropping it detaches everything.
pub struct EbpfRuntime {
    _bpf: Ebpf,
    /// Human-readable list of attached tracepoints, for `hermian status`.
    pub attached: Vec<&'static str>,
    /// The ones of those hooked through a kprobe on the syscall instead.
    pub kprobes: Vec<&'static str>,
}

struct Hook {
    program: &'static str,
    category: &'static str,
    tracepoint: &'static str,
    required: bool,
    /// (program, syscall): a kprobe on the syscall wrapper, tried first.
    /// From 6.19 (7.0 on Ubuntu 26.04) a syscall tracepoint with a user
    /// string argument drops events before BPF runs: on 7.0, 0 of 50
    /// chmods and some execs never reached the tracepoint program.
    kprobe: Option<(&'static str, &'static str)>,
}

/// The running arch for the kprobes: id for the object, the wrappers'
/// prefix, and where each syscall argument sits in `struct pt_regs`, in u64
/// words. Must match KPROBE_ARCH in hermian-ebpf.
#[cfg(target_arch = "x86_64")]
const KPROBE_ARCH: Option<(u32, &str, [u32; 6])> = Some((1, "__x64_sys_", [14, 13, 12, 7, 9, 8]));
#[cfg(target_arch = "aarch64")]
const KPROBE_ARCH: Option<(u32, &str, [u32; 6])> = Some((2, "__arm64_sys_", [0, 1, 2, 3, 4, 5]));
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const KPROBE_ARCH: Option<(u32, &str, [u32; 6])> = None;

const HOOKS: &[Hook] = &[
    // Exec is observed at sched_process_exec (image is live: correct comm and
    // resolved path). The sys_enter_* hooks only stash argv0/envp intent.
    Hook {
        program: "hermian_sched_exec",
        category: "sched",
        tracepoint: "sched_process_exec",
        kprobe: None,
        required: true,
    },
    Hook {
        program: "hermian_execve",
        category: "syscalls",
        tracepoint: "sys_enter_execve",
        kprobe: Some(("hermian_kp_execve", "execve")),
        required: false,
    },
    Hook {
        program: "hermian_execveat",
        category: "syscalls",
        tracepoint: "sys_enter_execveat",
        kprobe: Some(("hermian_kp_execveat", "execveat")),
        required: false,
    },
    Hook {
        program: "hermian_connect",
        category: "syscalls",
        tracepoint: "sys_enter_connect",
        kprobe: Some(("hermian_kp_connect", "connect")),
        required: true,
    },
    Hook {
        program: "hermian_ptrace",
        category: "syscalls",
        tracepoint: "sys_enter_ptrace",
        kprobe: None,
        required: false,
    },
    // A file given setuid/setgid bits or capabilities, as it happens. The
    // setuid sweep stays as the safety net (files created with those bits,
    // or brought in from another filesystem). chmod doesn't exist on arm64,
    // fchmodat2 before 6.6.
    Hook {
        program: "hermian_fchmodat",
        category: "syscalls",
        tracepoint: "sys_enter_fchmodat",
        kprobe: Some(("hermian_kp_fchmodat", "fchmodat")),
        required: false,
    },
    Hook {
        program: "hermian_fchmodat2",
        category: "syscalls",
        tracepoint: "sys_enter_fchmodat2",
        kprobe: Some(("hermian_kp_fchmodat2", "fchmodat2")),
        required: false,
    },
    Hook {
        program: "hermian_chmod",
        category: "syscalls",
        tracepoint: "sys_enter_chmod",
        kprobe: Some(("hermian_kp_chmod", "chmod")),
        required: false,
    },
    Hook {
        program: "hermian_fchmod",
        category: "syscalls",
        tracepoint: "sys_enter_fchmod",
        kprobe: None,
        required: false,
    },
    Hook {
        program: "hermian_setxattr",
        category: "syscalls",
        tracepoint: "sys_enter_setxattr",
        kprobe: Some(("hermian_kp_setxattr", "setxattr")),
        required: false,
    },
    Hook {
        program: "hermian_lsetxattr",
        category: "syscalls",
        tracepoint: "sys_enter_lsetxattr",
        kprobe: Some(("hermian_kp_lsetxattr", "lsetxattr")),
        required: false,
    },
    Hook {
        program: "hermian_fsetxattr",
        category: "syscalls",
        tracepoint: "sys_enter_fsetxattr",
        kprobe: Some(("hermian_kp_fsetxattr", "fsetxattr")),
        required: false,
    },
];

pub fn load_and_attach(tx: mpsc::Sender<RawEvent>) -> Result<EbpfRuntime> {
    let mut loader = aya::EbpfLoader::new();
    // Hand the programs the running kernel's task_struct layout so they can
    // read the parent tgid directly. Without BTF they fall back to ppid=0 and
    // userspace resolves it from /proc (racy for short-lived processes).
    let offsets = crate::btf::task_struct_offsets();
    let (parent_off, tgid_off) = offsets.unwrap_or((0, 0));
    if offsets.is_some() {
        loader.set_global("TASK_REAL_PARENT_OFF", &parent_off, true);
        loader.set_global("TASK_TGID_OFF", &tgid_off, true);
    }
    // The inode behind an fd, for chmod/setcap callers gone before /proc
    // can be read. Without BTF those events fall back to the sweep.
    let file_offs = crate::btf::file_offsets();
    if let Some(offs) = &file_offs {
        loader.set_global("FILE_OFFS", offs, true);
        loader.set_global("FILE_OFFS_SET", &1u32, true);
    }
    if let Some((arch, _, words)) = &KPROBE_ARCH {
        loader.set_global("KPROBE_ARCH", arch, true);
        loader.set_global("SYSCALL_ARG_WORDS", words, true);
    }
    let mut bpf = loader
        .load(include_bytes_aligned!(env!("HERMIAN_EBPF_OBJECT")))
        .context("failed to load eBPF object (kernel too old, or missing CAP_BPF/CAP_SYS_ADMIN)")?;
    if offsets.is_none() {
        eprintln!("hermian: kernel BTF unavailable; parent resolution falls back to /proc");
    }

    let mut attached = Vec::new();
    let mut kprobes = Vec::new();
    for hook in HOOKS {
        if let (Some((program, syscall)), Some((_, prefix, _))) = (hook.kprobe, &KPROBE_ARCH) {
            match attach_kprobe(&mut bpf, program, &format!("{}{}", prefix, syscall)) {
                Ok(()) => {
                    attached.push(hook.tracepoint);
                    kprobes.push(hook.tracepoint);
                    continue;
                }
                // Falls back to the tracepoint below; chmod has no wrapper
                // on arm64, fchmodat2 none before 6.6.
                Err(e) => eprintln!(
                    "hermian: kprobe {}{} unavailable ({}); using the tracepoint",
                    prefix, syscall, e
                ),
            }
        }
        match attach(&mut bpf, hook) {
            Ok(()) => attached.push(hook.tracepoint),
            Err(e) if hook.required => {
                return Err(e)
                    .with_context(|| format!("required tracepoint {} failed", hook.tracepoint));
            }
            Err(e) => {
                eprintln!(
                    "hermian: optional tracepoint {} unavailable ({}); continuing",
                    hook.tracepoint, e
                );
            }
        }
    }

    spawn_readers(&mut bpf, tx)?;
    Ok(EbpfRuntime {
        _bpf: bpf,
        attached,
        kprobes,
    })
}

fn attach_kprobe(bpf: &mut Ebpf, program: &str, function: &str) -> Result<()> {
    let prog: &mut KProbe = bpf
        .program_mut(program)
        .ok_or_else(|| anyhow!("program {} not found in object", program))?
        .try_into()?;
    prog.load()?;
    prog.attach(function, 0)?;
    Ok(())
}

fn attach(bpf: &mut Ebpf, hook: &Hook) -> Result<()> {
    let prog: &mut TracePoint = bpf
        .program_mut(hook.program)
        .ok_or_else(|| anyhow!("program {} not found in object", hook.program))?
        .try_into()?;
    prog.load()?;
    prog.attach(hook.category, hook.tracepoint)?;
    Ok(())
}

#[derive(Clone, Copy)]
enum MapKind {
    Exec,
    Connect,
    Ptrace,
    Priv,
}

fn decode(kind: MapKind, buf: &BytesMut) -> Option<RawEvent> {
    // SAFETY: the BPF side writes a `#[repr(C)]` struct of exactly this layout;
    // we check the length and use an unaligned read.
    unsafe {
        match kind {
            MapKind::Exec => (buf.len() >= std::mem::size_of::<RawExec>()).then(|| {
                RawEvent::Exec(Box::new((buf.as_ptr() as *const RawExec).read_unaligned()))
            }),
            MapKind::Connect => (buf.len() >= std::mem::size_of::<RawConnect>())
                .then(|| RawEvent::Connect((buf.as_ptr() as *const RawConnect).read_unaligned())),
            MapKind::Ptrace => (buf.len() >= std::mem::size_of::<RawPtrace>())
                .then(|| RawEvent::Ptrace((buf.as_ptr() as *const RawPtrace).read_unaligned())),
            MapKind::Priv => (buf.len() >= std::mem::size_of::<RawPriv>()).then(|| {
                RawEvent::Priv(Box::new((buf.as_ptr() as *const RawPriv).read_unaligned()))
            }),
        }
    }
}

/// Perf ring size per CPU, in pages (power of two). aya's default is small:
/// at ~430 bytes per exec event it held only a few dozen, so a fork/exec
/// burst overflowed it. 64 pages is 256 KiB per CPU on 4 KiB pages.
const EXEC_PAGES: usize = 64;
const OTHER_PAGES: usize = 16;

/// Events the kernel dropped because a perf ring was full, since startup.
pub static LOST_EVENTS: AtomicU64 = AtomicU64::new(0);

/// Log lost events at most once a minute, with the running total.
fn report_lost(map: &str, cpu: u32, lost: usize, last_report: &mut Option<std::time::Instant>) {
    let total = LOST_EVENTS.fetch_add(lost as u64, Ordering::Relaxed) + lost as u64;
    let due = last_report
        .map(|t| t.elapsed() >= Duration::from_secs(60))
        .unwrap_or(true);
    if due {
        *last_report = Some(std::time::Instant::now());
        crate::daemon::log_daemon(
            hermian_core::Severity::High,
            &format!(
                "eBPF {} ring on cpu {} dropped {} event(s) ({} total since start); \
                 exec/connect events are being missed",
                map, cpu, lost, total
            ),
        );
    }
}

/// CPUs that have perf readers. A CPU brought online later has none: its
/// events are neither delivered nor counted as lost.
static READER_CPUS: std::sync::OnceLock<Vec<u32>> = std::sync::OnceLock::new();

/// Online CPUs without a reader (hot-plugged since the daemon started).
/// Empty when eBPF isn't in use.
pub fn unmonitored_cpus() -> Vec<u32> {
    let Some(have) = READER_CPUS.get() else {
        return Vec::new();
    };
    online_cpus()
        .map(|cpus| cpus.into_iter().filter(|c| !have.contains(c)).collect())
        .unwrap_or_default()
}

fn spawn_readers(bpf: &mut Ebpf, tx: mpsc::Sender<RawEvent>) -> Result<()> {
    let _ = READER_CPUS.set(online_cpus().map_err(|(_, e)| e)?);
    for (map_name, kind, pages) in [
        ("EXEC_EVENTS", MapKind::Exec, EXEC_PAGES),
        ("CONNECT_EVENTS", MapKind::Connect, OTHER_PAGES),
        ("PTRACE_EVENTS", MapKind::Ptrace, OTHER_PAGES),
        ("PRIV_EVENTS", MapKind::Priv, OTHER_PAGES),
    ] {
        let map = bpf
            .take_map(map_name)
            .ok_or_else(|| anyhow!("map {} not found", map_name))?;
        let mut array = AsyncPerfEventArray::try_from(map)?;
        for cpu in online_cpus().map_err(|(_, e)| e)? {
            let mut buf = array.open(cpu, Some(pages))?;
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut buffers = (0..64)
                    .map(|_| BytesMut::with_capacity(1024))
                    .collect::<Vec<_>>();
                let mut last_report = None;
                let mut last_error: Option<std::time::Instant> = None;
                loop {
                    let events = match buf.read_events(&mut buffers).await {
                        Ok(e) => e,
                        Err(e) => {
                            if last_error
                                .map(|t| t.elapsed() >= Duration::from_secs(60))
                                .unwrap_or(true)
                            {
                                last_error = Some(std::time::Instant::now());
                                crate::daemon::log_daemon(
                                    hermian_core::Severity::Low,
                                    &format!("eBPF {} read on cpu {} failed: {}", map_name, cpu, e),
                                );
                            }
                            tokio::time::sleep(Duration::from_millis(250)).await;
                            continue;
                        }
                    };
                    if events.lost > 0 {
                        report_lost(map_name, cpu, events.lost, &mut last_report);
                    }
                    for b in buffers.iter().take(events.read) {
                        if let Some(ev) = decode(kind, b) {
                            if tx.send(ev).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lost_events_are_counted_and_throttled() {
        let before = LOST_EVENTS.load(Ordering::Relaxed);
        let mut last = None;
        report_lost("EXEC_EVENTS", 0, 3, &mut last);
        let first = last;
        assert!(first.is_some());
        report_lost("EXEC_EVENTS", 0, 2, &mut last);
        assert_eq!(last, first, "second report within a minute is throttled");
        assert_eq!(LOST_EVENTS.load(Ordering::Relaxed) - before, 5);
    }

    /// Loads the embedded object into the running kernel, so the verifier
    /// checks every program. Needs root; CI runs it with sudo:
    ///   sudo <test-binary> --ignored ebpf_object_loads
    #[test]
    #[ignore]
    fn ebpf_object_loads_and_sees_ld_preload() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (tx, mut rx) = mpsc::channel(4096);
            let runtime = load_and_attach(tx).expect("eBPF object must load and attach");
            assert!(runtime.attached.contains(&"sched_process_exec"));
            assert!(runtime.attached.contains(&"sys_enter_execve"));
            // Through the wrapper kprobe: the tracepoint loses events on 6.19+.
            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            assert!(runtime.kprobes.contains(&"sys_enter_execve"));

            // Filler variables sort before LD_PRELOAD (Command keeps env
            // sorted), pushing it past the old 12-entry scan.
            let mut cmd = std::process::Command::new("/bin/true");
            cmd.env_clear();
            for i in 0..20 {
                cmd.env(format!("HERMIAN_FILLER_{:02}", i), "x");
            }
            cmd.env("LD_PRELOAD", "");
            let child = cmd.spawn().unwrap();
            let pid = child.id();
            let _ = child.wait_with_output();

            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            loop {
                let ev = tokio::time::timeout_at(deadline, rx.recv())
                    .await
                    .expect("no exec event for the test child")
                    .unwrap();
                if let RawEvent::Exec(e) = ev {
                    if e.pid == pid {
                        assert_eq!(e.ld_preload, 1, "LD_PRELOAD not seen");
                        break;
                    }
                }
            }
            drop(runtime);
        });
    }

    /// LD_AUDIT counts like LD_PRELOAD, and the scan reaches past 32 vars.
    #[test]
    #[ignore]
    fn ebpf_sees_ld_audit_past_many_vars() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (tx, mut rx) = mpsc::channel(4096);
            let runtime = load_and_attach(tx).expect("eBPF object must load and attach");
            let mut cmd = std::process::Command::new("/bin/true");
            cmd.env_clear();
            for i in 0..50 {
                cmd.env(format!("HERMIAN_FILLER_{:02}", i), "x");
            }
            cmd.env("LD_AUDIT", "");
            let child = cmd.spawn().unwrap();
            let pid = child.id();
            let _ = child.wait_with_output();
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            loop {
                let ev = tokio::time::timeout_at(deadline, rx.recv())
                    .await
                    .expect("no exec event for the test child")
                    .unwrap();
                if let RawEvent::Exec(e) = ev {
                    if e.pid == pid {
                        assert_eq!(e.ld_preload, 1, "LD_AUDIT not seen");
                        break;
                    }
                }
            }
            drop(runtime);
        });
    }

    /// A sockaddr_in that ends exactly at a page boundary, with nothing
    /// mapped after it. The old fixed 28-byte read failed there and the
    /// connect went unreported.
    #[test]
    #[ignore]
    fn ebpf_sees_connect_with_sockaddr_at_page_end() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (tx, mut rx) = mpsc::channel(4096);
            let runtime = load_and_attach(tx).expect("eBPF object must load and attach");
            let page = crate::procsrc::page_size() as usize;
            // SAFETY: anonymous mapping of two pages; the second is made
            // inaccessible, and all access stays inside the first.
            let port: u16 = unsafe {
                let base = libc::mmap(
                    std::ptr::null_mut(),
                    2 * page,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                ) as *mut u8;
                assert!(!base.is_null() && base as isize != -1);
                assert_eq!(
                    libc::mprotect(base.add(page) as *mut libc::c_void, page, libc::PROT_NONE),
                    0
                );
                let sa = base.add(page - std::mem::size_of::<libc::sockaddr_in>())
                    as *mut libc::sockaddr_in;
                let port = 47_000 + (std::process::id() % 1000) as u16;
                (*sa).sin_family = libc::AF_INET as libc::sa_family_t;
                (*sa).sin_port = port.to_be();
                (*sa).sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
                let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
                assert!(fd >= 0);
                // Nothing listens: ECONNREFUSED is fine, the attempt is what counts.
                libc::connect(
                    fd,
                    sa as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                );
                libc::close(fd);
                libc::munmap(base as *mut libc::c_void, 2 * page);
                port
            };
            let me = std::process::id();
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            loop {
                let ev = tokio::time::timeout_at(deadline, rx.recv())
                    .await
                    .expect("connect at a page end was not reported")
                    .unwrap();
                if let RawEvent::Connect(c) = ev {
                    if c.pid == me && c.dport == port {
                        assert_eq!(connect_to_ip(&c), Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
                        break;
                    }
                }
            }
            drop(runtime);
        });
    }

    /// setuid bits and capabilities come up as they're set; a plain chmod and
    /// the ptrace requests a tracer makes after attaching don't.
    #[test]
    #[ignore]
    fn ebpf_sees_setuid_and_caps_but_not_trace_steps() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (tx, mut rx) = mpsc::channel(65536);
            let runtime = load_and_attach(tx).expect("eBPF object must load and attach");
            for t in [
                "sys_enter_fchmodat",
                "sys_enter_fchmod",
                "sys_enter_setxattr",
            ] {
                assert!(runtime.attached.contains(&t), "{} not attached", t);
            }
            let dir =
                std::env::temp_dir().join(format!("hermian-priv-ebpf-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let plain = dir.join("plain");
            let suid = dir.join("suid");
            let caps = dir.join("caps");
            let byfd = dir.join("byfd");
            for f in [&plain, &suid, &caps, &byfd] {
                std::fs::write(f, b"x").unwrap();
            }
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&plain, std::fs::Permissions::from_mode(0o755)).unwrap();
            std::fs::set_permissions(&suid, std::fs::Permissions::from_mode(0o4755)).unwrap();
            // VFS_CAP_REVISION_2 with cap_net_raw permitted; the hook fires on
            // entry, so it's reported even if the kernel refused the value.
            let mut blob = [0u8; 20];
            blob[..4].copy_from_slice(&0x0200_0000u32.to_le_bytes());
            blob[4..8].copy_from_slice(&(1u32 << 13).to_le_bytes());
            let cpath = std::ffi::CString::new(caps.to_str().unwrap()).unwrap();
            // SAFETY: valid C strings and a 20-byte buffer.
            unsafe {
                libc::setxattr(
                    cpath.as_ptr(),
                    c"security.capability".as_ptr(),
                    blob.as_ptr() as *const libc::c_void,
                    blob.len(),
                    0,
                );
                // setcap's way: by fd. The path has to come from the inode.
                let f = std::fs::File::open(&byfd).unwrap();
                use std::os::fd::AsRawFd;
                libc::fsetxattr(
                    f.as_raw_fd(),
                    c"security.capability".as_ptr(),
                    blob.as_ptr() as *const libc::c_void,
                    blob.len(),
                    0,
                );
                // A tracer's step on a pid that doesn't exist (ESRCH), then an
                // attach to another: only the attach should come up.
                libc::ptrace(libc::PTRACE_PEEKDATA, 999_999 as libc::pid_t, 0, 0);
                libc::ptrace(libc::PTRACE_ATTACH, 999_998 as libc::pid_t, 0, 0);
            }
            let me = std::process::id();
            use std::os::unix::fs::MetadataExt;
            let byfd_md = std::fs::metadata(&byfd).unwrap();
            let (mut saw_suid, mut saw_caps, mut saw_attach) = (false, false, false);
            let mut saw_fd = false;
            let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
            while let Ok(Some(ev)) = tokio::time::timeout_at(deadline, rx.recv()).await {
                match ev {
                    RawEvent::Priv(p) if p.pid == me => {
                        let path = to_str(&p.path);
                        assert!(!path.ends_with("/plain"), "plain chmod reported");
                        if p.kind == PRIV_SETID && path.ends_with("/suid") {
                            assert_eq!(p.mode & 0o7777, 0o4755);
                            saw_suid = true;
                        }
                        if p.kind == PRIV_CAPS && path.ends_with("/caps") {
                            saw_caps = true;
                        }
                        if p.kind == PRIV_CAPS && path.is_empty() {
                            assert_eq!(p.ino, byfd_md.ino(), "fd's inode");
                            assert_eq!(
                                crate::fallback::st_dev_of_kernel(p.dev),
                                byfd_md.dev(),
                                "fd's device"
                            );
                            assert!(!to_str(&p.comm).is_empty(), "comm");
                            saw_fd = true;
                        }
                    }
                    RawEvent::Ptrace(p) if p.pid == me => {
                        assert_ne!(p.target_pid, 999_999, "a trace step was passed up");
                        if p.target_pid == 999_998 {
                            saw_attach = true;
                        }
                    }
                    _ => {}
                }
            }
            let _ = std::fs::remove_dir_all(&dir);
            assert!(saw_suid, "setuid chmod not reported");
            assert!(saw_caps, "security.capability not reported");
            assert!(saw_attach, "ptrace attach not reported");
            assert!(saw_fd, "fsetxattr by fd not reported with its inode");
            drop(runtime);
        });
    }

    /// Failed execs leave their intent behind. With a plain hash map, 4096 of
    /// them filled it and every later exec lost argv0/LD_PRELOAD.
    #[test]
    #[ignore]
    fn ebpf_intents_survive_a_failed_exec_flood() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (tx, mut rx) = mpsc::channel(65536);
            let runtime = load_and_attach(tx).expect("eBPF object must load and attach");
            for _ in 0..5000 {
                let _ = std::process::Command::new("/nonexistent/hermian-flood").status();
            }
            let child = std::process::Command::new("/bin/true")
                .env_clear()
                .env("LD_PRELOAD", "")
                .spawn()
                .unwrap();
            let pid = child.id();
            let _ = child.wait_with_output();
            let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
            loop {
                let ev = tokio::time::timeout_at(deadline, rx.recv())
                    .await
                    .expect("no exec event for the test child")
                    .unwrap();
                if let RawEvent::Exec(e) = ev {
                    if e.pid == pid {
                        assert_eq!(e.ld_preload, 1, "intent lost after the flood");
                        assert_eq!(to_str(&e.argv0), "/bin/true");
                        break;
                    }
                }
            }
            drop(runtime);
        });
    }
}
