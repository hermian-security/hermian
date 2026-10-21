#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_task,
        bpf_get_current_uid_gid, bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes,
        bpf_probe_read_user, bpf_probe_read_user_str_bytes,
    },
    macros::{kprobe, map, tracepoint},
    maps::{LruHashMap, PerCpuArray, PerfEventArray},
    programs::{ProbeContext, TracePointContext},
    EbpfContext,
};

/// Offsets into `struct task_struct` supplied by userspace at load time (read
/// from BTF), so the same object works across kernel versions. Zero means
/// "unknown; leave ppid = 0 and let userspace fall back to /proc".
#[no_mangle]
static TASK_REAL_PARENT_OFF: u32 = 0;
#[no_mangle]
static TASK_TGID_OFF: u32 = 0;

/// Offsets for finding the inode behind an fd or the working directory,
/// from BTF at load time (indexes below). Only used when FILE_OFFS_SET is 1:
/// some of them (fdtable.max_fds) are legitimately 0.
#[no_mangle]
static FILE_OFFS: [u32; 12] = [0; 12];
#[no_mangle]
static FILE_OFFS_SET: u32 = 0;

const OFF_TASK_FILES: usize = 0;
const OFF_FILES_FDT: usize = 1;
const OFF_FDT_MAX_FDS: usize = 2;
const OFF_FDT_FD: usize = 3;
const OFF_FILE_INODE: usize = 4;
const OFF_INODE_INO: usize = 5;
const OFF_INODE_SB: usize = 6;
const OFF_SB_DEV: usize = 7;
const OFF_TASK_FS: usize = 8;
const OFF_FS_PWD: usize = 9;
const OFF_PATH_DENTRY: usize = 10;
const OFF_DENTRY_INODE: usize = 11;

/// For the kprobes on the syscall wrappers (`__x64_sys_*`, `__arm64_sys_*`),
/// set by userspace for the running arch, so one object serves both:
/// KPROBE_ARCH says where the wrapper's own argument (the caller's saved
/// registers) is, SYSCALL_ARG_WORDS where each syscall argument sits in
/// them, in u64 words (x86_64: di si dx r10 r8 r9; arm64: x0..x5).
/// 0 means unknown, and userspace doesn't attach the kprobes.
#[no_mangle]
static KPROBE_ARCH: u32 = 0;
#[no_mangle]
static SYSCALL_ARG_WORDS: [u32; 6] = [0; 6];

const ARCH_X86_64: u32 = 1;
const ARCH_ARM64: u32 = 2;

/// Where the wrapper's own argument sits in the kprobe's `struct pt_regs`:
/// x86_64's di, arm64's x0.
const X86_64_DI: usize = 14 * 8;
const ARM64_X0: usize = 0;

/// A hook's syscall arguments: from the tracepoint record, or, for a kprobe
/// on the syscall wrapper, from the caller's saved registers.
///
/// Since 6.19 (7.0 on Ubuntu 26.04), a syscall tracepoint with a user string
/// argument (execve, chmod, setxattr...) copies that string before running
/// BPF, and drops the event, BPF included, often enough: 0 out of 50 chmods
/// seen on 7.0. The wrapper kprobes don't go through that path.
///
/// 0 when the argument can't be read, which every caller already treats as
/// absent (a NULL pointer, a mode without setid bits). Not an Option: LLVM
/// left a register unset on the None path and the verifier refused it.
trait SysArgs: EbpfContext {
    fn arg(&self, i: usize) -> u64;
}

impl SysArgs for TracePointContext {
    #[inline(always)]
    fn arg(&self, i: usize) -> u64 {
        // SAFETY: the 6 u64 args start at ARG0 in the record.
        unsafe { self.read_at::<u64>(ARG0 + 8 * i).unwrap_or(0) }
    }
}

impl SysArgs for ProbeContext {
    #[inline(always)]
    fn arg(&self, i: usize) -> u64 {
        if i >= 6 {
            return 0;
        }
        // Through the helper: the verifier refuses a load from the context
        // at an offset LLVM has already added to the pointer.
        let off = match unsafe { core::ptr::read_volatile(&KPROBE_ARCH) } {
            ARCH_X86_64 => X86_64_DI,
            ARCH_ARM64 => ARM64_X0,
            _ => return 0,
        };
        // SAFETY: a fixed offset inside pt_regs on both arches; bounds-checked
        // kernel read.
        let user: u64 = unsafe {
            bpf_probe_read_kernel((self.regs as *const u8).add(off) as *const u64).unwrap_or(0)
        };
        if user == 0 {
            return 0;
        }
        // SAFETY: our own global.
        let word = unsafe { core::ptr::read_volatile(&SYSCALL_ARG_WORDS[i]) } as u64;
        // SAFETY: the saved registers are kernel memory; bounds-checked read.
        unsafe { bpf_probe_read_kernel((user + word * 8) as *const u64).unwrap_or(0) }
    }
}

#[map]
static EXEC_EVENTS: PerfEventArray<ExecEvent> = PerfEventArray::new(0);

#[map]
static CONNECT_EVENTS: PerfEventArray<ConnectEvent> = PerfEventArray::new(0);

#[map]
static PTRACE_EVENTS: PerfEventArray<PtraceEvent> = PerfEventArray::new(0);

/// Scratch space for the exec event. The struct is ~400 bytes and the BPF
/// stack is 512, so it must live in a map, not on the stack.
#[map]
static EXEC_SCRATCH: PerCpuArray<ExecEvent> = PerCpuArray::with_max_entries(1, 0);

/// Facts captured at sys_enter_execve* that are gone by the time the new
/// image is running: argv[0], LD_PRELOAD presence, and whether execveat was
/// used. Keyed by tgid; consumed (and deleted) at sched_process_exec.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecIntent {
    pub ld_preload: u8,
    pub via_execveat: u8,
    pub _pad: [u8; 6],
    pub argv0: [u8; 128],
}

/// LRU: an intent is only consumed by a *successful* exec, so failed execs
/// (execvp walking PATH, or a loop of execve("/nonexistent") in short-lived
/// processes) used to fill a plain hash map until every later insert failed
/// and argv0/LD_PRELOAD went missing for good. LRU evicts the stale ones.
#[map]
static EXEC_INTENT: LruHashMap<u32, ExecIntent> = LruHashMap::with_max_entries(4096, 0);

/// Layout must match `hermian::ebpf::RawExec` exactly.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecEvent {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub ld_preload: u8,
    /// 1 when the event came from execveat(2) (fexecve / memfd style exec).
    pub via_execveat: u8,
    pub _pad: [u8; 6],
    /// Path of the image that is now running (from sched_process_exec).
    pub filename: [u8; 256],
    pub argv0: [u8; 128],
    /// comm of the new image.
    pub comm: [u8; 16],
}

/// Layout must match `hermian::ebpf::RawConnect` exactly.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnectEvent {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub family: u16,
    pub dport: u16,
    pub daddr6: [u8; 16],
}

#[map]
static PRIV_EVENTS: PerfEventArray<PrivEvent> = PerfEventArray::new(0);

/// Scratch for the privilege event: with its path it's too big for comfort
/// on the 512-byte BPF stack.
#[map]
static PRIV_SCRATCH: PerCpuArray<PrivEvent> = PerCpuArray::with_max_entries(1, 0);

/// A file was given the setuid/setgid bits or file capabilities.
/// Layout must match `hermian::ebpf::RawPriv` exactly.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PrivEvent {
    pub pid: u32,
    pub uid: u32,
    /// The directory `path` is relative to (AT_FDCWD for the cwd), or the
    /// file itself when `path` is empty (fchmod, fsetxattr).
    pub fd: i32,
    pub mode: u32,
    /// PRIV_SETID or PRIV_CAPS.
    pub kind: u8,
    pub _pad: [u8; 3],
    /// The kernel's dev_t and inode number of what `fd` stands for (the
    /// file, its directory, or the working directory), 0 if unknown. The
    /// caller is usually gone before userspace can read /proc/<pid>/fd.
    pub dev: u32,
    pub ino: u64,
    pub comm: [u8; 16],
    pub path: [u8; 256],
}

pub const PRIV_SETID: u8 = 1;
pub const PRIV_CAPS: u8 = 2;

/// Layout must match `hermian::ebpf::RawPtrace` exactly.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PtraceEvent {
    pub pid: u32,
    pub uid: u32,
    pub target_pid: u32,
    pub _pad: [u8; 4],
    pub request: u64,
}

// Tracepoint argument offsets for syscalls/sys_enter_* (common header is 16 bytes,
// followed by `int __syscall_nr` + padding, then the 6 u64 args starting at 16).
const ARG0: usize = 16;
const ARG1: usize = 24;

// sched/sched_process_exec: { common(8) ; __data_loc char[] filename (4) ; pid_t pid (4) ; pid_t old_pid (4) }
// __data_loc packs (len << 16 | offset) relative to the start of the record.
const SCHED_EXEC_FILENAME_LOC: usize = 8;
const SCHED_EXEC_PID: usize = 12;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

const PTRACE_ATTACH: u64 = 16;
const PTRACE_SEIZE: u64 = 0x4206;

/// S_ISUID | S_ISGID.
const SETID_BITS: u64 = 0o6000;
const AT_FDCWD: i32 = -100;
const XATTR_CAPS: &[u8; 20] = b"security.capability\0";

/// How many envp entries to inspect for LD_PRELOAD / LD_AUDIT. Each probe
/// costs verifier budget; 12 was trivially bypassed by exporting a dozen
/// dummy variables first, and 32 by a few dozen. Still a bound, not a
/// guarantee: userspace reports it as such.
const ENV_SCAN: usize = 64;

const LD_PRELOAD_EQ: &[u8; 11] = b"LD_PRELOAD=";
/// LD_AUDIT loads a library into the process just like LD_PRELOAD (via the
/// rtld-audit interface) and was not checked at all.
const LD_AUDIT_EQ: &[u8; 9] = b"LD_AUDIT=";

#[inline(always)]
fn current_pid_uid() -> (u32, u32, u32) {
    let tgid = bpf_get_current_pid_tgid();
    let ugid = bpf_get_current_uid_gid();
    ((tgid >> 32) as u32, (ugid >> 32) as u32, ugid as u32)
}

/// Parent tgid of the current task via task_struct->real_parent->tgid, using
/// offsets provided by userspace. Returns 0 if offsets are unknown.
#[inline(always)]
fn current_ppid() -> u32 {
    // Read through volatile so the linker keeps the symbols patchable.
    let parent_off = unsafe { core::ptr::read_volatile(&TASK_REAL_PARENT_OFF) } as usize;
    let tgid_off = unsafe { core::ptr::read_volatile(&TASK_TGID_OFF) } as usize;
    if parent_off == 0 || tgid_off == 0 {
        return 0;
    }
    // SAFETY: bpf_get_current_task returns the current task_struct pointer;
    // reads are bounds-checked kernel probes at userspace-supplied offsets.
    unsafe {
        let task = bpf_get_current_task() as *const u8;
        let parent: u64 = match bpf_probe_read_kernel(task.add(parent_off) as *const u64) {
            Ok(p) => p,
            Err(_) => return 0,
        };
        if parent == 0 {
            return 0;
        }
        bpf_probe_read_kernel((parent as *const u8).add(tgid_off) as *const u32).unwrap_or(0)
    }
}

#[inline(always)]
fn read_user_ptr(addr: u64) -> Option<u64> {
    // SAFETY: addr is a user pointer; the helper bounds-checks it.
    let word: u64 = unsafe { bpf_probe_read_user(addr as *const u64).ok()? };
    if word == 0 {
        None
    } else {
        Some(word)
    }
}

#[inline(always)]
fn scan_env_for_ld_preload(envp: u64) -> u8 {
    // One byte more than "LD_PRELOAD=": the helper always NUL-terminates, so
    // an 11-byte buffer only ever held "LD_PRELOAD" + NUL and never matched.
    let mut buf = [0u8; 12];
    for i in 0..ENV_SCAN {
        let Some(p) = read_user_ptr(envp + (i as u64) * 8) else {
            break;
        };
        // SAFETY: p is a user pointer; the helper bounds-checks it.
        if unsafe { bpf_probe_read_user_str_bytes(p as *const u8, &mut buf) }.is_ok()
            && (buf[..11] == LD_PRELOAD_EQ[..] || buf[..9] == LD_AUDIT_EQ[..])
        {
            return 1;
        }
    }
    0
}

/// Record the caller's intent at syscall entry. The image has not changed yet,
/// so only argv/envp are read here; the authoritative filename and comm come
/// from sched_process_exec once the exec has succeeded.
///
/// The intent is built on the BPF stack (136 bytes) rather than in a per-CPU
/// scratch map. Syscall tracepoints can be preempted on newer kernels
/// (faultable tracepoints), and a second exec on the same CPU mid-way would
/// have overwritten a shared slot, mixing argv0/LD_PRELOAD between tasks.
#[inline(always)]
fn record_intent<C: SysArgs>(ctx: &C, argv_i: usize, envp_i: usize, via_execveat: u8) {
    let mut intent = ExecIntent {
        ld_preload: 0,
        via_execveat,
        _pad: [0u8; 6],
        argv0: [0u8; 128],
    };

    let argv = ctx.arg(argv_i);
    let envp = ctx.arg(envp_i);
    if argv != 0 {
        if let Some(a0) = read_user_ptr(argv) {
            // SAFETY: user pointer, bounds-checked by the helper; dst is map memory.
            let _ = unsafe { bpf_probe_read_user_str_bytes(a0 as *const u8, &mut intent.argv0) };
        }
    }
    if envp != 0 {
        intent.ld_preload = scan_env_for_ld_preload(envp);
    }
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let _ = EXEC_INTENT.insert(&tgid, &intent, 0);
}

/// execve(const char *filename, char *const argv[], char *const envp[])
#[tracepoint(name = "hermian_execve", category = "syscalls")]
pub fn hermian_execve(ctx: TracePointContext) -> u32 {
    record_intent(&ctx, 1, 2, 0);
    0
}

#[kprobe]
pub fn hermian_kp_execve(ctx: ProbeContext) -> u32 {
    record_intent(&ctx, 1, 2, 0);
    0
}

/// execveat(int dfd, const char *filename, char *const argv[], char *const envp[], int flags)
#[tracepoint(name = "hermian_execveat", category = "syscalls")]
pub fn hermian_execveat(ctx: TracePointContext) -> u32 {
    record_intent(&ctx, 2, 3, 1);
    0
}

#[kprobe]
pub fn hermian_kp_execveat(ctx: ProbeContext) -> u32 {
    record_intent(&ctx, 2, 3, 1);
    0
}

/// Fires once the new image is live. Everything read here (comm, pid) reflects
/// the program that is now running, which is what the detection engine needs.
#[tracepoint(name = "hermian_sched_exec", category = "sched")]
pub fn hermian_sched_exec(ctx: TracePointContext) -> u32 {
    let Some(ev) = EXEC_SCRATCH.get_ptr_mut(0) else {
        return 0;
    };
    // SAFETY: per-CPU scratch slot.
    let ev = unsafe { &mut *ev };

    let (tgid, uid, gid) = current_pid_uid();
    ev.pid = tgid;
    ev.ppid = current_ppid();
    ev.uid = uid;
    ev.gid = gid;
    ev.ld_preload = 0;
    ev.via_execveat = 0;
    ev.filename[0] = 0;
    ev.argv0[0] = 0;
    ev.comm = [0u8; 16];

    // SAFETY: fixed offsets in the sched_process_exec record.
    let loc: u32 = unsafe { ctx.read_at::<u32>(SCHED_EXEC_FILENAME_LOC).unwrap_or(0) };
    let off = (loc & 0xffff) as usize;
    if off != 0 {
        // SAFETY: the filename lives inside the tracepoint record in kernel memory.
        let _ = unsafe {
            bpf_probe_read_kernel_str_bytes(ctx.as_ptr().add(off) as *const u8, &mut ev.filename)
        };
    }
    if let Ok(c) = bpf_get_current_comm() {
        ev.comm = c;
    }
    // SAFETY: fixed offset.
    let tp_pid: u32 = unsafe { ctx.read_at::<u32>(SCHED_EXEC_PID).unwrap_or(tgid) };
    if tp_pid != 0 {
        ev.pid = tp_pid;
    }

    // SAFETY: the map value is only read here and then removed.
    if let Some(intent) = unsafe { EXEC_INTENT.get(&tgid) } {
        ev.ld_preload = intent.ld_preload;
        ev.via_execveat = intent.via_execveat;
        ev.argv0 = intent.argv0;
        let _ = EXEC_INTENT.remove(&tgid);
    }
    EXEC_EVENTS.output(&ctx, ev, 0);
    0
}

/// connect(int fd, const struct sockaddr *addr, socklen_t addrlen)
#[tracepoint(name = "hermian_connect", category = "syscalls")]
pub fn hermian_connect(ctx: TracePointContext) -> u32 {
    on_connect(&ctx);
    0
}

#[kprobe]
pub fn hermian_kp_connect(ctx: ProbeContext) -> u32 {
    on_connect(&ctx);
    0
}

#[inline(always)]
fn on_connect<C: SysArgs>(ctx: &C) {
    let (pid, uid, gid) = current_pid_uid();
    let sa_addr = ctx.arg(1);
    if sa_addr == 0 {
        return;
    }
    // Read the family first, then only as many bytes as that family needs.
    // A fixed 28-byte read failed (and dropped the event) whenever a 16-byte
    // sockaddr_in sat at the end of a mapped page: an easy way to connect
    // unseen.
    // SAFETY: sa_addr is a user pointer; the helper bounds-checks the read.
    let family: u16 = match unsafe { bpf_probe_read_user(sa_addr as *const u16) } {
        Ok(f) => f,
        Err(_) => return,
    };
    let mut ev = ConnectEvent {
        pid,
        uid,
        gid,
        family,
        dport: 0,
        daddr6: [0u8; 16],
    };
    match family {
        AF_INET => {
            #[repr(C)]
            #[derive(Clone, Copy)]
            struct In4 {
                family: u16,
                port_be: u16,
                addr: [u8; 4],
            }
            // SAFETY: 8 bytes, inside any valid sockaddr_in (16 bytes).
            let sa: In4 = match unsafe { bpf_probe_read_user(sa_addr as *const In4) } {
                Ok(v) => v,
                Err(_) => return,
            };
            ev.dport = u16::from_be(sa.port_be);
            ev.daddr6[..4].copy_from_slice(&sa.addr);
        }
        AF_INET6 => {
            #[repr(C)]
            #[derive(Clone, Copy)]
            struct In6 {
                family: u16,
                port_be: u16,
                flowinfo: u32,
                addr: [u8; 16],
            }
            // SAFETY: 24 bytes, inside any valid sockaddr_in6 (28 bytes).
            let sa: In6 = match unsafe { bpf_probe_read_user(sa_addr as *const In6) } {
                Ok(v) => v,
                Err(_) => return,
            };
            ev.dport = u16::from_be(sa.port_be);
            ev.daddr6.copy_from_slice(&sa.addr);
        }
        _ => return,
    }
    CONNECT_EVENTS.output(ctx, &ev, 0);
}

/// ptrace(long request, long pid, void *addr, void *data)
#[tracepoint(name = "hermian_ptrace", category = "syscalls")]
pub fn hermian_ptrace(ctx: TracePointContext) -> u32 {
    let (pid, uid, _gid) = current_pid_uid();
    // SAFETY: offsets are inside the tracepoint argument block.
    let (request, target) = match unsafe { (ctx.read_at::<u64>(ARG0), ctx.read_at::<u64>(ARG1)) } {
        (Ok(r), Ok(t)) => (r, t),
        _ => return 0,
    };
    // Attach and seize are all userspace acts on. A tracer issues a ptrace
    // call for every step of its tracee (strace: one per syscall), and
    // passing those up overflowed the ring and cost a /proc walk each.
    if request != PTRACE_ATTACH && request != PTRACE_SEIZE {
        return 0;
    }
    if target == 0 || target > u32::MAX as u64 {
        return 0;
    }
    let ev = PtraceEvent {
        pid,
        uid,
        target_pid: target as u32,
        _pad: [0u8; 4],
        request,
    };
    PTRACE_EVENTS.output(&ctx, &ev, 0);
    0
}

#[inline(always)]
fn file_off(i: usize) -> usize {
    // SAFETY: reading our own global; volatile so it stays patchable.
    unsafe { core::ptr::read_volatile(&FILE_OFFS[i]) as usize }
}

#[inline(always)]
fn read_kptr(base: u64, off: usize) -> Option<u64> {
    if base == 0 {
        return None;
    }
    // SAFETY: a bounds-checked kernel probe read.
    match unsafe { bpf_probe_read_kernel((base as *const u8).add(off) as *const u64) } {
        Ok(0) | Err(_) => None,
        Ok(p) => Some(p),
    }
}

/// (s_dev, i_ino) of an inode.
fn inode_id(inode: u64) -> Option<(u32, u64)> {
    // SAFETY: bounds-checked kernel probe reads at BTF offsets.
    let ino = unsafe {
        bpf_probe_read_kernel((inode as *const u8).add(file_off(OFF_INODE_INO)) as *const u64)
    }
    .ok()?;
    let sb = read_kptr(inode, file_off(OFF_INODE_SB))?;
    // SAFETY: as above.
    let dev =
        unsafe { bpf_probe_read_kernel((sb as *const u8).add(file_off(OFF_SB_DEV)) as *const u32) }
            .ok()?;
    Some((dev, ino))
}

/// The inode behind `fd` (AT_FDCWD: the working directory) in the current task.
fn fd_inode(fd: i32) -> Option<(u32, u64)> {
    // SAFETY: reading our own global.
    if unsafe { core::ptr::read_volatile(&FILE_OFFS_SET) } != 1 {
        return None;
    }
    // SAFETY: returns the current task_struct pointer; only probe-read.
    let task = unsafe { bpf_get_current_task() };
    if fd == AT_FDCWD {
        let fs = read_kptr(task, file_off(OFF_TASK_FS))?;
        let dentry = read_kptr(fs, file_off(OFF_FS_PWD) + file_off(OFF_PATH_DENTRY))?;
        return inode_id(read_kptr(dentry, file_off(OFF_DENTRY_INODE))?);
    }
    if fd < 0 {
        return None;
    }
    let files = read_kptr(task, file_off(OFF_TASK_FILES))?;
    let fdt = read_kptr(files, file_off(OFF_FILES_FDT))?;
    // SAFETY: bounds-checked kernel probe read.
    let max = unsafe {
        bpf_probe_read_kernel((fdt as *const u8).add(file_off(OFF_FDT_MAX_FDS)) as *const u32)
    }
    .ok()?;
    if fd as u32 >= max {
        return None;
    }
    let arr = read_kptr(fdt, file_off(OFF_FDT_FD))?;
    let file = read_kptr(arr, (fd as usize) * 8)?;
    inode_id(read_kptr(file, file_off(OFF_FILE_INODE))?)
}

/// Pass up a file being given setuid/setgid bits or capabilities. Userspace
/// resolves the path, checks the call took effect and judges the location.
fn emit_priv<C: EbpfContext>(ctx: &C, fd: i32, path: u64, mode: u64, kind: u8) {
    let Some(ev) = PRIV_SCRATCH.get_ptr_mut(0) else {
        return;
    };
    // SAFETY: per-CPU scratch slot.
    let ev = unsafe { &mut *ev };
    let (pid, uid, _gid) = current_pid_uid();
    ev.pid = pid;
    ev.uid = uid;
    ev.fd = fd;
    ev.mode = mode as u32;
    ev.kind = kind;
    ev._pad = [0u8; 3];
    ev.comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
    let (dev, ino) = fd_inode(fd).unwrap_or((0, 0));
    ev.dev = dev;
    ev.ino = ino;
    ev.path[0] = 0;
    if path != 0 {
        // SAFETY: a user pointer from the syscall's arguments; the helper
        // checks it and bounds the copy.
        if unsafe { bpf_probe_read_user_str_bytes(path as *const u8, &mut ev.path) }.is_err() {
            return;
        }
    }
    PRIV_EVENTS.output(ctx, ev, 0);
}

/// Shared by fchmodat(int dfd, const char *filename, umode_t mode) and
/// fchmodat2(..., int flags).
#[inline(always)]
fn on_fchmodat<C: SysArgs>(ctx: &C) {
    let (dfd, path, mode) = (ctx.arg(0), ctx.arg(1), ctx.arg(2));
    if mode & SETID_BITS != 0 && path != 0 {
        emit_priv(ctx, dfd as i32, path, mode, PRIV_SETID);
    }
}

#[tracepoint(name = "hermian_fchmodat", category = "syscalls")]
pub fn hermian_fchmodat(ctx: TracePointContext) -> u32 {
    on_fchmodat(&ctx);
    0
}

#[tracepoint(name = "hermian_fchmodat2", category = "syscalls")]
pub fn hermian_fchmodat2(ctx: TracePointContext) -> u32 {
    on_fchmodat(&ctx);
    0
}

#[kprobe]
pub fn hermian_kp_fchmodat(ctx: ProbeContext) -> u32 {
    on_fchmodat(&ctx);
    0
}

#[kprobe]
pub fn hermian_kp_fchmodat2(ctx: ProbeContext) -> u32 {
    on_fchmodat(&ctx);
    0
}

/// chmod(const char *filename, umode_t mode); x86_64 only, arm64 has fchmodat.
#[tracepoint(name = "hermian_chmod", category = "syscalls")]
pub fn hermian_chmod(ctx: TracePointContext) -> u32 {
    on_chmod(&ctx);
    0
}

#[kprobe]
pub fn hermian_kp_chmod(ctx: ProbeContext) -> u32 {
    on_chmod(&ctx);
    0
}

#[inline(always)]
fn on_chmod<C: SysArgs>(ctx: &C) {
    let (path, mode) = (ctx.arg(0), ctx.arg(1));
    if mode & SETID_BITS != 0 && path != 0 {
        emit_priv(ctx, AT_FDCWD, path, mode, PRIV_SETID);
    }
}

/// fchmod(unsigned int fd, umode_t mode): `cp -p`, `install`, tar and rsync.
#[tracepoint(name = "hermian_fchmod", category = "syscalls")]
pub fn hermian_fchmod(ctx: TracePointContext) -> u32 {
    // SAFETY: offsets are inside the tracepoint argument block.
    if let (Ok(fd), Ok(mode)) = unsafe { (ctx.read_at::<u64>(ARG0), ctx.read_at::<u64>(ARG1)) } {
        if mode & SETID_BITS != 0 {
            emit_priv(&ctx, fd as i32, 0, mode, PRIV_SETID);
        }
    }
    0
}

/// Whether the xattr name at `name` is security.capability.
fn is_caps_xattr(name: u64) -> bool {
    if name == 0 {
        return false;
    }
    let mut buf = [0u8; 20];
    // SAFETY: user pointer from the syscall's arguments; bounded copy.
    if unsafe { bpf_probe_read_user_str_bytes(name as *const u8, &mut buf) }.is_err() {
        return false;
    }
    buf == *XATTR_CAPS
}

/// Shared by setxattr and lsetxattr(const char *pathname, const char *name, ...).
#[inline(always)]
fn on_setxattr<C: SysArgs>(ctx: &C) {
    let (path, name) = (ctx.arg(0), ctx.arg(1));
    if path != 0 && is_caps_xattr(name) {
        emit_priv(ctx, AT_FDCWD, path, 0, PRIV_CAPS);
    }
}

/// setcap.
#[tracepoint(name = "hermian_setxattr", category = "syscalls")]
pub fn hermian_setxattr(ctx: TracePointContext) -> u32 {
    on_setxattr(&ctx);
    0
}

#[tracepoint(name = "hermian_lsetxattr", category = "syscalls")]
pub fn hermian_lsetxattr(ctx: TracePointContext) -> u32 {
    on_setxattr(&ctx);
    0
}

#[kprobe]
pub fn hermian_kp_setxattr(ctx: ProbeContext) -> u32 {
    on_setxattr(&ctx);
    0
}

#[kprobe]
pub fn hermian_kp_lsetxattr(ctx: ProbeContext) -> u32 {
    on_setxattr(&ctx);
    0
}

/// fsetxattr(int fd, const char *name, ...).
#[tracepoint(name = "hermian_fsetxattr", category = "syscalls")]
pub fn hermian_fsetxattr(ctx: TracePointContext) -> u32 {
    on_fsetxattr(&ctx);
    0
}

#[kprobe]
pub fn hermian_kp_fsetxattr(ctx: ProbeContext) -> u32 {
    on_fsetxattr(&ctx);
    0
}

#[inline(always)]
fn on_fsetxattr<C: SysArgs>(ctx: &C) {
    let (fd, name) = (ctx.arg(0), ctx.arg(1));
    if is_caps_xattr(name) {
        emit_priv(ctx, fd as i32, 0, 0, PRIV_CAPS);
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
