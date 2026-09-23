#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_task,
        bpf_get_current_uid_gid, bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes,
        bpf_probe_read_user, bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::{HashMap, PerCpuArray, PerfEventArray},
    programs::TracePointContext,
    EbpfContext,
};

/// Offsets into `struct task_struct` supplied by userspace at load time (read
/// from BTF), so the same object works across kernel versions. Zero means
/// "unknown; leave ppid = 0 and let userspace fall back to /proc".
#[no_mangle]
static TASK_REAL_PARENT_OFF: u32 = 0;
#[no_mangle]
static TASK_TGID_OFF: u32 = 0;

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

#[map]
static EXEC_INTENT: HashMap<u32, ExecIntent> = HashMap::with_max_entries(4096, 0);

#[map]
static INTENT_SCRATCH: PerCpuArray<ExecIntent> = PerCpuArray::with_max_entries(1, 0);

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
const ARG2: usize = 32;
const ARG3: usize = 40;

// sched/sched_process_exec: { common(8) ; __data_loc char[] filename (4) ; pid_t pid (4) ; pid_t old_pid (4) }
// __data_loc packs (len << 16 | offset) relative to the start of the record.
const SCHED_EXEC_FILENAME_LOC: usize = 8;
const SCHED_EXEC_PID: usize = 12;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

/// How many envp entries to inspect for LD_PRELOAD. Each probe costs verifier
/// budget; 12 was trivially bypassed by exporting a dozen dummy variables
/// first. Still a bound, not a guarantee.
const ENV_SCAN: usize = 32;

const LD_PRELOAD_EQ: &[u8; 11] = b"LD_PRELOAD=";

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
            && buf[..11] == LD_PRELOAD_EQ[..]
        {
            return 1;
        }
    }
    0
}

/// Record the caller's intent at syscall entry. The image has not changed yet,
/// so only argv/envp are read here; the authoritative filename and comm come
/// from sched_process_exec once the exec has succeeded.
#[inline(always)]
fn record_intent(ctx: &TracePointContext, argv_off: usize, envp_off: usize, via_execveat: u8) {
    let Some(intent) = INTENT_SCRATCH.get_ptr_mut(0) else {
        return;
    };
    // SAFETY: per-CPU scratch slot; not preempted by another tracepoint on this CPU.
    let intent = unsafe { &mut *intent };
    intent.ld_preload = 0;
    intent.via_execveat = via_execveat;
    intent.argv0[0] = 0;

    // SAFETY: offsets are within the tracepoint's fixed argument block.
    let (argv, envp) = unsafe {
        (
            ctx.read_at::<u64>(argv_off).unwrap_or(0),
            ctx.read_at::<u64>(envp_off).unwrap_or(0),
        )
    };
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
    let _ = EXEC_INTENT.insert(&tgid, intent, 0);
}

/// execve(const char *filename, char *const argv[], char *const envp[])
#[tracepoint(name = "hermian_execve", category = "syscalls")]
pub fn hermian_execve(ctx: TracePointContext) -> u32 {
    record_intent(&ctx, ARG1, ARG2, 0);
    0
}

/// execveat(int dfd, const char *filename, char *const argv[], char *const envp[], int flags)
#[tracepoint(name = "hermian_execveat", category = "syscalls")]
pub fn hermian_execveat(ctx: TracePointContext) -> u32 {
    record_intent(&ctx, ARG2, ARG3, 1);
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
    let (pid, uid, gid) = current_pid_uid();
    // SAFETY: ARG1 is inside the tracepoint argument block.
    let sa_addr: u64 = match unsafe { ctx.read_at::<u64>(ARG1) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    if sa_addr == 0 {
        return 0;
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct SockAddrPrefix {
        family: u16,
        port_be: u16,
        v4_addr: [u8; 4], // = flowinfo for AF_INET6
        v6_addr: [u8; 16],
        _tail: u32,
    }
    // SAFETY: sa_addr is a user pointer; the helper bounds-checks the 28-byte read.
    let sa: SockAddrPrefix = match unsafe { bpf_probe_read_user(sa_addr as *const SockAddrPrefix) }
    {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let mut ev = ConnectEvent {
        pid,
        uid,
        gid,
        family: sa.family,
        dport: u16::from_be(sa.port_be),
        daddr6: [0u8; 16],
    };
    match sa.family {
        AF_INET => ev.daddr6[..4].copy_from_slice(&sa.v4_addr),
        AF_INET6 => ev.daddr6.copy_from_slice(&sa.v6_addr),
        _ => return 0,
    }
    CONNECT_EVENTS.output(&ctx, &ev, 0);
    0
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

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
