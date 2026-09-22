//! eBPF loader and perf-buffer readers.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use aya::maps::perf::AsyncPerfEventArray;
use aya::programs::TracePoint;
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

pub enum RawEvent {
    Exec(Box<RawExec>),
    Connect(RawConnect),
    Ptrace(RawPtrace),
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
}

struct Hook {
    program: &'static str,
    category: &'static str,
    tracepoint: &'static str,
    required: bool,
}

const HOOKS: &[Hook] = &[
    // Exec is observed at sched_process_exec (image is live: correct comm and
    // resolved path). The sys_enter_* hooks only stash argv0/envp intent.
    Hook {
        program: "hermian_sched_exec",
        category: "sched",
        tracepoint: "sched_process_exec",
        required: true,
    },
    Hook {
        program: "hermian_execve",
        category: "syscalls",
        tracepoint: "sys_enter_execve",
        required: false,
    },
    Hook {
        program: "hermian_execveat",
        category: "syscalls",
        tracepoint: "sys_enter_execveat",
        required: false,
    },
    Hook {
        program: "hermian_connect",
        category: "syscalls",
        tracepoint: "sys_enter_connect",
        required: true,
    },
    Hook {
        program: "hermian_ptrace",
        category: "syscalls",
        tracepoint: "sys_enter_ptrace",
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
    let mut bpf = loader
        .load(include_bytes_aligned!(env!("HERMIAN_EBPF_OBJECT")))
        .context("failed to load eBPF object (kernel too old, or missing CAP_BPF/CAP_SYS_ADMIN)")?;
    if offsets.is_none() {
        eprintln!("hermian: kernel BTF unavailable; parent resolution falls back to /proc");
    }

    let mut attached = Vec::new();
    for hook in HOOKS {
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
    })
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
        }
    }
}

fn spawn_readers(bpf: &mut Ebpf, tx: mpsc::Sender<RawEvent>) -> Result<()> {
    for (map_name, kind) in [
        ("EXEC_EVENTS", MapKind::Exec),
        ("CONNECT_EVENTS", MapKind::Connect),
        ("PTRACE_EVENTS", MapKind::Ptrace),
    ] {
        let map = bpf
            .take_map(map_name)
            .ok_or_else(|| anyhow!("map {} not found", map_name))?;
        let mut array = AsyncPerfEventArray::try_from(map)?;
        for cpu in online_cpus().map_err(|(_, e)| e)? {
            let mut buf = array.open(cpu, None)?;
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut buffers = (0..16)
                    .map(|_| BytesMut::with_capacity(1024))
                    .collect::<Vec<_>>();
                loop {
                    let events = match buf.read_events(&mut buffers).await {
                        Ok(e) => e,
                        Err(_) => {
                            tokio::time::sleep(Duration::from_millis(250)).await;
                            continue;
                        }
                    };
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
