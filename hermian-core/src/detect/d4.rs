//! D4 - Privilege escalation indicators.

use crate::alert::Finding;
use crate::detect::{writer_label, Ctx};
use crate::events::{
    is_container_overlay_path, is_editor_artifact, DetectionId, ExecEvent, FileEvent, FileKind,
    PtraceEvent, Severity,
};
use crate::proctree::{is_container_runtime, is_user_mgmt_tool, role_of, Role};

const PTRACE_TRACEME: u64 = 0;
const PTRACE_ATTACH: u64 = 16;
const PTRACE_SEIZE: u64 = 0x4206;

pub fn evaluate_ptrace(ev: &PtraceEvent, ctx: &Ctx) -> Vec<Finding> {
    // Only attach/seize are interesting; TRACEME and the per-thread control
    // requests that follow an attach are noise.
    if ev.request != PTRACE_ATTACH && ev.request != PTRACE_SEIZE {
        return Vec::new();
    }
    if ev.request == PTRACE_TRACEME || ev.target_pid == ev.pid {
        return Vec::new();
    }
    if role_of(&ev.comm, "") == Role::Debugger
        || is_container_runtime(&ev.comm)
        || ctx.allowlist.debugger_allowed(&ev.comm)
    {
        return Vec::new();
    }
    // A parent tracing its own child (test harnesses, sandboxes, language runtimes).
    let target_is_descendant = ctx
        .tree
        .ancestors_of(ev.target_pid)
        .iter()
        .any(|p| p.pid == ev.pid);
    if target_is_descendant {
        return Vec::new();
    }
    let target = ctx.tree.get(ev.target_pid);
    let target_label = target
        .map(|t| format!("{} (pid {})", t.comm, t.pid))
        .unwrap_or_else(|| format!("pid {}", ev.target_pid));
    let target_privileged = target.map(|t| t.uid == 0).unwrap_or(false);
    let severity = if target_privileged || ev.uid != 0 {
        Severity::High
    } else {
        Severity::Low
    };
    vec![Finding::new(
        DetectionId::D4,
        severity,
        "Unexpected ptrace attach by a non-debugger",
        &format!("d4|ptrace|{}|{}", ev.comm, ev.uid),
    )
    .what(format!(
        "{} (pid {}, {}) attached to unrelated process {} with ptrace.",
        ev.comm,
        ev.pid,
        ctx.user_name(ev.uid).unwrap_or("unknown user"),
        target_label
    ))
    .chain(ctx.chain_nodes(ev.pid))
    .fact("Target", target_label)
    .why(
        "ptrace grants full control over another process's memory and execution. Debuggers use \
         it legitimately; anything else attaching to an unrelated process is a strong signal of \
         credential scraping or code injection.",
    )
    .actions([
        "Identify what the attaching process is and who started it.",
        "Treat secrets held by the target process as exposed.",
        "Kill the attaching process if it is unauthorized.",
    ])]
}

pub fn evaluate_exec(ev: &ExecEvent, ctx: &Ctx) -> Vec<Finding> {
    if !ev.ld_preload {
        return Vec::new();
    }
    if ctx.allowlist.binary_allowed(&ev.exe) {
        return Vec::new();
    }
    // Developers and profilers set LD_PRELOAD interactively all the time
    // (jemalloc, ASan, fakeroot, libeatmydata...). Escalate only when unattended.
    let interactive = ctx.tree.has_interactive_session(ev.pid, ev.tty_nr);
    let chain = ctx.tree.chain_of(ev.pid);
    let from_build_tool = chain.iter().any(|p| {
        matches!(
            p.comm.as_str(),
            "make" | "cargo" | "cmake" | "ninja" | "fakeroot" | "dpkg-buildpackage"
        )
    });
    if interactive || from_build_tool {
        return vec![Finding::new(
            DetectionId::D4,
            Severity::Info,
            "LD_PRELOAD used in an interactive or build context",
            &format!("d4|ld-preload-env-session|{}", ev.comm),
        )
        .what(format!(
            "{} (pid {}) started with LD_PRELOAD set.",
            ev.comm, ev.pid
        ))
        .chain(ctx.chain_nodes(ev.pid))
        .why("Logged for context; common during development and packaging.")];
    }
    vec![Finding::new(
        DetectionId::D4,
        Severity::High,
        "LD_PRELOAD injection in an unattended process",
        &format!("d4|ld-preload-env|{}|{}", ev.comm, ev.uid),
    )
    .what(format!(
        "{} (pid {}) was executed with LD_PRELOAD set while no interactive session was involved.",
        ev.comm, ev.pid
    ))
    .chain(ctx.chain_nodes(ev.pid))
    .fact("Executable", &ev.exe)
    .why(
        "LD_PRELOAD injects a shared library into a process at startup and can hook any libc \
         function. Attackers use it to hide processes, files and connections from tooling.",
    )
    .actions([
        "Find the preloaded library (/proc/<pid>/environ, /proc/<pid>/maps) and its origin.",
        "Verify the parent process is legitimate.",
        "Check the library for rootkit behaviour before removing it.",
    ])]
}

pub fn evaluate_file(ev: &FileEvent, ctx: &Ctx) -> Vec<Finding> {
    let mut findings = Vec::new();
    if ev.container && is_container_overlay_path(&ev.path) {
        return findings;
    }
    if matches!(ev.kind, FileKind::Removed | FileKind::MovedFrom) {
        return findings;
    }
    if is_editor_artifact(&ev.path) || ctx.allowlist.path_allowed(&ev.path) {
        return findings;
    }
    findings.extend(suid_in_transient(ev, ctx));
    findings.extend(file_caps(ev, ctx));
    findings.extend(sudoers(ev, ctx));
    findings.extend(account_files(ev, ctx));
    findings
}

fn is_user_owned_location(path: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "/tmp", "/dev/shm", "/var/tmp", "/home", "/root", "/var/www", "/srv", "/opt",
    ];
    PREFIXES
        .iter()
        .any(|p| path == *p || path.starts_with(&format!("{}/", p)))
}

fn suid_in_transient(ev: &FileEvent, ctx: &Ctx) -> Option<Finding> {
    if !ev.is_suid || !is_user_owned_location(&ev.path) {
        return None;
    }
    Some(
        Finding::new(
            DetectionId::D4,
            Severity::Critical,
            "setuid binary created outside system directories",
            &format!("d4|suid|{}", ev.path),
        )
        .what(format!(
            "A setuid/setgid executable appeared at {} ({}).",
            ev.path,
            writer_label(ev.writer.as_ref())
        ))
        .chain(
            ev.writer
                .as_ref()
                .map(|w| ctx.chain_nodes(w.pid))
                .unwrap_or_default(),
        )
        .fact("Path", &ev.path)
        .why(
            "A setuid binary runs with its owner's privileges regardless of who invokes it. \
             Legitimate ones live in system directories owned by packages; one appearing in a \
             writable or user-owned location is a prepared privilege-escalation path.",
        )
        .actions([
            "Remove the setuid bit or delete the file immediately.",
            "Identify the process and user that created it.",
            "Assume the creating account is compromised and audit it.",
        ]),
    )
}

fn file_caps(ev: &FileEvent, ctx: &Ctx) -> Option<Finding> {
    if !ev.has_file_caps || !is_user_owned_location(&ev.path) {
        return None;
    }
    Some(
        Finding::new(
            DetectionId::D4,
            Severity::High,
            "File capabilities granted outside system directories",
            &format!("d4|file-caps|{}", ev.path),
        )
        .what(format!(
            "An executable with filesystem capabilities appeared at {} ({}).",
            ev.path,
            writer_label(ev.writer.as_ref())
        ))
        .chain(
            ev.writer
                .as_ref()
                .map(|w| ctx.chain_nodes(w.pid))
                .unwrap_or_default(),
        )
        .fact("Path", &ev.path)
        .why(
            "File capabilities grant specific root privileges (raw sockets, ptrace, setuid) \
             without a setuid bit, making them a stealthier escalation primitive.",
        )
        .actions([
            "Inspect with getcap and remove the capabilities if unauthorized.",
            "Identify the process that set them.",
        ]),
    )
}

fn sudoers(ev: &FileEvent, ctx: &Ctx) -> Option<Finding> {
    let is_sudoers = ev.path == "/etc/sudoers" || ev.path.starts_with("/etc/sudoers.d/");
    if !is_sudoers {
        return None;
    }
    if let Some(w) = &ev.writer {
        if w.comm == "visudo" || is_user_mgmt_tool(&w.comm) || is_installer_chain(w.pid, ctx) {
            return None;
        }
    } else if ctx
        .tree
        .recent_process(ctx.now, chrono::Duration::seconds(8), |p| {
            p.comm == "visudo"
        })
        .is_some()
    {
        return None;
    }
    // Editor lock files (visudo's own `.tmp`, sudoers.tmp) never hold rules.
    if ev.path.ends_with(".tmp") {
        return None;
    }
    let nopasswd = ev
        .content
        .as_deref()
        .map(|c| {
            c.lines()
                .any(|l| l.contains("NOPASSWD") && !l.trim_start().starts_with('#'))
        })
        .unwrap_or(false);
    let attribution = ctx.attribute(ev);
    let severity = if nopasswd && !attribution.is_interactive() {
        Severity::Critical
    } else if attribution.is_interactive() {
        Severity::Low
    } else {
        Severity::High
    };
    Some(
        Finding::new(
            DetectionId::D4,
            severity,
            if nopasswd {
                "sudoers changed to grant password-less sudo"
            } else {
                "sudoers modified outside visudo"
            },
            &format!("d4|sudoers|{}", ev.path),
        )
        .what(format!(
            "{} was {} by {}, not by visudo{}.",
            ev.path,
            ev.kind.as_str(),
            writer_label(ev.writer.as_ref()),
            if attribution.is_interactive() {
                ""
            } else {
                ", with no interactive session active"
            }
        ))
        .fact("Path", &ev.path)
        .fact("NOPASSWD", if nopasswd { "present" } else { "" })
        .why(
            "sudoers decides who becomes root. Bypassing visudo skips syntax validation and is \
             how attackers grant themselves silent, password-less root.",
        )
        .actions([
            "Inspect the file for unauthorized entries, especially NOPASSWD and ALL=(ALL).",
            "Run visudo -c to validate syntax.",
            "Remove any entry you did not create.",
        ]),
    )
}

fn is_installer_chain(pid: u32, ctx: &Ctx) -> bool {
    ctx.tree.chain_of(pid).iter().any(|p| {
        matches!(
            role_of(&p.comm, &p.exe),
            Role::PackageManager | Role::ConfigManager
        )
    })
}

/// The standard tools write account files via temp+rename and exit at once,
/// so the writer is usually gone by the time we look. A user-management tool
/// (or a package manager) that ran in the last few seconds is the writer.
fn recent_account_tool(ctx: &Ctx) -> bool {
    ctx.tree
        .recent_process(ctx.now, chrono::Duration::seconds(8), |p| {
            is_user_mgmt_tool(&p.comm)
                || matches!(
                    role_of(&p.comm, &p.exe),
                    Role::PackageManager | Role::ConfigManager
                )
        })
        .is_some()
}

fn account_files(ev: &FileEvent, ctx: &Ctx) -> Option<Finding> {
    let sensitive = ev.path == "/etc/shadow" || ev.path == "/etc/gshadow";
    let account = ev.path == "/etc/passwd" || ev.path == "/etc/group";
    if !sensitive && !account {
        return None;
    }
    // Lock files and backups the tools leave behind.
    if let Some(w) = &ev.writer {
        if is_user_mgmt_tool(&w.comm) || is_installer_chain(w.pid, ctx) {
            return None;
        }
    } else if recent_account_tool(ctx) {
        return None;
    }
    let attribution = ctx.attribute(ev);
    // `account` files are diffed by D2 which produces the actionable alert; here
    // we only escalate the shadow files or clearly unattended direct writes.
    if account && attribution.is_interactive() {
        return None;
    }
    let severity = if sensitive && !attribution.is_interactive() {
        Severity::Critical
    } else {
        Severity::High
    };
    Some(
        Finding::new(
            DetectionId::D4,
            severity,
            if sensitive {
                "shadow file modified outside user-management tools"
            } else {
                "Account file modified outside user-management tools"
            },
            &format!("d4|account-file|{}", ev.path),
        )
        .what(format!(
            "{} was {} by {}, not by passwd/useradd/usermod{}.",
            ev.path,
            ev.kind.as_str(),
            writer_label(ev.writer.as_ref()),
            if attribution.is_interactive() {
                ""
            } else {
                ", with no interactive session active"
            }
        ))
        .fact("Path", &ev.path)
        .why(
            "The account databases should only change through the standard tools, which keep \
             passwd and shadow consistent. Direct edits are how attackers plant hidden accounts \
             or replace password hashes.",
        )
        .actions([
            "Diff the file against a backup and look for new uid-0 or changed hashes.",
            "Restore from backup if the change is unauthorized.",
            "Identify the process that wrote the file.",
        ]),
    )
}
