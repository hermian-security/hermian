//! D1 - Suspicious process chains.

use crate::alert::Finding;
use crate::detect::Ctx;
use crate::events::{is_suspicious_exec_dir, DetectionId, ExecEvent, ProcInfo, Severity};
use crate::proctree::{role_of, Role};

pub fn evaluate(ev: &ExecEvent, ctx: &Ctx) -> Vec<Finding> {
    let mut findings = Vec::new();
    let chain = ctx.tree.chain_of(ev.pid);
    let roles: Vec<Role> = chain.iter().map(|p| role_of(&p.comm, &p.exe)).collect();

    // Container entrypoints are `PID 1`-parented inside their namespace and
    // routinely run `sh -c`; they are not web-to-shell RCE.
    let container_entrypoint = ev.container && ev.ppid == 1;

    if !container_entrypoint {
        findings.extend(service_to_shell(ev, ctx, &roles, Role::WebServer));
        findings.extend(service_to_shell(ev, ctx, &roles, Role::Database));
        findings.extend(web_shell_downloader_exec(ev, ctx, &roles));
    }

    findings.extend(exec_from_transient_dir(ev, ctx));
    findings.extend(exec_from_deleted_inode(ev, ctx));
    findings.extend(shell_script_exec(ev, ctx, &roles));

    findings
}

/// Programs that only set something up and then exec the real command.
/// `env sh`, `setsid bash`, `nohup sh -c` (or Java's Runtime.exec through
/// `/usr/bin/env`) put one of these between the service and the shell.
const WRAPPERS: &[&str] = &[
    "env", "setsid", "nohup", "timeout", "nice", "ionice", "stdbuf", "chrt", "taskset", "xargs",
    "script", "unbuffer", "flock",
];

fn is_wrapper(p: &ProcInfo) -> bool {
    let base = p.exe.rsplit('/').next().unwrap_or("");
    WRAPPERS.contains(&p.comm.as_str()) || WRAPPERS.contains(&base)
}

/// Index of the nearest ancestor of `chain[last]` that isn't a wrapper.
fn effective_parent(chain: &[ProcInfo], last: usize) -> Option<usize> {
    (0..last).rev().find(|i| !is_wrapper(&chain[*i]))
}

/// Tools that open a raw network channel: reverse/bind shells, relays.
const NETCAT_LIKE: &[&str] = &["nc", "ncat", "netcat", "socat", "openssl", "telnet"];

fn service_to_shell(ev: &ExecEvent, ctx: &Ctx, roles: &[Role], service: Role) -> Option<Finding> {
    if roles.len() < 2 {
        return None;
    }
    let last = roles.len() - 1;
    let chain = ctx.tree.chain_of(ev.pid);
    let parent_idx = effective_parent(&chain, last)?;
    if roles[parent_idx] != service {
        return None;
    }
    // Shells always; downloaders and netcat-style tools are the next most
    // common first step. General interpreters are logged, since apps do run
    // `php artisan` or `python manage.py` legitimately.
    let base = ev.exe.rsplit('/').next().unwrap_or("");
    let netcat = NETCAT_LIKE.contains(&ev.comm.as_str()) || NETCAT_LIKE.contains(&base);
    if roles[last] != Role::Shell {
        return service_to_tool(ev, ctx, &chain, parent_idx, roles[last], netcat, service);
    }
    let parent = &chain[parent_idx];
    if ctx
        .allowlist
        .chain_allowed(&parent.comm, &ev.comm, Some(ev.uid), ctx.user_name(ev.uid))
    {
        return None;
    }
    let (kind, why, actions): (&str, &str, [&str; 3]) = match service {
        Role::WebServer => (
            "web-shell",
            "Web servers do not spawn interactive shells in normal operation. This pattern is \
             consistent with remote code execution through a vulnerable web application or an \
             uploaded web shell.",
            [
                "Review the web server access logs for the request that coincides with this alert.",
                "Identify the application component that spawned the shell.",
                "Isolate the host if the activity is unexpected.",
            ],
        ),
        _ => (
            "db-shell",
            "Database servers never need to run shells. This pattern is associated with \
             exploitation of database features (UDFs, COPY PROGRAM, xp_cmdshell-style primitives) \
             to gain code execution.",
            [
                "Review database logs and active client connections.",
                "Check for recently created functions, extensions, or scheduled jobs.",
                "Isolate the host if the activity is unexpected.",
            ],
        ),
    };
    let title = match service {
        Role::WebServer => "Web server spawned a shell",
        _ => "Database server spawned a shell",
    };
    // Keyed on the service, not the shell: `bash -c '... sh ...'` is one
    // incident, not two.
    Some(
        Finding::new(
            DetectionId::D1,
            Severity::High,
            title,
            &format!("d1|{}|{}|{}", kind, parent.comm, parent.pid),
        )
        .what(format!(
            "{} (pid {}) spawned the shell {} (pid {}) running as {}.",
            parent.comm,
            parent.pid,
            ev.comm,
            ev.pid,
            ctx.user_name(ev.uid).unwrap_or("an unknown user")
        ))
        .chain(ctx.chain_nodes(ev.pid))
        .fact("Command", &ev.argv0)
        .why(why)
        .actions(actions),
    )
}

fn service_to_tool(
    ev: &ExecEvent,
    ctx: &Ctx,
    chain: &[ProcInfo],
    parent_idx: usize,
    role: Role,
    netcat: bool,
    service: Role,
) -> Option<Finding> {
    let severity = if netcat || role == Role::Downloader {
        Severity::High
    } else if role == Role::Interpreter {
        Severity::Low
    } else {
        return None;
    };
    let parent = &chain[parent_idx];
    if ctx
        .allowlist
        .chain_allowed(&parent.comm, &ev.comm, Some(ev.uid), ctx.user_name(ev.uid))
    {
        return None;
    }
    let svc = if service == Role::WebServer {
        "Web server"
    } else {
        "Database server"
    };
    let (title, why) = if netcat {
        (
            format!("{} spawned a network relay tool", svc),
            "nc, socat and similar tools are how reverse and bind shells are opened; a service \
             has no reason to start one.",
        )
    } else if role == Role::Downloader {
        (
            format!("{} spawned a download tool", svc),
            "Fetching content with curl or wget straight from a service process is the staging \
             step of most remote code execution chains.",
        )
    } else {
        (
            format!("{} spawned an interpreter", svc),
            "Some applications run scripts this way; it's also how injected code gets a full \
             interpreter without a shell. Logged for context.",
        )
    };
    Some(
        Finding::new(
            DetectionId::D1,
            severity,
            &title,
            &format!("d1|service-tool|{}|{}|{}", parent.comm, parent.pid, ev.comm),
        )
        .what(format!(
            "{} (pid {}) started {} (pid {}) running as {}.",
            parent.comm,
            parent.pid,
            ev.comm,
            ev.pid,
            ctx.user_name(ev.uid).unwrap_or("an unknown user")
        ))
        .chain(ctx.chain_nodes(ev.pid))
        .fact("Command", &ev.argv0)
        .why(why)
        .actions([
            "Review the service's logs for the request that coincides with this alert.",
            "Identify the application component that started the process.",
            "Allowlist the parent/child pair if this is expected behaviour.",
        ]),
    )
}

/// A downloader that ran recently from the web-shell part of this chain:
/// `curl ... | sh` and `curl -o x; ./x` make the payload the downloader's
/// *sibling*, not its child.
fn recent_sibling_download<'a>(
    ctx: &'a Ctx,
    chain: &[ProcInfo],
    from: usize,
    last: usize,
) -> Option<&'a ProcInfo> {
    let shell_pids: Vec<u32> = chain[from..last].iter().map(|p| p.pid).collect();
    ctx.tree
        .recent_process(ctx.now, chrono::Duration::seconds(120), |p| {
            shell_pids.contains(&p.ppid) && role_of(&p.comm, &p.exe) == Role::Downloader
        })
}

fn web_shell_downloader_exec(ev: &ExecEvent, ctx: &Ctx, roles: &[Role]) -> Option<Finding> {
    let last = roles.len().checked_sub(1)?;
    let web_idx = roles.iter().position(|r| *r == Role::WebServer)?;
    let shell_idx = roles[web_idx..]
        .iter()
        .position(|r| *r == Role::Shell)
        .map(|i| i + web_idx)?;
    if shell_idx >= last && roles[last] != Role::Downloader {
        return None;
    }
    let chain = ctx.tree.chain_of(ev.pid);

    if roles[last] == Role::Downloader {
        return Some(
            Finding::new(
                DetectionId::D1,
                Severity::High,
                "Web server shell chain started a download",
                &format!("d1|web-shell-download|{}|{}", chain[web_idx].comm, ev.comm),
            )
            .what(format!(
                "A shell descended from {} executed the download tool {}.",
                chain[web_idx].comm, ev.comm
            ))
            .chain(ctx.chain_nodes(ev.pid))
            .fact("Command", &ev.argv0)
            .why(
                "A web server spawning a shell is already suspicious; that shell fetching content \
                 from the network is the staging step of most web exploitation chains.",
            )
            .actions([
                "Identify the download destination (see D5 connect alerts from the same chain).",
                "Review web server access logs for the triggering request.",
                "Block the destination if it is unknown.",
            ]),
        );
    }

    let parent_is_downloader = last >= 1 && roles[last - 1] == Role::Downloader;
    // The payload: a shell/interpreter or a binary outside system dirs, run
    // after a download from the same web-shell chain.
    let payload_like = matches!(roles[last], Role::Shell | Role::Interpreter)
        || !crate::proctree::is_system_exe_path(&ev.exe);
    let sibling = if parent_is_downloader || !payload_like || last <= shell_idx {
        None
    } else {
        recent_sibling_download(ctx, &chain, shell_idx, last)
    };
    let parent = match (parent_is_downloader, sibling) {
        (true, _) => &chain[last - 1],
        (false, Some(dl)) => dl,
        (false, None) => return None,
    };
    if ctx
        .allowlist
        .chain_allowed(&parent.comm, &ev.comm, Some(ev.uid), ctx.user_name(ev.uid))
    {
        return None;
    }
    Some(
        Finding::new(
            DetectionId::D1,
            Severity::Critical,
            "Web server chain downloaded and executed remote content",
            &format!(
                "d1|web-shell-download-exec|{}|{}",
                chain[web_idx].comm, ev.comm
            ),
        )
        .what(format!(
            "{} spawned a shell, the shell ran {} to fetch content, and that content is now \
             executing as {} (pid {}).",
            chain[web_idx].comm, parent.comm, ev.comm, ev.pid
        ))
        .chain(ctx.chain_nodes(ev.pid))
        .fact("Executable", &ev.exe)
        .why(
            "Web server, shell, downloader, execution: this exact sequence is the signature of \
             remote code execution - an attacker exploiting the application, staging a payload, \
             and running it.",
        )
        .actions([
            "Isolate this host from the network unless the activity is known and expected.",
            "Preserve the executed file and the process memory for analysis.",
            "Review web server access logs around the alert time to find the entry point.",
        ]),
    )
}

fn exec_from_transient_dir(ev: &ExecEvent, ctx: &Ctx) -> Option<Finding> {
    let path = if is_suspicious_exec_dir(&ev.exe) {
        &ev.exe
    } else if is_suspicious_exec_dir(&ev.argv0) {
        &ev.argv0
    } else {
        return None;
    };
    if ctx.allowlist.binary_allowed(&ev.exe) || ctx.allowlist.binary_allowed(path) {
        return None;
    }

    let chain = ctx.tree.chain_of(ev.pid);
    let in_flagged = ctx.has_recent_flag(ev.pid, 120, None);
    let interactive = ctx.tree.has_interactive_session(ev.pid, ev.tty_nr);
    let from_installer = chain.iter().any(|p| {
        matches!(
            role_of(&p.comm, &p.exe),
            Role::PackageManager | Role::ConfigManager
        )
    }) && ctx.tool_exemption_applies(ev.pid);

    // Severity ladder: flagged chain > unattended > interactive/installer.
    let (severity, title) = if in_flagged {
        (
            Severity::Critical,
            "Execution from a transient directory inside a flagged chain",
        )
    } else if interactive || from_installer {
        (Severity::Low, "Binary executed from a transient directory")
    } else {
        (
            Severity::High,
            "Unattended execution from a transient directory",
        )
    };

    Some(
        Finding::new(
            DetectionId::D1,
            severity,
            title,
            &format!("d1|exec-transient|{}", path),
        )
        .what(format!(
            "{} (pid {}) executed {} - a world-writable, non-persistent location.",
            ev.comm, ev.pid, path
        ))
        .chain(ctx.chain_nodes(ev.pid))
        .fact("Path", path)
        .fact(
            "Context",
            if interactive {
                "interactive session"
            } else if from_installer {
                "package/config manager"
            } else {
                "no interactive session"
            },
        )
        .why(
            "Installed software does not live in /tmp, /dev/shm or /var/tmp. Attackers stage \
             tools there because those locations are always writable. Installers and build \
             tools do this legitimately, which is why the severity depends on context.",
        )
        .actions([
            "Inspect the executed file and determine how it got there.",
            "Remove it if it is not yours.",
            "Review the parent chain for other indicators (downloads, network connections).",
        ]),
    )
}

fn exec_from_deleted_inode(ev: &ExecEvent, ctx: &Ctx) -> Option<Finding> {
    if !ev.deleted_exe {
        return None;
    }
    // Package upgrades replace binaries under running processes; that shows as a
    // deleted exe for the *already running* process, not for a fresh exec. A fresh
    // exec from a deleted inode or a memfd is the fileless pattern.
    let is_memfd = ev.exe.contains("memfd:") || ev.argv0.contains("/fd/");
    let parent = ctx.tree.get(ev.ppid);
    let loader = parent
        .map(|p| format!("{} (pid {})", p.comm, p.pid))
        .unwrap_or_else(|| format!("pid {}", ev.ppid));
    let what = if is_memfd {
        format!(
            "{} launched a program from an anonymous in-memory file (memfd); it now runs as pid {} \
             with no backing file on disk.",
            loader, ev.pid
        )
    } else {
        format!(
            "{} (pid {}) is executing code whose backing file has been deleted from disk.",
            ev.comm, ev.pid
        )
    };
    Some(
        Finding::new(
            DetectionId::D1,
            Severity::High,
            if is_memfd {
                "Fileless execution from memory (memfd)"
            } else {
                "Execution from a deleted file"
            },
            &format!("d1|exec-deleted|{}|{}", ev.comm, ev.uid),
        )
        .what(what)
        .chain(ctx.chain_nodes(ev.pid))
        .fact(
            "Loader",
            if parent.is_some() {
                loader.clone()
            } else {
                String::new()
            },
        )
        .fact("Reported path", &ev.exe)
        .why(
            "Executing from a deleted inode or an anonymous memfd is a fileless technique: the \
             payload is loaded and then unlinked so nothing remains to inspect on disk.",
        )
        .actions([
            "Treat the host as potentially compromised.",
            "Capture the process memory (e.g. from /proc/<pid>/) before killing it.",
            "Inspect the parent chain to find the loader.",
        ]),
    )
}

/// Interpreter launched from a shell *outside any interactive session*. This
/// is the "cron job runs a python script" / "service runs a helper" shape:
/// context for correlation, never notified. Interactive shells spawning
/// interpreters are what terminals are for and are not recorded at all.
fn shell_script_exec(ev: &ExecEvent, ctx: &Ctx, roles: &[Role]) -> Option<Finding> {
    let last = roles.len().checked_sub(1)?;
    if last == 0 {
        return None;
    }
    let is_script_host = matches!(roles[last], Role::Shell | Role::Interpreter);
    if !is_script_host || roles[last - 1] != Role::Shell {
        return None;
    }
    if ctx.tree.has_interactive_session(ev.pid, ev.tty_nr) {
        return None;
    }
    Some(
        Finding::new(
            DetectionId::D1,
            Severity::Info,
            "Script executed from a shell",
            &format!("d1|shell-script|{}|{}", ev.comm, ev.uid),
        )
        .what(format!("A shell spawned {} (pid {}).", ev.comm, ev.pid))
        .chain(ctx.chain_nodes(ev.pid))
        .why(
            "Common during administration and development. Logged for context only; it only \
             becomes meaningful in combination with other detections.",
        ),
    )
}
