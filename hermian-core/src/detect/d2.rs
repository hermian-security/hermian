//! D2 - SSH and authentication abuse.

use std::collections::HashMap;

use crate::alert::Finding;
use crate::detect::{content_tag, writer_label, BurstTracker, Ctx};
use crate::events::{
    is_editor_artifact, AuthEvent, AuthResult, DetectionId, FileEvent, FileKind, Severity,
};

pub fn evaluate_auth(ev: &AuthEvent, ctx: &Ctx, bursts: &mut BurstTracker) -> Vec<Finding> {
    let mut findings = Vec::new();
    if ev.service != "sshd" && ev.service != "ssh" {
        return findings;
    }
    let Some(rhost) = ev.rhost else {
        return findings;
    };
    if ctx.allowlist.source_allowed(rhost) {
        return findings;
    }

    let window = ctx
        .cfg
        .ssh
        .failed_burst_window_secs
        .clamp(1, crate::config::MAX_WINDOW_SECS) as i64;
    let threshold = ctx.cfg.ssh.failed_burst_count as usize;

    match ev.result {
        AuthResult::Attempt | AuthResult::Failure => {
            let count = bursts.record_failure(rhost, ev.ts, window, &ev.user);
            if count == threshold {
                // Internet scanners trip this all day. Log it; don't page.
                findings.push(
                    Finding::new(
                        DetectionId::D2,
                        Severity::Info,
                        "SSH authentication burst",
                        &format!("d2|burst|{}", rhost),
                    )
                    .what(format!(
                        "{} authentication attempts from {} within {} seconds, most recently for \
                         user '{}'.",
                        count, rhost, ctx.cfg.ssh.failed_burst_window_secs, ev.user
                    ))
                    .fact("Source", rhost.to_string())
                    .fact("Last user", &ev.user)
                    .why(
                        "Failed-auth bursts are common on any public SSH port. Logged for context; \
                         a later login from this source is what gets a HIGH alert.",
                    ),
                );
            }
        }
        AuthResult::Success => {
            let recent = bursts.recent_failures(rhost, ev.ts, window);
            let after_burst = recent >= threshold;
            if after_burst {
                let users = bursts.recent_users(rhost);
                findings.push(
                    Finding::new(
                        DetectionId::D2,
                        Severity::High,
                        "SSH login after a failed-auth burst",
                        &format!("d2|burst-success|{}", rhost),
                    )
                    .what(format!(
                        "User '{}' authenticated from {} after {} failed attempts within {} \
                         seconds{}.",
                        ev.user,
                        rhost,
                        recent,
                        ctx.cfg.ssh.failed_burst_window_secs,
                        if users.is_empty() {
                            String::new()
                        } else {
                            format!(" (tried: {})", users.join(", "))
                        }
                    ))
                    .fact("Source", rhost.to_string())
                    .fact("User", &ev.user)
                    .fact("Failed attempts", recent.to_string())
                    .why(
                        "A login from an address that was just brute-forcing this host is the \
                         credential-stuffing outcome, not the background noise of failed attempts.",
                    )
                    .actions([
                        "Treat this session as hostile until proven otherwise.",
                        "Lock or rotate the account that succeeded and any others the source tried.",
                        "Block the source and review what the session did.",
                    ]),
                );
            }
            if ev.user == "root" && !ctx.cfg.ssh.permit_root && !after_burst {
                // A root login is a policy concern, not per se an anomaly. It is
                // HIGH the first time a source is seen; the same operator logging
                // in again from the same place is context, not a new incident.
                let seen_before = ctx.baseline.root_source_is_known(rhost);
                let off_hours = ctx.is_off_hours(ev.ts);
                let severity = if !seen_before || off_hours {
                    Severity::High
                } else {
                    Severity::Info
                };
                findings.push(
                    Finding::new(
                        DetectionId::D2,
                        severity,
                        if seen_before {
                            "Root login over SSH"
                        } else {
                            "Root login over SSH from a new source"
                        },
                        &format!("d2|root-login|{}", rhost),
                    )
                    .what(format!(
                        "root authenticated over SSH from {}{}.",
                        rhost,
                        if seen_before {
                            ", a source that has logged in as root before"
                        } else {
                            " for the first time"
                        }
                    ))
                    .fact("Source", rhost.to_string())
                    .fact("Timing", if off_hours { "off-hours" } else { "" })
                    .why(
                        "Direct root logins remove accountability and are the preferred target of \
                         credential attacks. If this host relies on them, set ssh.permit_root = true \
                         or allowlist the source; otherwise prefer PermitRootLogin prohibit-password.",
                    )
                    .actions([
                        "Confirm this login was expected.",
                        "If not, rotate credentials and revoke the keys involved.",
                        "Add the source to allowlist.ssh_sources if it is your management host.",
                    ]),
                );
            }
            if !after_burst
                && ctx.baseline.can_judge_novelty()
                && !ctx.baseline.ssh_source_is_known(rhost)
            {
                let off_hours = ctx.is_off_hours(ev.ts);
                let elevated = ev.user == "root" || off_hours;
                let severity = if elevated {
                    Severity::High
                } else {
                    Severity::Low
                };
                findings.push(
                    Finding::new(
                        DetectionId::D2,
                        severity,
                        if elevated {
                            "SSH login from a new source at an unusual time"
                        } else {
                            "SSH login from a new source"
                        },
                        &format!("d2|new-source|{}|{}", rhost, ev.user),
                    )
                    .what(format!(
                        "User '{}' authenticated from {}, a source never seen during the baseline \
                         period{}.",
                        ev.user,
                        rhost,
                        if off_hours { " (off-hours)" } else { "" }
                    ))
                    .fact("Source", rhost.to_string())
                    .fact("User", &ev.user)
                    .why(
                        "HERMIAN learned this host's SSH sources during its baseline period. A \
                         first-time source combined with root access or off-hours timing deserves \
                         a look.",
                    )
                    .actions([
                        "Confirm this login was expected.",
                        "Review what the session did (shell history, journal).",
                        "Add the source to allowlist.ssh_sources if it is legitimate.",
                    ]),
                );
            }
        }
    }
    // A suspicious login (after a burst, from a new source, root from a new
    // place) gets Ignore / Disconnect / Disconnect-and-block. A routine
    // repeat (INFO) doesn't.
    if ev.result == AuthResult::Success {
        findings = findings
            .into_iter()
            .map(|f| {
                if f.severity >= Severity::Low {
                    login_offers(f, ev, rhost)
                } else {
                    f
                }
            })
            .collect();
    }
    findings
}

const SSH_CONFIG_PATHS: &[&str] = &[
    "/etc/ssh/sshd_config",
    "/etc/ssh/ssh_config",
    "/etc/ssh/sshd_config.d",
    "/etc/ssh/ssh_config.d",
];

pub fn evaluate_ssh_config_file(ev: &FileEvent, ctx: &Ctx) -> Option<Finding> {
    let is_ssh_config = SSH_CONFIG_PATHS
        .iter()
        .any(|p| ev.path == *p || ev.path.starts_with(&format!("{}/", p)));
    let is_user_ssh_config = ev.path.contains("/.ssh/") && ev.path.ends_with("/config");
    if !is_ssh_config && !is_user_ssh_config {
        return None;
    }
    if matches!(ev.kind, FileKind::Removed | FileKind::MovedFrom) || is_editor_artifact(&ev.path) {
        return None;
    }
    if ctx.allowlist.path_allowed(&ev.path) {
        return None;
    }
    let attribution = ctx.attribute(ev);
    if attribution.is_interactive() {
        return Some(
            Finding::new(
                DetectionId::D2,
                Severity::Info,
                "SSH configuration edited during a session",
                &format!("d2|ssh-config-session|{}", ev.path),
            )
            .what(format!(
                "{} was {} while an interactive session was active.",
                ev.path,
                ev.kind.as_str()
            ))
            .fact("Path", &ev.path)
            .why("Logged for context. Operators edit SSH configuration interactively."),
        );
    }
    Some(
        Finding::new(
            DetectionId::D2,
            Severity::High,
            "SSH configuration changed with no session present",
            &format!("d2|ssh-config|{}", ev.path),
        )
        .what(format!(
            "{} was {} by {} while no interactive session was active on the host.",
            ev.path,
            ev.kind.as_str(),
            writer_label(ev.writer.as_ref())
        ))
        .fact("Path", &ev.path)
        .why(
            "SSH configuration controls who can authenticate and how. Unattended changes can \
             weaken authentication or add backdoor keys, listeners or authorized-key commands.",
        )
        .actions([
            "Diff the file against its previous version or the package default.",
            "Revert any change you did not make and restart sshd.",
            "Identify the process that performed the write.",
        ]),
    )
}

pub fn check_account_changes(
    ev: &FileEvent,
    ctx: &Ctx,
    old_content: Option<&String>,
) -> Option<Finding> {
    let new_content = ev.content.as_ref()?;
    let old_content = old_content?;
    let change = if ev.path == "/etc/passwd" {
        diff_accounts(old_content, new_content)?
    } else if ev.path == "/etc/group" {
        diff_groups(old_content, new_content)?
    } else {
        return None;
    };
    let interactive = ctx.attribute(ev).is_interactive();
    let severity = if change.privileged {
        Severity::High
    } else if interactive {
        Severity::Low
    } else {
        Severity::High
    };
    Some(
        Finding::new(
            DetectionId::D2,
            severity,
            change.title,
            // Keyed on what changed: a second, different change to the same
            // file within the dedup window is its own alert.
            &format!(
                "d2|account-change|{}|{}",
                ev.path,
                content_tag(&change.summary)
            ),
        )
        .what(format!("{}: {}", ev.path, change.summary))
        .fact("Path", &ev.path)
        .fact(
            "Context",
            if interactive {
                "interactive session present"
            } else {
                "no interactive session"
            },
        )
        .why(
            "New local accounts, and especially new members of sudo/wheel/admin, are a durable way \
             for an attacker to keep access after the initial foothold is closed.",
        )
        .actions([
            "Verify the new account or group membership is authorized.",
            "If not, remove it immediately and audit the host for how it was created.",
        ]),
    )
}

pub struct AccountChange {
    pub summary: String,
    pub privileged: bool,
    pub title: &'static str,
}

/// One /etc/passwd entry, as far as the diff cares.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PasswdEntry {
    uid: String,
    gid: String,
    home: String,
    shell: String,
}

/// Numeric id 0, however it's written ("0", "00", " 0").
fn is_zero_id(s: &str) -> bool {
    s.trim().parse::<u64>() == Ok(0)
}

/// Shells that mean "no interactive login".
pub fn is_nologin(shell: &str) -> bool {
    let base = shell.rsplit('/').next().unwrap_or("");
    shell.is_empty() || matches!(base, "nologin" | "false" | "sync" | "halt" | "shutdown")
}

/// Accounts that can log in: those with a real shell in /etc/passwd.
pub fn login_users(passwd: &str) -> std::collections::HashSet<String> {
    parse_passwd(passwd)
        .into_iter()
        .filter(|(_, e)| !is_nologin(&e.shell))
        .map(|(n, _)| n)
        .collect()
}

/// The three responses offered with a suspicious login.
fn login_offers(f: Finding, ev: &AuthEvent, rhost: std::net::IpAddr) -> Finding {
    use crate::response::ResponseAction;
    f.offer(ResponseAction::Ignore {
        sources: Vec::new(),
        hours: 0,
    })
    .offer(ResponseAction::Disconnect {
        source: rhost,
        port: ev.port,
        user: ev.user.clone(),
        block: false,
    })
    .offer(ResponseAction::Disconnect {
        source: rhost,
        port: ev.port,
        user: ev.user.clone(),
        block: true,
    })
}

fn parse_passwd(s: &str) -> Vec<(String, PasswdEntry)> {
    s.lines()
        .filter(|l| !l.trim_start().starts_with('#') && l.contains(':'))
        .filter_map(|l| {
            let mut it = l.split(':');
            let name = it.next()?.to_string();
            it.next()?;
            let uid = it.next()?.to_string();
            let gid = it.next().unwrap_or("").to_string();
            it.next(); // gecos
            let home = it.next().unwrap_or("").to_string();
            let shell = it.next().unwrap_or("").trim().to_string();
            Some((
                name,
                PasswdEntry {
                    uid,
                    gid,
                    home,
                    shell,
                },
            ))
        })
        .collect()
}

fn diff_accounts(old: &str, new: &str) -> Option<AccountChange> {
    let old_map: HashMap<String, PasswdEntry> = parse_passwd(old).into_iter().collect();
    let mut changes = Vec::new();
    let mut privileged = false;
    for (name, e) in parse_passwd(new) {
        match old_map.get(&name) {
            None => {
                changes.push(format!("{} (uid {}) added", name, e.uid));
                privileged |= is_zero_id(&e.uid) || is_zero_id(&e.gid);
            }
            Some(o) if o == &e => {}
            Some(o) => {
                let mut what = Vec::new();
                if o.uid != e.uid {
                    what.push(format!("uid {} -> {}", o.uid, e.uid));
                    privileged |= is_zero_id(&e.uid);
                }
                if o.gid != e.gid {
                    what.push(format!("gid {} -> {}", o.gid, e.gid));
                    privileged |= is_zero_id(&e.gid);
                }
                if o.shell != e.shell {
                    what.push(format!("shell {} -> {}", o.shell, e.shell));
                    // A service account that suddenly gets a login shell is
                    // a classic backdoor.
                    privileged |= is_nologin(&o.shell) && !is_nologin(&e.shell);
                }
                if o.home != e.home {
                    what.push(format!("home {} -> {}", o.home, e.home));
                }
                changes.push(format!("{} changed ({})", name, what.join(", ")));
            }
        }
    }
    if changes.is_empty() {
        return None;
    }
    Some(AccountChange {
        summary: format!("accounts: {}", changes.join("; ")),
        privileged,
        title: if privileged {
            "Privileged account added or changed"
        } else {
            "System account database changed"
        },
    })
}

/// Groups whose members are root, or close to it: sudo/wheel/admin by
/// policy, docker/lxd/incus/libvirt via the daemons they control, disk and
/// shadow via raw access to block devices and password hashes.
const PRIVILEGED_GROUPS: &[&str] = &[
    "sudo",
    "wheel",
    "admin",
    "root",
    "docker",
    "lxd",
    "incus-admin",
    "libvirt",
    "disk",
    "shadow",
    "adm",
];

fn diff_groups(old: &str, new: &str) -> Option<AccountChange> {
    let parse = |s: &str| -> HashMap<String, Vec<String>> {
        s.lines()
            .filter(|l| !l.trim_start().starts_with('#') && l.contains(':'))
            .filter_map(|l| {
                let mut it = l.split(':');
                let name = it.next()?.to_string();
                it.next()?;
                it.next()?;
                let members = it.next().unwrap_or("");
                Some((
                    name,
                    members
                        .split(',')
                        .filter(|m| !m.is_empty())
                        .map(str::to_string)
                        .collect(),
                ))
            })
            .collect()
    };
    let old_map = parse(old);
    let new_map = parse(new);
    let mut changes = Vec::new();
    let mut privileged = false;
    for target in PRIVILEGED_GROUPS.iter().copied() {
        let old_members = old_map.get(target).cloned().unwrap_or_default();
        let new_members = new_map.get(target).cloned().unwrap_or_default();
        let added: Vec<&String> = new_members
            .iter()
            .filter(|m| !old_members.contains(m))
            .collect();
        if !added.is_empty() {
            privileged = true;
            changes.push(format!(
                "added to {}: {}",
                target,
                added
                    .iter()
                    .map(|m| m.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }
    let mut new_groups: Vec<&String> = new_map
        .keys()
        .filter(|g| !old_map.contains_key(g.as_str()))
        .collect();
    new_groups.sort();
    if !new_groups.is_empty() {
        changes.push(format!(
            "new groups: {}",
            new_groups
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if changes.is_empty() {
        None
    } else {
        Some(AccountChange {
            summary: changes.join("; "),
            privileged,
            title: if privileged {
                "Privileged group membership changed"
            } else {
                "System account database changed"
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_diff_detects_new_user() {
        let old = "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n";
        let new = format!("{}mallory:x:1001:1001::/home/mallory:/bin/bash\n", old);
        let diff = diff_accounts(old, &new).expect("diff");
        assert!(diff.summary.contains("mallory"));
        assert!(!diff.privileged);
    }

    #[test]
    fn account_diff_flags_uid_zero() {
        let old = "root:x:0:0:root:/root:/bin/bash\n";
        let new = "root:x:0:0:root:/root:/bin/bash\ntoor:x:0:0::/root:/bin/bash\n";
        let diff = diff_accounts(old, new).expect("diff");
        assert!(diff.privileged);
    }

    #[test]
    fn account_diff_flags_zero_uid_however_written() {
        let old = "root:x:0:0:root:/root:/bin/bash\n";
        let new = "root:x:0:0:root:/root:/bin/bash\nsvc:x:00:0::/:/bin/sh\n";
        assert!(diff_accounts(old, new).unwrap().privileged);
    }

    #[test]
    fn account_diff_flags_a_service_account_getting_a_shell() {
        let old = "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n";
        let new = "www-data:x:33:33:www-data:/var/www:/bin/bash\n";
        let d = diff_accounts(old, new).unwrap();
        assert!(d.privileged);
        assert!(d.summary.contains("shell"), "{}", d.summary);
        // Home and gid changes are reported too.
        let moved = "www-data:x:33:0:www-data:/root:/usr/sbin/nologin\n";
        let d = diff_accounts(old, moved).unwrap();
        assert!(d.privileged, "gid 0");
        assert!(d.summary.contains("home"), "{}", d.summary);
    }

    #[test]
    fn group_diff_covers_root_equivalent_groups() {
        for g in ["docker", "lxd", "disk", "shadow"] {
            let old = format!("{}:x:999:\n", g);
            let new = format!("{}:x:999:eve\n", g);
            let d = diff_groups(&old, &new).unwrap_or_else(|| panic!("{}", g));
            assert!(d.privileged, "{}", g);
        }
    }

    #[test]
    fn group_diff_detects_sudo_add() {
        let old = "sudo:x:27:alice\nwheel:x:10:\n";
        let new = "sudo:x:27:alice,mallory\nwheel:x:10:\n";
        let diff = diff_groups(old, new).expect("diff");
        assert!(diff.summary.contains("mallory"));
        assert!(diff.privileged);
    }

    #[test]
    fn group_diff_new_unprivileged_group() {
        let old = "sudo:x:27:alice\n";
        let new = "sudo:x:27:alice\ndocker:x:999:\n";
        let diff = diff_groups(old, new).expect("diff");
        assert!(diff.summary.contains("docker"));
        assert!(!diff.privileged);
    }

    #[test]
    fn no_diff_when_unchanged() {
        let c = "root:x:0:0:root:/root:/bin/bash\n";
        assert!(diff_accounts(c, c).is_none());
        assert!(diff_groups("sudo:x:27:alice\n", "sudo:x:27:alice\n").is_none());
    }
}
