//! D2 - SSH and authentication abuse.

use std::collections::HashMap;

use crate::alert::Finding;
use crate::detect::{writer_label, BurstTracker, Ctx};
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

    match ev.result {
        AuthResult::Attempt | AuthResult::Failure => {
            let count = bursts.record(rhost, ev.ts, ctx.cfg.ssh.failed_burst_window_secs as i64);
            if count == ctx.cfg.ssh.failed_burst_count as usize {
                // Fire exactly once when the threshold is crossed; dedup handles the rest.
                findings.push(
                    Finding::new(
                        DetectionId::D2,
                        Severity::High,
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
                        "A burst of authentication attempts from one source is the signature of \
                         brute-force or credential-stuffing against SSH.",
                    )
                    .actions([
                        format!(
                            "Confirm nobody is legitimately failing to log in from {}.",
                            rhost
                        ),
                        "Block the source (fail2ban, nftables) or restrict SSH to known networks."
                            .to_string(),
                        "Check whether any attempt from this source eventually succeeded."
                            .to_string(),
                    ]),
                );
            }
        }
        AuthResult::Success => {
            if ev.user == "root" && !ctx.cfg.ssh.permit_root {
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
            if ctx.baseline.can_judge_novelty() && !ctx.baseline.ssh_source_is_known(rhost) {
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
            if change.privileged {
                "Privileged group membership changed"
            } else {
                "System account database changed"
            },
            &format!("d2|account-change|{}", ev.path),
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
}

fn diff_accounts(old: &str, new: &str) -> Option<AccountChange> {
    let parse = |s: &str| -> Vec<(String, String)> {
        s.lines()
            .filter(|l| !l.trim_start().starts_with('#') && l.contains(':'))
            .filter_map(|l| {
                let mut it = l.split(':');
                let name = it.next()?.to_string();
                it.next()?;
                let uid = it.next()?.to_string();
                Some((name, uid))
            })
            .collect()
    };
    let old_map: HashMap<String, String> = parse(old).into_iter().collect();
    let added: Vec<String> = parse(new)
        .into_iter()
        .filter(|(n, uid)| old_map.get(n.as_str()) != Some(uid))
        .map(|(n, uid)| format!("{} (uid {})", n, uid))
        .collect();
    if added.is_empty() {
        return None;
    }
    let privileged = added.iter().any(|a| a.contains("(uid 0)"));
    Some(AccountChange {
        summary: format!("new or changed accounts: {}", added.join(", ")),
        privileged,
    })
}

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
    for target in ["sudo", "wheel", "admin", "root"] {
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
