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
            let mut root_login: Option<Finding> = None;
            let mut new_source: Option<Finding> = None;
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
                        "User '{}' authenticated{} from {} after {} failed attempts within {} \
                         seconds{}.",
                        ev.user,
                        how(ev),
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
                    .facts_from(key_facts(ev))
                    .why(
                        "A login right after failed attempts from the same source usually means \
                         one of those attempts worked. The failures alone were just noise.",
                    )
                    .actions([
                        "Confirm this session was expected before treating it as hostile.",
                        "Lock or rotate the account that succeeded and any others the source tried.",
                        "Block the source and review what the session did.",
                    ]),
                );
            }
            // A key that has logged in before, from a new address on a network
            // the account already uses: a dynamic IP, not a new incident.
            // Passwords and unknown keys don't get this; they're what an
            // attacker who isn't the operator would be using.
            let key_known = ev
                .key
                .as_ref()
                .is_some_and(|k| ctx.baseline.key_is_known(&ev.user, &k.fingerprint));
            // An allowlisted key (CI runners, automation) is never "new",
            // wherever it logs in from.
            let key_allowed = ev
                .key
                .as_ref()
                .is_some_and(|k| ctx.allowlist.key_allowed(&ev.user, &k.fingerprint));
            let fingerprint = ev
                .key
                .as_ref()
                .map(|k| k.fingerprint.as_str())
                .unwrap_or("");
            // A known key from a new network is usually its owner on another
            // connection (travel, mobile, VPN, a CI runner); with "log" it's
            // recorded, not sent.
            let quiet_known_key = ctx.cfg.ssh.known_key_new_network == "log";
            if ev.user == "root" && !ctx.cfg.ssh.permit_root && !after_burst {
                // A root login is a policy concern, not per se an anomaly. It is
                // HIGH the first time a source is seen; the same operator logging
                // in again from the same place is context, not a new incident.
                let seen_before = ctx.baseline.root_source_is_known(rhost) || key_allowed;
                let nearby = !seen_before && key_known && ctx.baseline.root_net_is_known(rhost);
                let new_network = !seen_before && !nearby && key_known;
                let severity = if seen_before || nearby {
                    Severity::Info
                } else if new_network && quiet_known_key {
                    Severity::Low
                } else {
                    Severity::High
                };
                root_login = Some(
                    Finding::new(
                        DetectionId::D2,
                        severity,
                        if seen_before {
                            "Root login over SSH"
                        } else if nearby {
                            "Root login with a known key from a nearby address"
                        } else if new_network {
                            "Root login with a known key from a new network"
                        } else {
                            "Root login over SSH from a new source"
                        },
                        // One key logging in from several new networks (a CI
                        // runner) is one incident, not one per address.
                        &if new_network {
                            format!("d2|root-login-key|{}", fingerprint)
                        } else {
                            format!("d2|root-login|{}", rhost)
                        },
                    )
                    .what(format!(
                        "root authenticated over SSH{} from {}{}.",
                        how(ev),
                        rhost,
                        if key_allowed {
                            ", with an allowlisted key"
                        } else if seen_before {
                            ", a source that has logged in as root before"
                        } else if nearby {
                            ", a new address on a network root already logs in from"
                        } else if new_network {
                            ", a network root hasn't logged in from, with a key it has used before"
                        } else {
                            " for the first time"
                        }
                    ))
                    .fact("Source", rhost.to_string())
                    .facts_from(key_facts(ev))
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
                && !key_allowed
                && ctx.baseline.can_judge_novelty()
                && !ctx.baseline.ssh_source_is_known(rhost)
                && !(key_known && ctx.baseline.ssh_net_is_known(rhost))
            {
                let elevated = ev.user == "root";
                let severity = if elevated && !(key_known && quiet_known_key) {
                    Severity::High
                } else {
                    Severity::Low
                };
                new_source = Some(
                    Finding::new(
                        DetectionId::D2,
                        severity,
                        match (elevated, key_known) {
                            (true, true) => "Root login with a known key from a new network",
                            (false, true) => "SSH login with a known key from a new network",
                            (true, false) => "Root login from a new source",
                            (false, false) => "SSH login from a new source",
                        },
                        &if key_known {
                            format!("d2|new-source-key|{}|{}", ev.user, fingerprint)
                        } else {
                            format!("d2|new-source|{}|{}", rhost, ev.user)
                        },
                    )
                    .what(if key_known {
                        format!(
                            "User '{}' authenticated{} from {}, a network this account hasn't \
                             used, with a key it has used before.",
                            ev.user,
                            how(ev),
                            rhost
                        )
                    } else {
                        format!(
                            "User '{}' authenticated{} from {}, a source never seen before.",
                            ev.user,
                            how(ev),
                            rhost
                        )
                    })
                    .fact("Source", rhost.to_string())
                    .fact("User", &ev.user)
                    .facts_from(key_facts(ev))
                    .why(
                        "Hermian records every source it sees log in. A first-time source isn't \
                         proof of anything by itself; it's just where a surprise login would show \
                         up. Confirm it was expected.",
                    )
                    .actions([
                        "Confirm this login was expected.",
                        "Review what the session did (shell history, journal).",
                        "Add the source to allowlist.ssh_sources if it is legitimate.",
                    ]),
                );
            }
            // One login, one alert. A root login from a never-seen source
            // matches both rules above; keeping both sent two notifications
            // for one event. The sharper finding wins (ties go to the root
            // policy alert, which carries the novelty in its title anyway).
            // A key from a hidden key file pages whatever the source: the
            // file is the backdoor, and a familiar IP doesn't make it less so.
            let hidden = ev.key.as_ref().and_then(|k| {
                let file = k.file.as_deref()?;
                hidden_key_path(file).map(|why| (k, file, why))
            });
            if let Some((k, file, why)) = hidden {
                findings.push(
                    Finding::new(
                        DetectionId::D2,
                        Severity::High,
                        "SSH login with a key from a hidden key file",
                        &format!("{}{}|{}", HIDDEN_KEY_LOGIN_SIG, ev.user, k.fingerprint),
                    )
                    .what(format!(
                        "User '{}' authenticated{} from {}. The key is in {}, on {}, not in \
                         the account's ~/.ssh.",
                        ev.user,
                        how(ev),
                        rhost,
                        file,
                        why
                    ))
                    .fact("Source", rhost.to_string())
                    .fact("User", &ev.user)
                    .facts_from(key_facts(ev))
                    .why(
                        "sshd was configured to accept keys from an extra file that sits \
                         outside every home directory. That's a common way to keep access \
                         that nobody sees in authorized_keys.",
                    )
                    .actions([
                        "Confirm this login and this key were expected.".to_string(),
                        format!("Review the keys in {}: ssh-keygen -lf {}", file, file),
                        "If not yours, remove the AuthorizedKeysFile entry and the file, \
                         restart sshd and rotate keys."
                            .to_string(),
                    ]),
                );
            } else {
                match (root_login, new_source) {
                    (Some(r), Some(n)) => {
                        findings.push(if n.severity > r.severity { n } else { r })
                    }
                    (Some(r), None) => findings.push(r),
                    (None, Some(n)) => findings.push(n),
                    (None, None) => {}
                }
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

/// How the login authenticated, for alert text: " with key 'alice@laptop'",
/// " with key ED25519 SHA256:abc…xyz", " (password)", or nothing.
fn how(ev: &AuthEvent) -> String {
    match &ev.key {
        Some(k) => match &k.comment {
            Some(c) => format!(" with key '{}'", c),
            None => format!(" with key {}", k.short()),
        },
        None => ev.method.note().to_string(),
    }
}

/// Method, key and where the key sits in authorized_keys.
fn key_facts(ev: &AuthEvent) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    match &ev.key {
        Some(k) => {
            out.push(("Method", "public key".to_string()));
            out.push(("Key", format!("{} {}", k.kind, k.fingerprint)));
            if let Some(loc) = k.location() {
                out.push(("Key file", loc));
            }
        }
        None => {
            let m = ev.method.note().trim().trim_matches(['(', ')']).to_string();
            if !m.is_empty() {
                out.push(("Method", m));
            }
        }
    }
    out
}

/// sshd settings that decide which keys open the door. Each value is one or
/// more paths (`AuthorizedKeysFile`) or a command and its arguments.
/// Signature prefix of the hidden-key login alert. The engine checks it so a
/// backdoor key is never learned as a known key.
pub const HIDDEN_KEY_LOGIN_SIG: &str = "d2|hidden-key-login|";

const KEY_SOURCE_SETTINGS: &[(&str, &str)] = &[
    ("authorizedkeysfile", "AuthorizedKeysFile"),
    ("authorizedkeyscommand", "AuthorizedKeysCommand"),
    ("authorizedprincipalsfile", "AuthorizedPrincipalsFile"),
    ("authorizedprincipalscommand", "AuthorizedPrincipalsCommand"),
    ("trustedusercakeys", "TrustedUserCAKeys"),
];

/// Why a path sshd reads keys (or runs a key command) from looks hidden, or
/// `None` if it's an ordinary place. Relative paths and `%h/...` are inside
/// the user's home, where only `.ssh` is expected. Volatile or pseudo
/// filesystems and dot-directories are where a backdoor key file hides:
/// nobody reviews them, and `ls ~/.ssh` shows nothing.
pub fn hidden_key_path(path: &str) -> Option<&'static str> {
    if path.is_empty() || path == "none" {
        return None;
    }
    let (rel, home) = if let Some(r) = path.strip_prefix("%h/") {
        (r, true)
    } else if !path.starts_with('/') {
        (path, true)
    } else {
        (path, false)
    };
    if !home {
        const VOLATILE: &[&str] = &["/dev/", "/tmp/", "/var/tmp/", "/run/", "/proc/", "/sys/"];
        if VOLATILE.iter().any(|v| rel.starts_with(v)) {
            return Some("a temporary or pseudo filesystem");
        }
    }
    let hidden = rel
        .split('/')
        .filter(|c| !c.is_empty())
        .any(|c| c.starts_with('.') && c != ".ssh" && c != "." && c != "..");
    if hidden {
        return Some("a hidden directory or file");
    }
    None
}

/// Key sources in sshd's effective configuration (`sshd -T` output) that
/// point somewhere hidden, as (setting, value, reason).
pub fn hidden_key_sources(sshd_t: &str) -> Vec<(&'static str, String, &'static str)> {
    let mut out = Vec::new();
    for line in sshd_t.lines() {
        let Some((key, value)) = line.trim().split_once(' ') else {
            continue;
        };
        let Some((_, name)) = KEY_SOURCE_SETTINGS
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
        else {
            continue;
        };
        let is_command = name.ends_with("Command");
        // A command is judged by its program; files by every path listed.
        let words: Vec<&str> = value.split_whitespace().collect();
        let paths = if is_command {
            words.into_iter().take(1).collect::<Vec<_>>()
        } else {
            words
        };
        for p in paths {
            if let Some(why) = hidden_key_path(p) {
                out.push((*name, p.to_string(), why));
            }
        }
    }
    out
}

/// One finding per hidden key source (the engine reports each only once).
pub fn hidden_key_source_finding(setting: &str, path: &str, why: &str) -> Finding {
    let grants = if setting.contains("Principals") || setting == "TrustedUserCAKeys" {
        "decides which certificates and principals may log in"
    } else {
        "lists keys that may log in"
    };
    Finding::new(
        DetectionId::D2,
        Severity::High,
        "sshd reads login keys from a hidden location",
        &format!("d2|hidden-key-source|{}|{}", setting, path),
    )
    .what(format!(
        "sshd's effective configuration includes {} in {}, on {}. That {} for SSH, \
         outside every ~/.ssh where keys are normally reviewed.",
        path, setting, why, grants
    ))
    .fact("Setting", setting)
    .fact("Path", path)
    .why(
        "Pointing sshd at an extra key file is a quiet backdoor: the key works for every \
         account it covers, survives password changes, and doesn't show up in \
         ~/.ssh/authorized_keys. Files under /dev, /run or /tmp, or in dot-directories, are \
         where nobody looks.",
    )
    .actions([
        "Find what sets it: grep -ri authorizedkeys /etc/ssh/sshd_config /etc/ssh/sshd_config.d/"
            .to_string(),
        format!("List the keys it grants: ssh-keygen -lf {}", path),
        "If you didn't add it, remove the setting and the file, restart sshd and rotate keys."
            .to_string(),
    ])
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

    /// The test VPS: a drop-in added /dev/.cache/rdpii as an extra key file
    /// and nothing noticed. Ordinary key locations stay quiet.
    #[test]
    fn hidden_key_paths() {
        for p in [
            "/dev/.cache/rdpii",
            "/dev/shm/k",
            "/tmp/keys",
            "/run/user/0/k",
            "/var/tmp/x",
            "/etc/.ssh_keys/%u",
            "/usr/lib/.cache/k",
            ".config/.k",
            "%h/.local/share/keys",
        ] {
            assert!(hidden_key_path(p).is_some(), "{}", p);
        }
        for p in [
            ".ssh/authorized_keys",
            ".ssh/authorized_keys2",
            "%h/.ssh/authorized_keys",
            "/etc/ssh/authorized_keys/%u",
            "/etc/ssh/keys/%u",
            "/var/lib/sshkeys/%u",
            "none",
            "",
        ] {
            assert!(hidden_key_path(p).is_none(), "{}", p);
        }
    }

    #[test]
    fn hidden_key_sources_in_sshd_t() {
        let t = "port 22\n\
                 authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2 /dev/.cache/rdpii\n\
                 authorizedkeyscommand /tmp/.k/fetch %u\n\
                 authorizedprincipalsfile none\n\
                 trustedusercakeys /etc/ssh/ca.pub\n";
        let found = hidden_key_sources(t);
        assert_eq!(
            found
                .iter()
                .map(|(s, p, _)| format!("{} {}", s, p))
                .collect::<Vec<_>>(),
            vec![
                "AuthorizedKeysFile /dev/.cache/rdpii",
                "AuthorizedKeysCommand /tmp/.k/fetch"
            ]
        );
        // A command's arguments aren't paths.
        assert!(hidden_key_sources("authorizedkeyscommand /usr/bin/fetch /tmp/x\n").is_empty());
        let f = hidden_key_source_finding("AuthorizedKeysFile", "/dev/.cache/rdpii", "x");
        assert_eq!(f.severity, Severity::High);
        assert!(f
            .actions
            .iter()
            .any(|a| a.contains("ssh-keygen -lf /dev/.cache/rdpii")));
    }

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
