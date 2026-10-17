//! `hermian audit` and the start-up audit: gather what's on the host for
//! [`hermian_core::audit`] and ask the package manager who owns what.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use anyhow::Result;
use hermian_core::audit::{self, AuditInput, ProcView, Sign};
use hermian_core::events::Severity;

use crate::cli::AuditArgs;
use crate::ui::Style;

/// Bounds, so a hostile host can't make the audit slow or huge.
const MAX_PROCESSES: usize = 4_000;
const MAX_MAPPED_PER_PROCESS: usize = 512;
const MAX_AUTOSTART_FILES: usize = 500;
const MAX_FILE_BYTES: u64 = 256 * 1024;

/// Crontabs and shell profiles: files that start programs on their own.
const AUTOSTART_FILES: &[&str] = &[
    "/etc/crontab",
    "/etc/profile",
    "/etc/bash.bashrc",
    "/etc/bashrc",
    "/etc/zsh/zshrc",
    "/etc/environment",
    "/root/.profile",
    "/root/.bashrc",
    "/root/.bash_profile",
    "/root/.zshrc",
];
const AUTOSTART_DIRS: &[&str] = &[
    "/etc/cron.d",
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/var/spool/cron/crontabs",
    "/var/spool/cron",
    "/etc/profile.d",
];
const HOME_PROFILES: &[&str] = &[".profile", ".bashrc", ".bash_profile", ".zshrc"];

/// Run the audit on this host.
pub fn run_audit() -> Vec<Sign> {
    let input = gather();
    let owners = Owners::query(&audit::ownership_queries(&input));
    audit::audit(&input, &|p| owners.owned(p))
}

pub fn cmd_audit(args: &AuditArgs) -> Result<()> {
    crate::config::require_root()?;
    let signs = run_audit();
    if args.json {
        for s in &signs {
            println!(
                "{}",
                serde_json::json!({
                    "severity": s.severity.as_str(),
                    "kind": format!("{:?}", s.kind).to_lowercase(),
                    "path": s.path,
                    "what": s.what,
                })
            );
        }
    } else {
        let st = Style::detect();
        let right = if signs.is_empty() {
            "clean".to_string()
        } else {
            format!(
                "{} sign{}",
                signs.len(),
                if signs.len() == 1 { "" } else { "s" }
            )
        };
        println!("{}", st.masthead("audit", &right));
        if signs.is_empty() {
            println!(
                "  {}",
                st.ok("No signs of an intrusion from before Hermian started.")
            );
            println!(
                "  {}",
                st.dim("Checked: /etc/ld.so.preload, running programs and their libraries,")
            );
            println!("  {}", st.dim("crontabs and shell profiles."));
        } else {
            for s in &signs {
                println!(
                    "  {}  {}",
                    st.sev(s.severity, &format!("{:<8}", s.severity.as_str())),
                    s.what
                );
            }
            println!("{}", st.rule());
            if signs.iter().any(|s| s.severity >= Severity::High) {
                println!(
                    "  {}",
                    st.bad(
                        "This host looks compromised. Snapshot it for evidence, then rebuild it."
                    )
                );
            } else {
                println!(
                    "  {}",
                    st.warn("Nothing conclusive: worth a look, but common on a healthy host.")
                );
            }
            println!(
                "  {}",
                st.dim("A rootkit can hide from this audit: a clean result is not a guarantee.")
            );
        }
    }
    if signs.iter().any(|s| s.severity >= Severity::High) {
        std::process::exit(2);
    }
    Ok(())
}

fn gather() -> AuditInput {
    AuditInput {
        preload: fs::read_to_string("/etc/ld.so.preload").ok(),
        processes: processes(),
        autostart: autostart_files(),
    }
}

fn processes() -> Vec<ProcView> {
    let me = std::process::id();
    let Ok(dir) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in dir.flatten().take(MAX_PROCESSES * 2) {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        if pid == me {
            continue;
        }
        let base = entry.path();
        // Containers bring their own /usr; judging their files against the
        // host's package database would be noise.
        if fs::read_link(base.join("root"))
            .map(|r| r != Path::new("/"))
            .unwrap_or(true)
        {
            continue;
        }
        let Ok(exe) = fs::read_link(base.join("exe")) else {
            continue; // kernel thread, or gone
        };
        let comm = fs::read_to_string(base.join("comm"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        out.push(ProcView {
            pid,
            comm,
            exe: exe.to_string_lossy().into_owned(),
            mapped: mapped_code(&base.join("maps")),
        });
        if out.len() >= MAX_PROCESSES {
            break;
        }
    }
    out
}

/// File-backed executable mappings, deduplicated.
fn mapped_code(maps: &Path) -> Vec<String> {
    let Ok(text) = fs::read_to_string(maps) else {
        return Vec::new();
    };
    let mut seen: Vec<String> = Vec::new();
    for line in text.lines() {
        // address perms offset dev inode, then the path after padding.
        let mut f = line.split_whitespace();
        if !f.nth(1).is_some_and(|perms| perms.contains('x')) {
            continue;
        }
        let path = f.skip(3).collect::<Vec<_>>().join(" ");
        if path.starts_with('/') && !seen.contains(&path) {
            seen.push(path);
            if seen.len() >= MAX_MAPPED_PER_PROCESS {
                break;
            }
        }
    }
    seen
}

fn autostart_files() -> Vec<(String, String)> {
    let mut paths: Vec<String> = AUTOSTART_FILES.iter().map(|s| s.to_string()).collect();
    for d in AUTOSTART_DIRS {
        if let Ok(rd) = fs::read_dir(d) {
            for e in rd.flatten() {
                paths.push(e.path().to_string_lossy().into_owned());
            }
        }
    }
    if let Ok(passwd) = fs::read_to_string("/etc/passwd") {
        for line in passwd.lines() {
            if let Some(home) = line.split(':').nth(5) {
                if home.starts_with("/home/") {
                    for f in HOME_PROFILES {
                        paths.push(format!("{}/{}", home, f));
                    }
                }
            }
        }
    }
    let mut out = Vec::new();
    for p in paths {
        // Regular files only, never through a symlink, and not huge.
        let Ok(meta) = fs::symlink_metadata(&p) else {
            continue;
        };
        if !meta.is_file() || meta.len() > MAX_FILE_BYTES {
            continue;
        }
        if let Ok(content) = fs::read_to_string(&p) {
            out.push((p, content));
        }
        if out.len() >= MAX_AUTOSTART_FILES {
            break;
        }
    }
    out
}

/// Package ownership for a batch of paths, in one dpkg-query call.
struct Owners {
    /// None: no package manager could answer.
    owned: Option<HashSet<String>>,
}

impl Owners {
    fn query(paths: &[String]) -> Owners {
        if paths.is_empty() {
            return Owners {
                owned: Some(HashSet::new()),
            };
        }
        // Merged /usr: dpkg may record /lib/x/libc.so.6 while the kernel
        // reports /usr/lib/x/libc.so.6, or the other way round. Ask both.
        let mut ask: Vec<String> = Vec::new();
        for p in paths {
            // dpkg-query -S takes globs (see procsrc::file_in_package_database).
            if p.contains(['*', '?', '[', ']', '\\']) {
                continue;
            }
            ask.push(p.clone());
            if let Some(a) = usr_alias(p) {
                ask.push(a);
            }
        }
        let out = std::process::Command::new("dpkg-query")
            .arg("-S")
            .args(&ask)
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output();
        match out {
            // 0: all found; 1: some weren't. Both list what was.
            Ok(o) if matches!(o.status.code(), Some(0) | Some(1)) => Owners {
                owned: Some(parse_dpkg_search(&String::from_utf8_lossy(&o.stdout))),
            },
            _ => Owners { owned: None },
        }
    }

    fn owned(&self, path: &str) -> Option<bool> {
        self.owned_if(path, |p| fs::symlink_metadata(p).is_ok())
    }

    fn owned_if(&self, path: &str, exists: impl Fn(&str) -> bool) -> Option<bool> {
        let set = self.owned.as_ref()?;
        if path.contains(['*', '?', '[', ']', '\\']) {
            return None;
        }
        // Only files that are there. A library replaced by an upgrade while
        // a process still maps it (not always marked "(deleted)"), or a
        // program a cron line only tests for (`test -x /usr/sbin/anacron`),
        // isn't evidence of anything.
        if !exists(path) {
            return None;
        }
        Some(set.contains(path) || usr_alias(path).is_some_and(|a| set.contains(&a)))
    }
}

/// /usr/lib/x <-> /lib/x, /usr/bin/x <-> /bin/x, and so on.
fn usr_alias(p: &str) -> Option<String> {
    for d in ["bin", "sbin", "lib", "lib64"] {
        if let Some(rest) = p.strip_prefix(&format!("/usr/{}/", d)) {
            return Some(format!("/{}/{}", d, rest));
        }
        if let Some(rest) = p.strip_prefix(&format!("/{}/", d)) {
            return Some(format!("/usr/{}/{}", d, rest));
        }
    }
    None
}

/// `dpkg-query -S` lines: "pkg1, pkg2: /path" and
/// "diversion by pkg from: /path".
fn parse_dpkg_search(stdout: &str) -> HashSet<String> {
    stdout
        .lines()
        .filter_map(|l| l.split_once(": ").map(|(_, p)| p.trim().to_string()))
        .filter(|p| p.starts_with('/'))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpkg_search_output_is_parsed() {
        let set = parse_dpkg_search(
            "libc6:amd64: /usr/lib/x86_64-linux-gnu/libc.so.6\n\
             coreutils, busybox: /bin/ls\n\
             diversion by dash from: /bin/sh\n",
        );
        assert!(set.contains("/usr/lib/x86_64-linux-gnu/libc.so.6"));
        assert!(set.contains("/bin/ls"));
        assert!(set.contains("/bin/sh"));
    }

    #[test]
    fn merged_usr_paths_count_as_owned_either_way() {
        let owners = Owners {
            owned: Some(["/lib/x86_64-linux-gnu/libc.so.6".to_string()].into()),
        };
        let there = |_: &str| true;
        assert_eq!(
            owners.owned_if("/usr/lib/x86_64-linux-gnu/libc.so.6", there),
            Some(true)
        );
        assert_eq!(
            owners.owned_if("/usr/lib/libfsnldev.so", there),
            Some(false)
        );
        // Gone (upgraded, or only tested for in a cron line): no verdict.
        assert_eq!(owners.owned_if("/usr/lib/libfsnldev.so", |_| false), None);
        assert_eq!(Owners { owned: None }.owned_if("/usr/bin/x", there), None);
        assert_eq!(usr_alias("/usr/bin/perfcc").as_deref(), Some("/bin/perfcc"));
        assert_eq!(
            usr_alias("/lib/libgcwrap.so").as_deref(),
            Some("/usr/lib/libgcwrap.so")
        );
        assert_eq!(usr_alias("/etc/x"), None);
    }

    #[test]
    fn maps_keep_executable_file_mappings_once() {
        let dir = std::env::temp_dir().join(format!("hermian-maps-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let maps = dir.join("maps");
        fs::write(
            &maps,
            "55d0-55d1 r--p 00000000 08:01 1 /usr/bin/node\n\
             55d1-55d2 r-xp 00001000 08:01 1 /usr/bin/node\n\
             7f00-7f01 r-xp 00000000 08:01 2 /lib/libgcwrap.so\n\
             7f01-7f02 r-xp 00001000 08:01 2 /lib/libgcwrap.so\n\
             7f02-7f03 rw-p 00000000 00:00 0 \n\
             7f03-7f04 r-xp 00000000 00:00 0 [vdso]\n\
             7f04-7f05 r-xp 00000000 08:01 3                          /tmp/x (deleted)\n",
        )
        .unwrap();
        assert_eq!(
            mapped_code(&maps),
            vec!["/usr/bin/node", "/lib/libgcwrap.so", "/tmp/x (deleted)"]
        );
        fs::remove_dir_all(&dir).ok();
    }
}
