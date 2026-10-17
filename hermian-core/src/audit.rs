//! Start-up audit: signs that a host was compromised before Hermian started.
//!
//! The rules judge what happens after Hermian starts. Persistence already in
//! place, an implant already running, or a rootkit already preloaded stays
//! unseen until it acts, and the baseline would learn its routine as normal.
//! On a perfctl-infected host (2026-10-17) all of this held: a preload rootkit
//! in /etc/ld.so.preload, unpackaged programs in /usr/bin and /usr/lib, an
//! implant running from /tmp/.perf.c and hidden directories under /var.
//!
//! The daemon gathers what's on the host ([`AuditInput`]) and says which
//! paths a package owns; this module only judges, so it can be tested.

use crate::alert::Finding;
use crate::detect::content_tag;
use crate::events::{is_suspicious_exec_dir, DetectionId, Severity};

/// A running process, as the audit sees it (host processes only).
#[derive(Debug, Clone, Default)]
pub struct ProcView {
    pub pid: u32,
    pub comm: String,
    /// `/proc/<pid>/exe`, possibly ending in " (deleted)".
    pub exe: String,
    /// File-backed executable mappings from `/proc/<pid>/maps`.
    pub mapped: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct AuditInput {
    /// Content of /etc/ld.so.preload, if it exists.
    pub preload: Option<String>,
    pub processes: Vec<ProcView>,
    /// Files that start programs on their own: crontabs, cron dirs, shell
    /// profiles. (path, content).
    pub autostart: Vec<(String, String)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SignKind {
    Preload,
    Code,
    Autostart,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sign {
    pub kind: SignKind,
    pub severity: Severity,
    pub path: String,
    /// One line, for the alert and `hermian audit`.
    pub what: String,
}

/// System directories where every program and library comes from a package.
/// /usr/local and /opt are left out: that's where hand-installed software
/// belongs.
const PACKAGED_DIRS: &[&str] = &[
    "/usr/bin",
    "/usr/sbin",
    "/bin",
    "/sbin",
    "/usr/lib",
    "/usr/lib64",
    "/lib",
    "/lib64",
    "/usr/libexec",
];

/// Top-level directories where a hidden directory has no business holding
/// code (/var/.i.ipr/, /usr/bin/.local/bin/, /dev/.cache/).
const SYSTEM_ROOTS: &[&str] = &[
    "bin", "boot", "dev", "etc", "lib", "lib64", "opt", "sbin", "srv", "usr", "var",
];

/// Most signs listed in one alert.
const MAX_LISTED: usize = 8;

fn strip_deleted(p: &str) -> &str {
    p.trim_end_matches(" (deleted)").trim()
}

/// Code under a hidden directory in a system tree.
pub fn in_hidden_system_dir(path: &str) -> bool {
    let p = strip_deleted(path);
    let mut parts = p.trim_start_matches('/').split('/');
    let Some(root) = parts.next() else {
        return false;
    };
    if !p.starts_with('/') || !SYSTEM_ROOTS.contains(&root) {
        return false;
    }
    let rest: Vec<&str> = parts.collect();
    // The last part is the file itself: only directories count.
    rest.len() > 1
        && rest[..rest.len() - 1]
            .iter()
            .any(|c| c.starts_with('.') && *c != "." && *c != "..")
}

pub fn in_packaged_dir(path: &str) -> bool {
    let p = strip_deleted(path);
    PACKAGED_DIRS
        .iter()
        .any(|d| p.starts_with(&format!("{}/", d)))
}

fn suspect_location(path: &str) -> bool {
    is_suspicious_exec_dir(path) || in_hidden_system_dir(path)
}

/// Paths the audit wants package ownership for (deduplicated): everything in
/// a packaged directory that's still on disk.
pub fn ownership_queries(input: &AuditInput) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut add = |p: &str| {
        if in_packaged_dir(p) && !p.ends_with(" (deleted)") && !out.iter().any(|o| o == p) {
            out.push(p.to_string());
        }
    };
    for e in preload_entries(input.preload.as_deref().unwrap_or("")) {
        add(&e);
    }
    for p in &input.processes {
        add(&p.exe);
        for m in &p.mapped {
            add(m);
        }
    }
    for (_, content) in &input.autostart {
        for w in command_paths(content) {
            add(&w);
        }
    }
    out
}

fn preload_entries(content: &str) -> Vec<String> {
    content
        .lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .flat_map(|l| l.split([' ', ':', '\t']))
        .filter(|w| !w.is_empty())
        .map(str::to_string)
        .collect()
}

/// Absolute paths in the non-comment lines of a crontab or profile.
fn command_paths(content: &str) -> Vec<String> {
    content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .flat_map(|l| {
            // ':' too: PATH=/usr/libexec/sysstat:/usr/sbin:/usr/bin is a list.
            l.split(|c: char| {
                c.is_whitespace()
                    || matches!(
                        c,
                        ';' | '&' | '|' | '(' | ')' | '"' | '\'' | '=' | ':' | '`'
                    )
            })
            .filter(|w| w.starts_with('/'))
            .map(str::to_string)
            .collect::<Vec<_>>()
        })
        .collect()
}

/// Judge the host. `owned(path)` says whether a package owns `path`:
/// `Some(false)` is "no package does", `None` is "couldn't tell".
pub fn audit(input: &AuditInput, owned: &dyn Fn(&str) -> Option<bool>) -> Vec<Sign> {
    let mut signs: Vec<Sign> = Vec::new();
    let mut push = |s: Sign| {
        if !signs.iter().any(|o| o.kind == s.kind && o.path == s.path) {
            signs.push(s);
        }
    };

    // Every new dynamically linked process loads these first.
    for lib in preload_entries(input.preload.as_deref().unwrap_or("")) {
        let unowned = owned(&lib) == Some(false);
        let severity = if unowned || suspect_location(&lib) {
            Severity::Critical
        } else {
            Severity::High
        };
        push(Sign {
            kind: SignKind::Preload,
            severity,
            what: format!(
                "/etc/ld.so.preload loads {} into every new process{}",
                lib,
                if unowned { "; no package owns it" } else { "" }
            ),
            path: lib,
        });
    }

    // Code running, or mapped, from where it shouldn't be.
    for p in &input.processes {
        let mut code: Vec<(&str, bool)> = vec![(p.exe.as_str(), true)];
        code.extend(p.mapped.iter().map(|m| (m.as_str(), false)));
        for (path, is_exe) in code {
            if path.is_empty() {
                continue;
            }
            let noun = if is_exe { "runs from" } else { "has loaded" };
            if suspect_location(path) {
                // Libraries unpacked into /tmp are routine for some runtimes
                // (Nx's native add-on, Netty, JNA, sqlite-jdbc): listed, not
                // paged. A program running from there, or anything in a
                // hidden system directory, is not.
                let routine = !is_exe && !in_hidden_system_dir(path);
                push(Sign {
                    kind: SignKind::Code,
                    severity: if routine {
                        Severity::Low
                    } else {
                        Severity::High
                    },
                    what: format!("{} (pid {}) {} {}", p.comm, p.pid, noun, path),
                    path: strip_deleted(path).to_string(),
                });
            } else if in_packaged_dir(path)
                && !path.ends_with(" (deleted)")
                && owned(path) == Some(false)
            {
                push(Sign {
                    kind: SignKind::Code,
                    severity: Severity::High,
                    what: format!(
                        "{} (pid {}) {} {}, which no package owns",
                        p.comm, p.pid, noun, path
                    ),
                    path: path.to_string(),
                });
            }
        }
    }

    // Persistence that starts such code.
    for (file, content) in &input.autostart {
        for path in command_paths(content) {
            let unowned = in_packaged_dir(&path) && owned(&path) == Some(false);
            if suspect_location(&path) || unowned {
                push(Sign {
                    kind: SignKind::Autostart,
                    severity: Severity::High,
                    what: format!(
                        "{} starts {}{}",
                        file,
                        path,
                        if unowned {
                            ", which no package owns"
                        } else {
                            ""
                        }
                    ),
                    path: format!("{} {}", file, path),
                });
            }
        }
    }

    signs.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.kind.cmp(&b.kind)));
    signs
}

/// One alert for the whole audit, or none when the host looks clean. Signs
/// of more than one kind (a preload and running code, say) make it CRITICAL.
pub fn finding(signs: &[Sign], baseline_note: Option<&str>) -> Option<Finding> {
    let top = signs.iter().map(|s| s.severity).max()?;
    let mut kinds: Vec<SignKind> = signs.iter().map(|s| s.kind).collect();
    kinds.sort();
    kinds.dedup();
    let severity = if kinds.len() > 1 && top >= Severity::High {
        Severity::Critical
    } else {
        top
    };
    let paths: Vec<&str> = signs.iter().map(|s| s.path.as_str()).collect();
    let mut f = Finding::new(
        DetectionId::D3,
        severity,
        "Signs of an intrusion from before Hermian started",
        &format!("d3|startup-audit|{}", content_tag(&paths.join("\n"))),
    )
    .what(format!(
        "The start-up audit found {} sign{} that this host was already compromised when \
         Hermian started.",
        signs.len(),
        if signs.len() == 1 { "" } else { "s" }
    ));
    for s in signs.iter().take(MAX_LISTED) {
        f = f.fact("Found", &s.what);
    }
    if signs.len() > MAX_LISTED {
        f = f.fact(
            "And",
            format!("{} more: run 'hermian audit'", signs.len() - MAX_LISTED),
        );
    }
    if let Some(note) = baseline_note {
        f = f.fact("Baseline", note);
    }
    Some(
        f.why(
            "Hermian's rules watch what happens from now on. Code already running from a \
             temporary or hidden directory, programs and libraries in system directories \
             that no package installed, and a preloaded library are what an implant or a \
             rootkit leaves behind.",
        )
        .actions([
            "Run 'hermian audit' for the full list.",
            "Treat the host as compromised: snapshot it for evidence, then rebuild it rather \
             than clean it in place.",
            "Rotate the secrets that were on it.",
        ]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc(pid: u32, comm: &str, exe: &str, mapped: &[&str]) -> ProcView {
        ProcView {
            pid,
            comm: comm.into(),
            exe: exe.into(),
            mapped: mapped.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Ownership as dpkg would answer on the infected host.
    fn owned(p: &str) -> Option<bool> {
        Some(!matches!(
            p,
            "/lib/libgcwrap.so"
                | "/usr/bin/perfcc"
                | "/bin/perfcc"
                | "/usr/lib/libfsnldev.so"
                | "/usr/bin/btrfsunmkinitramfs"
        ))
    }

    /// What perfctl left on buki, 2026-10-17.
    fn buki() -> AuditInput {
        AuditInput {
            preload: Some("/lib/libgcwrap.so\n".into()),
            processes: vec![
                proc(
                    1,
                    "systemd",
                    "/usr/lib/systemd/systemd",
                    &["/lib/libgcwrap.so", "/usr/lib/x86_64-linux-gnu/libc.so.6"],
                ),
                proc(2056227, "httpd", "/tmp/.perf.c/httpd (deleted)", &[]),
                proc(1996266, "blrdaemon", "/var/.i.ipr/blrdaemon", &[]),
                proc(4100, "btrfsunmkinitr", "/usr/bin/btrfsunmkinitramfs", &[]),
                proc(895, "agetty", "/usr/sbin/agetty (deleted)", &[]),
            ],
            autostart: vec![
                (
                    "/root/.profile".into(),
                    "# ~/.profile\ntest -x /bin/perfcc && FPROF=p /bin/perfcc\n".into(),
                ),
                (
                    "/var/spool/cron/crontabs/root".into(),
                    "# DO NOT EDIT\n11 * * * * /root/.config/cron/perfcc\n".into(),
                ),
            ],
        }
    }

    #[test]
    fn the_infected_host_fails_with_every_kind_of_sign() {
        let signs = audit(&buki(), &owned);
        let has = |kind, needle: &str| {
            signs
                .iter()
                .any(|s| s.kind == kind && s.what.contains(needle))
        };
        assert!(has(SignKind::Preload, "/lib/libgcwrap.so"), "{:#?}", signs);
        assert!(has(
            SignKind::Code,
            "systemd (pid 1) has loaded /lib/libgcwrap.so"
        ));
        assert!(has(
            SignKind::Code,
            "runs from /tmp/.perf.c/httpd (deleted)"
        ));
        assert!(has(SignKind::Code, "/var/.i.ipr/blrdaemon"));
        assert!(has(
            SignKind::Code,
            "/usr/bin/btrfsunmkinitramfs, which no package owns"
        ));
        assert!(has(
            SignKind::Autostart,
            "/root/.profile starts /bin/perfcc"
        ));
        // A packaged binary replaced by an upgrade is routine.
        assert!(!signs.iter().any(|s| s.what.contains("agetty")));
        assert_eq!(signs[0].severity, Severity::Critical);
        let f = finding(&signs, Some("learning stopped")).unwrap();
        assert_eq!(f.severity, Severity::Critical);
        assert!(f.facts.iter().any(|x| x.label == "Baseline"));
    }

    #[test]
    fn a_clean_host_raises_nothing() {
        let input = AuditInput {
            preload: None,
            processes: vec![
                proc(
                    1,
                    "systemd",
                    "/usr/lib/systemd/systemd",
                    &["/usr/lib/x86_64-linux-gnu/libc.so.6"],
                ),
                proc(800, "nginx", "/usr/sbin/nginx", &[]),
                proc(900, "node", "/usr/local/bin/node", &[]),
                proc(
                    950,
                    "code",
                    "/root/.vscode-server/bin/abc/node",
                    &["/root/.cache/x.so"],
                ),
            ],
            autostart: vec![(
                "/etc/cron.d/certbot".into(),
                "0 */12 * * * root test -x /usr/bin/certbot && certbot -q renew\n".into(),
            )],
        };
        let signs = audit(&input, &|_| Some(true));
        assert!(signs.is_empty(), "{:#?}", signs);
        assert!(finding(&signs, None).is_none());
    }

    /// Found on buki: Nx's native add-on is unpacked into /tmp and loaded by
    /// node. Listed as LOW; it alone raises no alert.
    #[test]
    fn a_library_unpacked_into_tmp_is_low() {
        let input = AuditInput {
            processes: vec![proc(
                18243,
                "node",
                "/usr/bin/node",
                &["/tmp/nx-native-file-cache-5006672/20.2.2-nx.linux-x64-gnu.node"],
            )],
            ..Default::default()
        };
        let signs = audit(&input, &|_| Some(true));
        assert_eq!(signs.len(), 1);
        assert_eq!(signs[0].severity, Severity::Low);
        assert_eq!(finding(&signs, None).unwrap().severity, Severity::Low);
    }

    /// Found on a clean Debian: PATH lists in cron.d/sysstat.
    #[test]
    fn path_lists_are_split() {
        let input = AuditInput {
            autostart: vec![(
                "/etc/cron.d/sysstat".into(),
                "PATH=/usr/libexec/sysstat:/usr/sbin:/usr/bin:/sbin:/bin\n".into(),
            )],
            ..Default::default()
        };
        let q = ownership_queries(&input);
        assert!(q.contains(&"/usr/libexec/sysstat".to_string()), "{:?}", q);
        assert!(!q.iter().any(|p| p.contains(':')), "{:?}", q);
    }

    #[test]
    fn unknown_ownership_is_not_a_sign() {
        let input = AuditInput {
            processes: vec![proc(4100, "kubectl", "/usr/bin/kubectl", &[])],
            ..Default::default()
        };
        assert!(audit(&input, &|_| None).is_empty());
    }

    #[test]
    fn a_single_kind_keeps_its_own_severity() {
        let input = AuditInput {
            processes: vec![proc(7, "x", "/dev/shm/x", &[])],
            ..Default::default()
        };
        let signs = audit(&input, &|_| Some(true));
        assert_eq!(finding(&signs, None).unwrap().severity, Severity::High);
    }

    #[test]
    fn hidden_dirs_count_only_in_system_trees() {
        assert!(in_hidden_system_dir("/var/.i.ipr/blrdaemon"));
        assert!(in_hidden_system_dir("/usr/bin/.local/bin/wizlmsh"));
        assert!(in_hidden_system_dir("/dev/.cache/x (deleted)"));
        assert!(!in_hidden_system_dir("/root/.cache/x.so"));
        assert!(!in_hidden_system_dir("/home/dev/.local/bin/tool"));
        assert!(!in_hidden_system_dir("/usr/bin/.hidden-file"));
        assert!(!in_hidden_system_dir("/var/lib/app/bin"));
    }

    #[test]
    fn ownership_is_asked_once_per_path_in_packaged_dirs() {
        let q = ownership_queries(&buki());
        assert!(q.contains(&"/lib/libgcwrap.so".to_string()));
        assert!(q.contains(&"/bin/perfcc".to_string()));
        assert_eq!(q.iter().filter(|p| *p == "/lib/libgcwrap.so").count(), 1);
        assert!(!q
            .iter()
            .any(|p| p.starts_with("/tmp") || p.contains("(deleted)")));
    }
}
