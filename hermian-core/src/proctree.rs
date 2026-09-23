use chrono::{DateTime, Utc};
use std::collections::HashMap;

use crate::events::{ExecEvent, PrevImage, ProcInfo};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    WebServer,
    Database,
    Sshd,
    Shell,
    Downloader,
    Interpreter,
    PackageManager,
    ConfigManager,
    Debugger,
    Cron,
    UserMgmt,
    System,
    Unknown,
}

const WEB_SERVERS: &[&str] = &[
    "nginx",
    "apache2",
    "httpd",
    "caddy",
    "lighttpd",
    "litespeed",
    "openlitespeed",
    "gunicorn",
    "uwsgi",
    "unicorn",
    "puma",
    "tomcat",
    "traefik",
    "haproxy",
    "varnishd",
    "envoy",
    "php-fpm",
];

const DATABASES: &[&str] = &[
    "mysqld",
    "mariadbd",
    "postgres",
    "postmaster",
    "mongod",
    "redis-server",
    "valkey-server",
    "elasticsearch",
    "clickhouse-server",
    "etcd",
    "influxd",
    "cockroach",
    "cassandra",
    "consul",
    "vault",
    "memcached",
];

const SHELLS: &[&str] = &[
    "bash", "sh", "dash", "zsh", "fish", "ksh", "ash", "busybox", "csh", "tcsh",
];

const DOWNLOADERS: &[&str] = &["curl", "wget", "wget2", "fetch", "aria2c", "axel"];

const INTERPRETERS: &[&str] = &[
    "python", "python2", "python3", "perl", "ruby", "php", "lua", "luajit", "node", "nodejs",
    "deno", "bun", "java", "openssl", "socat", "nc", "ncat", "netcat",
];

const PACKAGE_MANAGERS: &[&str] = &[
    "apt",
    "apt-get",
    "aptitude",
    "dpkg",
    "dpkg-deb",
    "unattended-upgrade",
    "yum",
    "dnf",
    "rpm",
    "pacman",
    "zypper",
    "emerge",
    "apk",
    "snap",
    "snapd",
    "flatpak",
    "nix",
    "nix-daemon",
];

const CONFIG_MANAGERS: &[&str] = &[
    "ansible",
    "ansible-playbook",
    "chef-client",
    "chef-solo",
    "puppet",
    "salt-minion",
    "salt-call",
    "terraform",
    "packer",
    "bolt",
    "cloud-init",
];

const DEBUGGERS: &[&str] = &[
    "gdb",
    "strace",
    "lldb",
    "ltrace",
    "gdbserver",
    "valgrind",
    "rr",
    "bpftrace",
    "perf",
    "trace-cmd",
    "delve",
    "dlv",
];

const USER_MGMT: &[&str] = &[
    "useradd", "adduser", "userdel", "deluser", "usermod", "groupadd", "addgroup", "groupdel",
    "delgroup", "groupmod", "passwd", "chpasswd", "chfn", "chsh", "vipw", "vigr", "pwconv",
    "grpconv", "newusers", "gpasswd",
];

const SESSION_DAEMONS: &[&str] = &[
    "sshd",
    "login",
    "su",
    "sudo",
    "doas",
    "tmux",
    "screen",
    "agetty",
    "systemd-logind",
    "gnome-shell",
    "gdm",
    "sddm",
    "lightdm",
    "code",
    "code-server",
    "sshd-session",
];

const CONTAINER_RUNTIMES: &[&str] = &[
    "docker",
    "dockerd",
    "containerd",
    "containerd-shim",
    "runc",
    "crun",
    "podman",
    "conmon",
    "nerdctl",
    "lxc-start",
    "snap-confine",
    "systemd-nspawn",
];

/// Tools that are scripts, so their exe is the interpreter and only comm
/// names them. (Debian's adduser is Perl; dnf, ansible and friends are Python.)
const SCRIPT_TOOLS: &[&str] = &[
    "adduser",
    "deluser",
    "addgroup",
    "delgroup",
    "unattended-upgrade",
    "yum",
    "dnf",
    "ansible",
    "ansible-playbook",
    "salt-minion",
    "salt-call",
    "cloud-init",
    "puppet",
    "chef-client",
    "chef-solo",
];

const SCRIPT_INTERPRETERS: &[&str] = &[
    "python", "python2", "python3", "perl", "ruby", "sh", "bash", "dash",
];

const CRON_DAEMONS: &[&str] = &["cron", "crond", "anacron", "atd"];
const INIT: &[&str] = &["systemd", "init"];
const KERNEL_THREADS: &[&str] = &["kthreadd", "rcu_sched", "migration"];

/// Root-owned install locations. Only a binary installed here can claim a
/// role that exempts it from detection.
const TRUSTED_EXE_DIRS: &[&str] = &[
    "/usr/bin/",
    "/usr/sbin/",
    "/bin/",
    "/sbin/",
    "/usr/lib/",
    "/usr/lib64/",
    "/usr/libexec/",
    "/lib/",
    "/lib64/",
    "/usr/local/bin/",
    "/usr/local/sbin/",
    "/usr/local/lib/",
    "/opt/",
    "/snap/",
    "/nix/store/",
];

/// Whether `exe` is an intact binary in a root-owned install location.
pub fn is_trusted_exe(exe: &str) -> bool {
    !exe.ends_with(" (deleted)")
        && !exe.contains("/../")
        && !exe.contains("/./")
        && !exe.contains("//")
        && TRUSTED_EXE_DIRS.iter().any(|d| exe.starts_with(d))
}

fn exe_basename(exe: &str) -> &str {
    exe.trim_end_matches(" (deleted)")
        .rsplit('/')
        .next()
        .unwrap_or("")
}

/// Is this process one of the tools in `names`, judged in a way a local user
/// can't fake?
///
/// `comm` is just the binary's file name (or whatever `prctl` set), so a copy
/// of anything at `/tmp/dpkg` has comm "dpkg". When the exe is known it must
/// sit in a root-owned directory and either be named like the tool or be a
/// script interpreter running a known script tool. With no exe (the process
/// vanished before /proc was read) we fall back to comm.
pub fn is_system_tool(comm: &str, exe: &str, names: &[&str]) -> bool {
    let c = comm.trim();
    if exe.is_empty() {
        return comm_matches(c, names);
    }
    if !is_trusted_exe(exe) {
        return false;
    }
    let base = exe_basename(exe);
    if comm_matches(base, names) {
        return true;
    }
    comm_matches(base, SCRIPT_INTERPRETERS)
        && comm_matches(c, names)
        && comm_matches(c, SCRIPT_TOOLS)
}

pub fn role_of(comm: &str, exe: &str) -> Role {
    let c = comm.trim();
    let base = exe_basename(exe);
    // Roles that add suspicion match comm *or* exe name: renaming a copied
    // shell mustn't hide it.
    let named = |set: &[&str]| comm_matches(c, set) || comm_matches(base, set);
    // Roles that exempt a process from detection need a trusted exe.
    let tool = |set: &[&str]| is_system_tool(c, exe, set);
    if named(WEB_SERVERS) || exe_contains(exe, &["php-fpm"]) {
        return Role::WebServer;
    }
    if named(DATABASES) {
        return Role::Database;
    }
    if tool(&["sshd", "sshd-session"]) {
        return Role::Sshd;
    }
    // Tools before shells/interpreters: dnf or adduser's exe *is* python/perl.
    if tool(PACKAGE_MANAGERS) {
        return Role::PackageManager;
    }
    if tool(CONFIG_MANAGERS) {
        return Role::ConfigManager;
    }
    if tool(DEBUGGERS) {
        return Role::Debugger;
    }
    if tool(USER_MGMT) {
        return Role::UserMgmt;
    }
    if tool(CRON_DAEMONS) {
        return Role::Cron;
    }
    // Kernel threads have no exe at all.
    if tool(INIT) || (exe.is_empty() && comm_matches(c, KERNEL_THREADS)) {
        return Role::System;
    }
    if named(SHELLS) {
        return Role::Shell;
    }
    if named(DOWNLOADERS) {
        return Role::Downloader;
    }
    if named(INTERPRETERS) || exe_contains(exe, &["/php"]) {
        return Role::Interpreter;
    }
    Role::Unknown
}

/// Match `comm` against a set, tolerating versioned or annotated names such as
/// `python3.11`, `nginx: worker`, `php-fpm8.2`, and the kernel's 15-char comm
/// truncation (`unattended-upgr`).
fn comm_matches(c: &str, set: &[&str]) -> bool {
    if c.is_empty() {
        return false;
    }
    set.iter().any(|k| {
        if *k == c {
            return true;
        }
        if c.len() == 15 && k.len() > 15 && k.starts_with(c) {
            return true;
        }
        match c.strip_prefix(k) {
            Some(rest) => {
                let first = rest.chars().next().unwrap_or(' ');
                first == ' ' || first == ':' || first == '.' || first.is_ascii_digit()
            }
            None => false,
        }
    })
}

fn exe_contains(exe: &str, needles: &[&str]) -> bool {
    !exe.is_empty() && needles.iter().any(|n| exe.contains(n))
}

pub fn is_session_daemon(comm: &str, exe: &str) -> bool {
    is_system_tool(comm, exe, SESSION_DAEMONS)
}

pub fn is_container_runtime(comm: &str, exe: &str) -> bool {
    is_system_tool(comm, exe, CONTAINER_RUNTIMES)
}

pub fn is_user_mgmt_tool(comm: &str, exe: &str) -> bool {
    is_system_tool(comm, exe, USER_MGMT)
}

#[derive(Debug, Default)]
pub struct ProcessTree {
    procs: HashMap<u32, ProcInfo>,
}

impl ProcessTree {
    pub fn new() -> Self {
        ProcessTree::default()
    }

    pub fn upsert(&mut self, info: ProcInfo) {
        self.procs.insert(info.pid, info);
    }

    /// Maximum re-exec history retained per PID.
    const MAX_PREVIOUS: usize = 4;

    pub fn upsert_exec(&mut self, ev: &ExecEvent) {
        // Same PID re-exec'ing (exec in a shell, wrappers, `env`, setuid
        // helpers): keep the prior image so the chain still shows the shell.
        let previous = match self.procs.get(&ev.pid) {
            // Different parent = PID reuse by an unrelated process: start fresh.
            Some(old) if old.ppid != ev.ppid => Vec::new(),
            // Same image again (re-running the same binary): keep history as is.
            Some(old) if old.comm == ev.comm && old.exe == ev.exe => old.previous.clone(),
            Some(old) => {
                let mut prev = Vec::with_capacity(Self::MAX_PREVIOUS);
                prev.push(PrevImage {
                    comm: old.comm.clone(),
                    exe: old.exe.clone(),
                });
                prev.extend(old.previous.iter().take(Self::MAX_PREVIOUS - 1).cloned());
                prev
            }
            None => Vec::new(),
        };
        let info = ProcInfo {
            pid: ev.pid,
            ppid: ev.ppid,
            uid: ev.uid,
            comm: ev.comm.clone(),
            exe: if ev.deleted_exe && !ev.exe.ends_with("(deleted)") {
                format!("{} (deleted)", ev.exe)
            } else {
                ev.exe.clone()
            },
            start: ev.ts.timestamp().max(0) as u64,
            tty_nr: ev.tty_nr,
            container: ev.container,
            container_id: ev.container_id.clone(),
            seen_at: ev.ts,
            previous,
        };
        self.procs.insert(ev.pid, info);
    }

    /// Refresh `seen_at` for a live process so pruning does not drop it.
    pub fn touch(&mut self, pid: u32, now: DateTime<Utc>) {
        if let Some(p) = self.procs.get_mut(&pid) {
            p.seen_at = now;
        }
    }

    pub fn get(&self, pid: u32) -> Option<&ProcInfo> {
        self.procs.get(&pid)
    }

    pub fn remove(&mut self, pid: u32) {
        self.procs.remove(&pid);
    }

    pub fn len(&self) -> usize {
        self.procs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.procs.is_empty()
    }

    /// Ancestors of `pid`, nearest first. Does not include `pid` itself.
    pub fn ancestors_of(&self, pid: u32) -> Vec<ProcInfo> {
        let mut out = Vec::new();
        let mut current = match self.procs.get(&pid) {
            Some(info) => info.ppid,
            None => return out,
        };
        let mut depth = 0;
        while depth < 32 && current != 0 {
            match self.procs.get(&current) {
                Some(info) => {
                    if info.pid == pid {
                        break;
                    }
                    out.push(info.clone());
                    current = info.ppid;
                }
                None => break,
            }
            depth += 1;
        }
        out
    }

    /// Full chain root-first, ending with `pid` (if known).
    ///
    /// A PID that re-exec'd is expanded into one node per image (oldest
    /// first), so `bash -c 'exec /tmp/x'` yields `... -> bash -> x` even
    /// though both share a PID. Expanded nodes carry the real PID.
    pub fn chain_of(&self, pid: u32) -> Vec<ProcInfo> {
        let mut chain = Vec::new();
        let mut ancestors = self.ancestors_of(pid);
        ancestors.reverse();
        for a in ancestors {
            Self::push_expanded(&mut chain, a);
        }
        if let Some(info) = self.procs.get(&pid) {
            Self::push_expanded(&mut chain, info.clone());
        }
        chain
    }

    fn push_expanded(chain: &mut Vec<ProcInfo>, info: ProcInfo) {
        for prev in info.previous.iter().rev() {
            chain.push(ProcInfo {
                comm: prev.comm.clone(),
                exe: prev.exe.clone(),
                previous: Vec::new(),
                ..info.clone()
            });
        }
        chain.push(ProcInfo {
            previous: Vec::new(),
            ..info
        });
    }

    pub fn chain_includes_role(&self, pid: u32, role: Role) -> bool {
        self.chain_of(pid)
            .iter()
            .any(|p| role_of(&p.comm, &p.exe) == role)
    }

    /// True when `pid` (or any ancestor) has a controlling TTY or descends from a
    /// session daemon (sshd, login, sudo, tmux...).
    pub fn has_interactive_session(&self, pid: u32, own_tty_nr: i64) -> bool {
        if own_tty_nr != 0 {
            return true;
        }
        if let Some(p) = self.procs.get(&pid) {
            if is_session_daemon(&p.comm, &p.exe) {
                return true;
            }
        }
        self.ancestors_of(pid)
            .iter()
            .any(|p| p.tty_nr != 0 || is_session_daemon(&p.comm, &p.exe))
    }

    /// True if any known process on the host is part of an interactive session.
    /// Used as the fallback when a file writer cannot be identified.
    pub fn any_interactive_session(&self) -> bool {
        // A TTY-attached process that is not a getty waiting for login.
        if self
            .procs
            .values()
            .any(|p| p.tty_nr != 0 && !p.comm.starts_with("agetty") && !p.comm.starts_with("getty"))
        {
            return true;
        }
        // A session daemon (sshd, su, sudo, tmux...) that has spawned something:
        // the bare sshd listener has no children of its own.
        self.procs.values().any(|child| {
            child.ppid != 0
                && self
                    .procs
                    .get(&child.ppid)
                    .map(|parent| {
                        is_session_daemon(&parent.comm, &parent.exe)
                            && parent.comm != "systemd-logind"
                            && !is_session_daemon(&child.comm, &child.exe)
                    })
                    .unwrap_or(false)
        })
    }

    pub fn prune(&mut self, cutoff: DateTime<Utc>) {
        self.procs.retain(|_, v| v.seen_at >= cutoff);
    }

    /// Any process matching `pred` that started (or was last seen) within
    /// `window` of `now`. Used to attribute atomic-rename writes, where the
    /// writer has already closed the file, to the tool that just ran.
    pub fn recent_process(
        &self,
        now: DateTime<Utc>,
        window: chrono::Duration,
        pred: impl Fn(&ProcInfo) -> bool,
    ) -> Option<&ProcInfo> {
        let cutoff = now - window;
        self.procs
            .values()
            .filter(|p| p.seen_at >= cutoff && pred(p))
            .max_by_key(|p| p.seen_at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(pid: u32, ppid: u32, comm: &str) -> ProcInfo {
        ProcInfo {
            pid,
            ppid,
            uid: 33,
            comm: comm.to_string(),
            exe: format!("/usr/sbin/{}", comm),
            start: 0,
            tty_nr: 0,
            container: false,
            container_id: None,
            seen_at: Utc::now(),
            previous: Vec::new(),
        }
    }

    #[test]
    fn roles() {
        assert_eq!(role_of("nginx", ""), Role::WebServer);
        assert_eq!(role_of("nginx: worker", ""), Role::WebServer);
        assert_eq!(role_of("php-fpm8.2", ""), Role::WebServer);
        assert_eq!(role_of("mysqld", ""), Role::Database);
        assert_eq!(role_of("bash", ""), Role::Shell);
        assert_eq!(role_of("curl", ""), Role::Downloader);
        assert_eq!(role_of("python3", ""), Role::Interpreter);
        assert_eq!(role_of("python3.11", ""), Role::Interpreter);
        assert_eq!(role_of("apt-get", ""), Role::PackageManager);
        assert_eq!(role_of("gdb", ""), Role::Debugger);
        assert_eq!(role_of("useradd", ""), Role::UserMgmt);
        assert_eq!(role_of("", "/usr/sbin/php-fpm8.2"), Role::WebServer);
        assert_eq!(role_of("sshd", ""), Role::Sshd);
        assert_eq!(role_of("sshd-session", ""), Role::Sshd);
        assert_eq!(role_of("totally-unknown-binary", ""), Role::Unknown);
        // No false prefix matches.
        assert_eq!(role_of("shred", ""), Role::Unknown);
        assert_eq!(role_of("nodemon", ""), Role::Unknown);
    }

    #[test]
    fn exempt_roles_need_a_trusted_exe() {
        // A copy at /tmp/dpkg has comm "dpkg" but isn't a package manager.
        assert_eq!(role_of("dpkg", "/tmp/dpkg"), Role::Unknown);
        assert_eq!(role_of("dpkg", "/usr/bin/dpkg"), Role::PackageManager);
        assert_eq!(role_of("gdb", "/dev/shm/gdb"), Role::Unknown);
        assert_eq!(role_of("gdb", "/usr/bin/gdb"), Role::Debugger);
        assert_eq!(role_of("usermod", "/home/x/usermod"), Role::Unknown);
        assert_eq!(role_of("sshd", "/var/tmp/sshd"), Role::Unknown);
        assert_eq!(role_of("systemd", "/tmp/systemd"), Role::Unknown);
        // Deleted or path-trick binaries aren't trusted either.
        assert_eq!(role_of("dpkg", "/usr/bin/dpkg (deleted)"), Role::Unknown);
        assert_eq!(role_of("dpkg", "/usr/bin/../../tmp/dpkg"), Role::Unknown);
        // Script tools: exe is the interpreter.
        assert_eq!(role_of("dnf", "/usr/bin/python3.9"), Role::PackageManager);
        assert_eq!(
            role_of("unattended-upgr", "/usr/bin/python3.12"),
            Role::PackageManager
        );
        assert_eq!(role_of("adduser", "/usr/bin/perl"), Role::UserMgmt);
        // ...but only known script tools.
        assert_eq!(role_of("dpkg", "/usr/bin/python3"), Role::Interpreter);
        // Kernel threads have no exe.
        assert_eq!(role_of("kthreadd", ""), Role::System);
        assert_eq!(role_of("kthreadd", "/tmp/kthreadd"), Role::Unknown);
    }

    #[test]
    fn renamed_shells_keep_their_role() {
        assert_eq!(role_of("x", "/var/www/uploads/bash"), Role::Shell);
        assert_eq!(role_of("kworker", "/tmp/curl"), Role::Downloader);
    }

    #[test]
    fn fake_session_daemon_is_not_interactive() {
        let mut t = ProcessTree::new();
        t.upsert(info(1, 0, "systemd"));
        t.upsert(info(400, 1, "cron"));
        let mut fake = info(401, 400, "tmux");
        fake.exe = "/tmp/tmux".into();
        t.upsert(fake);
        t.upsert(info(402, 401, "bash"));
        assert!(!t.has_interactive_session(402, 0));
        assert!(!t.any_interactive_session());
    }

    #[test]
    fn chain_tracking() {
        let mut t = ProcessTree::new();
        t.upsert(info(1, 0, "systemd"));
        t.upsert(info(100, 1, "sshd"));
        t.upsert(info(200, 100, "sshd"));
        t.upsert(info(300, 200, "bash"));
        let chain = t.chain_of(300);
        let comms: Vec<&str> = chain.iter().map(|p| p.comm.as_str()).collect();
        assert_eq!(comms, vec!["systemd", "sshd", "sshd", "bash"]);
        assert!(t.has_interactive_session(300, 0));
        assert!(t.any_interactive_session());
    }

    #[test]
    fn no_session_without_daemons() {
        let mut t = ProcessTree::new();
        t.upsert(info(1, 0, "systemd"));
        t.upsert(info(400, 1, "cron"));
        t.upsert(info(401, 400, "bash"));
        assert!(!t.has_interactive_session(401, 0));
        assert!(!t.any_interactive_session());
    }

    #[test]
    fn same_pid_reexec_keeps_history_in_chain() {
        let mut t = ProcessTree::new();
        t.upsert(info(1, 0, "systemd"));
        t.upsert(info(100, 1, "nginx"));
        let mk = |comm: &str, exe: &str| ExecEvent {
            ts: Utc::now(),
            pid: 200,
            ppid: 100,
            uid: 33,
            gid: 33,
            comm: comm.into(),
            exe: exe.into(),
            argv0: exe.into(),
            ld_preload: false,
            deleted_exe: false,
            tty_nr: 0,
            container: false,
            container_id: None,
        };
        t.upsert_exec(&mk("bash", "/usr/bin/bash"));
        t.upsert_exec(&mk(".x.sh", "/tmp/.x.sh"));
        let comms: Vec<String> = t.chain_of(200).iter().map(|p| p.comm.clone()).collect();
        assert_eq!(comms, vec!["systemd", "nginx", "bash", ".x.sh"]);
        assert!(t.chain_of(200).iter().all(|p| p.previous.is_empty()));
        // A re-exec to the same image (e.g. re-running the same binary) adds nothing.
        t.upsert_exec(&mk(".x.sh", "/tmp/.x.sh"));
        assert_eq!(t.chain_of(200).len(), 4);
        // New PID under a different parent: no history carried over.
        let mut fresh = mk("bash", "/usr/bin/bash");
        fresh.ppid = 1;
        t.upsert_exec(&fresh);
        assert_eq!(t.chain_of(200).len(), 2);
    }

    #[test]
    fn ppid_cycle_is_bounded() {
        let mut t = ProcessTree::new();
        t.upsert(info(5, 6, "a"));
        t.upsert(info(6, 5, "b"));
        assert!(t.ancestors_of(5).len() <= 32);
    }

    #[test]
    fn prune_removes_old_and_touch_keeps() {
        let mut t = ProcessTree::new();
        let mut old = info(9, 1, "x");
        old.seen_at = Utc::now() - chrono::Duration::hours(48);
        t.upsert(old);
        t.upsert(info(10, 1, "y"));
        let mut kept = info(11, 1, "z");
        kept.seen_at = Utc::now() - chrono::Duration::hours(48);
        t.upsert(kept);
        t.touch(11, Utc::now());
        t.prune(Utc::now() - chrono::Duration::hours(24));
        assert!(t.get(9).is_none());
        assert!(t.get(10).is_some());
        assert!(t.get(11).is_some());
    }
}
