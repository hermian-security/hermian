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

pub fn role_of(comm: &str, exe: &str) -> Role {
    let c = comm.trim();
    if comm_matches(c, WEB_SERVERS) || exe_contains(exe, &["php-fpm"]) {
        return Role::WebServer;
    }
    if comm_matches(c, DATABASES) {
        return Role::Database;
    }
    if c == "sshd" || c == "sshd-session" {
        return Role::Sshd;
    }
    if comm_matches(c, SHELLS) {
        return Role::Shell;
    }
    if comm_matches(c, DOWNLOADERS) {
        return Role::Downloader;
    }
    if comm_matches(c, INTERPRETERS) || exe_contains(exe, &["/php"]) {
        return Role::Interpreter;
    }
    if comm_matches(c, PACKAGE_MANAGERS) {
        return Role::PackageManager;
    }
    if comm_matches(c, CONFIG_MANAGERS) {
        return Role::ConfigManager;
    }
    if comm_matches(c, DEBUGGERS) {
        return Role::Debugger;
    }
    if comm_matches(c, USER_MGMT) {
        return Role::UserMgmt;
    }
    if matches!(c, "cron" | "crond" | "anacron" | "atd") {
        return Role::Cron;
    }
    if matches!(
        c,
        "systemd" | "init" | "kthreadd" | "rcu_sched" | "migration"
    ) {
        return Role::System;
    }
    Role::Unknown
}

/// Match `comm` against a set, tolerating versioned or annotated names such as
/// `python3.11`, `nginx: worker`, `php-fpm8.2`.
fn comm_matches(c: &str, set: &[&str]) -> bool {
    if c.is_empty() {
        return false;
    }
    set.iter().any(|k| {
        if *k == c {
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

pub fn is_session_daemon(comm: &str) -> bool {
    comm_matches(comm, SESSION_DAEMONS)
}

pub fn is_container_runtime(comm: &str) -> bool {
    comm_matches(comm, CONTAINER_RUNTIMES)
}

pub fn is_user_mgmt_tool(comm: &str) -> bool {
    comm_matches(comm, USER_MGMT)
}

/// How long an exited process stays in the tree: long enough to attribute a
/// write that inotify reports after the writer is gone, and to keep ancestry
/// for alerts on its children.
pub const EXIT_GRACE_SECS: i64 = 300;

#[derive(Debug, Default)]
pub struct ProcessTree {
    procs: HashMap<u32, ProcInfo>,
    /// When a tracked pid was seen to exit. Exited processes don't count as
    /// live sessions, and a new exec on the pid is a new process.
    exited: HashMap<u32, DateTime<Utc>>,
    /// When the current image was exec'd, for processes we saw start.
    /// (`ProcInfo::start` mixes units: exec time vs. /proc clock ticks.)
    exec_at: HashMap<u32, DateTime<Utc>>,
}

impl ProcessTree {
    pub fn new() -> Self {
        ProcessTree::default()
    }

    pub fn upsert(&mut self, info: ProcInfo) {
        self.exited.remove(&info.pid);
        self.procs.insert(info.pid, info);
    }

    pub fn is_exited(&self, pid: u32) -> bool {
        self.exited.contains_key(&pid)
    }

    /// Reconcile with the set of pids that exist right now: mark the missing
    /// ones as exited and drop those that exited more than
    /// [`EXIT_GRACE_SECS`] ago, unless a live process still descends from
    /// them (its chain would lose them otherwise).
    pub fn reap(&mut self, alive: &std::collections::HashSet<u32>, now: DateTime<Utc>) {
        for pid in self.procs.keys() {
            if !alive.contains(pid) {
                self.exited.entry(*pid).or_insert(now);
            }
        }
        self.exited.retain(|pid, _| !alive.contains(pid));
        let cutoff = now - chrono::Duration::seconds(EXIT_GRACE_SECS);
        let parents_of_live: std::collections::HashSet<u32> = self
            .procs
            .values()
            .filter(|p| !self.exited.contains_key(&p.pid))
            .map(|p| p.ppid)
            .collect();
        let expired: Vec<u32> = self
            .exited
            .iter()
            .filter(|(pid, at)| **at < cutoff && !parents_of_live.contains(pid))
            .map(|(pid, _)| *pid)
            .collect();
        for pid in expired {
            self.remove(pid);
        }
    }

    /// Maximum re-exec history retained per PID.
    const MAX_PREVIOUS: usize = 4;

    pub fn upsert_exec(&mut self, ev: &ExecEvent) {
        // Same PID re-exec'ing (exec in a shell, wrappers, `env`, setuid
        // helpers): keep the prior image so the chain still shows the shell.
        // The old holder of this pid exited: this is a new process (PID
        // reuse), not a re-exec, so it inherits nothing.
        let reused = self.exited.remove(&ev.pid).is_some();
        let previous = match self.procs.get(&ev.pid) {
            _ if reused => Vec::new(),
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
        self.exec_at.insert(ev.pid, ev.ts);
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
        self.exited.remove(&pid);
        self.exec_at.remove(&pid);
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
            if is_session_daemon(&p.comm) {
                return true;
            }
        }
        self.ancestors_of(pid)
            .iter()
            .any(|p| p.tty_nr != 0 || is_session_daemon(&p.comm))
    }

    /// True if any known process on the host is part of an interactive session.
    /// Used as the fallback when a file writer cannot be identified.
    pub fn any_interactive_session(&self) -> bool {
        // Only live processes: a session that ended an hour ago doesn't make
        // an unattended write look operator-driven.
        let live = || self.procs.values().filter(|p| !self.is_exited(p.pid));
        // A TTY-attached process that is not a getty waiting for login.
        if live()
            .any(|p| p.tty_nr != 0 && !p.comm.starts_with("agetty") && !p.comm.starts_with("getty"))
        {
            return true;
        }
        // A session daemon (sshd, su, sudo, tmux...) that has spawned something:
        // the bare sshd listener has no children of its own.
        live().any(|child| {
            child.ppid != 0
                && !self.is_exited(child.ppid)
                && self
                    .procs
                    .get(&child.ppid)
                    .map(|parent| {
                        is_session_daemon(&parent.comm)
                            && parent.comm != "systemd-logind"
                            && !is_session_daemon(&child.comm)
                    })
                    .unwrap_or(false)
        })
    }

    pub fn prune(&mut self, cutoff: DateTime<Utc>) {
        let stale: Vec<u32> = self
            .procs
            .values()
            .filter(|v| v.seen_at < cutoff)
            .map(|v| v.pid)
            .collect();
        for pid in stale {
            self.remove(pid);
        }
    }

    /// Any process matching `pred` that was exec'd or exited within `window`
    /// of `now`. Used to attribute atomic-rename writes, where the writer has
    /// already closed the file, to the tool that just ran.
    ///
    /// Not `seen_at`: that's refreshed by every connect, so a long-running
    /// daemon with a matching role (snapd, nix-daemon) would look "recent"
    /// forever and excuse any write.
    pub fn recent_process(
        &self,
        now: DateTime<Utc>,
        window: chrono::Duration,
        pred: impl Fn(&ProcInfo) -> bool,
    ) -> Option<&ProcInfo> {
        let cutoff = now - window;
        let activity = |p: &ProcInfo| {
            let started = self.exec_at.get(&p.pid).copied();
            let ended = self.exited.get(&p.pid).copied();
            started
                .into_iter()
                .chain(ended)
                .filter(|t| *t >= cutoff)
                .max()
        };
        self.procs
            .values()
            .filter_map(|p| activity(p).filter(|_| pred(p)).map(|t| (t, p)))
            .max_by_key(|(t, _)| *t)
            .map(|(_, p)| p)
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

    fn exec_ev(pid: u32, ppid: u32, comm: &str, ts: DateTime<Utc>) -> ExecEvent {
        ExecEvent {
            ts,
            pid,
            ppid,
            uid: 0,
            gid: 0,
            comm: comm.into(),
            exe: format!("/usr/bin/{}", comm),
            argv0: comm.into(),
            ld_preload: false,
            deleted_exe: false,
            tty_nr: 0,
            container: false,
            container_id: None,
        }
    }

    #[test]
    fn ended_sessions_stop_counting() {
        let mut t = ProcessTree::new();
        let now = Utc::now();
        t.upsert(info(1, 0, "systemd"));
        t.upsert(info(100, 1, "sshd"));
        t.upsert(info(200, 100, "sshd"));
        t.upsert(info(300, 200, "bash"));
        assert!(t.any_interactive_session());
        // The session's processes exit; only systemd and the listener remain.
        let alive: std::collections::HashSet<u32> = [1, 100].into_iter().collect();
        t.reap(&alive, now);
        assert!(!t.any_interactive_session());
        // Still in the tree during the grace period...
        assert!(t.get(300).is_some());
        // ...and gone after it.
        t.reap(&alive, now + chrono::Duration::seconds(EXIT_GRACE_SECS + 1));
        assert!(t.get(300).is_none() && t.get(200).is_none());
        assert!(t.get(100).is_some());
    }

    #[test]
    fn exited_ancestors_of_live_processes_are_kept() {
        let mut t = ProcessTree::new();
        let now = Utc::now();
        t.upsert(info(1, 0, "systemd"));
        t.upsert(info(100, 1, "nginx"));
        t.upsert(info(200, 100, "bash"));
        t.upsert(info(300, 200, "implant"));
        // The shell exited but its child keeps running.
        let alive: std::collections::HashSet<u32> = [1, 100, 300].into_iter().collect();
        t.reap(&alive, now);
        t.reap(&alive, now + chrono::Duration::seconds(EXIT_GRACE_SECS + 1));
        let comms: Vec<String> = t.chain_of(300).iter().map(|p| p.comm.clone()).collect();
        assert_eq!(comms, vec!["systemd", "nginx", "bash", "implant"]);
    }

    #[test]
    fn exec_on_an_exited_pid_is_a_new_process() {
        let mut t = ProcessTree::new();
        let now = Utc::now();
        t.upsert(info(1, 0, "systemd"));
        t.upsert_exec(&exec_ev(500, 1, "bash", now));
        t.reap(&[1].into_iter().collect(), now);
        // Same pid, same parent, different program: reuse, not re-exec.
        t.upsert_exec(&exec_ev(500, 1, "cron", now));
        let comms: Vec<String> = t.chain_of(500).iter().map(|p| p.comm.clone()).collect();
        assert_eq!(comms, vec!["systemd", "cron"]);
        assert!(!t.is_exited(500));
    }

    #[test]
    fn a_busy_daemon_is_not_a_recent_process() {
        let mut t = ProcessTree::new();
        let now = Utc::now();
        // snapd was already running at startup and keeps making connections.
        t.upsert(info(700, 1, "snapd"));
        t.touch(700, now);
        let is_pm = |p: &ProcInfo| p.comm == "snapd" || p.comm == "useradd";
        assert!(t
            .recent_process(now, chrono::Duration::seconds(8), is_pm)
            .is_none());
        // A tool that just ran does count, including right after it exits.
        t.upsert_exec(&exec_ev(701, 1, "useradd", now));
        assert!(t
            .recent_process(now, chrono::Duration::seconds(8), is_pm)
            .is_some());
        let later = now + chrono::Duration::seconds(30);
        t.reap(&[1, 700].into_iter().collect(), later);
        assert!(t
            .recent_process(later, chrono::Duration::seconds(8), is_pm)
            .is_some());
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
