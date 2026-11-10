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
    "fakeroot",
    "dpkg-buildpackage",
];

const SCRIPT_INTERPRETERS: &[&str] = &[
    "python", "python2", "python3", "perl", "ruby", "sh", "bash", "dash",
];

const CRON_DAEMONS: &[&str] = &["cron", "crond", "anacron", "atd"];
const INIT: &[&str] = &["systemd", "init"];
const KERNEL_THREADS: &[&str] = &["kthreadd", "rcu_sched", "migration"];

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

pub const SYSTEM_UID_MAX: u32 = 999;

pub fn genuine_service(exe: &str, uid: u32) -> bool {
    if !is_trusted_exe(exe) {
        return false;
    }
    let base = exe_basename(exe);
    comm_matches(base, WEB_SERVERS)
        || comm_matches(base, DATABASES)
        || base.starts_with("php-fpm")
        || uid <= SYSTEM_UID_MAX
}

pub fn script_tool_exe(comm: &str, exe: &str, argv: &[&str]) -> String {
    let c = comm.trim();
    let interp = exe_basename(exe);
    if !comm_matches(c, SCRIPT_TOOLS) || !comm_matches(interp, SCRIPT_INTERPRETERS) {
        return exe.to_string();
    }
    let script = argv.iter().skip(1).find(|a| {
        let base = exe_basename(a);
        !base.is_empty() && (base == c || (c.len() == 15 && base.starts_with(c)))
    });
    match script {
        Some(s) => s.to_string(),
        None => format!("(unverified script) {}", exe),
    }
}

pub fn role_of(comm: &str, exe: &str) -> Role {
    let c = comm.trim();
    let base = exe_basename(exe);
    let named = |set: &[&str]| comm_matches(c, set) || comm_matches(base, set);
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

const EDITORS: &[&str] = &[
    "vim",
    "vi",
    "nvim",
    "vim.basic",
    "vim.tiny",
    "nano",
    "emacs",
    "micro",
    "joe",
    "mcedit",
    "hx",
    "helix",
    "ne",
    "jed",
    "ed",
    "sudoedit",
    "visudo",
    "vipw",
    "vigr",
];

pub fn is_editor(comm: &str, exe: &str) -> bool {
    comm_matches(comm.trim(), EDITORS) || comm_matches(exe_basename(exe), EDITORS)
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

pub fn is_system_exe_path(exe: &str) -> bool {
    const DIRS: &[&str] = &[
        "/usr/",
        "/bin/",
        "/sbin/",
        "/lib/",
        "/lib64/",
        "/snap/",
        "/nix/store/",
    ];
    !exe.contains("/../") && DIRS.iter().any(|d| exe.starts_with(d))
}

pub const EXIT_GRACE_SECS: i64 = 300;

#[derive(Debug, Default)]
pub struct ProcessTree {
    procs: HashMap<u32, ProcInfo>,
    exited: HashMap<u32, DateTime<Utc>>,
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

    pub fn reap(&mut self, alive: &std::collections::HashSet<u32>, now: DateTime<Utc>) {
        for pid in self.procs.keys() {
            if !alive.contains(pid) {
                self.exited.entry(*pid).or_insert(now);
            }
        }
        self.exited.retain(|pid, _| !alive.contains(pid));
        let cutoff = now - chrono::Duration::seconds(EXIT_GRACE_SECS);
        let mut ancestors_of_live: std::collections::HashSet<u32> =
            std::collections::HashSet::new();
        for p in self
            .procs
            .values()
            .filter(|p| !self.exited.contains_key(&p.pid))
        {
            let mut cur = p.ppid;
            let mut depth = 0;
            while cur > 1 && depth < 32 && ancestors_of_live.insert(cur) {
                cur = self.procs.get(&cur).map(|a| a.ppid).unwrap_or(0);
                depth += 1;
            }
        }
        let expired: Vec<u32> = self
            .exited
            .iter()
            .filter(|(pid, at)| **at < cutoff && !ancestors_of_live.contains(pid))
            .map(|(pid, _)| *pid)
            .collect();
        for pid in expired {
            self.remove(pid);
        }
    }

    const MAX_PREVIOUS: usize = 4;

    pub fn upsert_exec(&mut self, ev: &ExecEvent) {
        let reused = self.exited.remove(&ev.pid).is_some();
        let previous = match self.procs.get(&ev.pid) {
            _ if reused => Vec::new(),
            Some(old) if old.ppid != ev.ppid => Vec::new(),
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

    pub fn has_interactive_session(&self, pid: u32, own_tty_nr: i64) -> bool {
        let ancestors = self.ancestors_of(pid);
        let me = self.procs.get(&pid);
        let unattended_origin = ancestors.iter().any(|p| {
            matches!(
                role_of(&p.comm, &p.exe),
                Role::WebServer | Role::Database | Role::Cron
            )
        });
        if unattended_origin {
            return false;
        }
        if own_tty_nr != 0 {
            return true;
        }
        if let Some(p) = me {
            if is_session_daemon(&p.comm, &p.exe) {
                return true;
            }
        }
        ancestors
            .iter()
            .any(|p| p.tty_nr != 0 || is_session_daemon(&p.comm, &p.exe))
    }

    pub fn recent_interactive_activity(
        &self,
        now: DateTime<Utc>,
        window: chrono::Duration,
    ) -> bool {
        self.procs.values().any(|p| {
            if is_session_daemon(&p.comm, &p.exe) {
                return false;
            }
            let recent = self
                .exec_at
                .get(&p.pid)
                .map(|t| *t <= now + window && now - *t <= window)
                .unwrap_or(false);
            let live_editor = !self.is_exited(p.pid) && is_editor(&p.comm, &p.exe);
            (recent || live_editor) && self.has_interactive_session(p.pid, p.tty_nr)
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
        assert_eq!(role_of("shred", ""), Role::Unknown);
        assert_eq!(role_of("nodemon", ""), Role::Unknown);
    }

    #[test]
    fn genuine_services_need_more_than_a_name() {
        assert!(genuine_service("/usr/sbin/nginx", 0));
        assert!(genuine_service("/usr/sbin/php-fpm8.2", 33));
        assert!(genuine_service("/usr/sbin/mysqld", 111));
        assert!(!genuine_service("/usr/bin/python3.12", 1000));
        assert!(!genuine_service("/home/eve/nginx", 33));
        assert!(genuine_service("/usr/bin/python3.12", 33));
        assert!(genuine_service("/usr/lib/jvm/java-17/bin/java", 998));
    }

    #[test]
    fn script_tools_are_judged_by_the_script() {
        let real = script_tool_exe(
            "dnf",
            "/usr/bin/python3.9",
            &["/usr/bin/python3", "/usr/bin/dnf", "install"],
        );
        assert_eq!(real, "/usr/bin/dnf");
        assert_eq!(role_of("dnf", &real), Role::PackageManager);
        let fake = script_tool_exe("dnf", "/usr/bin/dash", &["/bin/sh", "/tmp/dnf"]);
        assert_eq!(fake, "/tmp/dnf");
        assert_ne!(role_of("dnf", &fake), Role::PackageManager);
        let rel = script_tool_exe("adduser", "/usr/bin/perl", &["/usr/bin/perl", "./adduser"]);
        assert_ne!(role_of("adduser", &rel), Role::UserMgmt);
        let renamed = script_tool_exe("dnf", "/usr/bin/python3", &["python3", "-c", "..."]);
        assert_ne!(role_of("dnf", &renamed), Role::PackageManager);
        let ua = script_tool_exe(
            "unattended-upgr",
            "/usr/bin/python3.12",
            &["/usr/bin/python3", "/usr/bin/unattended-upgrade"],
        );
        assert_eq!(role_of("unattended-upgr", &ua), Role::PackageManager);
        assert_eq!(
            script_tool_exe("bash", "/usr/bin/bash", &["bash"]),
            "/usr/bin/bash"
        );
        assert_eq!(
            script_tool_exe("dpkg", "/usr/bin/dpkg", &["dpkg"]),
            "/usr/bin/dpkg"
        );
    }

    #[test]
    fn a_tty_under_a_service_or_cron_is_not_a_session() {
        let mut t = ProcessTree::new();
        t.upsert(info(100, 1, "nginx"));
        let mut sh = info(200, 100, "bash");
        sh.exe = "/usr/bin/bash".into();
        sh.tty_nr = 34816;
        t.upsert(sh);
        assert!(!t.has_interactive_session(200, 34816));
        t.upsert(info(300, 1, "cron"));
        let mut sudo = info(301, 300, "sudo");
        sudo.exe = "/usr/bin/sudo".into();
        t.upsert(sudo);
        assert!(!t.has_interactive_session(301, 0));
        t.upsert(info(50, 1, "sshd"));
        let mut login = info(60, 50, "bash");
        login.exe = "/usr/bin/bash".into();
        login.tty_nr = 34817;
        t.upsert(login);
        assert!(t.has_interactive_session(60, 34817));
    }

    #[test]
    fn exempt_roles_need_a_trusted_exe() {
        assert_eq!(role_of("dpkg", "/tmp/dpkg"), Role::Unknown);
        assert_eq!(role_of("dpkg", "/usr/bin/dpkg"), Role::PackageManager);
        assert_eq!(role_of("gdb", "/dev/shm/gdb"), Role::Unknown);
        assert_eq!(role_of("gdb", "/usr/bin/gdb"), Role::Debugger);
        assert_eq!(role_of("usermod", "/home/x/usermod"), Role::Unknown);
        assert_eq!(role_of("sshd", "/var/tmp/sshd"), Role::Unknown);
        assert_eq!(role_of("systemd", "/tmp/systemd"), Role::Unknown);
        assert_eq!(role_of("dpkg", "/usr/bin/dpkg (deleted)"), Role::Unknown);
        assert_eq!(role_of("dpkg", "/usr/bin/../../tmp/dpkg"), Role::Unknown);
        assert_eq!(role_of("dnf", "/usr/bin/python3.9"), Role::PackageManager);
        assert_eq!(
            role_of("unattended-upgr", "/usr/bin/python3.12"),
            Role::PackageManager
        );
        assert_eq!(role_of("adduser", "/usr/bin/perl"), Role::UserMgmt);
        assert_eq!(role_of("dpkg", "/usr/bin/python3"), Role::Interpreter);
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
    }

    #[test]
    fn no_session_without_daemons() {
        let mut t = ProcessTree::new();
        t.upsert(info(1, 0, "systemd"));
        t.upsert(info(400, 1, "cron"));
        t.upsert(info(401, 400, "bash"));
        assert!(!t.has_interactive_session(401, 0));
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
        t.upsert_exec(&mk(".x.sh", "/tmp/.x.sh"));
        assert_eq!(t.chain_of(200).len(), 4);
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
        let alive: std::collections::HashSet<u32> = [1, 100].into_iter().collect();
        t.reap(&alive, now);
        assert!(t.get(300).is_some());
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
        let alive: std::collections::HashSet<u32> = [1, 100, 300].into_iter().collect();
        t.reap(&alive, now);
        t.reap(&alive, now + chrono::Duration::seconds(EXIT_GRACE_SECS + 1));
        let comms: Vec<String> = t.chain_of(300).iter().map(|p| p.comm.clone()).collect();
        assert_eq!(comms, vec!["systemd", "nginx", "bash", "implant"]);
    }

    #[test]
    fn exited_grandparents_of_live_processes_are_kept() {
        let mut t = ProcessTree::new();
        let now = Utc::now();
        t.upsert(info(1, 0, "systemd"));
        t.upsert(info(100, 1, "nginx"));
        t.upsert(info(200, 100, "sh"));
        t.upsert(info(250, 200, "setsid"));
        t.upsert(info(300, 250, "implant"));
        let alive: std::collections::HashSet<u32> = [1, 300].into_iter().collect();
        t.reap(&alive, now);
        t.reap(&alive, now + chrono::Duration::seconds(EXIT_GRACE_SECS + 1));
        let comms: Vec<String> = t.chain_of(300).iter().map(|p| p.comm.clone()).collect();
        assert_eq!(comms, vec!["systemd", "nginx", "sh", "setsid", "implant"]);
    }

    #[test]
    fn exec_on_an_exited_pid_is_a_new_process() {
        let mut t = ProcessTree::new();
        let now = Utc::now();
        t.upsert(info(1, 0, "systemd"));
        t.upsert_exec(&exec_ev(500, 1, "bash", now));
        t.reap(&[1].into_iter().collect(), now);
        t.upsert_exec(&exec_ev(500, 1, "cron", now));
        let comms: Vec<String> = t.chain_of(500).iter().map(|p| p.comm.clone()).collect();
        assert_eq!(comms, vec!["systemd", "cron"]);
        assert!(!t.is_exited(500));
    }

    #[test]
    fn a_busy_daemon_is_not_a_recent_process() {
        let mut t = ProcessTree::new();
        let now = Utc::now();
        t.upsert(info(700, 1, "snapd"));
        t.touch(700, now);
        let is_pm = |p: &ProcInfo| p.comm == "snapd" || p.comm == "useradd";
        assert!(t
            .recent_process(now, chrono::Duration::seconds(8), is_pm)
            .is_none());
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
