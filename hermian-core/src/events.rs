use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    High,
    Critical,
}

impl Severity {
    pub const ALL: [Severity; 4] = [
        Severity::Info,
        Severity::Low,
        Severity::High,
        Severity::Critical,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }

    /// Whether this severity should interrupt a human (notify) rather than just be logged.
    pub fn is_actionable(&self) -> bool {
        *self >= Severity::High
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Severity {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_uppercase().as_str() {
            "INFO" => Ok(Severity::Info),
            "LOW" => Ok(Severity::Low),
            "HIGH" => Ok(Severity::High),
            "CRITICAL" => Ok(Severity::Critical),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DetectionId {
    D1,
    D2,
    D3,
    D4,
    D5,
    /// Self-protection and daemon lifecycle events (integrity, config, delivery).
    Self_,
}

impl DetectionId {
    pub fn name(&self) -> &'static str {
        match self {
            DetectionId::D1 => "Suspicious process chain",
            DetectionId::D2 => "SSH and authentication abuse",
            DetectionId::D3 => "Persistence modification",
            DetectionId::D4 => "Privilege escalation indicator",
            DetectionId::D5 => "Anomalous network behavior",
            DetectionId::Self_ => "HERMIAN self-protection",
        }
    }

    pub fn short(&self) -> &'static str {
        match self {
            DetectionId::D1 => "D1",
            DetectionId::D2 => "D2",
            DetectionId::D3 => "D3",
            DetectionId::D4 => "D4",
            DetectionId::D5 => "D5",
            DetectionId::Self_ => "SELF",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    Created,
    Modified,
    Removed,
    MovedTo,
    MovedFrom,
}

impl FileKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            FileKind::Created => "created",
            FileKind::Modified => "modified",
            FileKind::Removed => "removed",
            FileKind::MovedTo => "moved into place",
            FileKind::MovedFrom => "moved away",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcInfo {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub comm: String,
    pub exe: String,
    pub start: u64,
    pub tty_nr: i64,
    pub container: bool,
    pub container_id: Option<String>,
    pub seen_at: DateTime<Utc>,
    /// Programs this PID ran *before* the current image (newest first). A
    /// shell that tail-calls `exec /tmp/x` keeps its PID, so without this the
    /// chain would lose the shell. Bounded to a few entries.
    pub previous: Vec<PrevImage>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrevImage {
    pub comm: String,
    pub exe: String,
}

impl ProcInfo {
    pub fn label(&self) -> String {
        format!("{} (uid={}, PID {})", self.comm, self.uid, self.pid)
    }
}

#[derive(Debug, Clone)]
pub struct ExecEvent {
    pub ts: DateTime<Utc>,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,
    pub exe: String,
    pub argv0: String,
    pub ld_preload: bool,
    pub deleted_exe: bool,
    pub tty_nr: i64,
    pub container: bool,
    pub container_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ConnectEvent {
    pub ts: DateTime<Utc>,
    pub pid: u32,
    pub uid: u32,
    pub daddr: IpAddr,
    pub dport: u16,
    pub comm: String,
    pub container: bool,
}

#[derive(Debug, Clone)]
pub struct PtraceEvent {
    pub ts: DateTime<Utc>,
    pub pid: u32,
    pub uid: u32,
    pub comm: String,
    pub target_pid: u32,
    pub request: u64,
}

#[derive(Debug, Clone)]
pub struct WriterInfo {
    pub pid: u32,
    pub uid: u32,
    pub comm: String,
    pub exe: String,
    pub tty_nr: i64,
}

#[derive(Debug, Clone)]
pub struct FileEvent {
    pub ts: DateTime<Utc>,
    pub path: String,
    pub kind: FileKind,
    pub dev: u64,
    pub ino: u64,
    /// The process that had the file open, if it could still be identified.
    /// Editors typically write via temp+rename and have closed the file by the
    /// time the event is observed, so this is frequently `None`.
    pub writer: Option<WriterInfo>,
    /// Whether an interactive session (a TTY-attached process or a login /
    /// sshd / sudo descendant) was active on the host when the change occurred.
    /// Used as the fallback for session attribution when `writer` is `None`.
    pub session_present: bool,
    pub is_suid: bool,
    pub has_file_caps: bool,
    pub content: Option<String>,
    pub container: bool,
    pub managed_by_package: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthResult {
    Attempt,
    Success,
    Failure,
}

impl AuthResult {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuthResult::Attempt => "attempt",
            AuthResult::Success => "success",
            AuthResult::Failure => "failure",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuthEvent {
    pub ts: DateTime<Utc>,
    pub result: AuthResult,
    pub user: String,
    pub rhost: Option<IpAddr>,
    pub service: String,
    pub tty: String,
}

#[derive(Debug, Clone)]
pub struct ListenerEvent {
    pub ts: DateTime<Utc>,
    pub proto: String,
    pub addr: IpAddr,
    pub port: u16,
    pub pid: u32,
    pub comm: String,
}

#[derive(Debug, Clone)]
pub enum Event {
    Exec(ExecEvent),
    Connect(ConnectEvent),
    Ptrace(PtraceEvent),
    File(FileEvent),
    Auth(AuthEvent),
    Listener(ListenerEvent),
}

impl Event {
    pub fn ts(&self) -> DateTime<Utc> {
        match self {
            Event::Exec(e) => e.ts,
            Event::Connect(e) => e.ts,
            Event::Ptrace(e) => e.ts,
            Event::File(e) => e.ts,
            Event::Auth(e) => e.ts,
            Event::Listener(e) => e.ts,
        }
    }

    pub fn set_ts(&mut self, ts: DateTime<Utc>) {
        match self {
            Event::Exec(e) => e.ts = ts,
            Event::Connect(e) => e.ts = ts,
            Event::Ptrace(e) => e.ts = ts,
            Event::File(e) => e.ts = ts,
            Event::Auth(e) => e.ts = ts,
            Event::Listener(e) => e.ts = ts,
        }
    }
}

const TRANSIENT_DIRS: &[&str] = &["/tmp", "/dev/shm", "/var/tmp"];

pub fn is_suspicious_exec_dir(path: &str) -> bool {
    let p = path.trim_end_matches(" (deleted)").trim();
    TRANSIENT_DIRS
        .iter()
        .any(|d| p == *d || p.starts_with(&format!("{}/", d)))
}

pub fn is_container_overlay_path(path: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "/var/lib/docker/overlay2",
        "/var/lib/docker/containers",
        "/var/lib/containerd",
        "/run/containerd",
        "/var/lib/podman",
        "/run/podman",
    ];
    PREFIXES.iter().any(|p| path.starts_with(p))
}

/// Temporary artifacts produced by editors and atomic-write tooling. These are
/// never persistence targets themselves and generate a burst of inotify events
/// around every legitimate edit.
pub fn is_editor_artifact(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    if name.is_empty() {
        return false;
    }
    // vim / neovim swap and backup files, emacs autosave/lock, nano, sed -i, generic tmp.
    name.ends_with(".swp")
        || name.ends_with(".swo")
        || name.ends_with(".swx")
        || name.ends_with('~')
        || name.starts_with(".#")
        || (name.starts_with('#') && name.ends_with('#'))
        || name.ends_with(".save")
        || name.starts_with(".sed")
        || name.starts_with(".tmp")
        || name.ends_with(".tmp")
        || (name.starts_with("tmp.") && name.len() == 10) // mkstemp: tmp.XXXXXX (crontab, dpkg)
        || name.ends_with(".dpkg-new")
        || name.ends_with(".dpkg-old")
        || name.ends_with(".dpkg-dist")
        || name.ends_with(".rpmnew")
        || name.ends_with(".rpmsave")
        || name == "4913" // vim's write-test file
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_roundtrip() {
        for s in Severity::ALL {
            assert_eq!(s.as_str().parse::<Severity>(), Ok(s));
        }
        assert_eq!("critical".parse::<Severity>(), Ok(Severity::Critical));
        assert!("bogus".parse::<Severity>().is_err());
    }

    #[test]
    fn transient_dirs() {
        assert!(is_suspicious_exec_dir("/tmp/x"));
        assert!(is_suspicious_exec_dir("/dev/shm/payload (deleted)"));
        assert!(!is_suspicious_exec_dir("/tmpfoo/x"));
        assert!(!is_suspicious_exec_dir("/usr/bin/tmp"));
    }

    #[test]
    fn editor_artifacts() {
        assert!(is_editor_artifact("/etc/cron.d/.job.swp"));
        assert!(is_editor_artifact("/etc/cron.d/job~"));
        assert!(is_editor_artifact("/etc/cron.d/4913"));
        assert!(is_editor_artifact("/etc/sudoers.tmp"));
        assert!(is_editor_artifact("/etc/sudoers.d/.#README"));
        assert!(is_editor_artifact("/var/spool/cron/crontabs/tmp.2kdpKZ"));
        assert!(!is_editor_artifact("/etc/cron.d/job"));
        assert!(!is_editor_artifact("/etc/cron.d/tmp.cleanup-job"));
        assert!(!is_editor_artifact("/etc/ld.so.preload"));
    }
}
