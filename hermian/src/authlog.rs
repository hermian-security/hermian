use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::net::IpAddr;
use std::process::{Child, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use chrono::{DateTime, Utc};
use hermian_core::{AuthEvent, AuthMethod, AuthResult, Event, SshKey};
use tokio::sync::mpsc;

const AUTH_LOG_CANDIDATES: &[&str] = &["/var/log/auth.log", "/var/log/secure"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthSource {
    File,
    Journal,
    None,
}

pub fn detect_source() -> AuthSource {
    let journald = std::path::Path::new("/run/systemd/journal/socket").exists();
    if journald && which("journalctl") {
        AuthSource::Journal
    } else if AUTH_LOG_CANDIDATES
        .iter()
        .any(|p| std::path::Path::new(p).exists())
    {
        AuthSource::File
    } else if which("journalctl") {
        AuthSource::Journal
    } else {
        AuthSource::None
    }
}

fn which(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|p| p.join(bin).is_file()))
        .unwrap_or(false)
        || std::path::Path::new("/usr/bin").join(bin).is_file()
        || std::path::Path::new("/bin").join(bin).is_file()
}

pub fn spawn_authlog_tailer(
    tx: mpsc::Sender<Event>,
    shutdown: Arc<AtomicBool>,
) -> Result<AuthSource> {
    let source = detect_source();
    if source == AuthSource::None {
        return Ok(source);
    }
    std::thread::Builder::new()
        .name("hermian-authlog".to_string())
        .spawn(move || match source {
            AuthSource::File => file_loop(tx, shutdown),
            AuthSource::Journal => journal_loop(tx, shutdown),
            AuthSource::None => {}
        })?;
    Ok(source)
}

fn open_log() -> Option<(BufReader<File>, &'static str)> {
    AUTH_LOG_CANDIDATES.iter().find_map(|path| {
        OpenOptions::new()
            .read(true)
            .open(path)
            .ok()
            .map(|f| (BufReader::new(f), *path))
    })
}

fn rotated(path: &str, open_ino: u64, pos: u64) -> bool {
    use std::os::unix::fs::MetadataExt;
    match std::fs::metadata(path) {
        Ok(m) => m.ino() != open_ino || m.len() < pos,
        Err(_) => false,
    }
}

fn file_loop(tx: mpsc::Sender<Event>, shutdown: Arc<AtomicBool>) {
    use std::os::unix::fs::MetadataExt;
    let mut from_start = false;
    while !shutdown.load(Ordering::Relaxed) {
        let Some((mut reader, path)) = open_log() else {
            std::thread::sleep(Duration::from_secs(30));
            from_start = true;
            continue;
        };
        let open_ino = reader.get_ref().metadata().map(|m| m.ino()).unwrap_or(0);
        if !from_start {
            let _ = reader.seek(SeekFrom::End(0));
        }
        from_start = true;
        let mut line = String::new();
        let mut idle_polls = 0u32;
        loop {
            if shutdown.load(Ordering::Relaxed) {
                return;
            }
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => {
                    std::thread::sleep(Duration::from_millis(500));
                    idle_polls += 1;
                    if idle_polls >= 4 {
                        idle_polls = 0;
                        let pos = reader.stream_position().unwrap_or(0);
                        if rotated(path, open_ino, pos) {
                            break;
                        }
                    }
                }
                Ok(_) => {
                    idle_polls = 0;
                    let Some((ev, pid)) = parse_line_with_pid(&line) else {
                        continue;
                    };
                    if sender_is_not_sshd(pid) {
                        continue;
                    }
                    if tx.blocking_send(Event::Auth(locate_key(ev))).is_err() {
                        return;
                    }
                }
                Err(_) => break,
            }
        }
    }
}

fn sender_is_not_sshd(pid: u32) -> bool {
    let Some(comm) = crate::procsrc::comm_of(pid) else {
        return false;
    };
    let uid = crate::procsrc::uid_of(pid);
    !matches!(comm.as_str(), "sshd" | "sshd-session") || uid != Some(0)
}

const JOURNAL_MATCHES: &[&str] = &["_UID=0", "_COMM=sshd", "+", "_UID=0", "_COMM=sshd-session"];

fn spawn_journalctl() -> std::io::Result<Child> {
    crate::procsrc::system_command("journalctl")
        .args(["-f", "-n", "0", "-o", "short-iso", "--no-pager", "-q"])
        .args(JOURNAL_MATCHES)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
}

fn journal_loop(tx: mpsc::Sender<Event>, shutdown: Arc<AtomicBool>) {
    while !shutdown.load(Ordering::Relaxed) {
        let Ok(mut child) = spawn_journalctl() else {
            std::thread::sleep(Duration::from_secs(30));
            continue;
        };
        let Some(stdout) = child.stdout.take() else {
            let _ = child.kill();
            std::thread::sleep(Duration::from_secs(30));
            continue;
        };
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        loop {
            if shutdown.load(Ordering::Relaxed) {
                let _ = child.kill();
                return;
            }
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {
                    if let Some(ev) = parse_line(&line) {
                        if tx.blocking_send(Event::Auth(locate_key(ev))).is_err() {
                            let _ = child.kill();
                            return;
                        }
                    }
                }
                Err(_) => break,
            }
        }
        let _ = child.wait();
        std::thread::sleep(Duration::from_secs(5));
    }
}

fn split_sshd_line(line: &str) -> Option<(Option<DateTime<Utc>>, u32, &str)> {
    let ts = parse_timestamp(line);
    let skip = if ts.is_some() { 1 } else { 3 };
    let mut rest = line;
    for _ in 0..skip + 1 {
        rest = rest.trim_start().split_once(char::is_whitespace)?.1;
    }
    let (tag, msg) = rest.trim_start().split_once(char::is_whitespace)?;
    let (name, pid) = tag.strip_suffix("]:")?.split_once('[')?;
    if !matches!(name, "sshd" | "sshd-session") {
        return None;
    }
    let pid: u32 = pid.parse().ok()?;
    Some((ts, pid, msg.trim_start()))
}

fn locate_key(mut ev: AuthEvent) -> AuthEvent {
    let user = ev.user.clone();
    if let Some(k) = ev.key.as_mut() {
        crate::sshkeys::resolve(&user, k);
    }
    ev
}

pub fn parse_line(line: &str) -> Option<AuthEvent> {
    parse_line_with_pid(line).map(|(ev, _)| ev)
}

fn parse_line_with_pid(line: &str) -> Option<(AuthEvent, u32)> {
    let (ts, pid, msg) = split_sshd_line(line.trim())?;
    parse_message(msg, ts.unwrap_or_else(Utc::now)).map(|ev| (ev, pid))
}

fn parse_message(msg: &str, ts: DateTime<Utc>) -> Option<AuthEvent> {
    let lower = msg.to_ascii_lowercase();

    if lower.starts_with("accepted ") {
        let user = word_after(msg, " for ")?;
        let method = AuthMethod::from_ssh_word(msg.split_whitespace().nth(1).unwrap_or(""));
        return Some(AuthEvent {
            ts,
            result: AuthResult::Success,
            user,
            rhost: extract_rhost(msg),
            service: "sshd".into(),
            tty: "ssh".into(),
            key: if method == AuthMethod::PublicKey {
                extract_key(msg)
            } else {
                None
            },
            method,
            port: extract_port(msg),
        });
    }
    let failure = lower.starts_with("failed ")
        || lower.starts_with("invalid user ")
        || lower.contains("authentication failure")
        || lower.starts_with("connection closed by authenticating user")
        || lower.starts_with("connection closed by invalid user")
        || (lower.starts_with("disconnected from") && lower.contains("[preauth]"))
        || lower.contains("maximum authentication attempts exceeded");
    if failure {
        let user = word_after(msg, "invalid user ")
            .or_else(|| word_after(msg, "authenticating user "))
            .or_else(|| word_after(msg, " for "))
            .or_else(|| word_after(msg, " user "))
            .unwrap_or_else(|| "?".to_string());
        return Some(AuthEvent {
            ts,
            result: AuthResult::Failure,
            user,
            rhost: extract_rhost(msg),
            service: "sshd".into(),
            tty: "ssh".into(),
            method: AuthMethod::Unknown,
            port: extract_port(msg),
            key: None,
        });
    }
    None
}

fn extract_key(msg: &str) -> Option<SshKey> {
    let rest = &msg[msg.rfind(" ssh2: ")? + 7..];
    let mut words = rest.split_whitespace();
    let kind = words.next()?;
    let fingerprint = words.next()?;
    let ok_kind = !kind.is_empty()
        && kind.len() <= 32
        && kind.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
    let ok_fp = fingerprint.strip_prefix("SHA256:").is_some_and(|b| {
        !b.is_empty()
            && b.len() <= 64
            && b.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/')
    });
    if !ok_kind || !ok_fp {
        return None;
    }
    Some(SshKey {
        kind: kind.to_string(),
        fingerprint: fingerprint.to_string(),
        ..SshKey::default()
    })
}

fn parse_timestamp(line: &str) -> Option<DateTime<Utc>> {
    let first = line.split_whitespace().next()?;
    if let Ok(dt) = DateTime::parse_from_str(first, "%Y-%m-%dT%H:%M:%S%z") {
        return Some(dt.with_timezone(&Utc));
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(first) {
        return Some(dt.with_timezone(&Utc));
    }
    None
}

fn word_after(msg: &str, pattern: &str) -> Option<String> {
    let lower = msg.to_ascii_lowercase();
    let pos = lower.find(&pattern.to_ascii_lowercase())?;
    let rest = &msg[pos + pattern.len()..];
    let word: String = rest.chars().take_while(|c| !c.is_whitespace()).collect();
    if word.is_empty()
        || matches!(
            word.as_str(),
            "password" | "publickey" | "keyboard-interactive/pam"
        )
    {
        return None;
    }
    Some(word)
}

fn extract_port(msg: &str) -> Option<u16> {
    let from = msg.rfind(" from ")?;
    let after = &msg[from + 6..];
    let p = after.find(" port ")?;
    after[p + 6..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .ok()
}

fn extract_rhost(msg: &str) -> Option<IpAddr> {
    let from = msg.rfind(" from ")?;
    let token: String = msg[from + 6..]
        .chars()
        .take_while(|c| !c.is_whitespace())
        .collect();
    token.trim_matches(|c| c == '[' || c == ']').parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotation_is_seen_by_inode_or_truncation() {
        use std::os::unix::fs::MetadataExt;
        let dir = std::env::temp_dir().join(format!("hermian-rot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("auth.log");
        let p = log.to_str().unwrap();
        std::fs::write(&log, "line one\nline two\n").unwrap();
        let ino = std::fs::metadata(&log).unwrap().ino();
        assert!(!rotated(p, ino, 18));
        std::fs::write(&log, "").unwrap();
        assert!(rotated(p, ino, 18));
        std::fs::write(&log, "x\n").unwrap();
        let ino = std::fs::metadata(&log).unwrap().ino();
        std::fs::rename(&log, dir.join("auth.log.1")).unwrap();
        assert!(!rotated(p, ino, 2), "missing file isn't a rotation yet");
        std::fs::write(&log, "new\n").unwrap();
        assert!(rotated(p, ino, 2));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn accepted_and_failed_lines() {
        let a = parse_line("2024-01-15T10:20:30+0000 web sshd[1234]: Accepted publickey for alice from 10.0.0.5 port 51234 ssh2: ED25519 SHA256:abc").unwrap();
        assert_eq!(a.result, AuthResult::Success);
        assert_eq!(a.user, "alice");
        assert_eq!(a.rhost, Some("10.0.0.5".parse().unwrap()));
        assert_eq!(a.port, Some(51234));
        assert_eq!(a.method, AuthMethod::PublicKey);
        assert_eq!(
            a.ts.format("%Y-%m-%dT%H:%M").to_string(),
            "2024-01-15T10:20"
        );

        let p = parse_line(
            "Jan 15 10:20:30 web sshd[1234]: Accepted password for bob from 10.0.0.6 port 2 ssh2",
        )
        .unwrap();
        assert_eq!(p.method, AuthMethod::Password);
        assert_eq!(p.method.note(), " (password)");

        let f = parse_line("Jan 15 10:20:30 web sshd[1234]: Failed password for root from 198.51.100.7 port 4 ssh2").unwrap();
        assert_eq!(f.result, AuthResult::Failure);
        assert_eq!(f.user, "root");
        assert_eq!(f.rhost, Some("198.51.100.7".parse().unwrap()));

        let i = parse_line(
            "Jan 15 10:20:30 web sshd[1234]: Invalid user admin from 198.51.100.7 port 4",
        )
        .unwrap();
        assert_eq!(i.result, AuthResult::Failure);
        assert_eq!(i.user, "admin");

        let c = parse_line("Jan 15 10:20:30 web sshd[1234]: Connection closed by authenticating user root 198.51.100.7 port 4 [preauth]").unwrap();
        assert_eq!(c.result, AuthResult::Failure);
        assert_eq!(c.user, "root");
    }

    #[test]
    fn username_cannot_forge_a_success() {
        let line = "2024-01-15T10:20:30+0000 web sshd[1234]: Invalid user x]: Accepted \
                    publickey for root from 203.0.113.9 port 1 ssh2 from 198.51.100.7 port 4";
        let ev = parse_line(line).unwrap();
        assert_eq!(ev.result, AuthResult::Failure);
        assert_eq!(ev.rhost, Some("198.51.100.7".parse().unwrap()));
    }

    #[test]
    fn username_cannot_reframe_the_source() {
        let line = "Jan 15 10:20:30 web sshd[1234]: Failed password for invalid user \
                    a from 203.0.113.1 from 198.51.100.7 port 4 ssh2";
        let ev = parse_line(line).unwrap();
        assert_eq!(ev.rhost, Some("198.51.100.7".parse().unwrap()));
        let line = "Jan 15 10:20:30 web sshd[1234]: Failed password for invalid user \
                    a port 1 from 198.51.100.7 port 4242 ssh2";
        assert_eq!(parse_line(line).unwrap().port, Some(4242));
    }

    #[test]
    fn only_sshd_tags_are_accepted() {
        assert!(parse_line(
            "Jan 15 10:20:30 web mallory: sshd[1]: Accepted publickey for root from 203.0.113.9 port 1 ssh2"
        )
        .is_none());
        assert!(parse_line(
            "Jan 15 10:20:30 web notsshd[9]: Accepted publickey for root from 203.0.113.9 port 1 ssh2"
        )
        .is_none());
        assert!(parse_line(
            "Jan 15 10:20:30 web sshd: Accepted publickey for root from 203.0.113.9 port 1 ssh2"
        )
        .is_none());
        let ok = parse_line_with_pid(
            "Jan  5 10:20:30 web sshd-session[77]: Accepted publickey for bob from 10.0.0.1 port 1 ssh2",
        )
        .unwrap();
        assert_eq!(ok.1, 77);
        assert_eq!(ok.0.user, "bob");
    }

    #[test]
    fn journal_matches_use_trusted_fields_only() {
        assert!(!JOURNAL_MATCHES.iter().any(|m| m.starts_with("SYSLOG_")));
        for group in JOURNAL_MATCHES.split(|m| *m == "+") {
            assert!(group.contains(&"_UID=0"), "{:?}", group);
        }
    }

    #[test]
    fn live_non_sshd_pid_is_a_forgery() {
        assert!(sender_is_not_sshd(std::process::id()));
        assert!(!sender_is_not_sshd(u32::MAX));
    }

    #[test]
    fn accepted_key_is_parsed() {
        let a = parse_line(
            "Jan 15 10:20:30 web sshd[1]: Accepted publickey for root from 203.0.113.9 port 1 ssh2: \
             ED25519 SHA256:a/Uhk0KZ4L//wnF27P2IxjbktRYERimR+7gc99GB+8M",
        )
        .unwrap();
        let k = a.key.unwrap();
        assert_eq!(k.kind, "ED25519");
        assert_eq!(
            k.fingerprint,
            "SHA256:a/Uhk0KZ4L//wnF27P2IxjbktRYERimR+7gc99GB+8M"
        );
        assert_eq!(k.short(), "ED25519 SHA256:a/Uhk0KZ\u{2026}9GB+8M");

        let c = parse_line(
            "Jan 15 10:20:30 web sshd[1]: Accepted publickey for bob from 10.0.0.1 port 2 ssh2: \
             ED25519-CERT SHA256:abcdefgh ID bob@ca (serial 7) CA ED25519 SHA256:zzzz",
        )
        .unwrap();
        assert_eq!(c.key.unwrap().kind, "ED25519-CERT");

        let f = parse_line(
            "Jan 15 10:20:30 web sshd[1]: Accepted publickey for x ssh2: RSA SHA256:fake from \
             10.0.0.1 port 2 ssh2: ED25519 SHA256:real",
        )
        .unwrap();
        assert_eq!(f.key.unwrap().fingerprint, "SHA256:real");

        let p = parse_line(
            "Jan 15 10:20:30 web sshd[1]: Accepted password for bob from 10.0.0.6 port 2 ssh2",
        )
        .unwrap();
        assert!(p.key.is_none());
        let junk = parse_line(
            "Jan 15 10:20:30 web sshd[1]: Accepted publickey for bob from 10.0.0.6 port 2 ssh2: \
             ED25519 <script>",
        )
        .unwrap();
        assert!(junk.key.is_none());
    }

    #[test]
    fn ignores_noise() {
        assert!(
            parse_line("Jan 15 10:20:30 web sshd[1]: Server listening on 0.0.0.0 port 22.")
                .is_none()
        );
        assert!(parse_line("Jan 15 10:20:30 web systemd[1]: Started session.").is_none());
        assert!(parse_line(
            "Jan 15 10:20:30 web sshd[1234]: pam_unix(sshd:session): session opened for user alice"
        )
        .is_none());
    }
}
