//! SSH authentication source without the PAM module.
//!
//! Prefers tailing a classic auth log; on journald-only hosts (Debian 12+,
//! Ubuntu 22.04+, Fedora, Arch) it follows `journalctl -u ssh -u sshd -f`.
//! Timestamps come from the log line so bursts are measured correctly even
//! when the daemon catches up after a stall.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::net::IpAddr;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use chrono::{DateTime, Utc};
use hermian_core::{AuthEvent, AuthResult, Event};
use tokio::sync::mpsc;

const AUTH_LOG_CANDIDATES: &[&str] = &["/var/log/auth.log", "/var/log/secure"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthSource {
    File,
    Journal,
    None,
}

pub fn detect_source() -> AuthSource {
    if AUTH_LOG_CANDIDATES
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

fn file_loop(tx: mpsc::Sender<Event>, shutdown: Arc<AtomicBool>) {
    while !shutdown.load(Ordering::Relaxed) {
        let Some((mut reader, path)) = open_log() else {
            std::thread::sleep(Duration::from_secs(30));
            continue;
        };
        let _ = reader.seek(SeekFrom::End(0));
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
                    // Detect rotation (file replaced or truncated) every ~10s.
                    if idle_polls >= 20 {
                        idle_polls = 0;
                        let rotated = std::fs::metadata(path)
                            .map(|m| m.len() < reader.stream_position().unwrap_or(0))
                            .unwrap_or(true);
                        if rotated {
                            break;
                        }
                    }
                }
                Ok(_) => {
                    idle_polls = 0;
                    if let Some(ev) = parse_line(&line) {
                        if tx.blocking_send(Event::Auth(ev)).is_err() {
                            return;
                        }
                    }
                }
                Err(_) => break,
            }
        }
    }
}

fn spawn_journalctl() -> std::io::Result<Child> {
    Command::new("journalctl")
        .args([
            "-f",
            "-n",
            "0",
            "-o",
            "short-iso",
            "--no-pager",
            "-q",
            "_COMM=sshd",
            "+",
            "_COMM=sshd-session",
            "+",
            "SYSLOG_IDENTIFIER=sshd",
        ])
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
                Ok(0) => break, // journalctl exited
                Ok(_) => {
                    if let Some(ev) = parse_line(&line) {
                        if tx.blocking_send(Event::Auth(ev)).is_err() {
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

/// Parse a syslog / journal `short-iso` sshd line into an [`AuthEvent`].
pub fn parse_line(line: &str) -> Option<AuthEvent> {
    let line = line.trim();
    if !line.contains("sshd") {
        return None;
    }
    let ts = parse_timestamp(line).unwrap_or_else(Utc::now);
    let msg = line.rsplit_once("]: ").map(|(_, m)| m).unwrap_or(line);
    let lower = msg.to_ascii_lowercase();

    if lower.starts_with("accepted ") {
        // Accepted publickey for alice from 10.0.0.5 port 51234 ssh2: ED25519 SHA256:...
        let user = word_after(msg, " for ")?;
        return Some(AuthEvent {
            ts,
            result: AuthResult::Success,
            user,
            rhost: extract_rhost(msg),
            service: "sshd".into(),
            tty: "ssh".into(),
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
        });
    }
    None
}

fn parse_timestamp(line: &str) -> Option<DateTime<Utc>> {
    let first = line.split_whitespace().next()?;
    // journalctl -o short-iso: 2024-01-15T10:20:30+0000
    if let Ok(dt) = DateTime::parse_from_str(first, "%Y-%m-%dT%H:%M:%S%z") {
        return Some(dt.with_timezone(&Utc));
    }
    // rsyslog RFC3339 (Debian/Ubuntu default): 2024-01-15T10:20:30.123456+00:00
    if let Ok(dt) = DateTime::parse_from_rfc3339(first) {
        return Some(dt.with_timezone(&Utc));
    }
    // Classic "Jan 15 10:20:30" has no year/zone; use now.
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

fn extract_rhost(msg: &str) -> Option<IpAddr> {
    let from = msg.find(" from ")?;
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
    fn accepted_and_failed_lines() {
        let a = parse_line("2024-01-15T10:20:30+0000 web sshd[1234]: Accepted publickey for alice from 10.0.0.5 port 51234 ssh2: ED25519 SHA256:abc").unwrap();
        assert_eq!(a.result, AuthResult::Success);
        assert_eq!(a.user, "alice");
        assert_eq!(a.rhost, Some("10.0.0.5".parse().unwrap()));
        assert_eq!(
            a.ts.format("%Y-%m-%dT%H:%M").to_string(),
            "2024-01-15T10:20"
        );

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
