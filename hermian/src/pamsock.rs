//! Datagram socket receiving auth events from `pam_hermian.so`.

use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixDatagram;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use hermian_core::{AuthEvent, AuthResult, Event};
use tokio::sync::mpsc;

use crate::paths;

pub fn pam_module_installed() -> bool {
    std::path::Path::new(paths::PAM_MODULE_PATH).exists()
}

pub fn spawn_pam_listener(
    tx: mpsc::Sender<Event>,
    shutdown: Arc<AtomicBool>,
    forward_attempts: bool,
) -> Result<()> {
    let dir = paths::run_dir();
    std::fs::create_dir_all(&dir)?;
    // The PAM module runs as root inside sshd; keep the dir private but the
    // socket itself must be writable by root only, which is the default.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    let path = paths::pam_socket();
    let _ = std::fs::remove_file(&path);
    let sock = UnixDatagram::bind(&path).with_context(|| format!("bind {}", path.display()))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    sock.set_read_timeout(Some(Duration::from_secs(1)))?;

    std::thread::Builder::new()
        .name("hermian-pam".to_string())
        .spawn(move || pam_listener_loop(sock, tx, shutdown, forward_attempts))?;
    Ok(())
}

/// Whether a PAM event should reach the engine. See `spawn_pam_listener`.
fn keep_event(ev: &AuthEvent, forward_attempts: bool) -> bool {
    forward_attempts || ev.result != AuthResult::Attempt
}

/// Larger than any datagram the module sends. The username is chosen by the
/// remote client; a 4 KiB buffer truncated long ones, the JSON then failed to
/// parse and the attempt vanished, so long usernames hid brute force.
const MAX_DATAGRAM: usize = 64 * 1024;

fn pam_listener_loop(
    sock: UnixDatagram,
    tx: mpsc::Sender<Event>,
    shutdown: Arc<AtomicBool>,
    forward_attempts: bool,
) {
    let mut buf = vec![0u8; MAX_DATAGRAM];
    while !shutdown.load(Ordering::Relaxed) {
        match sock.recv(&mut buf) {
            Ok(n) if n > 0 => {
                let parsed = parse_pam_payload(&String::from_utf8_lossy(&buf[..n]))
                    .filter(|ev| keep_event(ev, forward_attempts));
                if let Some(ev) = parsed {
                    if tx.blocking_send(Event::Auth(ev)).is_err() {
                        break;
                    }
                }
            }
            Ok(_) => {}
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => std::thread::sleep(Duration::from_millis(200)),
        }
    }
    let _ = std::fs::remove_file(paths::pam_socket());
}

pub fn parse_pam_payload(payload: &str) -> Option<AuthEvent> {
    let v: serde_json::Value = serde_json::from_str(payload).ok()?;
    let result = match v.get("result")?.as_str()? {
        "attempt" => AuthResult::Attempt,
        "success" => AuthResult::Success,
        "failure" => AuthResult::Failure,
        _ => return None,
    };
    let user = v.get("user")?.as_str()?.to_string();
    if user.is_empty() {
        return None;
    }
    let service = v
        .get("service")
        .and_then(|s| s.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("sshd")
        .to_string();
    let tty = v
        .get("tty")
        .and_then(|s| s.as_str())
        .unwrap_or("")
        .to_string();
    let rhost = v
        .get("rhost")
        .and_then(|s| s.as_str())
        .filter(|s| !s.is_empty())
        .and_then(|s| s.parse().ok());
    // The module stamps the time it saw the attempt; it's sent a moment ago,
    // so anything far off means a bad clock or a bad sender. Use now then.
    let now = chrono::Utc::now();
    let ts = v
        .get("ts")
        .and_then(|t| t.as_u64())
        .and_then(|secs| chrono::DateTime::from_timestamp(secs.min(i64::MAX as u64) as i64, 0))
        .filter(|t| (*t - now).num_seconds().abs() <= 60)
        .unwrap_or(now);
    Some(AuthEvent {
        ts,
        result,
        user,
        rhost,
        service,
        tty,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_module_payload() {
        let ev = parse_pam_payload(r#"{"ts":1700000000,"result":"success","user":"alice","rhost":"10.0.0.5","service":"sshd","tty":"ssh"}"#).unwrap();
        assert_eq!(ev.result, AuthResult::Success);
        assert_eq!(ev.user, "alice");
        assert_eq!(ev.rhost, Some("10.0.0.5".parse().unwrap()));
        assert!(parse_pam_payload(r#"{"result":"success","user":""}"#).is_none());
        assert!(parse_pam_payload("garbage").is_none());
    }

    #[test]
    fn attempts_are_dropped_when_logs_cover_failures() {
        let attempt = parse_pam_payload(r#"{"result":"attempt","user":"x"}"#).unwrap();
        let success = parse_pam_payload(r#"{"result":"success","user":"x"}"#).unwrap();
        assert!(!keep_event(&attempt, false));
        assert!(keep_event(&success, false));
        assert!(keep_event(&attempt, true));
    }

    #[test]
    fn bad_sender_timestamps_fall_back_to_now() {
        let ev = parse_pam_payload(r#"{"ts":99999999999,"result":"failure","user":"x"}"#).unwrap();
        assert!((ev.ts - chrono::Utc::now()).num_seconds().abs() < 5);
    }

    #[test]
    fn long_usernames_still_arrive() {
        let dir = std::env::temp_dir().join(format!("hermian-pam-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("s");
        let rx = UnixDatagram::bind(&path).unwrap();
        let tx = UnixDatagram::unbound().unwrap();
        let payload = serde_json::json!({
            "result": "attempt",
            "user": "a".repeat(20_000),
            "rhost": "198.51.100.7",
        })
        .to_string();
        tx.send_to(payload.as_bytes(), &path).unwrap();
        let mut buf = vec![0u8; MAX_DATAGRAM];
        let n = rx.recv(&mut buf).unwrap();
        let ev = parse_pam_payload(&String::from_utf8_lossy(&buf[..n])).unwrap();
        assert_eq!(ev.rhost, Some("198.51.100.7".parse().unwrap()));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
