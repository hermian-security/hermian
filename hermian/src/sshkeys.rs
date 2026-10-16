//! Which authorized_keys line a public-key login used.
//!
//! sshd logs the accepted key's fingerprint (`ssh2: ED25519 SHA256:...`).
//! This finds that key in the user's authorized_keys files by fingerprinting
//! every key there the way `ssh-keygen -l` does: SHA-256 of the decoded key
//! blob, base64 without padding. No process is spawned per login; `sshd -T`
//! (for `AuthorizedKeysFile`) is asked at most every ten minutes.

use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use hermian_core::SshKey;
use sha2::{Digest, Sha256};

/// Largest authorized_keys file read; bigger ones are skipped.
const MAX_FILE: u64 = 1 << 20;
/// Longest comment kept for alerts.
const MAX_COMMENT: usize = 100;

/// One key line of an authorized_keys file.
#[derive(Debug, PartialEq, Eq)]
pub struct Entry {
    /// 1-based.
    pub line: usize,
    pub fingerprint: String,
    pub comment: Option<String>,
}

/// Fill in `key.file`, `key.line` and `key.comment` from `user`'s
/// authorized_keys, if the fingerprint is there. Certificates are signed by
/// a CA rather than listed, so they're left as they are.
pub fn resolve(user: &str, key: &mut SshKey) {
    if key.kind.ends_with("-CERT") {
        return;
    }
    let Some(home) = home_of(user) else {
        return;
    };
    for path in key_files(user, &home) {
        let Some(content) = read_regular(&path) else {
            continue;
        };
        if let Some(e) = parse_authorized_keys(&content)
            .into_iter()
            .find(|e| e.fingerprint == key.fingerprint)
        {
            key.file = Some(path.display().to_string());
            key.line = Some(e.line);
            key.comment = e.comment;
            return;
        }
    }
}

/// Every key line in `content`, fingerprinted. Options before the key
/// (`command="..." ssh-ed25519 AAAA... comment`) are skipped by looking for
/// a key-type word whose next word decodes to a blob of that same type, so
/// a type name inside a quoted option can't be mistaken for the key.
pub fn parse_authorized_keys(content: &str) -> Vec<Entry> {
    let mut out = Vec::new();
    for (i, raw) in content.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let words: Vec<&str> = line.split_whitespace().collect();
        for (w, ty) in words.iter().enumerate() {
            if !is_key_type(ty) {
                continue;
            }
            let Some(blob) = words.get(w + 1).and_then(|b| b64_decode(b)) else {
                continue;
            };
            if !blob_has_type(&blob, ty) {
                continue;
            }
            let comment = words[w + 2..].join(" ");
            out.push(Entry {
                line: i + 1,
                fingerprint: fingerprint(&blob),
                comment: clean_comment(&comment),
            });
            break;
        }
    }
    out
}

/// "SHA256:<base64, no padding>", as `ssh-keygen -l` prints it.
pub fn fingerprint(blob: &[u8]) -> String {
    format!("SHA256:{}", b64_encode_nopad(&Sha256::digest(blob)))
}

fn is_key_type(w: &str) -> bool {
    matches!(
        w,
        "ssh-ed25519"
            | "ssh-rsa"
            | "ssh-dss"
            | "ecdsa-sha2-nistp256"
            | "ecdsa-sha2-nistp384"
            | "ecdsa-sha2-nistp521"
            | "sk-ssh-ed25519@openssh.com"
            | "sk-ecdsa-sha2-nistp256@openssh.com"
    )
}

/// A key blob starts with its own type as a length-prefixed string.
fn blob_has_type(blob: &[u8], ty: &str) -> bool {
    if blob.len() < 4 {
        return false;
    }
    let n = u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]) as usize;
    blob.get(4..4 + n) == Some(ty.as_bytes())
}

/// Printable, single-line, bounded: comments end up in chat messages.
fn clean_comment(c: &str) -> Option<String> {
    let c: String = c
        .chars()
        .filter(|ch| !ch.is_control())
        .take(MAX_COMMENT)
        .collect();
    let c = c.trim().to_string();
    (!c.is_empty()).then_some(c)
}

/// The user's home directory from /etc/passwd.
fn home_of(user: &str) -> Option<PathBuf> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    home_in(&passwd, user)
}

fn home_in(passwd: &str, user: &str) -> Option<PathBuf> {
    passwd.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() >= 7 && f[0] == user && f[5].starts_with('/')).then(|| PathBuf::from(f[5]))
    })
}

/// The files sshd reads keys from for `user`, from `AuthorizedKeysFile`.
fn key_files(user: &str, home: &Path) -> Vec<PathBuf> {
    expand_key_files(&authorized_keys_setting(), user, home)
}

/// `AuthorizedKeysFile` tokens: `%h` home, `%u` user, `%%` a percent sign;
/// relative paths are relative to the home directory. `none` means none.
fn expand_key_files(setting: &str, user: &str, home: &Path) -> Vec<PathBuf> {
    setting
        .split_whitespace()
        .filter(|t| *t != "none")
        .take(8)
        .filter_map(|t| {
            let mut out = String::new();
            let mut chars = t.chars();
            while let Some(c) = chars.next() {
                if c != '%' {
                    out.push(c);
                    continue;
                }
                match chars.next() {
                    Some('h') => out.push_str(&home.display().to_string()),
                    Some('u') => out.push_str(user),
                    Some('%') => out.push('%'),
                    // Other tokens (%U, %f, ...) aren't worth guessing.
                    _ => return None,
                }
            }
            let p = PathBuf::from(out);
            Some(if p.is_absolute() { p } else { home.join(p) })
        })
        .collect()
}

const DEFAULT_KEY_FILES: &str = ".ssh/authorized_keys .ssh/authorized_keys2";

/// `authorizedkeysfile` from `sshd -T`, cached for ten minutes.
fn authorized_keys_setting() -> String {
    static CACHE: Mutex<Option<(Instant, String)>> = Mutex::new(None);
    let mut c = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((at, v)) = c.as_ref() {
        if at.elapsed() < Duration::from_secs(600) {
            return v.clone();
        }
    }
    let v = sshd_authorized_keys_file().unwrap_or_else(|| DEFAULT_KEY_FILES.to_string());
    *c = Some((Instant::now(), v.clone()));
    v
}

fn sshd_authorized_keys_file() -> Option<String> {
    let sshd = ["/usr/sbin/sshd", "/sbin/sshd", "/usr/bin/sshd"]
        .into_iter()
        .find(|p| Path::new(p).is_file())?;
    let out = std::process::Command::new(sshd).arg("-T").output().ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout).lines().find_map(|l| {
        l.strip_prefix("authorizedkeysfile ")
            .map(|v| v.trim().to_string())
    })
}

/// Read a regular file without ever blocking: the user owns this path, and
/// a FIFO there must not stall the auth reader.
fn read_regular(path: &Path) -> Option<String> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    let meta = f.metadata().ok()?;
    if !meta.is_file() || meta.len() > MAX_FILE {
        return None;
    }
    let mut s = String::new();
    f.take(MAX_FILE).read_to_string(&mut s).ok()?;
    Some(s)
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_encode_nopad(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let chars = chunk.len() + 1;
        for i in 0..chars {
            out.push(B64[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

/// Standard base64 with optional padding; `None` on anything else.
fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim_end_matches('=');
    if s.is_empty() || s.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for c in s.bytes() {
        let v = B64.iter().position(|&b| b == c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // `ssh-keygen -t ed25519 -C mohamed@laptop`, and what `ssh-keygen -lf`
    // prints for it.
    const KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICxgK1FBnWPQpbUiTaDLrWMKoqJSh/qj6dYN4vfuBeSX";
    const FP: &str = "SHA256:a/Uhk0KZ4L//wnF27P2IxjbktRYERimR+7gc99GB+8M";

    #[test]
    fn base64_round_trips() {
        for data in [&b""[..], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"] {
            if data.is_empty() {
                continue;
            }
            let enc = b64_encode_nopad(data);
            assert_eq!(b64_decode(&enc).unwrap(), data, "{}", enc);
        }
        assert_eq!(b64_encode_nopad(b"foobar"), "Zm9vYmFy");
        assert_eq!(b64_encode_nopad(b"fo"), "Zm8");
        assert_eq!(b64_decode("Zm8=").unwrap(), b"fo");
        assert!(b64_decode("Zm9v!").is_none());
    }

    // An RSA key (padding in its base64) and its `ssh-keygen -lf` output.
    const RSA: &str = "AAAAB3NzaC1yc2EAAAADAQABAAABAQCTQByryahUQV3SIspiectL89QQIsOWaoj0AF8eBlXWrwHXmfbkrjSwaUJ6W0qsdSFWtzK3tbORxf7zeXXoAsRW30yHHg68gte/XsyfLZf7XqeLIYJlWGaE4bON3cJhGI5uukRpxY9zAV/2dyKTI5mV5BWaHfamBcxj1gdnhcXHP3BqQct0PRuU3zTP9Jf52qP9K6tybMp6lAHUhv9RxMc/SOVXGe1UuoA7jECw6VI/p1HpnoVRNkjGDpWyEruhXMswnFB00pfQVh3z86f5VuLB2ftf0dBOyIrsVVNiY2vDBzzlg3AIRnFmaHBe8NsoIkPopwc2645LhRuR2yyDuNtH";
    const RSA_FP: &str = "SHA256:T2rIZudaMSj7sXDCrWRQuLXpXJNVuz9X3GY7DZTM1EM";

    #[test]
    fn fingerprints_match_ssh_keygen() {
        let blob = b64_decode(KEY.split_whitespace().nth(1).unwrap()).unwrap();
        assert!(blob_has_type(&blob, "ssh-ed25519"));
        assert_eq!(fingerprint(&blob), FP);
        let blob = b64_decode(RSA).unwrap();
        assert!(blob_has_type(&blob, "ssh-rsa"));
        assert_eq!(fingerprint(&blob), RSA_FP);
    }

    #[test]
    fn finds_the_key_line_past_options_and_comments() {
        let file = format!(
            "# deploy keys\n\n\
             command=\"ssh-rsa not-a-key\",no-pty ssh-ed25519 AAAA!corrupt ci\n\
             from=\"10.0.0.0/8\" {} mohamed@laptop  work\x07\n",
            KEY
        );
        let entries = parse_authorized_keys(&file);
        let e = entries.iter().find(|e| e.fingerprint == FP).unwrap();
        assert_eq!(e.line, 4);
        assert_eq!(e.comment.as_deref(), Some("mohamed@laptop work"));
        // The quoted "ssh-rsa" option and the corrupt blob aren't keys.
        assert_eq!(entries.len(), 1, "{:?}", entries);
    }

    #[test]
    fn key_files_follow_authorized_keys_file() {
        let home = Path::new("/home/alice");
        assert_eq!(
            expand_key_files(DEFAULT_KEY_FILES, "alice", home),
            vec![
                PathBuf::from("/home/alice/.ssh/authorized_keys"),
                PathBuf::from("/home/alice/.ssh/authorized_keys2")
            ]
        );
        assert_eq!(
            expand_key_files("/etc/ssh/keys/%u %h/.keys %%x none", "alice", home),
            vec![
                PathBuf::from("/etc/ssh/keys/alice"),
                PathBuf::from("/home/alice/.keys"),
                PathBuf::from("/home/alice/%x")
            ]
        );
        assert!(expand_key_files("/keys/%U", "alice", home).is_empty());
    }

    #[test]
    fn home_comes_from_passwd() {
        let passwd = "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/sh\n";
        assert_eq!(home_in(passwd, "alice"), Some(PathBuf::from("/home/alice")));
        assert_eq!(home_in(passwd, "bob"), None);
    }

    #[test]
    fn a_fifo_is_never_read() {
        let dir = std::env::temp_dir().join(format!("hermian-fifo-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let fifo = dir.join("authorized_keys");
        let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        // Would block forever with a plain open/read.
        assert!(read_regular(&fifo).is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
