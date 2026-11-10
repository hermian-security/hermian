use std::ffi::{c_char, c_int, c_void, CStr};
use std::time::{SystemTime, UNIX_EPOCH};

const PAM_SUCCESS: c_int = 0;
const PAM_IGNORE: c_int = 25;

const PAM_SERVICE: c_int = 1;
const PAM_USER: c_int = 2;
const PAM_TTY: c_int = 3;
const PAM_RHOST: c_int = 4;

const SOCKET_PATH: &[u8] = b"/run/hermian/pam.sock\0";

#[link(name = "pam")]
extern "C" {
    fn pam_get_item(pamh: *const c_void, item_type: c_int, item: *mut *const c_void) -> c_int;
}

const MAX_FIELD_CHARS: usize = 512;

unsafe fn get_item(pamh: *const c_void, item_type: c_int) -> String {
    let mut raw: *const c_void = std::ptr::null();
    if pam_get_item(pamh, item_type, &mut raw) != PAM_SUCCESS || raw.is_null() {
        return String::new();
    }
    let s = CStr::from_ptr(raw as *const c_char).to_string_lossy();
    clip(&s)
}

fn clip(s: &str) -> String {
    if s.chars().count() <= MAX_FIELD_CHARS {
        return s.to_string();
    }
    let mut out: String = s.chars().take(MAX_FIELD_CHARS.saturating_sub(1)).collect();
    out.push('\u{2026}');
    out
}

fn report(pamh: *const c_void, result: &str) {
    let (user, rhost, service, tty) = unsafe {
        (
            get_item(pamh, PAM_USER),
            get_item(pamh, PAM_RHOST),
            get_item(pamh, PAM_SERVICE),
            get_item(pamh, PAM_TTY),
        )
    };
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    send_datagram(&payload(ts, result, &user, &rhost, &service, &tty));
}

fn payload(ts: u64, result: &str, user: &str, rhost: &str, service: &str, tty: &str) -> String {
    let mut out =
        String::with_capacity(64 + 6 * (user.len() + rhost.len() + service.len() + tty.len()));
    out.push_str("{\"ts\":");
    out.push_str(&ts.to_string());
    for (k, v) in [
        ("result", result),
        ("user", user),
        ("rhost", rhost),
        ("service", service),
        ("tty", tty),
    ] {
        out.push_str(",\"");
        out.push_str(k);
        out.push_str("\":\"");
        json_escape_into(&mut out, v);
        out.push('"');
    }
    out.push('}');
    out
}

fn json_escape_into(out: &mut String, s: &str) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let b = c as u32;
                out.push_str("\\u00");
                for nib in [(b >> 4) & 0xf, b & 0xf] {
                    if let Some(h) = HEX.get(nib as usize) {
                        out.push(char::from(*h));
                    }
                }
            }
            c => out.push(c),
        }
    }
}

fn send_datagram(payload: &str) {
    unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return;
        }
        let mut addr: libc::sockaddr_un = std::mem::zeroed();
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let n = SOCKET_PATH.len().min(addr.sun_path.len());
        for (dst, src) in addr.sun_path.iter_mut().zip(SOCKET_PATH.iter().take(n)) {
            *dst = libc::c_char::from_ne_bytes([*src]);
        }
        let len = (std::mem::size_of::<libc::sa_family_t>() + n) as libc::socklen_t;
        let _ = libc::sendto(
            fd,
            payload.as_ptr() as *const c_void,
            payload.len(),
            libc::MSG_DONTWAIT,
            &addr as *const libc::sockaddr_un as *const libc::sockaddr,
            len,
        );
        libc::close(fd);
    }
}

#[no_mangle]
pub extern "C" fn pam_sm_authenticate(
    pamh: *mut c_void,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    report(pamh, "attempt");
    PAM_IGNORE
}

#[no_mangle]
pub extern "C" fn pam_sm_setcred(
    _pamh: *mut c_void,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_IGNORE
}

#[no_mangle]
pub extern "C" fn pam_sm_open_session(
    pamh: *mut c_void,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    report(pamh, "success");
    PAM_IGNORE
}

#[no_mangle]
pub extern "C" fn pam_sm_close_session(
    _pamh: *mut c_void,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_IGNORE
}

#[no_mangle]
pub extern "C" fn pam_sm_acct_mgmt(
    _pamh: *mut c_void,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_IGNORE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_is_valid_json_with_hostile_fields() {
        let user = "eve\"},\"result\":\"success\\\n\u{1}x";
        let p = payload(1700000000, "attempt", user, "198.51.100.7", "sshd", "ssh");
        let v: serde_json::Value = serde_json::from_str(&p).unwrap();
        assert_eq!(v["ts"], 1700000000);
        assert_eq!(v["result"], "attempt");
        assert_eq!(v["user"], user);
        assert_eq!(v["rhost"], "198.51.100.7");
        assert!(!p.contains('\n'));
    }

    #[test]
    fn fields_are_clipped_on_a_char_boundary() {
        assert_eq!(clip("alice"), "alice");
        let long = "é".repeat(MAX_FIELD_CHARS + 50);
        let c = clip(&long);
        assert_eq!(c.chars().count(), MAX_FIELD_CHARS);
        assert!(c.ends_with('\u{2026}'));
    }
}
