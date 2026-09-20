//! `pam_hermian.so` - a passive PAM module that reports authentication
//! outcomes to the HERMIAN daemon over a local datagram socket.
//!
//! It never influences the authentication decision (always returns
//! `PAM_IGNORE`), never reads credentials, and fails silently when the daemon
//! is not running so it can never lock anyone out.
//!
//! Recommended `/etc/pam.d/sshd` lines (installed by `hermian enable --with-pam`):
//! ```text
//! auth    optional pam_hermian.so
//! session optional pam_hermian.so
//! ```

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

unsafe fn get_item(pamh: *const c_void, item_type: c_int) -> String {
    let mut raw: *const c_void = std::ptr::null();
    if pam_get_item(pamh, item_type, &mut raw) != PAM_SUCCESS || raw.is_null() {
        return String::new();
    }
    CStr::from_ptr(raw as *const c_char)
        .to_string_lossy()
        .into_owned()
}

fn report(pamh: *const c_void, result: &str) {
    // SAFETY: pamh is a live handle supplied by libpam for the duration of the call.
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
    let payload = serde_json::json!({
        "ts": ts,
        "result": result,
        "user": user,
        "rhost": rhost,
        "service": service,
        "tty": tty,
    });
    send_datagram(&payload.to_string());
}

fn send_datagram(payload: &str) {
    // SAFETY: plain socket/sendto/close on a freshly created fd; sockaddr_un is
    // zero-initialised and the path is NUL-terminated and shorter than sun_path.
    unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return;
        }
        let mut addr: libc::sockaddr_un = std::mem::zeroed();
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let n = SOCKET_PATH.len().min(addr.sun_path.len());
        for (dst, src) in addr.sun_path.iter_mut().zip(SOCKET_PATH.iter().take(n)) {
            *dst = *src as libc::c_char;
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

/// Called for every authentication attempt, before the outcome is known.
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

/// `setcred` runs on both success and failure paths, so it carries no signal.
#[no_mangle]
pub extern "C" fn pam_sm_setcred(
    _pamh: *mut c_void,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_IGNORE
}

/// A session only opens after successful authentication - the reliable signal.
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
