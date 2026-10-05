//! SSH session control and sshd settings, for the Telegram responses.

use std::net::IpAddr;

use anyhow::Result;

use crate::procsrc;

/// What `disconnect` did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Disconnected {
    pub connections: usize,
    pub processes: Vec<u32>,
}

/// Names sshd's per-connection processes go by.
fn is_sshd(comm: &str) -> bool {
    comm == "sshd" || comm == "sshd-session" || comm.starts_with("sshd:")
}

/// Established TCP connections from `source` (and `port`, when known) that
/// end at one of this host's sockets: the inodes of the SSH sessions to cut.
pub fn session_inodes(rows: &[procsrc::TcpEntry], source: IpAddr, port: Option<u16>) -> Vec<u64> {
    let same = |a: IpAddr, b: IpAddr| match (a, b) {
        (IpAddr::V6(v6), IpAddr::V4(v4)) | (IpAddr::V4(v4), IpAddr::V6(v6)) => {
            v6.to_ipv4_mapped() == Some(v4)
        }
        _ => a == b,
    };
    rows.iter()
        .filter(|r| r.state == procsrc::TCP_ESTABLISHED && r.inode != 0)
        .filter(|r| same(r.remote_addr, source))
        .filter(|r| port.is_none_or(|p| r.remote_port == p))
        .map(|r| r.inode)
        .collect()
}

/// End the SSH session(s) from `source` (`port` narrows it to one login).
///
/// Kills the sshd processes holding that connection. That closes the
/// session and its terminal; programs the user started get SIGHUP. Only
/// sshd processes are touched, so the same user's other sessions survive.
pub fn disconnect(source: IpAddr, port: Option<u16>) -> Result<Disconnected> {
    let rows = procsrc::read_tcp_tables();
    let inodes = session_inodes(&rows, source, port);
    if inodes.is_empty() {
        anyhow::bail!(
            "no open SSH connection from {}{}",
            source,
            port.map(|p| format!(" port {}", p)).unwrap_or_default()
        );
    }
    let mut killed = Vec::new();
    for pid in procsrc::all_pids_for_inodes(&inodes) {
        let comm = procsrc::comm_of(pid).unwrap_or_default();
        if !is_sshd(&comm) {
            continue;
        }
        // SAFETY: kill(2) on a pid we just read; failure is reported below.
        if unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) } == 0 {
            killed.push(pid);
        }
    }
    if killed.is_empty() {
        anyhow::bail!("found the connection but no sshd process to stop");
    }
    Ok(Disconnected {
        connections: inodes.len(),
        processes: killed,
    })
}

/// Whether root can log in over SSH with a password, from sshd's effective
/// configuration (`sshd -T` resolves includes and defaults). `None` if sshd
/// couldn't be asked.
pub fn root_password_login() -> Option<bool> {
    let sshd = ["/usr/sbin/sshd", "/sbin/sshd", "/usr/bin/sshd"]
        .into_iter()
        .find(|p| std::path::Path::new(p).is_file())?;
    let out = std::process::Command::new(sshd).arg("-T").output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(parse_root_password_login(&String::from_utf8_lossy(
        &out.stdout,
    )))
}

/// Last `sshd -T` answer: 0 unknown, 1 no, 2 yes.
static ROOT_PW: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// Ask sshd again and cache the answer (runs on a blocking thread).
pub fn refresh_root_password_login() {
    let v = match root_password_login() {
        Some(true) => 2,
        Some(false) => 1,
        None => 0,
    };
    if v != 0 {
        ROOT_PW.store(v, std::sync::atomic::Ordering::Relaxed);
    }
}

pub fn cached_root_password_login() -> Option<bool> {
    match ROOT_PW.load(std::sync::atomic::Ordering::Relaxed) {
        2 => Some(true),
        1 => Some(false),
        _ => None,
    }
}

fn parse_root_password_login(sshd_t: &str) -> bool {
    let get = |key: &str| {
        sshd_t
            .lines()
            .find_map(|l| l.strip_prefix(key).and_then(|v| v.strip_prefix(' ')))
            .map(|v| v.trim().to_ascii_lowercase())
    };
    let root_ok = get("permitrootlogin").as_deref() == Some("yes");
    let password = get("passwordauthentication").as_deref() == Some("yes")
        || get("kbdinteractiveauthentication").as_deref() == Some("yes");
    root_ok && password
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(remote: &str, port: u16, state: u8, inode: u64) -> procsrc::TcpEntry {
        procsrc::TcpEntry {
            proto: "tcp",
            local_addr: "10.0.0.2".parse().unwrap(),
            local_port: 22,
            remote_addr: remote.parse().unwrap(),
            remote_port: port,
            state,
            uid: 0,
            inode,
        }
    }

    #[test]
    fn only_that_sources_established_connections_match() {
        let rows = vec![
            row("198.51.100.7", 5000, procsrc::TCP_ESTABLISHED, 11),
            row("198.51.100.7", 5001, procsrc::TCP_ESTABLISHED, 12),
            row("198.51.100.7", 5002, procsrc::TCP_LISTEN, 13),
            row("203.0.113.9", 5000, procsrc::TCP_ESTABLISHED, 14),
            row("::ffff:198.51.100.7", 5003, procsrc::TCP_ESTABLISHED, 15),
        ];
        let ip: IpAddr = "198.51.100.7".parse().unwrap();
        assert_eq!(session_inodes(&rows, ip, Some(5001)), vec![12]);
        assert_eq!(session_inodes(&rows, ip, None), vec![11, 12, 15]);
    }

    #[test]
    fn root_password_login_needs_both_settings() {
        let on = "port 22\npermitrootlogin yes\npasswordauthentication yes\n";
        assert!(parse_root_password_login(on));
        let keys_only = "permitrootlogin prohibit-password\npasswordauthentication yes\n";
        assert!(!parse_root_password_login(keys_only));
        let no_pw =
            "permitrootlogin yes\npasswordauthentication no\nkbdinteractiveauthentication no\n";
        assert!(!parse_root_password_login(no_pw));
        let kbd =
            "permitrootlogin yes\npasswordauthentication no\nkbdinteractiveauthentication yes\n";
        assert!(parse_root_password_login(kbd));
    }

    /// A process named `sshd` holding a connection from 127.0.0.1:<port> is
    /// stopped; nothing else is touched. Uses python3 (skipped without it).
    #[test]
    fn disconnect_stops_the_sshd_holding_the_connection() {
        use std::io::{BufRead, BufReader};
        let script = "import ctypes,socket,sys\n\
                      ctypes.CDLL(None).prctl(15, b'sshd', 0, 0, 0)\n\
                      s=socket.socket(); s.bind(('127.0.0.1',0)); s.listen(1)\n\
                      print(s.getsockname()[1], flush=True)\n\
                      c,_=s.accept()\n\
                      import time; time.sleep(30)\n";
        let Ok(mut child) = std::process::Command::new("python3")
            .args(["-c", script])
            .stdout(std::process::Stdio::piped())
            .spawn()
        else {
            eprintln!("python3 not available; skipping");
            return;
        };
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let server_port: u16 = line.trim().parse().unwrap();
        let client = std::net::TcpStream::connect(("127.0.0.1", server_port)).unwrap();
        let client_port = client.local_addr().unwrap().port();
        // Wait until the fake sshd has accepted (the socket shows up as its).
        let src: IpAddr = "127.0.0.1".parse().unwrap();
        let mut result = None;
        for _ in 0..100 {
            match disconnect(src, Some(client_port)) {
                Ok(d) => {
                    result = Some(d);
                    break;
                }
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(20)),
            }
        }
        let d = result.expect("the fake sshd should have been found and stopped");
        assert_eq!(d.processes, vec![child.id()]);
        let status = child.wait().unwrap();
        assert!(!status.success(), "killed, not exited normally");
    }

    /// A real loopback connection is found by source and port, and only the
    /// process that's not sshd is left alone.
    #[test]
    fn finds_a_live_connection() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let c = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (_s, _) = l.accept().unwrap();
        let port = c.local_addr().unwrap().port();
        let rows = procsrc::read_tcp_tables();
        let inodes = session_inodes(&rows, "127.0.0.1".parse().unwrap(), Some(port));
        assert_eq!(inodes.len(), 1, "{:?}", inodes);
        let pids = procsrc::all_pids_for_inodes(&inodes);
        assert_eq!(pids, vec![std::process::id()]);
        // We aren't sshd, so disconnect refuses to kill us.
        assert!(disconnect("127.0.0.1".parse().unwrap(), Some(port)).is_err());
    }
}
