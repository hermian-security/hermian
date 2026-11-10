use std::net::{IpAddr, Ipv6Addr};
use std::time::Duration;

use anyhow::{Context, Result};
use hermian_core::Config;

pub const TABLE: &str = "hermian_block";

fn table_script() -> String {
    format!(
        "table inet {t} {{\n\
         \x20 set v4 {{ type ipv4_addr; flags timeout; }}\n\
         \x20 set v6 {{ type ipv6_addr; flags interval, timeout; }}\n\
         \x20 chain prerouting {{\n\
         \x20   type filter hook prerouting priority -300; policy accept;\n\
         \x20   ip saddr @v4 drop\n\
         \x20   ip6 saddr @v6 drop\n\
         \x20 }}\n\
         \x20 chain output {{\n\
         \x20   type filter hook output priority -300; policy accept;\n\
         \x20   ip daddr @v4 drop\n\
         \x20   ip6 daddr @v6 drop\n\
         \x20 }}\n\
         }}\n",
        t = TABLE
    )
}

const NFT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NftError {
    Missing,
    Timeout(Duration),
    Failed(String),
}

impl std::fmt::Display for NftError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NftError::Missing => write!(f, "nft isn't installed"),
            NftError::Timeout(t) => write!(f, "nft didn't finish within {}s", t.as_secs()),
            NftError::Failed(m) => write!(f, "nft said: {}", m),
        }
    }
}

impl std::error::Error for NftError {}

fn run_limited(
    mut cmd: std::process::Command,
    stdin: Option<&[u8]>,
    limit: Duration,
) -> std::result::Result<String, NftError> {
    use std::io::{Read, Write};
    use std::process::Stdio;
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    cmd.stdin(if stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    let mut child = cmd.spawn().map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => NftError::Missing,
        _ => NftError::Failed(e.to_string()),
    })?;
    if let (Some(input), Some(mut pipe)) = (stdin, child.stdin.take()) {
        let _ = pipe.write_all(input);
    }
    let reader = |pipe: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut p) = pipe {
                let _ = p.read_to_end(&mut buf);
            }
            buf
        })
    };
    let out = reader(
        child
            .stdout
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );
    let err = reader(
        child
            .stderr
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );
    let deadline = std::time::Instant::now() + limit;
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st,
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(NftError::Timeout(limit));
            }
        }
    };
    let stdout = out.join().unwrap_or_default();
    let stderr = err.join().unwrap_or_default();
    if status.success() {
        Ok(String::from_utf8_lossy(&stdout).into_owned())
    } else {
        let msg = String::from_utf8_lossy(&stderr);
        let first = msg.lines().map(str::trim).find(|l| !l.is_empty());
        Err(NftError::Failed(
            first.unwrap_or("it exited with an error").to_string(),
        ))
    }
}

fn nft(args: &[&str]) -> Result<String> {
    let mut cmd = crate::procsrc::system_command("nft");
    cmd.args(args);
    Ok(run_limited(cmd, None, NFT_TIMEOUT)?)
}

fn nft_script(script: &str) -> Result<()> {
    let mut cmd = crate::procsrc::system_command("nft");
    cmd.args(["-f", "-"]);
    run_limited(cmd, Some(script.as_bytes()), NFT_TIMEOUT)?;
    Ok(())
}

fn table_exists() -> bool {
    nft(&["list", "table", "inet", TABLE]).is_ok()
}

static NFT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn nft_lock() -> std::sync::MutexGuard<'static, ()> {
    NFT_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

fn ensure_table() -> Result<()> {
    if table_exists() {
        return Ok(());
    }
    nft_script(&table_script())
}

pub fn block_key(ip: IpAddr) -> (&'static str, String) {
    match ip {
        IpAddr::V4(v4) => ("v4", v4.to_string()),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => ("v4", v4.to_string()),
            None => {
                let net = u128::from(v6) & (u128::MAX << 64);
                ("v6", format!("{}/64", Ipv6Addr::from(net)))
            }
        },
    }
}

pub fn refusal(ip: IpAddr, cfg: &Config) -> Option<String> {
    let special = match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_link_local()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    };
    if special {
        return Some(format!(
            "{} is a loopback, link-local or other special address",
            ip
        ));
    }
    for c in &cfg.response.management_cidrs {
        if let Some(net) = hermian_core::allowlist::parse_cidr(c) {
            if cidr_contains(net, ip) || overlaps_v6_block(net, ip) {
                return Some(format!(
                    "{} is inside your management network {} (response.management_cidrs)",
                    ip, c
                ));
            }
        }
    }
    if cfg.allowlist.source_allowed(ip) {
        return Some(format!(
            "{} is an allowlisted SSH source (allowlist.ssh_sources)",
            ip
        ));
    }
    None
}

fn cidr_contains((net, prefix): (IpAddr, u32), ip: IpAddr) -> bool {
    match (net, ip) {
        (IpAddr::V4(n), IpAddr::V4(a)) => {
            let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
            u32::from(n) & mask == u32::from(a) & mask
        }
        (IpAddr::V6(n), IpAddr::V6(a)) => {
            let mask = u128::MAX.checked_shl(128 - prefix).unwrap_or(0);
            u128::from(n) & mask == u128::from(a) & mask
        }
        _ => false,
    }
}

fn overlaps_v6_block((net, prefix): (IpAddr, u32), ip: IpAddr) -> bool {
    match (net, ip) {
        (IpAddr::V6(n), IpAddr::V6(a)) => {
            let p = prefix.min(64);
            let mask = u128::MAX.checked_shl(128 - p).unwrap_or(0);
            u128::from(n) & mask == u128::from(a) & mask
        }
        _ => false,
    }
}

pub fn block(ip: IpAddr, hours: u32, cfg: &Config) -> Result<String> {
    if let Some(why) = refusal(ip, cfg) {
        anyhow::bail!("not blocking: {}", why);
    }
    let _guard = nft_lock();
    ensure_table()?;
    let (set, key) = block_key(ip);
    let _ = nft(&[
        "delete",
        "element",
        "inet",
        TABLE,
        set,
        &format!("{{ {} }}", key),
    ]);
    nft(&[
        "add",
        "element",
        "inet",
        TABLE,
        set,
        &format!("{{ {} timeout {}h }}", key, hours),
    ])?;
    Ok(key)
}

pub fn unblock(ip: IpAddr) -> Result<String> {
    let (set, key) = block_key(ip);
    let _guard = nft_lock();
    if !table_exists() {
        anyhow::bail!("nothing is blocked");
    }
    nft(&[
        "delete",
        "element",
        "inet",
        TABLE,
        set,
        &format!("{{ {} }}", key),
    ])
    .with_context(|| format!("{} isn't blocked", key))?;
    Ok(key)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blocked {
    pub key: String,
    pub expires: String,
}

pub fn list() -> Result<Vec<Blocked>> {
    if !table_exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for set in ["v4", "v6"] {
        out.extend(parse_set_listing(&nft(&[
            "list", "set", "inet", TABLE, set,
        ])?));
    }
    Ok(out)
}

fn parse_set_listing(text: &str) -> Vec<Blocked> {
    let Some(start) = text.find("elements = {") else {
        return Vec::new();
    };
    let body = &text[start + "elements = {".len()..];
    let body = body.split('}').next().unwrap_or("");
    body.split(',')
        .map(|e| e.split_whitespace().collect::<Vec<_>>())
        .filter(|w| !w.is_empty())
        .map(|w| {
            let expires = w
                .iter()
                .position(|x| *x == "expires")
                .and_then(|i| w.get(i + 1))
                .map(|s| s.to_string())
                .unwrap_or_default();
            Blocked {
                key: w[0].to_string(),
                expires,
            }
        })
        .collect()
}

pub fn remove_table() {
    if table_exists() {
        let _ = nft(&["delete", "table", "inet", TABLE]);
    }
}

pub fn cmd_blocked() -> Result<()> {
    crate::config::require_root()?;
    let st = crate::ui::Style::detect();
    let entries = list()?;
    if entries.is_empty() {
        println!("{}", st.dim("Nothing is blocked."));
        return Ok(());
    }
    for b in entries {
        println!(
            "  {:<40} {}",
            b.key,
            st.dim(&format!("expires in {}", b.expires))
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        let mut c = Config::default();
        c.response.management_cidrs = vec!["203.0.113.0/24".into(), "2001:db8:1::/48".into()];
        c
    }

    #[test]
    fn ipv6_blocks_cover_the_slash_64() {
        assert_eq!(
            block_key("198.51.100.7".parse().unwrap()),
            ("v4", "198.51.100.7".into())
        );
        assert_eq!(
            block_key("2001:db8:5:6:aaaa:bbbb:cccc:dddd".parse().unwrap()),
            ("v6", "2001:db8:5:6::/64".into())
        );
        assert_eq!(block_key("::ffff:198.51.100.7".parse().unwrap()).0, "v4");
    }

    #[test]
    fn management_and_special_addresses_are_refused() {
        let c = cfg();
        assert!(refusal("198.51.100.7".parse().unwrap(), &c).is_none());
        assert!(refusal("203.0.113.40".parse().unwrap(), &c).is_some());
        assert!(refusal("127.0.0.1".parse().unwrap(), &c).is_some());
        assert!(refusal("fe80::1".parse().unwrap(), &c).is_some());
        assert!(refusal("2001:db8:1:2::99".parse().unwrap(), &c).is_some());
        assert!(refusal("2001:db8:2::99".parse().unwrap(), &c).is_none());
    }

    #[test]
    fn nft_set_listing_is_parsed() {
        let text = "table inet hermian_block {\n\tset v4 {\n\t\ttype ipv4_addr\n\t\tflags timeout\n\t\telements = { 198.51.100.7 timeout 1d expires 23h59m58s948ms, 203.0.113.9 timeout 2h expires 1h2m }\n\t}\n}\n";
        let got = parse_set_listing(text);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].key, "198.51.100.7");
        assert_eq!(got[0].expires, "23h59m58s948ms");
        assert_eq!(got[1].key, "203.0.113.9");
        assert!(
            parse_set_listing("table inet hermian_block { set v4 { type ipv4_addr } }").is_empty()
        );
    }

    #[test]
    #[ignore]
    fn live_block_list_unblock() {
        let c = cfg();
        let v4: IpAddr = "198.51.100.7".parse().unwrap();
        let v6: IpAddr = "2001:db8:9:9::1".parse().unwrap();
        assert_eq!(block(v4, 24, &c).unwrap(), "198.51.100.7");
        assert_eq!(block(v6, 1, &c).unwrap(), "2001:db8:9:9::/64");
        block(v4, 24, &c).unwrap();
        remove_table();
        let presses: Vec<_> = ["198.51.100.8", "198.51.100.9"]
            .iter()
            .map(|ip| {
                let c = c.clone();
                let ip: IpAddr = ip.parse().unwrap();
                std::thread::spawn(move || block(ip, 24, &c))
            })
            .collect();
        for p in presses {
            p.join().unwrap().unwrap();
        }
        block(v4, 24, &c).unwrap();
        block(v6, 1, &c).unwrap();
        assert!(block("203.0.113.5".parse().unwrap(), 24, &c).is_err());
        let l = list().unwrap();
        assert!(
            l.iter()
                .any(|b| b.key == "198.51.100.7" && !b.expires.is_empty()),
            "{:?}",
            l
        );
        assert!(l.iter().any(|b| b.key == "2001:db8:9:9::/64"), "{:?}", l);
        let rules = nft(&["list", "table", "inet", TABLE]).unwrap();
        assert_eq!(rules.matches("ip saddr @v4 drop").count(), 1, "{}", rules);
        unblock(v4).unwrap();
        unblock("198.51.100.8".parse().unwrap()).unwrap();
        unblock("198.51.100.9".parse().unwrap()).unwrap();
        unblock("2001:db8:9:9::abcd".parse().unwrap()).unwrap();
        assert!(list().unwrap().is_empty());
        remove_table();
        assert!(!table_exists());
    }

    #[test]
    #[ignore]
    fn nft_accepts_the_block_table() {
        use std::io::Write;
        let mut child = crate::procsrc::system_command("nft")
            .args(["-c", "-f", "-"])
            .stdin(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("nft must be installed");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(table_script().as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn nft_problems_come_back_typed() {
        use std::process::Command;
        let sh = |script: &str| {
            let mut c = Command::new("sh");
            c.args(["-c", script]);
            c
        };
        assert_eq!(
            run_limited(Command::new("/nonexistent/nft"), None, NFT_TIMEOUT),
            Err(NftError::Missing)
        );
        assert_eq!(
            run_limited(sh("sleep 5"), None, Duration::from_millis(200)),
            Err(NftError::Timeout(Duration::from_millis(200)))
        );
        assert_eq!(
            run_limited(
                sh("printf '\nError: no such set\nmore\n' >&2; exit 1"),
                None,
                NFT_TIMEOUT
            ),
            Err(NftError::Failed("Error: no such set".into()))
        );
        assert_eq!(
            run_limited(sh("cat"), Some(b"fed in"), NFT_TIMEOUT).as_deref(),
            Ok("fed in")
        );
        let big = run_limited(
            sh("head -c 300000 /dev/zero | tr '\\0' x"),
            None,
            NFT_TIMEOUT,
        );
        assert_eq!(big.map(|o| o.len()), Ok(300_000));
    }
}
