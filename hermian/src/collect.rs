//! `hermian collect <ref>`: assemble a forensic context bundle for an alert.

use std::fs;

use anyhow::Result;
use chrono::Duration;
use hermian_core::{render, Theme};

use crate::cli::CollectArgs;
use crate::ui::Style;
use crate::{alerts, config, paths, procsrc};

/// Files at or above this size are hashed but not copied into the bundle.
const MAX_COPY: u64 = 4 * 1024 * 1024;

fn sha256_reader(r: &mut impl std::io::Read) -> std::io::Result<String> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

pub fn run(args: &CollectArgs) -> Result<()> {
    config::require_root()?;
    let alert = alerts::load_alert(&args.ref_id)?;
    let ref_id = alert.ref_id.clone();

    let bundle_dir = paths::collections_dir().join(&ref_id);
    fs::create_dir_all(&bundle_dir)?;

    let mut report = String::new();
    let hr = "\u{2500}".repeat(72);
    report.push_str(&format!("HERMIAN context bundle  {}\n", ref_id));
    report.push_str(&format!(
        "Collected  {}\n",
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    ));
    report.push_str(&format!(
        "Alert time {}\n",
        alert.ts.format("%Y-%m-%d %H:%M:%S UTC")
    ));
    report.push_str(&format!("Host       {}\n\n", alert.host));

    report.push_str(&format!("{}\nALERT\n{}\n", hr, hr));
    report.push_str(&render(&alert, Theme::Plain));
    report.push('\n');

    report.push_str(&format!("{}\nPROCESSES\n{}\n", hr, hr));
    let procs = procsrc::scan_processes();
    let involved: Vec<_> = procs
        .iter()
        .filter(|p| alert.chain_pids.contains(&p.pid))
        .collect();
    let descendants: Vec<_> = procs
        .iter()
        .filter(|p| !alert.chain_pids.contains(&p.pid) && alert.chain_pids.contains(&p.ppid))
        .collect();
    if involved.is_empty() {
        report.push_str("  Processes from the alert chain are no longer running.\n");
    }
    for p in &involved {
        report.push_str(&format!(
            "  {} pid {} ppid {} uid {}{}\n",
            p.comm,
            p.pid,
            p.ppid,
            p.uid,
            p.container_id
                .as_ref()
                .map(|id| format!(" container {}", &id[..id.len().min(12)]))
                .unwrap_or_default()
        ));
        report.push_str(&format!("    exe      {}\n", p.exe));
        if let Some(cmd) = procsrc::cmdline_of(p.pid) {
            report.push_str(&format!("    cmdline  {}\n", cmd));
        }
        if let Some(env) = procsrc::read_file(&format!("/proc/{}/environ", p.pid)) {
            let interesting: Vec<&str> = env
                .split('\0')
                .filter(|kv| {
                    kv.starts_with("LD_")
                        || kv.starts_with("PATH=")
                        || kv.starts_with("HOME=")
                        || kv.starts_with("SSH_")
                })
                .collect();
            if !interesting.is_empty() {
                report.push_str(&format!("    env      {}\n", interesting.join("  ")));
            }
        }
        if let Some(cwd) = fs::read_link(format!("/proc/{}/cwd", p.pid))
            .ok()
            .map(|c| c.to_string_lossy().into_owned())
        {
            report.push_str(&format!("    cwd      {}\n", cwd));
        }
        // Snapshot open sockets / files of interest.
        if let Ok(fds) = fs::read_dir(format!("/proc/{}/fd", p.pid)) {
            let targets: Vec<String> = fds
                .flatten()
                .filter_map(|fd| fs::read_link(fd.path()).ok())
                .map(|t| t.to_string_lossy().into_owned())
                .filter(|t| {
                    t.starts_with("socket:") || t.starts_with('/') && !t.starts_with("/dev/")
                })
                .take(20)
                .collect();
            if !targets.is_empty() {
                report.push_str(&format!("    fds      {}\n", targets.join("  ")));
            }
        }
    }
    if !descendants.is_empty() {
        report.push_str("\n  Descendants still running:\n");
        for p in descendants.iter().take(50) {
            report.push_str(&format!(
                "    {} pid {} ppid {} uid {}  {}\n",
                p.comm, p.pid, p.ppid, p.uid, p.exe
            ));
        }
    }
    report.push('\n');

    report.push_str(&format!("{}\nLISTENERS\n{}\n", hr, hr));
    let listeners: Vec<_> = procsrc::read_tcp_tables()
        .into_iter()
        .filter(|e| e.state == procsrc::TCP_LISTEN)
        .collect();
    let owners = procsrc::pids_for_inodes(&listeners.iter().map(|e| e.inode).collect::<Vec<_>>());
    for e in &listeners {
        let owner = owners
            .get(&e.inode)
            .map(|pid| format!("{} ({})", procsrc::comm_of(*pid).unwrap_or_default(), pid))
            .unwrap_or_else(|| "-".to_string());
        report.push_str(&format!(
            "  {:<5} {}:{}  uid {}  {}\n",
            e.proto, e.local_addr, e.local_port, e.uid, owner
        ));
    }
    report.push('\n');

    report.push_str(&format!("{}\nFILES REFERENCED\n{}\n", hr, hr));
    let mut paths_seen = Vec::new();
    for f in &alert.facts {
        if f.value.starts_with('/') && !paths_seen.contains(&f.value) {
            paths_seen.push(f.value.clone());
        }
    }
    for n in &alert.chain {
        if n.exe.starts_with('/') && !paths_seen.contains(&n.exe) {
            paths_seen.push(n.exe.clone());
        }
    }
    for p in &paths_seen {
        let clean = p.trim_end_matches(" (deleted)");
        // Paths come from alert facts, which can name attacker-controlled
        // files: never follow a symlink or open a FIFO/device as root.
        if let Ok(link) = fs::symlink_metadata(clean) {
            if !link.is_file() {
                let what = if link.file_type().is_symlink() {
                    format!(
                        "symlink -> {}",
                        fs::read_link(clean)
                            .map(|t| t.display().to_string())
                            .unwrap_or_default()
                    )
                } else {
                    "not a regular file".to_string()
                };
                report.push_str(&format!("  {}  ({}; not read)\n", clean, what));
                continue;
            }
        }
        match procsrc::open_regular(clean) {
            Some((mut f, m)) => {
                use std::io::{Read, Seek};
                use std::os::unix::fs::MetadataExt;
                let hash = sha256_reader(&mut f).unwrap_or_default();
                report.push_str(&format!(
                    "  {}\n    mode {:o} uid {} gid {} size {} mtime {}\n    sha256 {}\n",
                    clean,
                    m.mode() & 0o7777,
                    m.uid(),
                    m.gid(),
                    m.len(),
                    m.mtime(),
                    hash
                ));
                let copy_to = bundle_dir.join(clean.trim_start_matches('/').replace('/', "__"));
                if m.len() < MAX_COPY && f.rewind().is_ok() {
                    let mut buf = Vec::new();
                    if f.take(MAX_COPY).read_to_end(&mut buf).is_ok() {
                        let _ = config::write_secure_bytes(&copy_to, &buf);
                    }
                }
            }
            None if fs::symlink_metadata(clean).is_ok() => report.push_str(&format!(
                "  {}  (reached via a symlinked directory or unreadable; not read)\n",
                clean
            )),
            None => report.push_str(&format!("  {}  (no longer present)\n", clean)),
        }
    }
    report.push('\n');

    report.push_str(&format!("{}\nINTEGRITY\n{}\n", hr, hr));
    if let Some(state) = crate::status::read_state() {
        report.push_str(&format!(
            "  config sha256 {}\n  binary sha256 {}\n",
            state.config_hash, state.binary_hash
        ));
    }
    report.push('\n');
    report.push_str(&format!(
        "Journal around the event:\n  journalctl --since \"{}\" --until \"{}\"\n",
        (alert.ts - Duration::minutes(10)).format("%Y-%m-%d %H:%M:%S"),
        (alert.ts + Duration::minutes(10)).format("%Y-%m-%d %H:%M:%S")
    ));

    let report_path = bundle_dir.join("context.txt");
    config::write_secure(&report_path, &report)?;
    config::write_secure(
        &bundle_dir.join("alert.json"),
        &serde_json::to_string_pretty(&alert)?,
    )?;

    let st = Style::detect();
    print!("{}", report);
    println!("{}", st.rule());
    println!("  {} {}", st.ok("Bundle written to"), bundle_dir.display());
    Ok(())
}
