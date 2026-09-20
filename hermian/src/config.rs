//! Config/baseline persistence with secure, atomic writes.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use anyhow::{Context, Result};
use hermian_core::{Baseline, Config};

use crate::paths;

pub fn require_root() -> Result<()> {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        anyhow::bail!("this command requires root; re-run with sudo");
    }
    Ok(())
}

pub fn load_config() -> Result<Config> {
    let path = paths::config_path();
    if !path.exists() {
        save_default_config()?;
    }
    let text =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let cfg =
        Config::parse(&text).with_context(|| format!("failed to parse {}", path.display()))?;
    cfg.validate()
        .with_context(|| format!("invalid configuration in {}", path.display()))?;
    Ok(cfg)
}

pub fn save_default_config() -> Result<()> {
    let path = paths::config_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    }
    write_secure(&path, hermian_core::DEFAULT_CONFIG_TOML)
}

/// Write `content` to `path` with mode 0600 atomically (temp file + rename).
pub fn write_secure(path: &Path, content: &str) -> Result<()> {
    let parent = path.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let tmp = parent.join(format!(
        ".{}.tmp{}",
        path.file_name()
            .map(|s| s.to_string_lossy())
            .unwrap_or_default(),
        std::process::id()
    ));
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("failed to create {}", tmp.display()))?;
        f.write_all(content.as_bytes())?;
        f.sync_all()?;
    }
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    fs::rename(&tmp, path).with_context(|| format!("failed to replace {}", path.display()))?;
    Ok(())
}

pub fn write_secure_append(path: &Path, content: &str) -> Result<()> {
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(content.as_bytes())?;
    f.flush()?;
    Ok(())
}

pub fn load_baseline() -> Result<Baseline> {
    let path = paths::baseline_file();
    match fs::read_to_string(&path) {
        Ok(text) => serde_json::from_str(&text)
            .with_context(|| format!("failed to parse {}", path.display())),
        Err(_) => Ok(Baseline::default()),
    }
}

pub fn save_baseline(baseline: &Baseline) -> Result<()> {
    let text = serde_json::to_string_pretty(baseline)?;
    write_secure(&paths::baseline_file(), &text)
}
