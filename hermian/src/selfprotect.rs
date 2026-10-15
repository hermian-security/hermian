//! Integrity hashes for the binary and configuration.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use crate::config::write_secure;
use crate::paths;

pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

pub fn sha256_file(path: &Path) -> Result<String> {
    let data = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    Ok(sha256_hex(&data))
}

pub fn current_binary_hash() -> Result<String> {
    let exe = fs::read_link("/proc/self/exe").context("failed to resolve own binary")?;
    sha256_file(&exe)
}

pub fn init_hashes() -> Result<(String, String)> {
    let binary = current_binary_hash()?;
    let config = sha256_file(&paths::config_path())?;
    fs::create_dir_all(paths::state_dir())?;
    write_secure(&paths::binary_hash_file(), &binary)?;
    write_secure(&paths::config_hash_file(), &config)?;
    Ok((binary, config))
}

pub struct IntegrityStatus {
    pub binary_ok: bool,
    pub config_ok: bool,
    pub binary_hash: String,
    pub config_hash: String,
    /// The stored hash was missing (first start without `hermian enable`,
    /// or someone deleted it), so there was nothing to compare against.
    pub binary_record_missing: bool,
    pub config_record_missing: bool,
}

fn read_hash(path: &Path) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub fn stored_config_hash() -> Option<String> {
    read_hash(&paths::config_hash_file())
}

pub fn verify_at_startup() -> IntegrityStatus {
    let binary_hash = current_binary_hash().unwrap_or_default();
    let config_hash = sha256_file(&paths::config_path()).unwrap_or_default();
    let stored_binary = read_hash(&paths::binary_hash_file());
    let stored_config = stored_config_hash();
    // `hermian enable` (and the package) record both hashes before the first
    // start, so a missing one means someone deleted it, or a tarball upgrade
    // skipped `enable`. Deleting binary.sha256 and swapping the binary used to
    // pass silently: record the current value, but report it.
    if stored_binary.is_none() && !binary_hash.is_empty() {
        let _ = write_secure(&paths::binary_hash_file(), &binary_hash);
    }
    if stored_config.is_none() && !config_hash.is_empty() {
        let _ = write_secure(&paths::config_hash_file(), &config_hash);
    }
    let (binary_ok, binary_record_missing) = judge(stored_binary.as_deref(), &binary_hash);
    let (config_ok, config_record_missing) = judge(stored_config.as_deref(), &config_hash);
    IntegrityStatus {
        binary_record_missing,
        config_record_missing,
        binary_ok,
        config_ok,
        binary_hash,
        config_hash,
    }
}

/// `(matches, record_missing)` for a stored hash against the current one.
/// A missing record isn't a mismatch, but it is reported.
fn judge(stored: Option<&str>, current: &str) -> (bool, bool) {
    match stored {
        Some(s) => (s == current, false),
        None => (true, true),
    }
}

pub fn update_config_hash(hash: &str) -> Result<()> {
    write_secure(&paths::config_hash_file(), hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_record_is_reported_not_trusted_silently() {
        assert_eq!(judge(Some("abc"), "abc"), (true, false));
        assert_eq!(judge(Some("abc"), "def"), (false, false));
        assert_eq!(judge(None, "def"), (true, true));
    }
}
