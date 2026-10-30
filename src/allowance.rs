//! The machine-local allowance store: first-encrypt consent, keyed to the
//! trust pin and the principal.
//!
//! `tracked.json` is committed and unsigned, so any repo writer can
//! nominate a path in it. The allowance record is the user's own consent,
//! bound to the machine: this repository (anchored by the trust pin), this
//! git user, has allowed these paths. It lives in the key store, outside
//! the repository and permission-checked, because anything committed would
//! be attacker-writable and the refusal void. One repo-relative path per
//! line, no JSON, no header. See "Allowance" in docs/src/design.md.

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::fs_atomic::write_atomic;
use crate::trust_store::TrustPinStore;

/// The allowance record key: SHA-256 over the UTF-8 pin fingerprint
/// (canonicalised to lowercase hex) and the UTF-8 principal, separated by
/// exactly one colon, printed as 64 lowercase hex characters.
///
/// This is a record key, not a key fingerprint: it names a consent file
/// and derives from public repository facts. It is deliberately not part
/// of the single fingerprint derivation in src/fingerprint.rs.
pub fn allowance_record_key(pin_fingerprint: &str, principal: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(pin_fingerprint.trim().to_lowercase().as_bytes());
    hasher.update(b":");
    hasher.update(principal.as_bytes());
    hex::encode(hasher.finalize())
}

/// The per-machine allowance store.
pub struct AllowanceStore;

impl AllowanceStore {
    const DIR: &str = "allowances";

    /// The path of one principal's allowance record for `repo_id` under
    /// `key_store`.
    fn record_path(
        key_store: &Path,
        repo_id: &str,
        pin_fingerprint: &str,
        principal: &str,
    ) -> PathBuf {
        key_store
            .join(Self::DIR)
            .join(TrustPinStore::sanitize_repo_id(repo_id))
            .join(allowance_record_key(pin_fingerprint, principal))
    }

    /// Records one repo-relative path as allowed. Append only; dedup is
    /// unnecessary because membership is what hide asks.
    pub fn record(
        key_store: &Path,
        repo_id: &str,
        pin_fingerprint: &str,
        principal: &str,
        relative: &Path,
    ) -> Result<()> {
        let path = Self::record_path(key_store, repo_id, pin_fingerprint, principal);
        fs::create_dir_all(
            path.parent()
                .expect("allowance record path always has a parent"),
        )?;
        let mut existing = if path.exists() {
            fs::read_to_string(&path)?
        } else {
            String::new()
        };
        if !existing.is_empty() && !existing.ends_with('\n') {
            existing.push('\n');
        }
        existing.push_str(&relative.to_string_lossy());
        existing.push('\n');
        write_atomic(&path, existing.as_bytes())
            .context("Failed to record the allowance in the key store")
    }

    /// True when this machine has recorded an allowance for `relative` on
    /// behalf of `principal`.
    pub fn contains(
        key_store: &Path,
        repo_id: &str,
        pin_fingerprint: &str,
        principal: &str,
        relative: &Path,
    ) -> bool {
        let path = Self::record_path(key_store, repo_id, pin_fingerprint, principal);
        fs::read_to_string(&path)
            .map(|content| {
                let wanted = relative.to_string_lossy();
                content.lines().any(|line| line.trim() == wanted)
            })
            .unwrap_or(false)
    }

    /// Removes the principal's allowance record for `repo_id`, so a
    /// revoked collaborator leaves no ambient consent on this machine.
    /// Scope, stated honestly: the key store of the machine running the
    /// purge; every machine holds only its own records. Returns true when
    /// a record existed and was removed.
    pub fn purge(
        key_store: &Path,
        repo_id: &str,
        pin_fingerprint: &str,
        principal: &str,
    ) -> Result<bool> {
        let path = Self::record_path(key_store, repo_id, pin_fingerprint, principal);
        if !path.exists() {
            return Ok(false);
        }
        fs::remove_file(&path)?;
        Ok(true)
    }
}
