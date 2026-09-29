//! Machine-local encryption-intent log.
//!
//! `add` records each tracked path here so `hide` can refuse "nominated"
//! paths — committed to tracked.json by some other repo writer — that the
//! user on THIS machine never added. See "Encryption intent" in
//! docs/design.md. The log lives in the key store (outside the repository,
//! permission-checked) because anything committed would be attacker-writable
//! and the refusal void; one repo-relative path per line, no JSON, no header.

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use crate::trust_store::TrustPinStore;

pub struct LocalAdds;

impl LocalAdds {
    fn path(key_store: &Path, repo_id: &str) -> PathBuf {
        key_store
            .join("local-adds")
            .join(TrustPinStore::sanitize_repo_id(repo_id))
    }

    /// Records intent for one repo-relative path (append; dedup is
    /// unnecessary — membership is what hide asks).
    pub fn record(key_store: &Path, repo_id: &str, relative: &Path) -> Result<()> {
        let path = Self::path(key_store, repo_id);
        fs::create_dir_all(path.parent().expect("intent path always has a parent"))?;
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
        crate::fs_atomic::write_atomic(&path, existing.as_bytes())
            .context("Failed to record add intent in the key store")
    }

    /// True when this machine has recorded intent for `relative`.
    pub fn has_intent(key_store: &Path, repo_id: &str, relative: &Path) -> bool {
        let path = Self::path(key_store, repo_id);
        fs::read_to_string(&path)
            .map(|content| {
                let wanted = relative.to_string_lossy();
                content.lines().any(|line| line.trim() == wanted)
            })
            .unwrap_or(false)
    }
}
