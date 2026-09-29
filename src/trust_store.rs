use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::fs_atomic::write_atomic;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TrustStore {
    #[serde(default)]
    pub trusted_keys: HashMap<String, String>,
}

impl TrustStore {
    pub fn new() -> Self {
        Self {
            trusted_keys: HashMap::new(),
        }
    }

    pub fn add_trust(&mut self, repo_id: String, fingerprint: String) {
        self.trusted_keys.insert(repo_id, fingerprint);
    }

    pub fn get_trusted_fingerprint(&self, repo_id: &str) -> Option<&str> {
        self.trusted_keys.get(repo_id).map(|s| s.as_str())
    }

    pub fn serialize(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(Into::into)
    }

    pub fn deserialize(content: &str) -> Result<Self> {
        let store: TrustStore = serde_json::from_str(content)?;
        Ok(store)
    }

    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        let content = self.serialize()?;
        write_atomic(path, content.as_bytes())?;
        Ok(())
    }

    pub fn load_from_file(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let content = fs::read_to_string(path)?;
        Self::deserialize(&content)
    }
}

/// Per-machine trust pins, stored OUTSIDE the repository in the tool-owned
/// key store: `<key_store>/trust-pins/<sanitized-repo-id>` holds the pinned
/// fingerprint.
///
/// trust.json (repo_id -> fingerprint) is committed to the repository and
/// therefore attacker-writable by anyone with write access, and the keyring
/// it points at ships with the repo too. The pin is the out-of-band record,
/// written only by `git-veil trust` on this machine, of which fingerprint the
/// user actually chose to trust. A fresh clone has no pin, so trust must be
/// re-established per machine — the correct posture for a secrets tool.
pub struct TrustPinStore;

impl TrustPinStore {
    const PIN_DIR: &str = "trust-pins";

    /// Maps a repo_id to a safe, deterministic filename: characters in
    /// [A-Za-z0-9._-] are kept, every other byte is percent-encoded (UTF-8,
    /// uppercase hex) so path separators and exotic characters can never
    /// escape the pin directory. A sanitized name is never "." or "..".
    pub fn sanitize_repo_id(repo_id: &str) -> String {
        let mut out = String::with_capacity(repo_id.len());
        for byte in repo_id.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-' => {
                    out.push(byte as char)
                }
                _ => out.push_str(&format!("%{:02X}", byte)),
            }
        }
        // A repo_id made only of dots would sanitize to a directory alias
        // ("." or "..") and escape the pin directory; encode it instead.
        if out == "." || out == ".." {
            out = out.replace('.', "%2E");
        }
        out
    }

    /// The path of the pin file for `repo_id` under `key_store`.
    pub fn pin_path(key_store: &Path, repo_id: &str) -> PathBuf {
        key_store
            .join(Self::PIN_DIR)
            .join(Self::sanitize_repo_id(repo_id))
    }

    /// Writes the pinned fingerprint for `repo_id`, creating the pin
    /// directory as needed.
    pub fn write_pin(key_store: &Path, repo_id: &str, fingerprint: &str) -> Result<()> {
        let path = Self::pin_path(key_store, repo_id);
        fs::create_dir_all(path.parent().expect("pin path always has a parent"))?;
        write_atomic(&path, fingerprint.as_bytes())?;
        Ok(())
    }

    /// Reads the pinned fingerprint for `repo_id`; `Ok(None)` when no pin
    /// exists yet (the fresh-clone state).
    pub fn read_pin(key_store: &Path, repo_id: &str) -> Result<Option<String>> {
        let path = Self::pin_path(key_store, repo_id);
        if !path.exists() {
            return Ok(None);
        }
        let content = fs::read_to_string(&path)?;
        Ok(Some(content.trim().to_string()))
    }

    /// The path of the per-machine keyring baseline for `repo_id`:
    /// the highest keyring version this machine has ever accepted, plus —
    /// since the fork fix (issue #20) — the SHA-256 digest of the accepted
    /// signed content at that version. Lives beside the pin, OUTSIDE the
    /// repository — a committed baseline would be attacker-writable and the
    /// rollback refusal would be void. See "Keyring format and freshness" in
    /// docs/design.md.
    ///
    /// File format: line 1 is the version digits; line 2 (optional) is the
    /// hex digest. Pre-fork-fix baselines carried only the version; they are
    /// read as (version, None) and upgraded on the next accepted signed ring.
    fn ring_version_path(key_store: &Path, repo_id: &str) -> PathBuf {
        key_store
            .join(Self::PIN_DIR)
            .join(format!("{}.ring-version", Self::sanitize_repo_id(repo_id)))
    }

    /// Reads the freshness baseline; `Ok((None, None))` when this machine has
    /// never accepted a versioned keyring for this repo (fresh-clone state).
    pub fn read_ring_baseline(
        key_store: &Path,
        repo_id: &str,
    ) -> Result<(Option<u64>, Option<String>)> {
        let path = Self::ring_version_path(key_store, repo_id);
        if !path.exists() {
            return Ok((None, None));
        }
        let content = fs::read_to_string(&path)?;
        let mut lines = content.lines();
        let version = match lines.next().map(str::trim) {
            None | Some("") => None,
            Some(v) => Some(v.parse::<u64>().map_err(|_| {
                anyhow::anyhow!("corrupt keyring freshness baseline: {}", path.display())
            })?),
        };
        let digest = lines
            .next()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from);
        Ok((version, digest))
    }

    /// Records the freshness baseline for `repo_id`: the highest version
    /// accepted on this machine and the digest of the accepted signed content.
    pub fn write_ring_baseline(
        key_store: &Path,
        repo_id: &str,
        version: u64,
        digest: &str,
    ) -> Result<()> {
        let path = Self::ring_version_path(key_store, repo_id);
        fs::create_dir_all(path.parent().expect("baseline path always has a parent"))?;
        write_atomic(&path, format!("{}\n{}\n", version, digest).as_bytes())?;
        Ok(())
    }

    /// Clears the freshness baseline for `repo_id`. Run by `git-veil trust`:
    /// re-pinning is the documented recovery for an intended keyring
    /// rollback, so the baseline must reset with the pin or the next gated
    /// command would refuse the very keyring the user just re-anchored.
    pub fn clear_ring_version(key_store: &Path, repo_id: &str) -> Result<()> {
        let path = Self::ring_version_path(key_store, repo_id);
        if path.exists() {
            fs::remove_file(&path)?;
        }
        Ok(())
    }
}
