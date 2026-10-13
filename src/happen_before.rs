//! Git-history happen-before check for established ciphertexts (issue #19).
//!
//! The git index is attacker-writable: a repo writer can commit the
//! `tracked.json` nomination and a dummy `<path>.secret` together, and the
//! victim's next `hide` would treat the path as established. A committed
//! ciphertext is therefore established only when it predates the manifest
//! entry naming it: the ciphertext path must exist in the parent tree of
//! the commit that introduced the entry.
//!
//! The check walks git history, so its result is cached per manifest
//! version in the machine-local key store. The cache key is the SHA-256 of
//! the `tracked.json` content: the key store either holds a baseline for
//! that hash or it does not - there is no clone-versus-update distinction.
//! Any manifest change (add, remove, reorder) changes the hash and selects
//! a fresh cache entry, so remove-and-readd is re-checked with no
//! invalidation logic and no garbage collection. A path that fails the
//! check is never cached: every `hide` re-runs the check and refuses again.

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::tracked_files::TrackedFiles;
use crate::trust_store::TrustPinStore;

/// The baseline cache path for one manifest version:
/// `<key store>/baselines/<sanitized repo id>/<sha-256 of manifest>`.
pub fn baseline_path(key_store: &Path, repo_id: &str, manifest_digest_hex: &str) -> PathBuf {
    key_store
        .join("baselines")
        .join(TrustPinStore::sanitize_repo_id(repo_id))
        .join(manifest_digest_hex)
}

/// The proven repo-relative plaintext paths recorded for a manifest
/// version. A missing baseline file is an empty set (the never-checked
/// state for this manifest version).
pub fn read_baseline(path: &Path) -> HashSet<String> {
    fs::read_to_string(path)
        .map(|content| {
            content
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

/// Records one more proven path in a manifest version's baseline. The
/// baseline lives beside the intent log in the key store, outside any repo
/// writer's reach.
pub fn record_baseline(path: &Path, relative: &str) -> Result<()> {
    fs::create_dir_all(path.parent().expect("baseline path always has a parent"))?;
    let mut existing = if path.exists() {
        fs::read_to_string(path)?
    } else {
        String::new()
    };
    if existing.lines().any(|line| line.trim() == relative) {
        return Ok(());
    }
    if !existing.is_empty() && !existing.ends_with('\n') {
        existing.push('\n');
    }
    existing.push_str(relative);
    existing.push('\n');
    crate::fs_atomic::write_atomic(path, existing.as_bytes())
        .context("Failed to record the happen-before baseline in the key store")
}

/// The SHA-256 hex digest of the manifest content: the baseline cache key.
pub fn manifest_digest(manifest_content: &str) -> String {
    let digest = Sha256::digest(manifest_content.as_bytes());
    hex::encode(digest)
}

/// True when the ciphertext path exists in the parent tree of the commit
/// that introduced the `tracked.json` entry naming the plaintext path.
///
/// The walk is oldest-first over the commits that touched the manifest; the
/// first commit whose manifest version contains the entry is the
/// introducing commit. No introducing commit (manifest uncommitted, entry
/// never committed) is a fail-closed false.
pub fn ciphertext_predates_manifest_entry(
    repo_root: &Path,
    manifest_rel: &str,
    plaintext_rel: &str,
    ciphertext_rel: &str,
) -> Result<bool> {
    let log = Command::new("git")
        .current_dir(repo_root)
        .args(["log", "--format=%H", "--", manifest_rel])
        .output()
        .context("Failed to run git log for the happen-before check")?;
    if !log.status.success() {
        return Ok(false);
    }
    let stdout = String::from_utf8_lossy(&log.stdout);
    // Newest first: the entry's introduction commit is the MOST RECENT
    // commit where the entry appears while absent from the parent's
    // manifest version - the (re-)introduction. A remove-and-readd
    // therefore re-anchors the check at the re-add commit, exactly as the
    // issue specifies.
    for commit in stdout.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let manifest_at = Command::new("git")
            .current_dir(repo_root)
            .args(["show", &format!("{commit}:{manifest_rel}")])
            .output()
            .context("Failed to read the committed manifest for the happen-before check")?;
        if !manifest_at.status.success() {
            continue;
        }
        let content = String::from_utf8_lossy(&manifest_at.stdout);
        if !manifest_entry_present(&content, plaintext_rel) {
            continue;
        }
        let parent_manifest = Command::new("git")
            .current_dir(repo_root)
            .args(["show", &format!("{commit}^:{manifest_rel}")])
            .output()
            .context("Failed to read the parent manifest for the happen-before check")?;
        let parent_had_entry = parent_manifest.status.success()
            && manifest_entry_present(
                &String::from_utf8_lossy(&parent_manifest.stdout),
                plaintext_rel,
            );
        if parent_had_entry {
            continue;
        }
        return ciphertext_in_parent_tree(repo_root, commit, ciphertext_rel);
    }
    Ok(false)
}

/// Whether the manifest version at hand names the plaintext path. A
/// historical manifest that no longer parses (an older schema) counts as
/// not naming the path - fail-closed.
fn manifest_entry_present(manifest_content: &str, plaintext_rel: &str) -> bool {
    let tracked: TrackedFiles = match serde_json::from_str(manifest_content) {
        Ok(tracked) => tracked,
        Err(_) => return false,
    };
    let wanted = PathBuf::from(plaintext_rel);
    tracked.files.contains(&wanted)
}

/// Whether the ciphertext path exists in the parent tree of `commit`. A
/// root commit has no parent tree, so nothing can predate it.
fn ciphertext_in_parent_tree(repo_root: &Path, commit: &str, ciphertext_rel: &str) -> Result<bool> {
    let parent = Command::new("git")
        .current_dir(repo_root)
        .args(["rev-parse", "--verify", &format!("{commit}^{{commit}}^")])
        .output()
        .context("Failed to resolve the introducing commit parent")?;
    if !parent.status.success() {
        return Ok(false);
    }
    let parent_sha = String::from_utf8_lossy(&parent.stdout).trim().to_string();
    let probe = Command::new("git")
        .current_dir(repo_root)
        .args(["cat-file", "-e", &format!("{parent_sha}:{ciphertext_rel}")])
        .output()
        .context("Failed to probe the parent tree for the ciphertext")?;
    Ok(probe.status.success())
}
