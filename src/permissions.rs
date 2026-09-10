//! Key store permission checks — gpg-style, with a git-style trust
//! acknowledgment.
//!
//! git-veil checks its key store the way gpg checks `~/.gnupg`: the store
//! directory and the private key files (`identities.txt`,
//! `signing-keys.txt`) must carry no group or world permission bits. It
//! NEVER chmods key material it did not create — it reads it, and refuses
//! to read it while the permissions expose private keys beyond the owner.
//!
//! The refusal is escapable two ways, mirroring git's dubious-ownership
//! handling: record the exact current `(path, mode)` pairs as
//! acknowledged (`git-veil trust-permissions`), which re-fails the moment
//! any of them changes again, or bypass outright
//! (`--dangerously-skip-permissions-check` / `GIT_VEIL_SKIP_PERMISSIONS`).
//!
//! Unix only: Windows ACLs are a different model, and the checks there
//! are no-ops.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

use crate::exit_codes::{coded, ExitCode};

/// One acknowledged (path, mode) pair: the exact permission state the
/// user accepted. A later finding matches only on BOTH fields.
#[derive(Debug, Serialize, Deserialize)]
struct AckEntry {
    path: String,
    mode: u32,
}

fn ack_path(key_store: &Path) -> PathBuf {
    key_store.join("permissions-ack.json")
}

/// Canonicalises `path` for acknowledgment matching, so a store reached
/// by different relative/absolute spellings still matches.
fn canonical_string(path: &Path) -> String {
    fs::canonicalize(path)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| path.to_string_lossy().into_owned())
}

/// A path whose permissions expose key material to group or world.
#[derive(Debug, Clone)]
pub struct PermissionFinding {
    pub path: PathBuf,
    pub mode: u32,
}

/// Lists every unsafe permission finding in the key store: the store
/// directory itself plus `identities.txt` and `signing-keys.txt` when
/// present. Absent paths are skipped — a fresh machine has no store yet.
#[cfg(unix)]
pub fn find_unsafe_permissions(key_store: &Path) -> Result<Vec<PermissionFinding>> {
    use std::os::unix::fs::PermissionsExt as _;

    let mut findings = Vec::new();

    if let Ok(metadata) = fs::metadata(key_store) {
        if metadata.is_dir() && metadata.permissions().mode() & 0o077 != 0 {
            findings.push(PermissionFinding {
                path: key_store.to_path_buf(),
                mode: metadata.permissions().mode() & 0o777,
            });
        }
    }

    for name in ["identities.txt", "signing-keys.txt"] {
        let path = key_store.join(name);
        if let Ok(metadata) = fs::metadata(&path) {
            if metadata.is_file() && metadata.permissions().mode() & 0o077 != 0 {
                findings.push(PermissionFinding {
                    path,
                    mode: metadata.permissions().mode() & 0o777,
                });
            }
        }
    }

    Ok(findings)
}

#[cfg(not(unix))]
pub fn find_unsafe_permissions(_key_store: &Path) -> Result<Vec<PermissionFinding>> {
    Ok(Vec::new())
}

fn load_acknowledgments(key_store: &Path) -> Result<Vec<AckEntry>> {
    let path = ack_path(key_store);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content =
        fs::read_to_string(&path).with_context(|| format!("Failed to read {}", path.display()))?;
    serde_json::from_str(&content).with_context(|| format!("Failed to parse {}", path.display()))
}

/// Checks the key store permissions; `Err` carries exit code 30.
///
/// Passes when every finding matches an acknowledged `(path, mode)` pair
/// exactly — permissions that changed to anything else fail again.
pub fn check_key_store_permissions(key_store: &Path, skip: bool) -> Result<()> {
    if skip {
        return Ok(());
    }

    let findings = find_unsafe_permissions(key_store)?;
    if findings.is_empty() {
        return Ok(());
    }

    let acknowledgments = load_acknowledgments(key_store)?;
    let unacked: Vec<&PermissionFinding> = findings
        .iter()
        .filter(|finding| {
            let canonical = canonical_string(&finding.path);
            !acknowledgments
                .iter()
                .any(|ack| ack.path == canonical && ack.mode == finding.mode)
        })
        .collect();
    if unacked.is_empty() {
        return Ok(());
    }

    let mut message = String::from("unsafe permissions on git-veil key store material:\n\n");
    for finding in &unacked {
        message.push_str(&format!(
            "  {} (mode {:04o})\n",
            finding.path.display(),
            finding.mode
        ));
    }
    message.push_str("\nPrivate key material must not be group- or world-accessible. Fix it:\n\n");
    message.push_str(&format!("  chmod 700 {}\n", key_store.display()));
    for finding in &unacked {
        if finding.path != key_store {
            message.push_str(&format!("  chmod 600 {}\n", finding.path.display()));
        }
    }
    message.push_str(&format!(
        "\nOr, if you accept the risk, acknowledge the current state:\n\n  git-veil trust-permissions --key-store {}\n\nThis check can be bypassed with --dangerously-skip-permissions-check or GIT_VEIL_SKIP_PERMISSIONS=1.",
        key_store.display()
    ));

    Err(coded(ExitCode::UnsafeKeyStorePermissions, message))
}

/// Records the key store's current unsafe findings as acknowledged
/// (exact `(path, mode)` pairs, written mode 0600). The command behind
/// `git-veil trust-permissions`.
pub fn cmd_trust_permissions(key_store: &Path) -> Result<()> {
    let findings = find_unsafe_permissions(key_store)?;
    if findings.is_empty() {
        println!(
            "No unsafe permissions found in {}; nothing to acknowledge",
            key_store.display()
        );
        return Ok(());
    }

    let entries: Vec<AckEntry> = findings
        .iter()
        .map(|finding| AckEntry {
            path: canonical_string(&finding.path),
            mode: finding.mode,
        })
        .collect();

    let json = serde_json::to_string_pretty(&entries)
        .context("Failed to serialize permissions acknowledgment")?;
    crate::fs_atomic::write_atomic_mode(&ack_path(key_store), json.as_bytes(), 0o600)
        .context("Failed to write permissions-ack.json")?;

    println!(
        "Acknowledged the current permissions as trusted (recorded in {}):",
        ack_path(key_store).display()
    );
    for entry in &entries {
        println!("  {} (mode {:04o})", entry.path, entry.mode);
    }
    println!("If any of these change again, git-veil will refuse until you re-acknowledge.");
    Ok(())
}

/// Whether `GIT_VEIL_SKIP_PERMISSIONS` requests a bypass (truthy: "1",
/// "true" or "yes", case-insensitive).
pub fn permissions_check_bypassed_from_env() -> bool {
    match std::env::var("GIT_VEIL_SKIP_PERMISSIONS") {
        Ok(value) => matches!(value.trim().to_lowercase().as_str(), "1" | "true" | "yes"),
        Err(_) => false,
    }
}
