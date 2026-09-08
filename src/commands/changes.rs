use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use crate::commands::hide::{encrypted_path_for, ensure_ciphertext_beside_plaintext};
use crate::tracked_files::{ensure_regular_file, resolve_repo_relative_input, PathResolveMode};
use crate::{
    decrypt_with_identity, find_identity_by_recipient, verify_keyring_against_trust, TrackedFiles,
};

/// Splits bytes into lines on '\n' for the compact text diff.
fn split_lines(bytes: &[u8]) -> Vec<&[u8]> {
    bytes.split(|&b| b == b'\n').collect()
}

/// Reports where the on-disk plaintext differs from the last hidden
/// (encrypted) version.
///
/// Differences are data, not errors: the returned list names the tracked
/// files whose plaintext differs from the decrypted ciphertext. Files with
/// no ciphertext, or with no plaintext on disk, are skipped with a note and
/// are not counted as changed.
///
/// The user-supplied paths are resolved to their repo-relative forms the
/// same way cmd_cat resolves them (canonicalise-and-strip; relative paths
/// resolve against `repo_root`), and must match entries in tracked.json.
/// Tracked paths are stored repo-relative and are validated, so the
/// ciphertext path can never escape the repository root.
pub fn cmd_changes(
    repo_root: &Path,
    files: Vec<String>,
    email: &str,
    remote_name: &str,
    key_store: &PathBuf,
    passphrase: Option<&str>,
) -> Result<Vec<PathBuf>> {
    // Verify keyring signature first: never decrypt against an unverified keyring
    let (_, _, keyring) = verify_keyring_against_trust(repo_root, remote_name, key_store)?;

    // Find user's entry
    let entry = keyring.find_by_email(email)
        .with_context(|| format!("user {} not found in keyring; check --email, or ask the owner to add you with git-veil tell", email))?;

    // Find user's age identity by recipient string
    let identity = find_identity_by_recipient(key_store, &entry.recipient)?;

    // Load tracked files
    let tracked_path = repo_root.join(".git-veil/tracked.json");
    let tracked = TrackedFiles::load(&tracked_path)?;

    // Resolve the requested files to their repo-relative tracked forms
    let targets: Vec<PathBuf> = if files.is_empty() {
        tracked.files.clone()
    } else {
        let mut resolved = Vec::new();
        for file in &files {
            let relative = resolve_repo_relative_input(
                repo_root,
                file,
                PathResolveMode::CanonicaliseAbsoluteValidateRelative,
                "check",
            )?;

            if !tracked.files.contains(&relative) {
                anyhow::bail!(
                    "file not tracked: {}; run git-veil add '{}' to track it",
                    file,
                    file
                );
            }

            resolved.push(relative);
        }
        resolved
    };

    let mut changed = Vec::new();
    for file in &targets {
        // Lstat gate: refuse if the tracked path is a committed symlink —
        // reading the on-disk plaintext through it would diff (and print)
        // the link target outside the repository.
        ensure_regular_file(repo_root, file)?;

        // Compute encrypted path
        let encrypted_path = encrypted_path_for(repo_root, file);

        // Defence in depth: the ciphertext must stay inside the repository
        // root, beside its plaintext
        ensure_ciphertext_beside_plaintext(repo_root, file, &encrypted_path)?;

        // No ciphertext yet: the file was never hidden
        if !encrypted_path.exists() {
            println!("no hidden version: {}", file.display());
            continue;
        }

        // Plaintext absent: the file is still hidden
        let on_disk = match fs::read(repo_root.join(file)) {
            Ok(bytes) => bytes,
            Err(_) => {
                println!("not present on disk (hidden): {}", file.display());
                continue;
            }
        };

        // Read encrypted content
        let ciphertext = fs::read(&encrypted_path).with_context(|| {
            format!(
                "Failed to read encrypted file: {}",
                encrypted_path.display()
            )
        })?;

        // Decrypt
        let hidden = decrypt_with_identity(&ciphertext, &identity)?;

        if hidden == on_disk {
            println!("unchanged: {}", file.display());
            continue;
        }

        // Differ: print a compact summary
        let hidden_is_text = !hidden.contains(&0u8);
        let on_disk_is_text = !on_disk.contains(&0u8);
        if hidden_is_text && on_disk_is_text {
            let old_lines = split_lines(&hidden);
            let new_lines = split_lines(&on_disk);
            println!("changed: {}", file.display());
            let count = old_lines.len().max(new_lines.len());
            for i in 0..count {
                match (old_lines.get(i), new_lines.get(i)) {
                    (Some(old), Some(new)) if old == new => {}
                    (Some(old), Some(new)) => {
                        println!("- {}", String::from_utf8_lossy(old));
                        println!("+ {}", String::from_utf8_lossy(new));
                    }
                    (Some(old), None) => {
                        println!("- {}", String::from_utf8_lossy(old));
                    }
                    (None, Some(new)) => {
                        println!("+ {}", String::from_utf8_lossy(new));
                    }
                    (None, None) => unreachable!("loop bounded by max of both lengths"),
                }
            }
        } else {
            println!(
                "differs ({} bytes vs {} bytes): {}",
                hidden.len(),
                on_disk.len(),
                file.display()
            );
        }
        changed.push(file.clone());
    }

    println!("{} file(s) with changes", changed.len());
    Ok(changed)
}
