use anyhow::{Context, Result};
use std::env;
use std::fs;
use std::path::PathBuf;

use crate::commands::hide::encrypted_path_for;
use crate::tracked_files::validate_tracked_path;
use crate::{decrypt_with_gpg_key, find_private_key_by_email, TrackedFiles, verify_keyring_against_trust};

const SECRETS_DIR: &str = ".git-gpg/secrets";

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
/// same way cmd_cat resolves them (canonicalise-and-strip for absolute
/// paths, validate_tracked_path for relative ones), and must match entries
/// in tracked.json. Tracked paths are stored repo-relative and are
/// validated, so the ciphertext path can never escape .git-gpg/secrets.
pub fn cmd_changes(
    files: Vec<String>,
    email: &str,
    remote_name: &str,
    gpg_home: &PathBuf,
) -> Result<Vec<PathBuf>> {
    // Verify keyring signature first: never decrypt against an unverified keyring
    let (_, keyring) = verify_keyring_against_trust(remote_name, gpg_home)?;

    // Find user's entry
    keyring.find_by_email(email)
        .with_context(|| format!("User {} not found in keyring", email))?;

    // Find user's private key
    let private_key = find_private_key_by_email(gpg_home, email)?;

    // Load tracked files
    let tracked_path = PathBuf::from(".git-gpg/tracked.json");
    let tracked = TrackedFiles::load(&tracked_path)?;

    // Resolve the requested files to their repo-relative tracked forms
    let repo_root = env::current_dir().context("Failed to get current directory")?;
    let repo_root = fs::canonicalize(&repo_root)
        .context("Failed to canonicalise repository root")?;

    let targets: Vec<PathBuf> = if files.is_empty() {
        tracked.files.clone()
    } else {
        let mut resolved = Vec::new();
        for file in &files {
            let path = PathBuf::from(file);
            let relative: PathBuf = if path.is_absolute() {
                let canonical = fs::canonicalize(&path)
                    .with_context(|| format!("File not found: {}", file))?;
                canonical
                    .strip_prefix(&repo_root)
                    .with_context(|| format!(
                        "File is outside the repository: {} (resolves to {})",
                        file,
                        canonical.display()
                    ))?
                    .to_path_buf()
            } else {
                validate_tracked_path(&path)
                    .with_context(|| format!("Invalid path: {}", file))?;
                path
            };

            if relative.as_os_str().is_empty() {
                anyhow::bail!("Cannot check the repository root itself: {}", file);
            }

            if !tracked.files.contains(&relative) {
                anyhow::bail!("File not tracked: {}", file);
            }

            resolved.push(relative);
        }
        resolved
    };

    let mut changed = Vec::new();
    for file in &targets {
        // Compute encrypted path
        let encrypted_path = encrypted_path_for(file);

        // Defence in depth: the ciphertext must stay inside .git-gpg/secrets
        if !encrypted_path.starts_with(SECRETS_DIR) {
            anyhow::bail!(
                "Encrypted path escaped the secrets directory: {}",
                encrypted_path.display()
            );
        }

        // No ciphertext yet: the file was never hidden
        if !encrypted_path.exists() {
            println!("no hidden version: {}", file.display());
            continue;
        }

        // Plaintext absent: the file is still hidden
        let on_disk = match fs::read(file) {
            Ok(bytes) => bytes,
            Err(_) => {
                println!("not present on disk (hidden): {}", file.display());
                continue;
            }
        };

        // Read encrypted content
        let ciphertext = fs::read_to_string(&encrypted_path)
            .with_context(|| format!("Failed to read encrypted file: {}", encrypted_path.display()))?;

        // Decrypt
        let hidden = decrypt_with_gpg_key(&ciphertext, &private_key)?;

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
