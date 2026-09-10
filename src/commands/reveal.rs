use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use crate::commands::hide::{encrypted_path_for, ensure_ciphertext_beside_plaintext};
use crate::exit_codes::{coded, ExitCode};
use crate::fs_atomic::write_atomic;
use crate::key_discovery::discover_identity;
use crate::tracked_files::{ensure_regular_file, validate_tracked_path};
use crate::{cmd_verify_keyring, decrypt_with_identity, Keyring, TrackedFiles};

/// Decrypts all tracked files using the user's private key.
///
/// Tracked paths are repo-relative (relative to `repo_root`) and are
/// validated before any use, so a malicious committed tracked.json cannot
/// make reveal write attacker-chosen plaintext to an arbitrary path outside
/// the repository.
pub fn cmd_reveal(
    repo_root: &Path,
    email: &str,
    remote_name: &str,
    key_store: &PathBuf,
) -> Result<()> {
    // Verify keyring signature first
    cmd_verify_keyring(repo_root, remote_name, key_store)?;

    // Load keyring
    let keyring_path = repo_root.join(".git-veil/keyring");
    let keyring_text = fs::read_to_string(&keyring_path).context("Failed to read keyring file")?;
    let keyring = Keyring::parse(&keyring_text)?;

    // Find user's entry
    let entry = keyring.find_by_email(email).ok_or_else(|| {
        coded(
            ExitCode::IdentityNotInKeyring,
            format!(
                "user {} not found in keyring; check --email, or ask the owner to add you with git-veil tell",
                email
            ),
        )
    })?;

    // Find user's age identity by recipient string (exit code 21 with the
    // create-and-back-up recipe when absent)
    let identity = discover_identity(key_store, &entry.recipient)?;

    // Load tracked files
    let tracked_path = repo_root.join(".git-veil/tracked.json");
    let tracked = TrackedFiles::load(&tracked_path)?;

    if tracked.files.is_empty() {
        println!("No files tracked");
        return Ok(());
    }

    // Two-phase, all-or-nothing reveal (compute-then-commit). PHASE 1
    // verifies every tracked file's ciphertext exists and decrypts ALL of
    // them into memory; ANY failure (missing ciphertext, key error) aborts
    // with nothing changed on disk — no mixed state where some files are
    // revealed and others remain hidden. Memory trade: secrets are small
    // config-scale files, so holding every plaintext in memory is
    // acceptable; reveal is not a bulk-restoration path.
    let mut prepared: Vec<(PathBuf, PathBuf, Vec<u8>)> = Vec::new();
    for file in &tracked.files {
        validate_tracked_path(file)
            .with_context(|| format!("Refusing unsafe tracked path: {}", file.display()))?;

        // Lstat gate: writing the plaintext through a committed symlink
        // would corrupt the link target outside the repo (or silently
        // replace the link); refuse for consistency with the read gates.
        ensure_regular_file(repo_root, file)?;

        // Compute encrypted path
        let encrypted_path = encrypted_path_for(repo_root, file);

        // Defence in depth: the ciphertext must stay inside the repository
        // root, beside its plaintext
        ensure_ciphertext_beside_plaintext(repo_root, file, &encrypted_path)?;

        // Check encrypted file exists
        if !encrypted_path.exists() {
            anyhow::bail!(
                "Encrypted file not found: {}; run git-veil hide to create it",
                encrypted_path.display()
            );
        }

        // Read encrypted content
        let ciphertext = fs::read(&encrypted_path).with_context(|| {
            format!(
                "Failed to read encrypted file: {}",
                encrypted_path.display()
            )
        })?;

        // Decrypt
        let plaintext = decrypt_with_identity(&ciphertext, &identity)?;

        prepared.push((file.clone(), encrypted_path, plaintext));
    }

    let mut written: Vec<&(PathBuf, PathBuf, Vec<u8>)> = Vec::new();
    let mut first_error: Option<anyhow::Error> = None;
    for item in &prepared {
        let (file, _encrypted_path, plaintext) = item;
        if let Some(parent) = file.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(repo_root.join(parent))?;
            }
        }
        match write_atomic(&repo_root.join(file), plaintext)
            .with_context(|| format!("Failed to write decrypted file: {}", file.display()))
        {
            Ok(()) => {
                written.push(item);
                println!("Decrypted: {}", file.display());
            }
            Err(err) => {
                if first_error.is_none() {
                    first_error = Some(err);
                }
            }
        }
    }

    if let Some(err) = first_error {
        return Err(err.context(format!(
            "reveal failed: {} of {} plaintext(s) written",
            written.len(),
            prepared.len()
        )));
    }

    println!("✓ Files revealed");
    Ok(())
}
