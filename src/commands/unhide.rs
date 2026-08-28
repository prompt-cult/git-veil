use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use crate::commands::hide::{encrypted_path_for, ensure_ciphertext_beside_plaintext};
use crate::tracked_files::validate_tracked_path;
use crate::{
    decrypt_with_gpg_key, find_private_key_by_email, TrackedFiles,
    verify_keyring_against_trust,
};

/// Unhides a single tracked file: decrypts its in-place `<name>.secret`
/// ciphertext back to the tracked plaintext path and deletes the ciphertext.
///
/// This is the inverse of hide for ONE file (matching cat's single-file
/// scope): hide deleted the plaintext and left the ciphertext beside it;
/// unhide restores the plaintext and removes the ciphertext. The keyring
/// signature is verified against the pinned trust before any decryption,
/// exactly as reveal and cat do.
///
/// The user-supplied path is resolved to its repo-relative form the same way
/// cmd_cat resolves paths. Unlike cat, the plaintext may not exist (it is
/// hidden), so an absolute path is checked lexically against the canonical
/// repository root instead of canonicalised; relative paths go through the
/// shared tracked-path validation. The file must be tracked — unhide refuses
/// untracked paths — and the ciphertext must exist beside the plaintext.
pub fn cmd_unhide(
    repo_root: &Path,
    file: &str,
    email: &str,
    remote_name: &str,
    gpg_home: &PathBuf,
    passphrase: Option<&str>,
) -> Result<()> {
    // Verify keyring signature first: never decrypt against an unverified keyring
    let (_, _, keyring) = verify_keyring_against_trust(repo_root, remote_name, gpg_home)?;

    // Find user's entry
    keyring
        .find_by_email(email)
        .with_context(|| format!("User {} not found in keyring", email))?;

    // Find user's private key
    let private_key = find_private_key_by_email(gpg_home, email)?;

    // Load tracked files
    let tracked_path = repo_root.join(".git-gpg/tracked.json");
    let tracked = TrackedFiles::load(&tracked_path)?;

    // Canonicalise the repository root once
    let canonical_root = fs::canonicalize(repo_root)
        .context("Failed to canonicalise repository root")?;

    // Resolve the user-supplied path to its repo-relative form
    let path = PathBuf::from(file);

    let relative: PathBuf = if path.is_absolute() {
        path.strip_prefix(&canonical_root)
            .with_context(|| format!("File is outside the repository: {}", file))?
            .to_path_buf()
    } else {
        validate_tracked_path(&path)
            .with_context(|| format!("Invalid path: {}", file))?;
        path
    };

    if relative.as_os_str().is_empty() {
        anyhow::bail!("Cannot unhide the repository root itself: {}", file);
    }

    if !tracked.files.contains(&relative) {
        anyhow::bail!("File not tracked: {}", file);
    }

    // Compute encrypted path
    let encrypted_path = encrypted_path_for(repo_root, &relative);

    // Defence in depth: the ciphertext must stay inside the repository
    // root, beside its plaintext
    ensure_ciphertext_beside_plaintext(repo_root, &relative, &encrypted_path)?;

    // Check encrypted file exists
    if !encrypted_path.exists() {
        anyhow::bail!("Encrypted file not found: {}", encrypted_path.display());
    }

    // Read encrypted content
    let ciphertext = fs::read_to_string(&encrypted_path)
        .with_context(|| format!("Failed to read encrypted file: {}", encrypted_path.display()))?;

    // Decrypt
    let plaintext = decrypt_with_gpg_key(&ciphertext, &private_key, passphrase)?;

    // Write plaintext back to the tracked path
    if let Some(parent) = relative.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(repo_root.join(parent))?;
        }
    }
    fs::write(repo_root.join(&relative), plaintext)
        .with_context(|| format!("Failed to write decrypted file: {}", relative.display()))?;

    // Delete the ciphertext
    fs::remove_file(&encrypted_path)
        .with_context(|| format!("Failed to delete encrypted file: {}", encrypted_path.display()))?;

    println!("Decrypted: {}", relative.display());
    println!("✓ File unhidden");
    Ok(())
}
