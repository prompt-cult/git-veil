use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use crate::fs_atomic::write_atomic;
use crate::commands::hide::{encrypted_path_for, ensure_ciphertext_beside_plaintext};
use crate::tracked_files::{PathResolveMode, resolve_repo_relative_input};
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
        .with_context(|| format!("user {} not found in keyring; check --email, or ask the owner to add you with git-gpg tell", email))?;

    // Find user's private key
    let private_key = find_private_key_by_email(gpg_home, email)?;

    // Load tracked files
    let tracked_path = repo_root.join(".git-gpg/tracked.json");
    let tracked = TrackedFiles::load(&tracked_path)?;

    // Resolve the user-supplied path to its repo-relative form
    let relative = resolve_repo_relative_input(
        repo_root,
        file,
        PathResolveMode::LexicalStripValidateRelative,
        "unhide",
    )?;

    if !tracked.files.contains(&relative) {
        anyhow::bail!("file not tracked: {}; run git-gpg add '{}' to track it", file, file);
    }

    // Compute encrypted path
    let encrypted_path = encrypted_path_for(repo_root, &relative);

    // Defence in depth: the ciphertext must stay inside the repository
    // root, beside its plaintext
    ensure_ciphertext_beside_plaintext(repo_root, &relative, &encrypted_path)?;

    // Check encrypted file exists
    if !encrypted_path.exists() {
        anyhow::bail!("Encrypted file not found: {}; run git-gpg hide to create it", encrypted_path.display());
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
    // Write plaintext back atomically to the tracked path BEFORE deleting
    // the ciphertext: a crash mid-unhide leaves at worst both copies
    // (zero loss), never neither.
    write_atomic(&repo_root.join(&relative), &plaintext)
        .with_context(|| format!("Failed to write decrypted file: {}", relative.display()))?;

    // Delete the ciphertext
    fs::remove_file(&encrypted_path)
        .with_context(|| format!("Failed to delete encrypted file: {}", encrypted_path.display()))?;

    println!("Decrypted: {}", relative.display());
    println!("✓ File unhidden");
    Ok(())
}
