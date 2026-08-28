use anyhow::{Context, Result};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::commands::hide::{encrypted_path_for, ensure_ciphertext_beside_plaintext};
use crate::tracked_files::{ensure_regular_file, PathResolveMode, resolve_repo_relative_input};
use crate::{decrypt_with_private_key, find_private_key_by_email, TrackedFiles, verify_keyring_against_trust};

/// Decrypts a single tracked file to stdout without touching disk state.
///
/// The user-supplied path is resolved to its repo-relative form the same way
/// cmd_add/cmd_remove resolve paths (canonicalise-and-strip). Relative paths
/// resolve against `repo_root`; tracked paths are stored repo-relative and
/// are validated, so the ciphertext path can never escape the repository
/// root.
pub fn cmd_cat(repo_root: &Path, file: &str, email: &str, remote_name: &str, key_store: &PathBuf, passphrase: Option<&str>) -> Result<Vec<u8>> {
    // Verify keyring signature first: never decrypt against an unverified keyring
    let (_, _, keyring) = verify_keyring_against_trust(repo_root, remote_name, key_store)?;

    // Find user's entry
    keyring.find_by_email(email)
        .with_context(|| format!("user {} not found in keyring; check --email, or ask the owner to add you with git-veil tell", email))?;

    // Find user's private key
    let private_key = find_private_key_by_email(key_store, email)?;

    // Load tracked files
    let tracked_path = repo_root.join(".git-veil/tracked.json");
    let tracked = TrackedFiles::load(&tracked_path)?;

    // Resolve the user-supplied path to its repo-relative form
    let relative = resolve_repo_relative_input(
        repo_root,
        file,
        PathResolveMode::CanonicaliseAbsoluteValidateRelative,
        "cat",
    )?;

    if !tracked.files.contains(&relative) {
        anyhow::bail!("file not tracked: {}; run git-veil add '{}' to track it", file, file);
    }

    // Lstat gate: refuse if the tracked path is a committed symlink or not a
    // regular file (absent is fine — the plaintext is normally hidden).
    ensure_regular_file(repo_root, &relative)?;

    // Compute encrypted path
    let encrypted_path = encrypted_path_for(repo_root, &relative);

    // Defence in depth: the ciphertext must stay inside the repository
    // root, beside its plaintext
    ensure_ciphertext_beside_plaintext(repo_root, &relative, &encrypted_path)?;

    // Check encrypted file exists
    if !encrypted_path.exists() {
        anyhow::bail!("Encrypted file not found: {}; run git-veil hide to create it", encrypted_path.display());
    }

    // Read encrypted content
    let ciphertext = fs::read_to_string(&encrypted_path)
        .with_context(|| format!("Failed to read encrypted file: {}", encrypted_path.display()))?;

    // Decrypt
    let plaintext = decrypt_with_private_key(&ciphertext, &private_key, passphrase)?;

    // Write plaintext to stdout
    std::io::stdout()
        .write_all(&plaintext)
        .context("Failed to write plaintext to stdout")?;
    std::io::stdout().flush().context("Failed to flush stdout")?;

    Ok(plaintext)
}
