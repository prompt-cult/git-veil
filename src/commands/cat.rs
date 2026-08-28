use anyhow::{Context, Result};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::commands::hide::{encrypted_path_for, ensure_ciphertext_beside_plaintext};
use crate::tracked_files::validate_tracked_path;
use crate::{decrypt_with_gpg_key, find_private_key_by_email, TrackedFiles, verify_keyring_against_trust};

/// Decrypts a single tracked file to stdout without touching disk state.
///
/// The user-supplied path is resolved to its repo-relative form the same way
/// cmd_add/cmd_remove resolve paths (canonicalise-and-strip). Relative paths
/// resolve against `repo_root`; tracked paths are stored repo-relative and
/// are validated, so the ciphertext path can never escape the repository
/// root.
pub fn cmd_cat(repo_root: &Path, file: &str, email: &str, remote_name: &str, gpg_home: &PathBuf, passphrase: Option<&str>) -> Result<Vec<u8>> {
    // Verify keyring signature first: never decrypt against an unverified keyring
    let (_, keyring) = verify_keyring_against_trust(repo_root, remote_name, gpg_home)?;

    // Find user's entry
    keyring.find_by_email(email)
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
        let canonical = fs::canonicalize(&path)
            .with_context(|| format!("File not found: {}", file))?;
        canonical
            .strip_prefix(&canonical_root)
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
        anyhow::bail!("Cannot cat the repository root itself: {}", file);
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

    // Write plaintext to stdout
    std::io::stdout()
        .write_all(&plaintext)
        .context("Failed to write plaintext to stdout")?;
    std::io::stdout().flush().context("Failed to flush stdout")?;

    Ok(plaintext)
}
