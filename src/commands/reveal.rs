use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use crate::commands::hide::{encrypted_path_for, ensure_ciphertext_beside_plaintext};
use crate::tracked_files::validate_tracked_path;
use crate::{cmd_verify_keyring, decrypt_with_gpg_key, find_private_key_by_email, Keyring, TrackedFiles};

/// Decrypts all tracked files using the user's private key.
///
/// Tracked paths are repo-relative (relative to `repo_root`) and are
/// validated before any use, so a malicious committed tracked.json cannot
/// make reveal write attacker-chosen plaintext to an arbitrary path outside
/// the repository.
pub fn cmd_reveal(repo_root: &Path, email: &str, remote_name: &str, gpg_home: &PathBuf, passphrase: Option<&str>) -> Result<()> {
    // Verify keyring signature first
    cmd_verify_keyring(repo_root, remote_name, gpg_home)?;

    // Load keyring
    let keyring_path = repo_root.join(".git-gpg/keyring");
    let keyring_text = fs::read_to_string(&keyring_path)
        .context("Failed to read keyring file")?;
    let keyring = Keyring::parse(&keyring_text)?;

    // Find user's entry
    keyring.find_by_email(email)
        .with_context(|| format!("User {} not found in keyring", email))?;

    // Find user's private key
    let private_key = find_private_key_by_email(gpg_home, email)?;

    // Load tracked files
    let tracked_path = repo_root.join(".git-gpg/tracked.json");
    let tracked = TrackedFiles::load(&tracked_path)?;

    if tracked.files.is_empty() {
        println!("No files tracked");
        return Ok(());
    }

    for file in &tracked.files {
        validate_tracked_path(file)
            .with_context(|| format!("Refusing unsafe tracked path: {}", file.display()))?;

        // Compute encrypted path
        let encrypted_path = encrypted_path_for(repo_root, file);

        // Defence in depth: the ciphertext must stay inside the repository
        // root, beside its plaintext
        ensure_ciphertext_beside_plaintext(repo_root, file, &encrypted_path)?;

        // Check encrypted file exists
        if !encrypted_path.exists() {
            anyhow::bail!("Encrypted file not found: {}", encrypted_path.display());
        }

        // Read encrypted content
        let ciphertext = fs::read_to_string(&encrypted_path)
            .with_context(|| format!("Failed to read encrypted file: {}", encrypted_path.display()))?;

        // Decrypt
        let plaintext = decrypt_with_gpg_key(&ciphertext, &private_key, passphrase)?;

        // Write plaintext
        if let Some(parent) = file.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(repo_root.join(parent))?;
            }
        }
        fs::write(repo_root.join(file), plaintext)
            .with_context(|| format!("Failed to write decrypted file: {}", file.display()))?;

        // Delete encrypted file
        fs::remove_file(&encrypted_path)
            .with_context(|| format!("Failed to delete encrypted file: {}", encrypted_path.display()))?;

        println!("Decrypted: {}", file.display());
    }

    println!("✓ Files revealed");
    Ok(())
}
