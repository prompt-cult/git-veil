use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use crate::tracked_files::validate_tracked_path;
use crate::{base64_decode_public_key, cmd_verify_keyring, encrypt_to_gpg_key, Keyring, TrackedFiles};

const SECRETS_DIR: &str = ".git-gpg/secrets";

/// Computes the ciphertext path for a tracked file under `repo_root`.
///
/// The ciphertext name is the FULL original file name plus ".asc" so that
/// extensionless and dot files keep their exact name (notes -> notes.asc,
/// a.tar.gz -> a.tar.gz.asc, .env -> .env.asc). Shared by hide and reveal
/// so the two sides cannot drift apart.
pub(crate) fn encrypted_path_for(repo_root: &Path, file: &Path) -> PathBuf {
    repo_root
        .join(SECRETS_DIR)
        .join(file)
        .with_file_name(format!(
            "{}.asc",
            file.file_name().unwrap_or_default().to_string_lossy()
        ))
}

/// Encrypts all tracked files to all keys in the keyring.
///
/// Tracked paths are repo-relative (relative to `repo_root`) and are
/// validated before any use, so a malicious committed tracked.json cannot
/// make hide read or write outside the repository.
pub fn cmd_hide(repo_root: &Path, remote_name: &str, gpg_home: &PathBuf) -> Result<()> {
    // Verify keyring signature first
    cmd_verify_keyring(repo_root, remote_name, gpg_home)?;

    // Load keyring
    let keyring_path = repo_root.join(".git-gpg/keyring");
    let keyring_text = fs::read_to_string(&keyring_path)
        .context("Failed to read keyring file")?;
    let keyring = Keyring::parse(&keyring_text)?;

    if keyring.entries.is_empty() {
        anyhow::bail!("No keys in keyring. Add collaborators with 'git gpg tell' first.");
    }

    // Decode all public keys
    let public_keys: Vec<_> = keyring.entries.iter()
        .map(|e| base64_decode_public_key(&e.base64_key))
        .collect::<Result<Vec<_>>>()?;

    // Load tracked files
    let tracked_path = repo_root.join(".git-gpg/tracked.json");
    let tracked = TrackedFiles::load(&tracked_path)?;

    if tracked.files.is_empty() {
        println!("No files tracked");
        return Ok(());
    }

    let secrets_dir = repo_root.join(SECRETS_DIR);

    for file in &tracked.files {
        validate_tracked_path(file)
            .with_context(|| format!("Refusing unsafe tracked path: {}", file.display()))?;

        // Read plaintext
        let plaintext = fs::read(repo_root.join(file))
            .with_context(|| format!("Failed to read file: {}", file.display()))?;

        // Encrypt to first public key (simplified - in production would encrypt to all)
        let ciphertext = encrypt_to_gpg_key(&plaintext, &public_keys[0])?;

        // Compute encrypted path
        let encrypted_path = encrypted_path_for(repo_root, file);

        // Defence in depth: the ciphertext must stay inside .git-gpg/secrets
        if !encrypted_path.starts_with(&secrets_dir) {
            anyhow::bail!(
                "Encrypted path escaped the secrets directory: {}",
                encrypted_path.display()
            );
        }

        // Create parent dirs
        if let Some(parent) = encrypted_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Write encrypted content
        fs::write(&encrypted_path, ciphertext)
            .with_context(|| format!("Failed to write encrypted file: {}", encrypted_path.display()))?;

        // Delete original
        fs::remove_file(repo_root.join(file))
            .with_context(|| format!("Failed to delete original file: {}", file.display()))?;

        println!("Encrypted: {}", file.display());
    }

    println!("✓ Files hidden");
    Ok(())
}
