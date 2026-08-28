use anyhow::{Context, Result};
use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use crate::commands::hide::encrypted_path_for;
use crate::tracked_files::validate_tracked_path;
use crate::{decrypt_with_gpg_key, find_private_key_by_email, TrackedFiles, verify_keyring_against_trust};

const SECRETS_DIR: &str = ".git-gpg/secrets";

/// Decrypts a single tracked file to stdout without touching disk state.
///
/// The user-supplied path is resolved to its repo-relative form the same way
/// cmd_add/cmd_remove resolve paths (canonicalise-and-strip), and must match
/// an entry in tracked.json. Tracked paths are stored repo-relative and are
/// validated, so the ciphertext path can never escape .git-gpg/secrets.
pub fn cmd_cat(file: &str, email: &str, remote_name: &str, gpg_home: &PathBuf) -> Result<Vec<u8>> {
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

    // Resolve the user-supplied path to its repo-relative form
    let path = PathBuf::from(file);
    let repo_root = env::current_dir().context("Failed to get current directory")?;
    let repo_root = fs::canonicalize(&repo_root)
        .context("Failed to canonicalise repository root")?;

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
        anyhow::bail!("Cannot cat the repository root itself: {}", file);
    }

    if !tracked.files.contains(&relative) {
        anyhow::bail!("File not tracked: {}", file);
    }

    // Compute encrypted path
    let encrypted_path = encrypted_path_for(&relative);

    // Defence in depth: the ciphertext must stay inside .git-gpg/secrets
    if !encrypted_path.starts_with(SECRETS_DIR) {
        anyhow::bail!(
            "Encrypted path escaped the secrets directory: {}",
            encrypted_path.display()
        );
    }

    // Check encrypted file exists
    if !encrypted_path.exists() {
        anyhow::bail!("Encrypted file not found: {}", encrypted_path.display());
    }

    // Read encrypted content
    let ciphertext = fs::read_to_string(&encrypted_path)
        .with_context(|| format!("Failed to read encrypted file: {}", encrypted_path.display()))?;

    // Decrypt
    let plaintext = decrypt_with_gpg_key(&ciphertext, &private_key)?;

    // Write plaintext to stdout
    std::io::stdout()
        .write_all(&plaintext)
        .context("Failed to write plaintext to stdout")?;
    std::io::stdout().flush().context("Failed to flush stdout")?;

    Ok(plaintext)
}
