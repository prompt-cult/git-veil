use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use crate::tracked_files::validate_tracked_path;
use crate::{base64_decode_public_key, cmd_verify_keyring, encrypt_to_gpg_keys, validate_public_key_for_use, KeyUse, Keyring, TrackedFiles};

/// Computes the ciphertext path for a tracked file under `repo_root`.
///
/// The ciphertext lives BESIDE the plaintext, named after git-secret's
/// convention: the FULL original file name plus ".secret" (notes ->
/// notes.secret, a.tar.gz -> a.tar.gz.secret, .env -> .env.secret,
/// sub/dir/x -> sub/dir/x.secret). Shared by hide, reveal, cat and changes
/// so the sides cannot drift apart.
pub(crate) fn encrypted_path_for(repo_root: &Path, file: &Path) -> PathBuf {
    repo_root
        .join(file)
        .with_file_name(format!(
            "{}.secret",
            file.file_name().unwrap_or_default().to_string_lossy()
        ))
}

/// Defence in depth: the ciphertext must stay inside the repository root,
/// exactly beside its plaintext — i.e. it must be `<plaintext>.secret`.
/// Call this after computing the ciphertext path with `encrypted_path_for`;
/// never re-invent per-call-site path math.
pub(crate) fn ensure_ciphertext_beside_plaintext(
    repo_root: &Path,
    file: &Path,
    encrypted_path: &Path,
) -> Result<()> {
    let plaintext_path = repo_root.join(file);
    let beside_plaintext = plaintext_path.with_file_name(format!(
        "{}.secret",
        file.file_name().unwrap_or_default().to_string_lossy()
    ));
    if encrypted_path != beside_plaintext || !encrypted_path.starts_with(repo_root) {
        anyhow::bail!(
            "Encrypted path escaped the repository root: {}",
            encrypted_path.display()
        );
    }
    Ok(())
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

    // Key-validity policy: EVERY keyring key must be valid for encryption
    // use. Fail-closed, naming the offending keyring entry — a secrets tool
    // must never silently narrow its recipient set by skipping an invalid
    // key. This runs before any file is touched, so no ciphertext or
    // plaintext state changes when a key is rejected.
    for (entry, key) in keyring.entries.iter().zip(public_keys.iter()) {
        if let Err(cause) = validate_public_key_for_use(key, KeyUse::Encrypt) {
            anyhow::bail!(
                "keyring entry '{}' (fingerprint {}) is not usable for encryption: {}",
                entry.email,
                entry.fingerprint,
                cause
            );
        }
    }

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

        // Read plaintext
        let plaintext = fs::read(repo_root.join(file))
            .with_context(|| format!("Failed to read file: {}", file.display()))?;

        // Encrypt to EVERY key in the keyring: the collaboration promise is
        // that any collaborator can reveal, so the one ciphertext carries a
        // PKESK per recipient.
        let ciphertext = encrypt_to_gpg_keys(&plaintext, &public_keys)?;

        // Compute encrypted path
        let encrypted_path = encrypted_path_for(repo_root, file);

        // Defence in depth: the ciphertext must stay inside the repository
        // root, beside its plaintext
        ensure_ciphertext_beside_plaintext(repo_root, file, &encrypted_path)?;

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
