use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use crate::fs_atomic::write_atomic;
use crate::tracked_files::{ensure_regular_file, validate_tracked_path};
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
    let keyring_path = repo_root.join(".git-veil/keyring");
    let keyring_text = fs::read_to_string(&keyring_path)
        .context("Failed to read keyring file")?;
    let keyring = Keyring::parse(&keyring_text)?;

    if keyring.entries.is_empty() {
        anyhow::bail!("No keys in keyring. Add collaborators with 'git-veil tell' first.");
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
    let tracked_path = repo_root.join(".git-veil/tracked.json");
    let tracked = TrackedFiles::load(&tracked_path)?;

    if tracked.files.is_empty() {
        println!("No files tracked");
        return Ok(());
    }

    // Two-phase, all-or-nothing hide (compute-then-commit). PHASE 1 reads and
    // validates every tracked plaintext and encrypts EVERY file to the full
    // recipient set, holding all ciphertexts in memory; ANY failure here
    // aborts with nothing changed on disk — no mixed state where some files
    // are hidden and others remain plaintext. Memory trade: secrets are
    // small config-scale files, so holding every ciphertext in memory is
    // acceptable; hide is not a bulk-archival path.
    let mut prepared: Vec<(PathBuf, PathBuf, Vec<u8>)> = Vec::new();
    for file in &tracked.files {
        validate_tracked_path(file)
            .with_context(|| format!("Refusing unsafe tracked path: {}", file.display()))?;

        // Lstat gate: a committed tracked.json can name a committed symlink
        // pointing outside the repo; reading through it would exfiltrate the
        // link target into the ciphertext written back to the repo.
        ensure_regular_file(repo_root, file)?;

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

        prepared.push((file.clone(), encrypted_path, ciphertext.into_bytes()));
    }

    // PHASE 2 (only reached after every encryption succeeded): write each
    // .secret atomically, then delete each plaintext. A plaintext is deleted
    // only AFTER its own ciphertext is durably on disk, so at worst both
    // copies exist (zero loss), never neither. If a write fails part-way,
    // the remaining ciphertexts are still written and only plaintexts whose
    // ciphertext was successfully written are deleted; the summary of what
    // was done and what was left is reported and hide exits with an error.
    let mut written: Vec<&(PathBuf, PathBuf, Vec<u8>)> = Vec::new();
    let mut first_error: Option<anyhow::Error> = None;
    for item in &prepared {
        let (_file, encrypted_path, ciphertext) = item;
        if let Some(parent) = encrypted_path.parent() {
            fs::create_dir_all(parent)?;
        }
        match write_atomic(encrypted_path, ciphertext)
            .with_context(|| format!("Failed to write encrypted file: {}", encrypted_path.display()))
        {
            Ok(()) => written.push(item),
            Err(err) => {
                if first_error.is_none() {
                    first_error = Some(err);
                }
            }
        }
    }

    let mut deleted: Vec<&PathBuf> = Vec::new();
    let mut delete_error: Option<anyhow::Error> = None;
    for (file, _encrypted_path, _ciphertext) in &written {
        match fs::remove_file(repo_root.join(file))
            .with_context(|| format!("Failed to delete original file: {}", file.display()))
        {
            Ok(()) => {
                deleted.push(file);
                println!("Encrypted: {}", file.display());
            }
            Err(err) => {
                if delete_error.is_none() {
                    delete_error = Some(err);
                }
            }
        }
    }

    if let Some(err) = first_error.or(delete_error) {
        let plaintext_left: Vec<String> = prepared
            .iter()
            .filter(|(file, _, _)| !deleted.contains(&file))
            .map(|(file, _, _)| file.display().to_string())
            .collect();
        return Err(err.context(format!(
            "hide failed part-way through the commit phase: {} of {} ciphertext(s) written, \
             {} plaintext(s) deleted; plaintext(s) left as-is: {}. \
             Re-run 'git-veil hide' once the cause is fixed.",
            written.len(),
            prepared.len(),
            deleted.len(),
            plaintext_left.join(", ")
        )));
    }

    println!("✓ Files hidden");
    Ok(())
}
