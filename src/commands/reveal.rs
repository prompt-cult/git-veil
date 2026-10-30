use anyhow::{Context, Result};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::commands::add_file::is_tracked_in_git;
use crate::commands::hide::{encrypted_path_for, ensure_ciphertext_beside_plaintext};
use crate::exit_codes::{coded, ExitCode};
use crate::fs_atomic::write_atomic;
use crate::key_discovery::discover_x25519_private_key;
use crate::tracked_files::{
    ensure_regular_file, resolve_repo_relative_input, validate_tracked_path, PathResolveMode,
};
use crate::{cmd_verify_keys, decrypt_with_x25519_private_key, Keyring, TrackedFiles};

/// Refuses (exit 43) when the tracked plaintext path is tracked in the git
/// index. See docs/src/design.md "Ignore safety" gate 4.
fn ensure_not_tracked_in_git(repo_root: &Path, file: &Path) -> Result<()> {
    if is_tracked_in_git(repo_root, file) {
        return Err(coded(
            ExitCode::PlaintextTracked,
            "refusing to overwrite a file tracked in git. It is repository content \
             not a git-veil secret. A committed ciphertext for it may be attacker-nominated. \
             See the plaintext handling documentation. Error code 43"
                .to_string(),
        ));
    }
    Ok(())
}

/// Decrypts tracked files using the user's private key.
///
/// `files` names the working set: reveal covers exactly the named files.
/// Each is resolved with the plaintext-absent rule (the plaintext is
/// normally absent at reveal time, so the name need not exist on disk),
/// and must already be tracked - an unknown or untracked name refuses
/// with the path-safety code (71). Reveal is ungated: ring membership is
/// the only requirement, so the encryption allowance never applies here.
/// There is no change detection: the caller names the file, reveal
/// restores that file. The CLI requires at least one path; there is no
/// bare whole-manifest form.
///
/// Tracked paths are repo-relative (relative to `repo_root`) and are
/// validated before any use, so a malicious committed tracked.json cannot
/// make reveal write attacker-chosen plaintext to an arbitrary path outside
/// the repository.
pub fn cmd_reveal(
    repo_root: &Path,
    email: &str,
    remote_name: &str,
    key_store: &Path,
    files: Vec<String>,
) -> Result<()> {
    // Verify keyring signature first
    cmd_verify_keys(repo_root, remote_name, key_store)?;

    // Load keyring
    let keyring_path = repo_root.join(".git-veil/keyring");
    let keyring_text = fs::read_to_string(&keyring_path).context("Failed to read keyring file")?;
    let keyring = Keyring::parse(&keyring_text)?;

    // Find user's entry
    let entry = keyring.find_by_email(email).ok_or_else(|| {
        coded(
            ExitCode::PrincipalNotInKeyring,
            "user not found in the keyring. Check the principal, or ask the owner to add it"
                .to_string(),
        )
    })?;

    // Find the user's X25519 private key by its public key encoding (exit
    // code 21 with the create-and-back-up recipe when absent)
    let private_key = discover_x25519_private_key(key_store, &entry.public_key)?;

    // Load tracked files
    let tracked_path = repo_root.join(".git-veil/tracked.json");
    let tracked = TrackedFiles::load(&tracked_path)?;

    // The working set. Reveal covers exactly the named files: each is
    // resolved with the plaintext-absent rule, and must already be tracked.
    // No change detection.
    let mut seen: HashSet<PathBuf> = HashSet::new();
    let mut scoped: Vec<PathBuf> = Vec::new();
    for file in &files {
        let relative = resolve_repo_relative_input(
            repo_root,
            file,
            PathResolveMode::LexicalStripValidateRelative,
            "reveal",
        )?;
        if !tracked.files.contains(&relative) {
            return Err(coded(
                ExitCode::UnsafePath,
                format!(
                    "refusing to reveal: {} is not a tracked path in .git-veil/tracked.json. \
                      Track it with git-veil add-file first. Error code 71.",
                    relative.to_string_lossy()
                ),
            ));
        }
        if seen.insert(relative.clone()) {
            scoped.push(relative);
        }
    }

    if scoped.is_empty() {
        anyhow::bail!("reveal requires at least one file name");
    }

    // Two-phase, all-or-nothing reveal (compute-then-commit). Phase 1
    // verifies every tracked file's ciphertext exists and decrypts all of
    // them into memory. Any failure, a missing ciphertext or a key error,
    // aborts with nothing changed on disk. There is no mixed state where
    // some files are revealed and others remain hidden. Secrets are small
    // config-scale files, so holding every plaintext in memory is
    // acceptable. Reveal is not a bulk-restoration path.
    let mut prepared: Vec<(PathBuf, PathBuf, Vec<u8>)> = Vec::new();
    for file in &scoped {
        validate_tracked_path(file)
            .with_context(|| format!("Refusing unsafe tracked path: {}", file.display()))?;

        // Lstat gate. Writing the plaintext through a committed symlink
        // would corrupt the link target outside the repo or silently
        // replace the link. Refuse for consistency with the read gates.
        ensure_regular_file(repo_root, file)?;

        // Tracked-plaintext gate (exit 43, docs/src/design.md "Ignore safety"
        // gate 4). A plaintext tracked in git is ordinary repository
        // content, not a secret. Overwriting it from committed ciphertext
        // is the reveal-clobber channel: a repo writer nominates a source
        // file in the unsigned tracked.json and commits payload ciphertext
        // encrypted to the public ring keys. The victim's reveal would
        // overwrite the source file for the CI to execute.
        ensure_not_tracked_in_git(repo_root, file)?;

        // Compute encrypted path
        let encrypted_path = encrypted_path_for(repo_root, file);

        // Defence in depth: the ciphertext must stay inside the repository
        // root, beside its plaintext
        ensure_ciphertext_beside_plaintext(repo_root, file, &encrypted_path)?;

        // Check encrypted file exists
        if !encrypted_path.exists() {
            anyhow::bail!(
                "encrypted file not found: {}. Hide it first to create it",
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
        let plaintext = decrypt_with_x25519_private_key(&ciphertext, &private_key)?;

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
            "reveal failed: {} of {} plaintexts written",
            written.len(),
            prepared.len()
        )));
    }

    println!("files revealed");
    Ok(())
}
