use anyhow::{Context, Result};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::age_crypto::X25519PublicKey;
use crate::allowance::AllowanceStore;
use crate::commands::add_file::is_gitignored;
use crate::commands::rotate::index_state;
use crate::exit_codes::{coded, ExitCode};
use crate::fs_atomic::write_atomic;
use crate::tracked_files::{
    ensure_regular_file, get_git_config_email, resolve_repo_relative_input, validate_tracked_path,
    PathResolveMode,
};
use crate::{
    encrypt_to_x25519_public_keys, parse_x25519_public_key, verify_keyring_against_trust,
    TrackedFiles,
};

/// Computes the ciphertext path for a tracked file under `repo_root`.
///
/// The ciphertext lives beside the plaintext, named after git-secret's
/// convention: the full original file name plus ".secret" (notes becomes
/// notes.secret, a.tar.gz becomes a.tar.gz.secret, .env becomes
/// .env.secret, sub/dir/x becomes sub/dir/x.secret). Shared by hide,
/// reveal, cat, changes and rotate so the sides cannot drift apart.
pub(crate) fn encrypted_path_for(repo_root: &Path, file: &Path) -> PathBuf {
    repo_root.join(file).with_file_name(format!(
        "{}.secret",
        file.file_name().unwrap_or_default().to_string_lossy()
    ))
}

/// Defence in depth: the ciphertext must stay inside the repository
/// root, exactly beside its plaintext, as `<plaintext>.secret`. Call this
/// after computing the ciphertext path with `encrypted_path_for`. Never
/// re-invent per-call-site path math.
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

/// Encrypts tracked files to all keys in the keyring.
///
/// `files` names the working set: hide covers exactly the named files.
/// Each is resolved the way add resolves paths (canonicalise,
/// repo-relative, validated), and must already be tracked - an unknown or
/// untracked name refuses with the path-safety code (71). The gates below
/// then apply to that set only. There is no change detection: the caller
/// names the file, the gate checks that file. The CLI requires at least
/// one path; the whole-manifest pass is rotate, the ring-change ceremony.
///
/// Tracked paths are repo-relative (relative to `repo_root`) and are
/// validated before any use, so a malicious committed tracked.json cannot
/// make hide read or write outside the repository.
pub fn cmd_hide(
    repo_root: &Path,
    remote_name: &str,
    key_store: &Path,
    keep_plaintext: bool,
    files: Vec<String>,
) -> Result<()> {
    // Verify the keyring signature first. The same call yields the repo id
    // and the pin fingerprint the allowance gate keys on, plus the keyring
    // hide encrypts with.
    let (repo_id, pin_fingerprint, keyring) =
        verify_keyring_against_trust(repo_root, remote_name, key_store)?;

    if keyring.entries.is_empty() {
        anyhow::bail!("no keys in the keyring. Add a collaborator first.");
    }

    // Parse all X25519 public key encodings
    let public_keys: Vec<X25519PublicKey> = keyring
        .entries
        .iter()
        .map(|e| parse_x25519_public_key(&e.public_key))
        .collect::<Result<Vec<_>>>()?;

    // Load tracked files
    let tracked_path = repo_root.join(".git-veil/tracked.json");
    let tracked = TrackedFiles::load(&tracked_path)?;

    // The working set. Hide covers exactly the named files: each is
    // resolved like add resolves paths, and must already be tracked. No
    // change detection.
    let mut seen: HashSet<PathBuf> = HashSet::new();
    let mut scoped: Vec<PathBuf> = Vec::new();
    for file in &files {
        let relative = resolve_repo_relative_input(
            repo_root,
            file,
            PathResolveMode::CanonicaliseRequireExists,
            "hide",
        )?;
        if !tracked.files.contains(&relative) {
            return Err(coded(
                ExitCode::UnsafePath,
                format!(
                    "refusing to hide: {} is not a tracked path in .git-veil/tracked.json. \
                     Track it with git-veil add first. Error code 71.",
                    relative.to_string_lossy()
                ),
            ));
        }
        if seen.insert(relative.clone()) {
            scoped.push(relative);
        }
    }

    // The git index classifies the working set: which tracked paths
    // already have a committed ciphertext (established, so the allowance
    // gate skips them), and which committed ciphertexts are orphans. Hide
    // runs no orphan refusal; rotate refuses on them. See index_state.
    let (established, _orphans) = index_state(repo_root, &tracked)?;

    // Encryption-allowance gate (exit 72, see "Allowance" in
    // docs/design.md). tracked.json is committed and unsigned, so a repo
    // writer can nominate a path. A tracked path with a plaintext on disk,
    // no committed ciphertext in the index and no allowance on this machine
    // is exactly a nominated first-encrypt: encrypting it would write the
    // plaintext's contents into a committed ciphertext to every keyring
    // member, including the attacker's, silently when the plaintext is
    // gitignored. The allowance record lives in the key store, outside any
    // repo writer's reach, keyed to this machine's trust pin and this git
    // user. Re-encryption of an established ciphertext needs no allowance.
    let mut unintended: Vec<String> = Vec::new();
    let mut principal: Option<String> = None;
    for file in &scoped {
        // Only paths that have a plaintext can be first-encrypted. A path
        // whose plaintext is absent has nothing to exfiltrate. A name
        // resolved a moment ago, so this is the between-resolve-and-read
        // window only; the read in phase 1 would fail anyway.
        if established.contains(file) || !repo_root.join(file).exists() {
            continue;
        }
        // The principal is resolved lazily, and only when the gate has a
        // candidate path, so a repo without user.email set keeps hiding
        // established ciphertexts.
        if principal.is_none() {
            principal = Some(get_git_config_email(repo_root).context(
                "hide checks the encryption allowance for this machine, which needs your git config user.email",
            )?);
        }
        if !AllowanceStore::contains(
            key_store,
            &repo_id,
            &pin_fingerprint,
            principal.as_ref().expect("principal was just resolved"),
            file,
        ) {
            unintended.push(file.to_string_lossy().to_string());
        }
    }
    if !unintended.is_empty() {
        return Err(coded(
            ExitCode::UnintendedEncryption,
            format!(
                "refusing to hide: paths are tracked but were never allowed for encryption on \
                 this machine. tracked.json may have been modified by someone else. Allow the \
                 paths deliberately if the tracking is wanted. Error code 72. \
                 The offending tracked paths:\n  {}",
                unintended.join("\n  ")
            ),
        ));
    }

    if scoped.is_empty() {
        anyhow::bail!("hide requires at least one file name");
    }

    // Ciphertext-ignored gate. A `.secret` swallowed by a broad ignore rule,
    // such as a parent directory like `.tmp/`, would silently never reach
    // the repository. Add succeeded, but the ciphertext is untrackable.
    // Refuse outright before encrypting anything (exit code 40).
    let mut ignored_secrets: Vec<String> = Vec::new();
    for file in &scoped {
        let secret_relative = format!("{}.secret", file.to_string_lossy());
        if is_gitignored(repo_root, &secret_relative)? {
            ignored_secrets.push(secret_relative);
        }
    }
    if !ignored_secrets.is_empty() {
        return Err(coded(
            ExitCode::CiphertextIgnored,
            "refusing to hide: ciphertext paths are git-ignored with error code 40 so they would never reach the repository. Fix .gitignore first. See the ignore safety documentation"
                .to_string(),
        ));
    }

    // Plaintext-leak warning. The plaintext's only protection is its
    // .gitignore entry, and add only guarantees it at add time. A rename
    // or .gitignore edit can drift it. A blind `git add -A` would then
    // commit the plaintext. Warning only (error code 41). Hide proceeds.
    for file in &scoped {
        let relative_str = file.to_string_lossy();
        if repo_root.join(file).exists() && !is_gitignored(repo_root, &relative_str)? {
            println!(
                "warning: the tracked plaintext is not git-ignored with error code 41. A blind add of every file would commit it: {}",
                relative_str
            );
        }
    }

    // Two-phase, all-or-nothing hide (compute-then-commit). Phase 1 reads
    // and validates every named plaintext and encrypts every file to the
    // full public key set, holding all ciphertexts in memory. Any failure
    // here aborts with nothing changed on disk. There is no mixed state
    // where some files are hidden and others remain plaintext. Secrets are
    // small config-scale files, so holding every ciphertext in memory is
    // acceptable. Hide is not a bulk-archival path.
    //
    // A named path resolved, so its plaintext existed moments ago. A
    // plaintext that vanished in between fails the read below, which is
    // the all-or-nothing contract doing its job.
    let mut prepared: Vec<(PathBuf, PathBuf, Vec<u8>)> = Vec::new();
    for file in &scoped {
        validate_tracked_path(file)
            .with_context(|| format!("Refusing unsafe tracked path: {}", file.display()))?;

        // Lstat gate. A committed tracked.json can name a committed symlink
        // pointing outside the repo. Reading through it would exfiltrate the
        // link target into the ciphertext written back to the repo.
        ensure_regular_file(repo_root, file)?;

        // Read plaintext
        let plaintext = fs::read(repo_root.join(file))
            .with_context(|| format!("Failed to read file: {}", file.display()))?;

        // Encrypt to every key in the keyring. The collaboration promise is
        // that any collaborator can reveal, so the one ciphertext carries a
        // stanza per public key.
        let ciphertext = encrypt_to_x25519_public_keys(&plaintext, &public_keys)?;

        // Compute encrypted path
        let encrypted_path = encrypted_path_for(repo_root, file);

        // Defence in depth: the ciphertext must stay inside the repository
        // root, beside its plaintext
        ensure_ciphertext_beside_plaintext(repo_root, file, &encrypted_path)?;

        prepared.push((file.clone(), encrypted_path, ciphertext));
    }

    let mut written: Vec<&(PathBuf, PathBuf, Vec<u8>)> = Vec::new();
    let mut first_error: Option<anyhow::Error> = None;
    for item in &prepared {
        let (file, encrypted_path, ciphertext) = item;
        if let Some(parent) = encrypted_path.parent() {
            fs::create_dir_all(parent)?;
        }
        match write_atomic(encrypted_path, ciphertext).with_context(|| {
            format!(
                "Failed to write encrypted file: {}",
                encrypted_path.display()
            )
        }) {
            Ok(()) => {
                written.push(item);
                println!("Encrypted: {}", file.display());
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
            "hide failed: {} of {} ciphertexts written",
            written.len(),
            prepared.len()
        )));
    }

    // Plaintext deletion is the default (docs/design.md "Plaintext
    // lifecycle"). The plaintext's only worktree protection is a
    // .gitignore line, so it is deleted once every ciphertext is durably
    // on disk. --keep-plaintext opts out. The delete happens only after
    // the full all-or-nothing write phase above succeeded. At worst both
    // copies exist, never neither.
    if !keep_plaintext {
        for (file, _, _) in &prepared {
            let plaintext_path = repo_root.join(file);
            fs::remove_file(&plaintext_path).with_context(|| {
                format!("Failed to delete plaintext: {}", plaintext_path.display())
            })?;
            println!("Deleted plaintext: {}", file.display());
        }
    }

    println!("files hidden");
    Ok(())
}
