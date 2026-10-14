use anyhow::{Context, Result};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::allowance::AllowanceStore;
use crate::commands::add::is_gitignored;
use crate::exit_codes::{coded, ExitCode};
use crate::fs_atomic::write_atomic;
use crate::tracked_files::{ensure_regular_file, get_git_config_email, validate_tracked_path};
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
/// reveal, cat and changes so the sides cannot drift apart.
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

/// Encrypts all tracked files to all keys in the keyring.
///
/// Tracked paths are repo-relative (relative to `repo_root`) and are
/// validated before any use, so a malicious committed tracked.json cannot
/// make hide read or write outside the repository.
pub fn cmd_hide(
    repo_root: &Path,
    remote_name: &str,
    key_store: &Path,
    keep_plaintext: bool,
) -> Result<()> {
    // Verify the keyring signature first. The same call yields the repo id
    // and the pin fingerprint the allowance gate keys on, plus the keyring
    // hide encrypts with.
    let (repo_id, pin_fingerprint, keyring) =
        verify_keyring_against_trust(repo_root, remote_name, key_store)?;

    let _ = &keyring;

    if keyring.entries.is_empty() {
        anyhow::bail!("no keys in the keyring. Add a collaborator first.");
    }

    // Parse all X25519 public key encodings
    let public_keys: Vec<_> = keyring
        .entries
        .iter()
        .map(|e| parse_x25519_public_key(&e.public_key))
        .collect::<Result<Vec<_>>>()?;

    // Load tracked files
    let tracked_path = repo_root.join(".git-veil/tracked.json");
    let tracked = TrackedFiles::load(&tracked_path)?;

    // Orphaned-ciphertext gate (exit 42). It runs before the
    // empty-manifest early return, because an emptied tracked.json is
    // exactly the de-tracking attack shape. A committed `.secret` whose
    // plaintext path is no longer tracked would be silently skipped by
    // rotation: removeperson + hide never re-encrypts it, leaving a
    // ciphertext a revoked collaborator can still decrypt. The gate reads
    // the git index, not the manifest, as the source of what is
    // established. Both are attacker-writable, but the index is what gets
    // pushed.
    let tracked_set: HashSet<&PathBuf> = tracked.files.iter().collect();
    // core.quotePath=false plus -z: the index listing arrives verbatim, no
    // octal-UTF8 quoting, NUL-separated, so the plaintext-path reversal
    // below sees the real names. With the default quoting, a committed
    // unicode or space ciphertext name never matches any tracked entry and
    // false-positives the orphan gate into a permanent exit-42 bricking.
    let ls = Command::new("git")
        .current_dir(repo_root)
        .args([
            "-c",
            "core.quotePath=false",
            "ls-files",
            "-z",
            "--",
            "*.secret",
        ])
        .output()
        .context("Failed to run git ls-files")?;
    if !ls.status.success() {
        anyhow::bail!(
            "git ls-files failed: {}",
            String::from_utf8_lossy(&ls.stderr).trim()
        );
    }
    let mut orphans: Vec<String> = Vec::new();
    // Tracked plaintext paths whose ciphertext is already committed. They
    // are established, so re-encrypting them needs no allowance. There is
    // no history check and no cache: the index either carries the
    // ciphertext path or it does not.
    let mut established: HashSet<PathBuf> = HashSet::new();
    for raw in ls.stdout.split(|b| *b == 0) {
        if raw.is_empty() {
            continue;
        }
        let line = String::from_utf8_lossy(raw).to_string();
        // Reverse of the ciphertext naming rule: `<name>.secret` guards
        // plaintext `<name>`. A committed file named exactly `.secret` has no
        // plaintext path. It cannot correspond to any tracked path, so
        // refusing on it would let one attacker-committed junk file brick
        // hide repo-wide. Ignore it with a warning instead.
        let ciphertext = PathBuf::from(&line);
        let stem = ciphertext.file_name().and_then(|name| {
            name.to_string_lossy()
                .strip_suffix(".secret")
                .map(String::from)
        });
        let Some(stem) = stem.filter(|s| !s.is_empty()) else {
            eprintln!("warning: ignoring committed file with no plaintext path: {line}");
            continue;
        };
        let plaintext = ciphertext
            .parent()
            .expect("file_name is Some, so a parent exists")
            .join(stem);
        if !tracked_set.contains(&plaintext) {
            orphans.push(line);
        } else {
            established.insert(plaintext);
        }
    }
    if !orphans.is_empty() {
        return Err(coded(
            ExitCode::OrphanedCiphertext,
            format!(
                "refusing to hide: committed ciphertext paths are not tracked with error code 42. \
                 Rotation would silently leave them decryptable by removed collaborators. \
                 Re-track the paths, or delete the stale ciphertext. See the rotation documentation. \
                 The offending committed ciphertext paths:\n  {}",
                orphans.join("\n  ")
            ),
        ));
    }

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
    for file in &tracked.files {
        // Only paths that have a plaintext can be first-encrypted. A path
        // with no plaintext has nothing to exfiltrate and is handled by the
        // skip-and-report semantics in phase 1 (docs/design.md "Plaintext
        // lifecycle").
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

    if tracked.files.is_empty() {
        println!("No files tracked");
        return Ok(());
    }

    // Ciphertext-ignored gate. A `.secret` swallowed by a broad ignore rule,
    // such as a parent directory like `.tmp/`, would silently never reach
    // the repository. Add succeeded, but the ciphertext is untrackable.
    // Refuse outright before encrypting anything (exit code 40).
    let mut ignored_secrets: Vec<String> = Vec::new();
    for file in &tracked.files {
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
    for file in &tracked.files {
        let relative_str = file.to_string_lossy();
        if repo_root.join(file).exists() && !is_gitignored(repo_root, &relative_str)? {
            println!(
                "warning: the tracked plaintext is not git-ignored with error code 41. A blind add of every file would commit it: {}",
                relative_str
            );
        }
    }

    // Two-phase, all-or-nothing hide (compute-then-commit). Phase 1 reads
    // and validates every tracked plaintext and encrypts every file to the
    // full public key set, holding all ciphertexts in memory. Any failure
    // here aborts with nothing changed on disk. There is no mixed state
    // where some files are hidden and others remain plaintext. Secrets are
    // small config-scale files, so holding every ciphertext in memory is
    // acceptable. Hide is not a bulk-archival path.
    let mut prepared: Vec<(PathBuf, PathBuf, Vec<u8>)> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();
    for file in &tracked.files {
        validate_tracked_path(file)
            .with_context(|| format!("Refusing unsafe tracked path: {}", file.display()))?;

        // Lstat gate. A committed tracked.json can name a committed symlink
        // pointing outside the repo. Reading through it would exfiltrate the
        // link target into the ciphertext written back to the repo.
        ensure_regular_file(repo_root, file)?;

        // Skip-and-report (docs/design.md "Plaintext lifecycle"). A tracked
        // path with no plaintext is the steady state of the delete-by-default
        // lifecycle, never an error. With a ciphertext present, on disk or
        // committed, the file is already hidden. With neither, it was never
        // hidden and has nothing to hide. Either way there is nothing to
        // encrypt and nothing to exfiltrate, so the path is skipped.
        if !repo_root.join(file).exists() {
            let state = if encrypted_path_for(repo_root, file).exists() {
                "already hidden because the plaintext is absent"
            } else {
                "never hidden because there is no plaintext and no ciphertext"
            };
            skipped.push(format!("{}: {}", file.display(), state));
            continue;
        }

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

    for line in &skipped {
        println!("Skipped: {line}");
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
