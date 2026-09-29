use anyhow::{Context, Result};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::commands::add::is_gitignored;
use crate::exit_codes::{coded, ExitCode};
use crate::fs_atomic::write_atomic;
use crate::intent::LocalAdds;
use crate::tracked_files::{ensure_regular_file, validate_tracked_path};
use crate::{encrypt_to_recipients, parse_recipient, verify_keyring_against_trust, TrackedFiles};

/// Computes the ciphertext path for a tracked file under `repo_root`.
///
/// The ciphertext lives BESIDE the plaintext, named after git-secret's
/// convention: the FULL original file name plus ".secret" (notes ->
/// notes.secret, a.tar.gz -> a.tar.gz.secret, .env -> .env.secret,
/// sub/dir/x -> sub/dir/x.secret). Shared by hide, reveal, cat and changes
/// so the sides cannot drift apart.
pub(crate) fn encrypted_path_for(repo_root: &Path, file: &Path) -> PathBuf {
    repo_root.join(file).with_file_name(format!(
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
pub fn cmd_hide(
    repo_root: &Path,
    remote_name: &str,
    key_store: &PathBuf,
    dangerously_delete_plaintext: bool,
) -> Result<()> {
    // Verify keyring signature first; the same call yields the repo id the
    // intent gate needs and the keyring hide encrypts with.
    let (repo_id, _, keyring) = verify_keyring_against_trust(repo_root, remote_name, key_store)?;

    // Load keyring
    let _ = &keyring;

    if keyring.entries.is_empty() {
        anyhow::bail!("No keys in keyring. Add collaborators with 'git-veil tell' first.");
    }

    // Parse all recipient strings
    let recipients: Vec<_> = keyring
        .entries
        .iter()
        .map(|e| parse_recipient(&e.recipient))
        .collect::<Result<Vec<_>>>()?;

    // Load tracked files
    let tracked_path = repo_root.join(".git-veil/tracked.json");
    let tracked = TrackedFiles::load(&tracked_path)?;

    // Orphaned-ciphertext gate (exit 42, runs before the empty-manifest
    // early return — an emptied tracked.json is exactly the de-tracking
    // attack shape). A committed `.secret` whose plaintext path is no
    // longer tracked would be silently skipped by rotation: removeperson +
    // hide never re-encrypts it, leaving a ciphertext a revoked
    // collaborator can still decrypt. The gate reads the git index, not
    // the manifest, as the source of what is established, because both are
    // attacker-writable but the index is what gets pushed.
    let tracked_set: HashSet<&PathBuf> = tracked.files.iter().collect();
    let ls = Command::new("git")
        .current_dir(repo_root)
        .args(["ls-files", "--", "*.secret"])
        .output()
        .context("Failed to run git ls-files")?;
    if !ls.status.success() {
        anyhow::bail!(
            "git ls-files failed: {}",
            String::from_utf8_lossy(&ls.stderr).trim()
        );
    }
    let mut orphans: Vec<String> = Vec::new();
    // Plaintext paths whose ciphertext is already committed (established —
    // no intent needed to re-encrypt them).
    let mut established: HashSet<PathBuf> = HashSet::new();
    for line in String::from_utf8_lossy(&ls.stdout).lines() {
        // Reverse of the ciphertext naming rule: `<name>.secret` guards
        // plaintext `<name>`. A file literally named `.secret` has no
        // plaintext path and is always an orphan.
        let ciphertext = PathBuf::from(line);
        let plaintext = ciphertext
            .file_name()
            .and_then(|name| {
                name.to_string_lossy()
                    .strip_suffix(".secret")
                    .map(String::from)
            })
            .filter(|stem| !stem.is_empty())
            .map(|stem| {
                ciphertext
                    .parent()
                    .expect("file_name is Some, so a parent exists")
                    .join(stem)
            })
            .unwrap_or_default();
        if !tracked_set.contains(&plaintext) {
            orphans.push(line.to_string());
        } else {
            established.insert(plaintext);
        }
    }
    if !orphans.is_empty() {
        return Err(coded(
            ExitCode::OrphanedCiphertext,
            format!(
                "refusing to hide: the committed ciphertext path(s) below are not tracked, so \
                 rotation would silently leave them decryptable by removed collaborators; \
                 re-track with `git-veil add <path>` or delete the stale ciphertext with \
                 `git rm` (error code 42):\n  {}",
                orphans.join("\n  ")
            ),
        ));
    }

    // Encryption-intent gate (exit 72, see "Encryption intent" in
    // docs/design.md): tracked.json is committed and unsigned, so a repo
    // writer can nominate a path. A tracked path whose ciphertext is NOT in
    // the index must have been added on THIS machine (the intent log lives
    // in the key store, outside any repo writer's reach) or hide refuses:
    // first-encrypting an attacker-nominated path is exactly the
    // exfiltration channel, and the gitignored-plaintext case would
    // otherwise be silent.
    let mut unintended: Vec<String> = Vec::new();
    for file in &tracked.files {
        if !established.contains(file) && !LocalAdds::has_intent(key_store, &repo_id, file) {
            unintended.push(file.to_string_lossy().to_string());
        }
    }
    if !unintended.is_empty() {
        return Err(coded(
            ExitCode::UnintendedEncryption,
            format!(
                "refusing to hide: the path(s) below are tracked but you never ran \
                 `git-veil add` for them on this machine and their ciphertext was never \
                 committed; tracked.json was likely modified by someone else — run \
                 `git-veil add <path>` if the tracking is wanted, or `git-veil remove <path>` \
                 if it is not (error code 72):\n  {}",
                unintended.join("\n  ")
            ),
        ));
    }

    if tracked.files.is_empty() {
        println!("No files tracked");
        return Ok(());
    }

    // Ciphertext-ignored gate: a `.secret` swallowed by a broad ignore rule
    // (e.g. a parent directory like `.tmp/`) would silently never reach the
    // repository — add succeeded, but the ciphertext is untrackable. Refuse
    // outright BEFORE encrypting anything (exit code 40).
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
            format!(
                "refusing to hide: the ciphertext path(s) below are git-ignored, so they would never reach the repository; fix .gitignore first (error code 40):\n  {}",
                ignored_secrets.join("\n  ")
            ),
        ));
    }

    // Plaintext-leak warning: the plaintext's only protection is its
    // .gitignore entry, and add only guarantees it at add time — a rename
    // or .gitignore edit can drift it. A blind `git add -A` would then
    // commit the plaintext. Warning only (error code 41); hide proceeds.
    for file in &tracked.files {
        let relative_str = file.to_string_lossy();
        if repo_root.join(file).exists() && !is_gitignored(repo_root, &relative_str)? {
            println!(
                "warning: tracked plaintext '{}' is not git-ignored; a blind `git add -A` would commit it (error code 41)",
                relative_str
            );
        }
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
        let ciphertext = encrypt_to_recipients(&plaintext, &recipients)?;

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
            "hide failed: {} of {} ciphertext(s) written",
            written.len(),
            prepared.len()
        )));
    }

    if dangerously_delete_plaintext {
        for (file, _, _) in &prepared {
            let plaintext_path = repo_root.join(file);
            fs::remove_file(&plaintext_path).with_context(|| {
                format!("Failed to delete plaintext: {}", plaintext_path.display())
            })?;
            println!("Deleted plaintext: {}", file.display());
        }
    }

    println!("✓ Files hidden");
    Ok(())
}
