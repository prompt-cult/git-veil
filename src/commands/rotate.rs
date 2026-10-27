use anyhow::{Context, Result};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::age_crypto::X25519PrivateKey;
use crate::age_crypto::X25519PublicKey;
use crate::commands::hide::{encrypted_path_for, ensure_ciphertext_beside_plaintext};
use crate::exit_codes::{coded, ExitCode};
use crate::fs_atomic::write_atomic;
use crate::tracked_files::{validate_tracked_path, TrackedFiles};
use crate::trust_store::RingPassStore;
use crate::{
    decrypt_with_x25519_private_key, encrypt_to_x25519_public_keys,
    extract_content_to_verify_from_keyring, keyring_content_digest,
    load_x25519_private_keys_from_store, parse_x25519_public_key, verify_keyring_against_trust,
    Keyring,
};

/// Reads the committed keyring's version and signed-content digest: the
/// ring state a due ring-change stamp must match. An unsigned keyring has
/// no digest, and an unsigned ring can never match a stamp, because only
/// tell and removeperson stamp a ring they have just signed.
fn committed_ring_state(repo_root: &Path) -> Result<(Option<u64>, Option<String>)> {
    let keyring_path = repo_root.join(".git-veil/keyring");
    let keyring_text = fs::read_to_string(&keyring_path).context("Failed to read keyring file")?;
    let keyring = Keyring::parse(&keyring_text)?;
    let digest = if keyring.signature.is_some() {
        Some(keyring_content_digest(
            &extract_content_to_verify_from_keyring(&keyring_text)?,
        ))
    } else {
        None
    };
    Ok((keyring.version, digest))
}

/// Reads the git index and classifies every committed `.secret` ciphertext
/// against the tracked manifest.
///
/// Returns the tracked plaintext paths whose ciphertext is already
/// committed (established, so re-encryption needs no allowance) and the
/// committed ciphertext paths with no tracked plaintext (orphans). The
/// caller decides what an orphan means: hide acts only on the paths it
/// names, so it ignores the list; rotate rotates the whole manifest, so
/// it refuses.
///
/// core.quotePath=false plus -z: the index listing arrives verbatim, no
/// octal-UTF8 quoting, NUL-separated, so the plaintext-path reversal below
/// sees the real names. With the default quoting, a committed unicode or
/// space ciphertext name never matches any tracked entry and mis-classes
/// it. There is no history check and no cache: the index either carries
/// the ciphertext path or it does not.
pub(crate) fn index_state(
    repo_root: &Path,
    tracked: &TrackedFiles,
) -> Result<(HashSet<PathBuf>, Vec<String>)> {
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
    let mut established: HashSet<PathBuf> = HashSet::new();
    let mut orphans: Vec<String> = Vec::new();
    for raw in ls.stdout.split(|b| *b == 0) {
        if raw.is_empty() {
            continue;
        }
        let line = String::from_utf8_lossy(raw).to_string();
        // Reverse of the ciphertext naming rule: `<name>.secret` guards
        // plaintext `<name>`. A committed file named exactly `.secret` has
        // no plaintext path. It cannot correspond to any tracked path.
        // Warn about it and move on: one junk file cannot brick the pass.
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
        if tracked.files.contains(&plaintext) {
            established.insert(plaintext);
        } else {
            orphans.push(line);
        }
    }
    Ok((established, orphans))
}

/// Decrypts a ciphertext with the key store's X25519 private keys: the
/// first key that opens it wins. Every ciphertext carries a stanza per
/// keyring public key, so the operator's own member key opens it. No
/// match is the crypto refusal (exit 60), naming the path.
fn decrypt_with_any_store_key(
    ciphertext: &[u8],
    private_keys: &[(X25519PrivateKey, String)],
    file: &Path,
) -> Result<Vec<u8>> {
    for (private_key, _) in private_keys {
        if let Ok(content) = decrypt_with_x25519_private_key(ciphertext, private_key) {
            return Ok(content);
        }
    }
    Err(coded(
        ExitCode::DecryptionFailed,
        format!(
            "rotate cannot decrypt {} with any X25519 private key in the key store. \
             Import the private key of a keyring member to rotate this ciphertext. \
             Error code 60.",
            file.display()
        ),
    ))
}

/// The ring-change pass: re-encrypts every tracked ciphertext to the
/// current keyring (docs/design.md "The ring-change ceremony"). Run it
/// after tell or removeperson so the committed ciphertext reflects the
/// updated keyring.
///
/// The plaintexts are never in the data path: the ciphertext is the
/// input, and no plaintext is read, written, deleted or compared. An
/// edited-not-yet-hidden plaintext is orthogonal to the pass; hide
/// encrypts it later.
///
/// The pass is gated before anything is rotated:
///
/// 1. The stamp gate. tell and removeperson stamp the ring they signed -
///    its version and signed-content digest - into this machine's key
///    store. The committed keyring must match that stamp exactly: the ring
///    changed HERE and no pass has consumed the change yet. Without a
///    stamp, or against a ring the stamp does not match, the pass
///    refuses with the policy code (70), naming the repository id.
/// 2. The orphan gate (exit 42). The pass rotates the whole manifest, so a
///    committed ciphertext whose path is not tracked would be silently
///    left decryptable by removed collaborators. It refuses the pass,
///    naming each orphan.
///
/// On success the stamp is cleared: one pass per ring change. A tracked
/// path with no `.secret` ciphertext on disk has nothing to re-encrypt
/// and is skipped with a note.
pub fn cmd_rotate(repo_root: &Path, remote_name: &str, key_store: &Path) -> Result<()> {
    // Verify the keyring signature first, the standard gated-chain entry.
    // The same call yields the repo id the stamp is keyed by.
    let (repo_id, _pin_fingerprint, keyring) =
        verify_keyring_against_trust(repo_root, remote_name, key_store)?;

    if keyring.entries.is_empty() {
        anyhow::bail!("no keys in the keyring. Add a collaborator first.");
    }

    // The stamp gate. Both sides must be present and equal: the version
    // and the digest of the signed content, stamped at the last ring
    // change on this machine, against the committed keyring as it verifies
    // right now.
    let stamp = RingPassStore::read(key_store, &repo_id)?;
    let (version, digest) = committed_ring_state(repo_root)?;
    let due = matches!(
        (&stamp, &version, &digest),
        (Some((sv, sd)), Some(rv), Some(rd)) if sv == rv && sd == rd
    );
    if !due {
        return Err(coded(
            ExitCode::Refused,
            format!(
                "refusing the ring-change pass: no due pass is stamped for repository identity \
                 {repo_id} on this machine. The pass is armed only where a keyring change was \
                 signed, and one pass consumes it. See the ring-change ceremony documentation. \
                 Error code 70."
            ),
        ));
    }

    // Load tracked files
    let tracked_path = repo_root.join(".git-veil/tracked.json");
    let tracked = TrackedFiles::load(&tracked_path)?;

    // Parse all X25519 public key encodings
    let public_keys: Vec<X25519PublicKey> = keyring
        .entries
        .iter()
        .map(|e| parse_x25519_public_key(&e.public_key))
        .collect::<Result<Vec<_>>>()?;

    // The orphan gate. It runs over the whole git index before anything is
    // rotated, because the pass rotates the whole manifest.
    let (_established, orphans) = index_state(repo_root, &tracked)?;
    if !orphans.is_empty() {
        return Err(coded(
            ExitCode::OrphanedCiphertext,
            format!(
                "refusing the ring-change pass: committed ciphertext paths are not tracked with \
                 error code 42. Rotation would silently leave them decryptable by removed \
                 collaborators. Re-track the paths, or delete the stale ciphertext. See the \
                 rotation documentation. The offending committed ciphertext paths:\n  {}",
                orphans.join("\n  ")
            ),
        ));
    }

    if tracked.files.is_empty() {
        // Nothing to re-encrypt: the pass is complete, so it consumes the
        // stamp. Files added later are encrypted to the current ring from
        // the start.
        RingPassStore::clear(key_store, &repo_id)?;
        println!("No files tracked");
        return Ok(());
    }

    // The working set is every tracked path whose `.secret` ciphertext
    // exists on disk. A tracked path with no ciphertext on disk has
    // nothing to re-encrypt, so it is skipped with a note: the pass
    // reports honestly what it did and did not rotate.
    let mut scoped: Vec<PathBuf> = Vec::new();
    for file in &tracked.files {
        let ciphertext_path = encrypted_path_for(repo_root, file);
        if ciphertext_path.exists() {
            scoped.push(file.clone());
        } else {
            println!(
                "skipped: no .secret ciphertext on disk, nothing to re-encrypt: {}",
                file.display()
            );
        }
    }

    // The operator's X25519 private keys, from the local key store. Each
    // ciphertext names every keyring public key, so the member key this
    // machine holds opens it.
    let private_keys = load_x25519_private_keys_from_store(key_store)?;

    // Two-phase, all-or-nothing rotate (compute-then-commit). Phase 1
    // decrypts every working-set ciphertext in memory and re-encrypts it
    // to the full public key set, holding all rotated ciphertexts in
    // memory. Any failure here aborts with nothing changed on disk. There
    // is no mixed state where some ciphertexts are rotated and others are
    // not. Secrets are small config-scale files, so holding every
    // rotated ciphertext in memory is acceptable. Rotate is not a
    // bulk-archival path.
    let mut prepared: Vec<(PathBuf, PathBuf, Vec<u8>)> = Vec::new();
    for file in &scoped {
        validate_tracked_path(file)
            .with_context(|| format!("Refusing unsafe tracked path: {}", file.display()))?;

        // Defence in depth: the ciphertext must stay inside the repository
        // root, exactly beside its plaintext
        let encrypted_path = encrypted_path_for(repo_root, file);
        ensure_ciphertext_beside_plaintext(repo_root, file, &encrypted_path)?;

        // The ciphertext is the input. The plaintext beside it, if any, is
        // never read.
        let ciphertext = fs::read(&encrypted_path).with_context(|| {
            format!(
                "Failed to read encrypted file: {}",
                encrypted_path.display()
            )
        })?;

        // Decrypt in memory, then re-encrypt to every key in the current
        // keyring. The collaboration promise is that any collaborator can
        // reveal, so the one ciphertext carries a stanza per public key.
        let content = decrypt_with_any_store_key(&ciphertext, &private_keys, file)?;
        let rotated = encrypt_to_x25519_public_keys(&content, &public_keys)?;

        prepared.push((file.clone(), encrypted_path, rotated));
    }

    let mut written: Vec<&(PathBuf, PathBuf, Vec<u8>)> = Vec::new();
    let mut first_error: Option<anyhow::Error> = None;
    for item in &prepared {
        let (file, encrypted_path, rotated) = item;
        if let Some(parent) = encrypted_path.parent() {
            fs::create_dir_all(parent)?;
        }
        match write_atomic(encrypted_path, rotated).with_context(|| {
            format!(
                "Failed to write encrypted file: {}",
                encrypted_path.display()
            )
        }) {
            Ok(()) => {
                written.push(item);
                println!("Rotated: {}", file.display());
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
            "rotate failed: {} of {} ciphertexts written",
            written.len(),
            prepared.len()
        )));
    }

    // One pass consumes the stamp.
    RingPassStore::clear(key_store, &repo_id)?;

    println!("files rotated");
    println!("ring-change pass complete: every tracked ciphertext is re-encrypted to the current keyring");
    Ok(())
}
