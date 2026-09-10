use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use crate::commands::hide::encrypted_path_for;
use crate::exit_codes::{coded, ExitCode};
use crate::fs_atomic::write_atomic;
use crate::key_discovery::discover_signing_key;
use crate::{
    create_signature_block, encrypt_to_recipient, extract_content_to_verify_from_keyring,
    fingerprint_for_recipient, parse_recipient, verify_keyring_against_trust, Keyring,
    TrackedFiles,
};

/// Fixed in-memory canary test-encrypted to the collaborator key before it is
/// signed into the keyring. It is discarded immediately and never written to
/// disk or transmitted; the point is only to prove the key can encrypt.
const TELL_CANARY: &[u8] = b"git-veil tell canary";

/// Adds a collaborator's public key to the keyring and signs it.
pub fn cmd_tell(
    repo_root: &Path,
    email: &str,
    collaborator_key_path: &str,
    remote_name: &str,
    key_store: &PathBuf,
    signing_key_selection: Option<&str>,
) -> Result<()> {
    // Verify trust is established AND the existing keyring signature
    // against the trusted key BEFORE any mutation. An unsigned keyring is
    // only acceptable when it has zero entries (the fresh-init state); a
    // keyring containing entries must already carry a valid signature
    // from the trusted key, otherwise tell would launder trust by
    // re-signing attacker-supplied content.
    let (_, trusted_fingerprint, _) =
        verify_keyring_against_trust(repo_root, remote_name, key_store)?;

    // Read and parse collaborator key (relative paths resolve against repo_root)
    // The key file contains the age recipient string on the first line.
    let key_content =
        fs::read_to_string(repo_root.join(collaborator_key_path)).with_context(|| {
            format!(
                "failed to read collaborator key file '{}'",
                collaborator_key_path
            )
        })?;
    let recipient_str = key_content.lines().next().unwrap_or("").trim();
    let collaborator_recipient = parse_recipient(recipient_str)?;

    // Test-encrypt a canary to the collaborator key to verify it can actually
    // encrypt, BEFORE any keyring mutation: a malformed-but-parseable key
    // must never be signed into the committed keyring. The canary is in-memory only.
    if let Err(cause) = encrypt_to_recipient(TELL_CANARY, &collaborator_recipient) {
        return Err(coded(
            ExitCode::EncryptionFailed,
            format!("collaborator key cannot encrypt for {}: {}", email, cause),
        ));
    }

    // Extract fingerprint from the recipient string
    let fingerprint = fingerprint_for_recipient(recipient_str);

    // Load keyring
    let keyring_path = repo_root.join(".git-veil/keyring");
    let keyring_content =
        fs::read_to_string(&keyring_path).context("Failed to read keyring file")?;
    let mut keyring = Keyring::parse(&keyring_content)?;

    // Add entry (this clears signature)
    keyring.add_entry(email.to_string(), recipient_str.to_string(), fingerprint)?;

    // Serialize keyring without signature
    let keyring_without_sig = keyring.serialize();

    // Find signing key: tell is run by the repo owner curating the
    // keyring, so it must sign with the TRUSTED key (the one verify_keyring
    // checks against), never with the collaborator's key. Discovery selects
    // the signing key whose verifying key matches the pinned fingerprint;
    // git-veil never generates one — a missing key fails with the recipe.
    let signing_key =
        discover_signing_key(key_store, signing_key_selection, Some(&trusted_fingerprint))?;

    // Sign keyring content: sign exactly the bytes that verify_keyring will
    // extract (everything up to and including the END marker, excluding the
    // trailing newline), using the same canonicalization function so the two
    // sides of the sign/verify contract cannot drift apart.
    let content_to_sign = extract_content_to_verify_from_keyring(&keyring_without_sig)?;
    let sig_block = create_signature_block(&content_to_sign, &signing_key)?;
    keyring.signature = Some(sig_block);

    // Save keyring
    write_atomic(&keyring_path, keyring.serialize().as_bytes())
        .context("Failed to write keyring file")?;

    println!("✓ Added {} to keyring", email);

    // UX hint: any ciphertext hidden BEFORE this tell was encrypted to the
    // previous keyring and does not include the new collaborator's key, so
    // their first reveal would fail. Point the owner at `git-veil hide`.
    // Informational only: a load failure or empty tracked list means there
    // is nothing (yet) to re-encrypt, so no hint and never an error.
    let tracked = TrackedFiles::load(&repo_root.join(".git-veil/tracked.json"));
    if let Ok(tracked) = tracked {
        let has_ciphertext = tracked
            .files
            .iter()
            .any(|file| encrypted_path_for(repo_root, file).exists());
        if has_ciphertext {
            println!(
                "note: existing ciphertext does not include {}; run git-veil hide to re-encrypt all tracked files to the current keyring",
                email
            );
        }
    }
    Ok(())
}
