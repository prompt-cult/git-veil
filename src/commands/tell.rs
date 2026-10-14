use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

use crate::commands::hide::encrypted_path_for;
use crate::exit_codes::{coded, ExitCode};
use crate::fs_atomic::write_atomic;
use crate::key_discovery::{discover_signing_key, discover_signing_key_explicit};
use crate::{
    create_signature_block, encrypt_to_x25519_public_key, extract_content_to_verify_from_keyring,
    parse_x25519_public_key, verify_keyring_against_trust, Keyring, TrackedFiles,
};

/// Fixed in-memory canary test-encrypted to the collaborator key before it is
/// signed into the keyring. It is discarded immediately and never written to
/// disk or transmitted. The point is only to prove the key can encrypt.
const TELL_CANARY: &[u8] = b"git-veil tell canary";

/// Adds a collaborator's public key to the keyring and signs it.
pub fn cmd_tell(
    repo_root: &Path,
    email: &str,
    collaborator_key_path: &str,
    remote_name: &str,
    key_store: &Path,
    signing_key_selection: Option<&str>,
) -> Result<()> {
    // Verify trust is established and the existing keyring signature
    // against the trusted key before any mutation. An unsigned keyring is
    // only acceptable when it has zero entries (the fresh-init state). A
    // keyring containing entries must already carry a valid signature
    // from the trusted key, otherwise tell would launder trust by
    // re-signing attacker-supplied content.
    let (repo_id, trusted_fingerprint, _) =
        verify_keyring_against_trust(repo_root, remote_name, key_store)?;

    // Read and parse the collaborator key file. Relative paths resolve
    // against repo_root. The first line holds the X25519 public key
    // encoding.
    let key_content = fs::read_to_string(repo_root.join(collaborator_key_path))
        .with_context(|| "failed to read the collaborator key file".to_string())?;
    let public_key_str = key_content.lines().next().unwrap_or("").trim();
    let collaborator_public_key = parse_x25519_public_key(public_key_str)?;

    // Test-encrypt a canary to the collaborator key to verify it can
    // actually encrypt, before any keyring mutation. A
    // malformed-but-parseable key must never be signed into the committed
    // keyring. The canary is in-memory only.
    if encrypt_to_x25519_public_key(TELL_CANARY, &collaborator_public_key).is_err() {
        return Err(coded(
            ExitCode::EncryptionFailed,
            "collaborator key cannot encrypt. The public key may be invalid. See the tell documentation"
                .to_string(),
        ));
    }

    // Load keyring
    let keyring_path = repo_root.join(".git-veil/keyring");
    let keyring_content =
        fs::read_to_string(&keyring_path).context("Failed to read keyring file")?;
    let mut keyring = Keyring::parse(&keyring_content)?;

    // Add the two-field entry (principal, X25519 public key). The binding
    // fingerprint is computed on demand and never stored.
    keyring.add_entry(email.to_string(), public_key_str.to_string())?;

    // Bump the monotonic freshness counter before signing, so the counter
    // is covered by the new signature (see docs/design.md "Keyring format and
    // freshness"). The counter lives in the signed payload and needs no
    // state outside the keyring, so no clock and no cross-machine bookkeeping.
    keyring.bump_version()?;

    // Serialize keyring without signature
    let keyring_without_sig = keyring.serialize();

    // Find the signing key. Tell is run by the repo owner curating the
    // keyring, so it must sign with the trusted key, the one
    // verify_keyring checks against, never with the collaborator's key.
    // Discovery selects the signing key whose owner key fingerprint
    // matches the pinned fingerprint. git-veil never generates one. A
    // missing key fails with the recipe.
    let signing_key = match signing_key_selection {
        Some(verifying_key_hex) => discover_signing_key_explicit(key_store, verifying_key_hex)?,
        None => discover_signing_key(key_store, &repo_id, &trusted_fingerprint)?,
    };

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

    println!("added {} to the keyring", email);

    // UX hint. Any ciphertext hidden before this tell was encrypted to
    // the previous keyring and does not include the new collaborator's
    // key, so their first reveal would fail. Point the owner at
    // `git-veil hide`.
    //
    // Informational only. A load failure or empty tracked list means there
    // is nothing yet to re-encrypt, so no hint and never an error.
    let tracked = TrackedFiles::load(&repo_root.join(".git-veil/tracked.json"));
    if let Ok(tracked) = tracked {
        let has_ciphertext = tracked
            .files
            .iter()
            .any(|file| encrypted_path_for(repo_root, file).exists());
        if has_ciphertext {
            println!("note: existing ciphertext does not include the new collaborator. Hide again to re-encrypt all tracked files to the current keyring.");
        }
    }
    Ok(())
}
