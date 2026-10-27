use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

use crate::exit_codes::{coded, ExitCode};
use crate::fs_atomic::write_atomic;
use crate::key_discovery::{discover_signing_key, discover_signing_key_explicit};
use crate::trust_store::RingPassStore;
use crate::{
    create_signature_block, encrypt_to_x25519_public_key, extract_content_to_verify_from_keyring,
    keyring_content_digest, parse_x25519_public_key, verify_keyring_against_trust, Keyring,
};

/// Fixed in-memory canary test-encrypted to the collaborator key before it is
/// signed into the keyring. It is discarded immediately and never written to
/// disk or transmitted. The point is only to prove the key can encrypt.
const TELL_CANARY: &[u8] = b"git-veil tell canary";

/// Adds a collaborator's public key to the keyring and signs it.
pub fn cmd_tell(
    repo_root: &Path,
    email: &str,
    collaborator_key: &str,
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

    // The second argument is the collaborator's bech32 X25519 public key
    // encoding, pasted literally. It is validated by parsing before any
    // keyring mutation, and the trimmed encoding is what the keyring
    // stores.
    let public_key_str = collaborator_key.trim();
    let collaborator_public_key = parse_x25519_public_key(public_key_str).map_err(|_| {
        coded(
            ExitCode::KeyParseFailure,
            "The second argument is not a valid X25519 public key encoding. Paste the bech32 public key printed by git-veil export or age-keygen -y.",
        )
    })?;

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

    // Stamp the ring-change pass as due (docs/design.md "The ring-change
    // ceremony"). The stamp records the version and the signed-content
    // digest just written, in this machine's key store: the whole-manifest
    // pass runs only against this exact ring, only on this machine, and
    // one pass consumes it. No committed repo content can forge it.
    let version = keyring.version.expect("bump_version set the version");
    let digest = keyring_content_digest(&content_to_sign);
    RingPassStore::write(key_store, &repo_id, version, &digest)?;

    println!("added {} to the keyring", email);

    // One plain line for the due pass: the fact, then the verb, and no
    // command (the issue #42 message policy). The stamp is written on
    // every tell, so the notice is unconditional: the fresh-start flow
    // reaches the same pass on its first hide --all.
    println!("note: the keyring has changed. To re-encrypt to the updated keyring, run the hide command with the all flag.");
    Ok(())
}
