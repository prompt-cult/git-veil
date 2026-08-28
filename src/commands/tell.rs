use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use crate::commands::hide::encrypted_path_for;
use crate::fs_atomic::write_atomic;
use crate::{base64_encode_public_key, check_email_in_identities, derive_repo_id, encrypt_to_gpg_key, extract_content_to_verify_from_keyring, extract_key_fingerprint, find_private_key_by_fingerprint, get_remote_push_url, parse_armored_public_key, sign_keyring_content, validate_public_key_for_use, verify_keyring_against_trust, KeyUse, Keyring, TrackedFiles, TrustStore};

/// Fixed in-memory canary test-encrypted to the collaborator key before it is
/// signed into the keyring. It is discarded immediately and never written to
/// disk or transmitted; the point is only to prove the key can encrypt.
const TELL_CANARY: &[u8] = b"git-veil tell canary";

/// Adds a collaborator's public key to the keyring and signs it.
pub fn cmd_tell(repo_root: &Path, email: &str, collaborator_key_path: &str, remote_name: &str, gpg_home: &PathBuf, passphrase: Option<&str>) -> Result<()> {
    // Verify trust is established
    let push_url = get_remote_push_url(repo_root, remote_name)?;
    let repo_id = derive_repo_id(&push_url)?;

    let trust_path = repo_root.join(".git-veil/trust.json");
    let trust_store = TrustStore::load_from_file(&trust_path)?;
    let trusted_fingerprint = trust_store.get_trusted_fingerprint(&repo_id).ok_or_else(|| {
        anyhow::anyhow!(
            "no trust established for {} (from remote '{}'); run git-veil trust {} <keyfile> to pin this repository's key on this machine",
            repo_id,
            remote_name,
            repo_id
        )
    })?;

    // Verify the existing keyring signature against the trusted key BEFORE any
    // mutation. An unsigned keyring is only acceptable when it has zero entries
    // (the fresh-init state); a keyring containing entries must already carry a
    // valid signature from the trusted key, otherwise tell would launder trust
    // by re-signing attacker-supplied content.
    verify_keyring_against_trust(repo_root, remote_name, gpg_home)?;

    // Read and parse collaborator key (relative paths resolve against repo_root)
    let key_content = fs::read_to_string(repo_root.join(collaborator_key_path))
        .with_context(|| format!("failed to read collaborator key file '{}'", collaborator_key_path))?;
    let collaborator_key = parse_armored_public_key(&key_content)?;

    // Verify email is in key identities
    if !check_email_in_identities(&collaborator_key, email) {
        anyhow::bail!(
            "collaborator key does not contain email: {}; pass a key file whose user ID carries that address",
            email
        );
    }

    // Test-encrypt a canary to the collaborator key to verify it can actually
    // encrypt, BEFORE any keyring mutation: a malformed-but-parseable key
    // without a usable encryption subkey must never be signed into the
    // committed keyring. The canary is in-memory only and never persisted.
    if let Err(cause) = encrypt_to_gpg_key(TELL_CANARY, &collaborator_key) {
        anyhow::bail!("collaborator key cannot encrypt for {}: {}", email, cause);
    }

    // Key-validity policy: an expired, revoked or unsigned collaborator key
    // must never be signed into the committed keyring. Fail-closed BEFORE any
    // keyring mutation.
    if let Err(cause) = validate_public_key_for_use(&collaborator_key, KeyUse::Encrypt) {
        anyhow::bail!("Refusing to tell collaborator key for {}: {}", email, cause);
    }

    // Extract fingerprint and base64 encode
    let fingerprint = extract_key_fingerprint(&collaborator_key);
    let base64_key = base64_encode_public_key(&collaborator_key)?;

    // Load keyring
    let keyring_path = repo_root.join(".git-veil/keyring");
    let keyring_content = fs::read_to_string(&keyring_path)
        .context("Failed to read keyring file")?;
    let mut keyring = Keyring::parse(&keyring_content)?;

    // Add entry (this clears signature)
    keyring.add_entry(email.to_string(), base64_key, fingerprint)?;

    // Serialize keyring without signature
    let keyring_without_sig = keyring.serialize();

    // Find signing private key: tell is run by the repo owner curating the
    // keyring, so it must sign with the TRUSTED key (the one verify_keyring
    // checks against), never with the collaborator's key.
    let signing_key = find_private_key_by_fingerprint(gpg_home, trusted_fingerprint)?;

    // Sign keyring content: sign exactly the bytes that verify_keyring will
    // extract (everything up to and including the END marker, excluding the
    // trailing newline), using the same canonicalization function so the two
    // sides of the sign/verify contract cannot drift apart.
    let content_to_sign = extract_content_to_verify_from_keyring(&keyring_without_sig)?;
    let signature = sign_keyring_content(&content_to_sign, &signing_key, passphrase)?;
    keyring.signature = Some(signature);

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
