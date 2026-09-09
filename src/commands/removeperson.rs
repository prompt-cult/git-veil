use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use crate::fs_atomic::write_atomic;
use crate::{
    create_signature_block, derive_repo_id, extract_content_to_verify_from_keyring,
    get_remote_push_url, parse_signing_key,
    verify_keyring_against_trust, Keyring, TrustStore,
};

/// Removes a collaborator's entry from the keyring and re-signs it.
pub fn cmd_removeperson(
    repo_root: &Path,
    email_to_remove: &str,
    remote_name: &str,
    key_store: &PathBuf,
    _passphrase: Option<&str>,
) -> Result<()> {
    // Verify trust is established
    let push_url = get_remote_push_url(repo_root, remote_name)?;
    let repo_id = derive_repo_id(&push_url)?;

    let trust_path = repo_root.join(".git-veil/trust.json");
    let trust_store = TrustStore::load_from_file(&trust_path)?;
    let _trusted_fingerprint = trust_store.get_trusted_fingerprint(&repo_id).ok_or_else(|| {
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
    // valid signature from the trusted key, otherwise removeperson would launder
    // trust by re-signing attacker-supplied content.
    verify_keyring_against_trust(repo_root, remote_name, key_store)?;

    // Load keyring
    let keyring_path = repo_root.join(".git-veil/keyring");
    let keyring_content =
        fs::read_to_string(&keyring_path).context("Failed to read keyring file")?;
    let mut keyring = Keyring::parse(&keyring_content)?;

    // Find the entry by exact email
    if keyring.find_by_email(email_to_remove).is_none() {
        anyhow::bail!(
            "'{}' not found in keyring; check the email against git-veil list-keys",
            email_to_remove
        );
    }

    // Remove entry (this clears signature)
    keyring.remove_entry(email_to_remove);

    // Serialize keyring without signature
    let keyring_without_sig = keyring.serialize();

    // Re-sign with the TRUSTED key: removeperson curates the keyring exactly
    // like tell does, so it must sign with the key verify_keyring checks
    // against, never with any collaborator's key.
    // Load the Ed25519 signing key from the key store.
    let signing_keys_path = key_store.join("signing-keys.txt");
    let signing_key_content = fs::read_to_string(&signing_keys_path)
        .context("Failed to read signing-keys.txt")?;
    let signing_key_hex = signing_key_content.lines().next().unwrap_or("").trim();
    let signing_key = parse_signing_key(signing_key_hex)?;

    // Sign keyring content: sign exactly the bytes that verify_keyring will
    // extract, using the same canonicalization function so the two sides of
    // the sign/verify contract cannot drift apart. An empty keyring is a
    // legitimate result (revoking the last collaborator); verify_keyring
    // accepts a signed keyring regardless of entry count.
    let content_to_sign = extract_content_to_verify_from_keyring(&keyring_without_sig)?;
    let sig_block = create_signature_block(&content_to_sign, &signing_key)?;
    keyring.signature = Some(sig_block);

    // Save keyring
    write_atomic(&keyring_path, keyring.serialize().as_bytes())
        .context("Failed to write keyring file")?;

    println!("✓ Removed {} from keyring", email_to_remove);
    Ok(())
}
