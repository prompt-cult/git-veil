use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use crate::{base64_encode_public_key, check_email_in_identities, derive_repo_id, extract_content_to_verify_from_keyring, extract_key_fingerprint, find_private_key_by_fingerprint, get_remote_push_url, parse_armored_public_key, sign_keyring_content, verify_keyring_against_trust, Keyring, TrustStore};

/// Adds a collaborator's public key to the keyring and signs it.
pub fn cmd_tell(repo_root: &Path, email: &str, collaborator_key_path: &str, remote_name: &str, gpg_home: &PathBuf) -> Result<()> {
    // Verify trust is established
    let push_url = get_remote_push_url(repo_root, remote_name)?;
    let repo_id = derive_repo_id(&push_url)?;

    let trust_path = repo_root.join(".git-gpg/trust.json");
    let trust_store = TrustStore::load_from_file(&trust_path)?;
    let trusted_fingerprint = trust_store.get_trusted_fingerprint(&repo_id)
        .context("No trust established for this repository. Run 'git gpg trust' first.")?;

    // Verify the existing keyring signature against the trusted key BEFORE any
    // mutation. An unsigned keyring is only acceptable when it has zero entries
    // (the fresh-init state); a keyring containing entries must already carry a
    // valid signature from the trusted key, otherwise tell would launder trust
    // by re-signing attacker-supplied content.
    verify_keyring_against_trust(repo_root, remote_name, gpg_home)?;

    // Read and parse collaborator key (relative paths resolve against repo_root)
    let key_content = fs::read_to_string(repo_root.join(collaborator_key_path))
        .context("Failed to read collaborator key file")?;
    let collaborator_key = parse_armored_public_key(&key_content)?;

    // Verify email is in key identities
    if !check_email_in_identities(&collaborator_key, email) {
        anyhow::bail!("Collaborator key does not contain email: {}", email);
    }

    // Extract fingerprint and base64 encode
    let fingerprint = extract_key_fingerprint(&collaborator_key);
    let base64_key = base64_encode_public_key(&collaborator_key);

    // Load keyring
    let keyring_path = repo_root.join(".git-gpg/keyring");
    let keyring_content = fs::read_to_string(&keyring_path)
        .context("Failed to read keyring file")?;
    let mut keyring = Keyring::parse(&keyring_content)?;

    // Add entry (this clears signature)
    keyring.add_entry(email.to_string(), base64_key, fingerprint);

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
    let signature = sign_keyring_content(&content_to_sign, &signing_key)?;
    keyring.signature = Some(signature);

    // Save keyring
    fs::write(&keyring_path, keyring.serialize())
        .context("Failed to write keyring file")?;

    println!("✓ Added {} to keyring", email);
    Ok(())
}
