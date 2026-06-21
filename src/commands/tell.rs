use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;

use crate::{parse_armored_public_key, extract_key_fingerprint, check_email_in_identities, base64_encode_public_key, Keyring, sign_keyring_content, find_private_key_by_email, TrustStore, derive_repo_id, get_remote_push_url, verify_keyring_signature, extract_content_to_verify_from_keyring, extract_signature_from_keyring};

/// Adds a collaborator's public key to the keyring and signs it.
pub fn cmd_tell(email: &str, collaborator_key_path: &str, remote_name: &str, gpg_home: &PathBuf) -> Result<()> {
    // Verify trust is established
    let repo_path = std::env::current_dir().context("Failed to get current directory")?;
    let push_url = get_remote_push_url(&repo_path, remote_name)?;
    let repo_id = derive_repo_id(&push_url)?;
    
    let trust_path = PathBuf::from(".git-gpg/trust.json");
    let trust_store = TrustStore::load_from_file(&trust_path)?;
    let trusted_fingerprint = trust_store.get_trusted_fingerprint(&repo_id)
        .context("No trust established for this repository. Run 'git gpg trust' first.")?;
    
    // Read and parse collaborator key
    let key_content = fs::read_to_string(collaborator_key_path)
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
    let keyring_path = PathBuf::from(".git-gpg/keyring");
    let keyring_content = fs::read_to_string(&keyring_path)
        .context("Failed to read keyring file")?;
    let mut keyring = Keyring::parse(&keyring_content)?;
    
    // Add entry (this clears signature)
    keyring.add_entry(email.to_string(), base64_key, fingerprint);
    
    // Serialize keyring without signature
    let keyring_without_sig = keyring.serialize();
    
    // Find signing private key
    let signing_key = find_private_key_by_email(gpg_home, email)?;
    
    // Sign keyring content
    let signature = sign_keyring_content(&keyring_without_sig, &signing_key)?;
    keyring.signature = Some(signature);
    
    // Save keyring
    fs::write(&keyring_path, keyring.serialize())
        .context("Failed to write keyring file")?;
    
    println!("✓ Added {} to keyring", email);
    Ok(())
}
