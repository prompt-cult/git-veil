use anyhow::{Context, Result};
use std::env;
use std::fs;
use std::path::PathBuf;

use crate::{derive_repo_id, get_remote_push_url, TrustStore, Keyring, verify_keyring_signature, extract_content_to_verify_from_keyring, extract_signature_from_keyring, export_key_from_gpg_home, parse_armored_public_key};

/// Verifies the keyring signature against the trusted signing key.
pub fn cmd_verify_keyring(remote_name: &str, gpg_home: &PathBuf) -> Result<()> {
    let repo_path = env::current_dir().context("Failed to get current directory")?;
    let push_url = get_remote_push_url(&repo_path, remote_name)?;
    let repo_id = derive_repo_id(&push_url)?;
    
    // Load trust store
    let trust_path = PathBuf::from(".git-gpg/trust.json");
    let trust_store = TrustStore::load_from_file(&trust_path)?;
    let trusted_fingerprint = trust_store.get_trusted_fingerprint(&repo_id)
        .context("No trust established for this repository")?;
    
    // Load signing public key
    let key_content = export_key_from_gpg_home(gpg_home, trusted_fingerprint)?;
    let public_key = parse_armored_public_key(&key_content)?;
    
    // Load keyring
    let keyring_path = PathBuf::from(".git-gpg/keyring");
    let keyring_text = fs::read_to_string(&keyring_path)
        .context("Failed to read keyring file")?;
    
    // Extract content and signature
    let content_to_verify = extract_content_to_verify_from_keyring(&keyring_text)?;
    let signature = extract_signature_from_keyring(&keyring_text)?;
    
    // Verify signature
    verify_keyring_signature(&content_to_verify, &signature, &public_key)?;
    
    let keyring = Keyring::parse(&keyring_text)?;
    println!("✓ Keyring signature verified");
    println!("Repository ID: {}", repo_id);
    println!("Keys in keyring: {}", keyring.entries.len());
    Ok(())
}
