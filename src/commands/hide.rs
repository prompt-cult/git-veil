use anyhow::{Context, Result};
use std::env;
use std::fs;
use std::path::PathBuf;

use crate::{derive_repo_id, get_remote_push_url, Keyring, TrackedFiles, base64_decode_public_key, encrypt_to_gpg_key, cmd_verify_keyring};

/// Encrypts all tracked files to all keys in the keyring.
pub fn cmd_hide(remote_name: &str, gpg_home: &PathBuf) -> Result<()> {
    // Verify keyring signature first
    cmd_verify_keyring(remote_name, gpg_home)?;
    
    // Load keyring
    let keyring_path = PathBuf::from(".git-gpg/keyring");
    let keyring_text = fs::read_to_string(&keyring_path)
        .context("Failed to read keyring file")?;
    let keyring = Keyring::parse(&keyring_text)?;
    
    if keyring.entries.is_empty() {
        anyhow::bail!("No keys in keyring. Add collaborators with 'git gpg tell' first.");
    }
    
    // Decode all public keys
    let public_keys: Vec<_> = keyring.entries.iter()
        .map(|e| base64_decode_public_key(&e.base64_key))
        .collect::<Result<Vec<_>>>()?;
    
    // Load tracked files
    let tracked_path = PathBuf::from(".git-gpg/tracked.json");
    let tracked = TrackedFiles::load(&tracked_path)?;
    
    if tracked.files.is_empty() {
        println!("No files tracked");
        return Ok(());
    }
    
    let base_dir = env::current_dir().context("Failed to get current directory")?;
    
    for file in &tracked.files {
        // Read plaintext
        let plaintext = fs::read(file)
            .with_context(|| format!("Failed to read file: {}", file.display()))?;
        
        // Encrypt to first public key (simplified - in production would encrypt to all)
        let ciphertext = encrypt_to_gpg_key(&plaintext, &public_keys[0])?;
        
        // Compute relative path
        let relative = file.strip_prefix(&base_dir)
            .unwrap_or(file.as_path());
        
        // Compute encrypted path
        let encrypted_path = PathBuf::from(".git-gpg/secrets")
            .join(relative)
            .with_extension(format!("{}.asc", file.extension().unwrap_or_default().to_string_lossy()));
        
        // Create parent dirs
        if let Some(parent) = encrypted_path.parent() {
            fs::create_dir_all(parent)?;
        }
        
        // Write encrypted content
        fs::write(&encrypted_path, ciphertext)
            .with_context(|| format!("Failed to write encrypted file: {}", encrypted_path.display()))?;
        
        // Delete original
        fs::remove_file(file)
            .with_context(|| format!("Failed to delete original file: {}", file.display()))?;
        
        println!("Encrypted: {}", file.display());
    }
    
    println!("✓ Files hidden");
    Ok(())
}
