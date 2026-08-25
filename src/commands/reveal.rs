use anyhow::{Context, Result};
use std::env;
use std::fs;
use std::path::PathBuf;

use crate::{cmd_verify_keyring, decrypt_with_gpg_key, find_private_key_by_email, Keyring, TrackedFiles};

/// Decrypts all tracked files using the user's private key.
pub fn cmd_reveal(email: &str, remote_name: &str, gpg_home: &PathBuf) -> Result<()> {
    // Verify keyring signature first
    cmd_verify_keyring(remote_name, gpg_home)?;
    
    // Load keyring
    let keyring_path = PathBuf::from(".git-gpg/keyring");
    let keyring_text = fs::read_to_string(&keyring_path)
        .context("Failed to read keyring file")?;
    let keyring = Keyring::parse(&keyring_text)?;
    
    // Find user's entry
    keyring.find_by_email(email)
        .with_context(|| format!("User {} not found in keyring", email))?;
    
    // Find user's private key
    let private_key = find_private_key_by_email(gpg_home, email)?;
    
    // Load tracked files
    let tracked_path = PathBuf::from(".git-gpg/tracked.json");
    let tracked = TrackedFiles::load(&tracked_path)?;
    
    if tracked.files.is_empty() {
        println!("No files tracked");
        return Ok(());
    }
    
    let base_dir = env::current_dir().context("Failed to get current directory")?;
    
    for file in &tracked.files {
        // Compute relative path
        let relative = file.strip_prefix(&base_dir)
            .unwrap_or(file.as_path());
        
        // Compute encrypted path
        let encrypted_path = PathBuf::from(".git-gpg/secrets")
            .join(relative)
            .with_extension(format!("{}.asc", file.extension().unwrap_or_default().to_string_lossy()));
        
        // Check encrypted file exists
        if !encrypted_path.exists() {
            anyhow::bail!("Encrypted file not found: {}", encrypted_path.display());
        }
        
        // Read encrypted content
        let ciphertext = fs::read_to_string(&encrypted_path)
            .with_context(|| format!("Failed to read encrypted file: {}", encrypted_path.display()))?;
        
        // Decrypt
        let plaintext = decrypt_with_gpg_key(&ciphertext, &private_key)?;
        
        // Write plaintext
        if let Some(parent) = file.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(file, plaintext)
            .with_context(|| format!("Failed to write decrypted file: {}", file.display()))?;
        
        // Delete encrypted file
        fs::remove_file(&encrypted_path)
            .with_context(|| format!("Failed to delete encrypted file: {}", encrypted_path.display()))?;
        
        println!("Decrypted: {}", file.display());
    }
    
    println!("✓ Files revealed");
    Ok(())
}
