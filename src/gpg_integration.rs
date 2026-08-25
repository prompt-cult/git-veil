use anyhow::{Context, Result};
use pgp::composed::{Deserializable, SignedPublicKey, SignedSecretKey};
use pgp::types::{KeyDetails, Password};
use rand::thread_rng;
use std::fs;
use std::path::PathBuf;

/// Returns the default GPG home directory (~/.gnupg).
pub fn default_gpg_home() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".gnupg")
}

/// Imports an armoured public key to the GPG home directory.
pub fn import_key_to_gpg_home(gpg_home: &PathBuf, armored_key: &str) -> Result<()> {
    fs::create_dir_all(gpg_home).context("Failed to create GPG home directory")?;
    let pubring_path = gpg_home.join("pubring.pgp");
    
    let mut existing = if pubring_path.exists() {
        fs::read_to_string(&pubring_path)?
    } else {
        String::new()
    };
    
    if !existing.is_empty() && !existing.ends_with('\n') {
        existing.push('\n');
    }
    existing.push_str(armored_key);
    fs::write(&pubring_path, existing).context("Failed to write pubring.pgp")?;
    Ok(())
}

/// Exports a public key from the GPG home directory by email or fingerprint.
pub fn export_key_from_gpg_home(gpg_home: &PathBuf, identifier: &str) -> Result<String> {
    let pubring_path = gpg_home.join("pubring.pgp");
    let content = fs::read_to_string(&pubring_path)
        .context("Failed to read pubring.pgp")?;
    
    // Simple search for the identifier in the keyring content
    if content.contains(identifier) {
        Ok(content)
    } else {
        anyhow::bail!("Key not found for identifier: {}", identifier)
    }
}

/// Finds a private key by email in the GPG home directory.
pub fn find_private_key_by_email(gpg_home: &PathBuf, email: &str) -> Result<SignedSecretKey> {
    let secring_path = gpg_home.join("secring.pgp");
    let content = fs::read_to_string(&secring_path)
        .context("Failed to read secring.pgp")?;
    
    // Parse the key and check if email matches
    let (key, _headers) = SignedSecretKey::from_string(&content)
        .context("Failed to parse secret key")?;
    
    let identities: Vec<String> = key.details.users.iter()
        .map(|u| u.id.to_string())
        .collect();
    
    if identities.iter().any(|id| id.contains(email)) {
        Ok(key)
    } else {
        anyhow::bail!("No secret key found for email: {}", email)
    }
}

/// Finds a private key by fingerprint in the GPG home directory.
pub fn find_private_key_by_fingerprint(gpg_home: &PathBuf, fingerprint: &str) -> Result<SignedSecretKey> {
    let secring_path = gpg_home.join("secring.pgp");
    let content = fs::read_to_string(&secring_path)
        .context("Failed to read secring.pgp")?;
    
    let (key, _headers) = SignedSecretKey::from_string(&content)
        .context("Failed to parse secret key")?;
    
    let key_fp = key.fingerprint().to_string();
    if key_fp.to_uppercase() == fingerprint.to_uppercase() {
        Ok(key)
    } else {
        anyhow::bail!("No secret key found for fingerprint: {}", fingerprint)
    }
}

/// Decrypts ciphertext using a private key.
pub fn decrypt_with_gpg_key(ciphertext: &str, private_key: &SignedSecretKey) -> Result<Vec<u8>> {
    use pgp::composed::Message;
    
    let passphrase = Password::empty();
    let (message, _headers) = Message::from_string(ciphertext)
        .context("Failed to parse encrypted message")?;
    
    let mut decrypted = message.decrypt(&passphrase, private_key)
        .context("Failed to decrypt message")?;
    
    let plaintext = decrypted.as_data_vec()
        .context("Failed to extract plaintext")?;
    
    Ok(plaintext)
}

/// Encrypts plaintext to a public key.
pub fn encrypt_to_gpg_key(plaintext: &[u8], public_key: &SignedPublicKey) -> Result<String> {
    use pgp::composed::MessageBuilder;
    use pgp::crypto::sym::SymmetricKeyAlgorithm;
    
    let mut rng = thread_rng();
    
    // Find encryption subkey
    let encryption_subkey = public_key.public_subkeys.iter()
        .find(|sk| sk.signatures.iter()
            .any(|sig| sig.key_flags().encrypt_comms() || sig.key_flags().encrypt_storage()))
        .context("No encryption subkey found in public key")?;
    
    let builder = MessageBuilder::from_bytes("", plaintext.to_vec());
    let mut builder = builder.seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
    builder.encrypt_to_key(&mut rng, &encryption_subkey.key)
        .context("Failed to encrypt to key")?;
    
    let armored = builder.to_armored_string(&mut rng, Default::default())
        .context("Failed to armor encrypted message")?;
    
    Ok(armored)
}
