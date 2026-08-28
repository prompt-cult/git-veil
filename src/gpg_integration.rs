use crate::pubkey::extract_email_from_user_id;
use anyhow::{Context, Result};
use pgp::composed::{Deserializable, SignedPublicKey, SignedSecretKey};
use pgp::types::{KeyDetails, Password};
use rand::thread_rng;
use std::fs;
use std::path::PathBuf;

/// Returns the default GPG home directory (`$HOME/.gnupg`).
///
/// Errors when `HOME` is unset or empty instead of silently falling back to
/// a world-writable location such as `/tmp`, where an attacker on a
/// multi-user system could plant or tamper with key material.
pub fn default_gpg_home() -> Result<PathBuf> {
    match std::env::var("HOME") {
        Ok(home) if !home.is_empty() => Ok(PathBuf::from(home).join(".gnupg")),
        _ => anyhow::bail!("HOME is not set; cannot locate the key store; pass --gpg-home"),
    }
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

const PRIVATE_KEY_BEGIN_MARKER: &str = "-----BEGIN PGP PRIVATE KEY BLOCK-----";
const PRIVATE_KEY_END_MARKER: &str = "-----END PGP PRIVATE KEY BLOCK-----";

/// Splits file content into individual armoured private key blocks.
///
/// A secring may hold several keys, each as its own armoured block.
/// Garbage between complete blocks is ignored, but a block with a BEGIN
/// marker and no END marker means the secring is corrupt (e.g. truncated
/// by a partial write or bad merge), which is a hard error: silently
/// dropping the tail would let an attacker remove keys by truncation.
pub(crate) fn split_armored_private_key_blocks(
    content: &str,
    secring_path: &std::path::Path,
) -> Result<Vec<String>> {
    let mut blocks = Vec::new();
    let mut rest = content;
    while let Some(start) = rest.find(PRIVATE_KEY_BEGIN_MARKER) {
        let after = &rest[start..];
        let end = match after.find(PRIVATE_KEY_END_MARKER) {
            Some(e) => e + PRIVATE_KEY_END_MARKER.len(),
            None => anyhow::bail!(
                "Unterminated private key block in {} (corrupt secring)",
                secring_path.display()
            ),
        };
        blocks.push(after[..end].to_string());
        rest = &after[end..];
    }
    Ok(blocks)
}

/// Loads and parses every private key in the GPG home directory.
fn load_secret_keys(gpg_home: &PathBuf) -> Result<Vec<SignedSecretKey>> {
    let secring_path = gpg_home.join("secring.pgp");
    let content = fs::read_to_string(&secring_path)
        .context("Failed to read secring.pgp")?;

    let blocks = split_armored_private_key_blocks(&content, &secring_path)?;
    if blocks.is_empty() {
        anyhow::bail!("No private key blocks found in {}", secring_path.display());
    }

    blocks
        .iter()
        .map(|block| {
            let (key, _headers) = SignedSecretKey::from_string(block)
                .context("Failed to parse secret key")?;
            Ok(key)
        })
        .collect()
}

/// Finds a private key by email in the GPG home directory.
///
/// Matching is exact equality (case-insensitive) between the requested email
/// and the address extracted from each user-ID — never substring matching.
pub fn find_private_key_by_email(gpg_home: &PathBuf, email: &str) -> Result<SignedSecretKey> {
    let keys = load_secret_keys(gpg_home)?;
    let wanted = email.trim().to_lowercase();

    keys.into_iter()
        .find(|key| {
            key.details.users.iter().any(|u| {
                extract_email_from_user_id(&String::from_utf8_lossy(u.id.id()))
                    .is_some_and(|addr| addr == wanted)
            })
        })
        .ok_or_else(|| anyhow::anyhow!("No secret key found for email: {}", email))
}

/// Finds a private key by fingerprint in the GPG home directory.
pub fn find_private_key_by_fingerprint(gpg_home: &PathBuf, fingerprint: &str) -> Result<SignedSecretKey> {
    let keys = load_secret_keys(gpg_home)?;

    let wanted = fingerprint.to_uppercase();
    keys.into_iter()
        .find(|key| key.fingerprint().to_string().to_uppercase() == wanted)
        .ok_or_else(|| anyhow::anyhow!("No secret key found for fingerprint: {}", fingerprint))
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
