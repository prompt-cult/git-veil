use anyhow::{Context, Result};
use age::{Decryptor, Encryptor};
use age::x25519::{Identity, Recipient};
use std::collections::HashSet;
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;

use crate::fs_atomic::write_atomic;

/// Returns the default key store directory (`$HOME/.git-veil`).
///
/// Errors when `HOME` is unset or empty instead of silently falling back to
/// a world-writable location such as `/tmp`, where an attacker on a
/// multi-user system could plant or tamper with key material.
pub fn default_key_store() -> Result<PathBuf> {
    match std::env::var("HOME") {
        Ok(home) if !home.is_empty() => Ok(PathBuf::from(home).join(".git-veil")),
        _ => anyhow::bail!(
            "HOME is not set; cannot locate the key store ($HOME/.git-veil); pass --key-store"
        ),
    }
}

/// Parses an age recipient string (`age1...`) into a Recipient.
pub fn parse_recipient(s: &str) -> Result<Recipient> {
    s.trim()
        .parse::<Recipient>()
        .map_err(|e| anyhow::anyhow!("Failed to parse age recipient: {}", e))
}

/// Parses an age identity string (`AGE-SECRET-KEY-1...`) into an Identity.
pub fn parse_identity(s: &str) -> Result<Identity> {
    s.trim()
        .parse::<Identity>()
        .map_err(|e| anyhow::anyhow!("Failed to parse age identity: {}", e))
}

/// Returns the recipient string for a given identity (public key).
pub fn recipient_from_identity(identity: &Identity) -> String {
    identity.to_public().to_string()
}

/// Generates a new age X25519 identity.
pub fn generate_identity() -> Identity {
    Identity::generate()
}

/// Derives a fingerprint from an age recipient string.
///
/// The recipient string itself is a unique identifier, but we hash it to
/// produce a compact fingerprint for display and trust-pin matching.
pub fn fingerprint_for_recipient(recipient_str: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    recipient_str.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

/// Encrypts plaintext to ALL the given recipients as ONE age message.
///
/// Each recipient gets its own stanza wrapping the same file key, so every
/// listed key can decrypt the identical ciphertext. Output is ASCII-armored
/// for text-safe storage in `<name>.secret` files.
pub fn encrypt_to_recipients(plaintext: &[u8], recipients: &[Recipient]) -> Result<Vec<u8>> {
    let encryptor = Encryptor::with_recipients(recipients.iter().map(|r| r as &dyn age::Recipient))
        .context("Failed to create age encryptor (no recipients?)")?;

    let mut encrypted = Vec::new();
    let mut writer = encryptor.wrap_output(&mut encrypted)
        .context("Failed to create age encryptor")?;
    writer.write_all(plaintext)
        .context("Failed to write plaintext to age encryptor")?;
    writer.finish()
        .context("Failed to finalize age encryption")?;

    Ok(encrypted)
}

/// Encrypts plaintext to a single recipient (convenience wrapper).
pub fn encrypt_to_recipient(plaintext: &[u8], recipient: &Recipient) -> Result<Vec<u8>> {
    encrypt_to_recipients(plaintext, std::slice::from_ref(recipient))
}

/// Decrypts age ciphertext using an identity.
pub fn decrypt_with_identity(ciphertext: &[u8], identity: &Identity) -> Result<Vec<u8>> {
    let decryptor = Decryptor::new(ciphertext)
        .context("Failed to parse age ciphertext")?;

    let mut decrypted = Vec::new();
    let mut reader = decryptor.decrypt(std::iter::once(identity as &dyn age::Identity))
        .map_err(|_| anyhow::anyhow!(
            "decryption failed: this ciphertext was not encrypted to your key (it is not a listed recipient)"
        ))?;
    reader.read_to_end(&mut decrypted)
        .context("Failed to extract plaintext")?;

    Ok(decrypted)
}

/// Imports an age identity string into the key store (identities.txt).
pub fn import_identity_to_store(key_store: &PathBuf, identity_str: &str) -> Result<()> {
    fs::create_dir_all(key_store).context("Failed to create key store directory")?;
    let identities_path = key_store.join("identities.txt");

    let mut existing = if identities_path.exists() {
        fs::read_to_string(&identities_path)?
    } else {
        String::new()
    };

    if !existing.is_empty() && !existing.ends_with('\n') {
        existing.push('\n');
    }
    existing.push_str(identity_str.trim());
    existing.push('\n');
    write_atomic(&identities_path, existing.as_bytes())
        .context("Failed to write identities.txt")?;
    Ok(())
}

/// Imports a recipient string into the key store (recipients.txt).
pub fn import_recipient_to_store(key_store: &PathBuf, recipient_str: &str) -> Result<()> {
    fs::create_dir_all(key_store).context("Failed to create key store directory")?;
    let recipients_path = key_store.join("recipients.txt");

    let mut existing = if recipients_path.exists() {
        fs::read_to_string(&recipients_path)?
    } else {
        String::new()
    };

    if !existing.is_empty() && !existing.ends_with('\n') {
        existing.push('\n');
    }
    existing.push_str(recipient_str.trim());
    existing.push('\n');
    write_atomic(&recipients_path, existing.as_bytes())
        .context("Failed to write recipients.txt")?;
    Ok(())
}

/// Loads all age identities from the key store.
///
/// Sources: `<key_store>/identities.txt` (one identity per line).
/// Returns an empty Vec if the store is absent (fresh machine).
pub fn load_identities_from_store(key_store: &PathBuf) -> Result<Vec<(Identity, String)>> {
    let identities_path = key_store.join("identities.txt");
    let mut result = Vec::new();

    if identities_path.exists() {
        let content = fs::read_to_string(&identities_path)
            .context("Failed to read identities.txt")?;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Ok(identity) = parse_identity(line) {
                let recipient = recipient_from_identity(&identity);
                result.push((identity, recipient));
            }
        }
    }

    Ok(result)
}

/// Loads all recipient strings from the key store.
pub fn load_recipients_from_store(key_store: &PathBuf) -> Result<Vec<(Recipient, String)>> {
    let recipients_path = key_store.join("recipients.txt");
    let mut result = Vec::new();
    let mut seen = HashSet::new();

    if recipients_path.exists() {
        let content = fs::read_to_string(&recipients_path)
            .context("Failed to read recipients.txt")?;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Ok(recipient) = parse_recipient(line) {
                let recipient_str = line.to_string();
                if seen.insert(recipient_str.clone()) {
                    result.push((recipient, recipient_str));
                }
            }
        }
    }

    // Also derive recipients from imported identities
    let identities_path = key_store.join("identities.txt");
    if identities_path.exists() {
        let content = fs::read_to_string(&identities_path)
            .context("Failed to read identities.txt")?;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Ok(identity) = parse_identity(line) {
                let recipient_str = recipient_from_identity(&identity);
                if seen.insert(recipient_str.clone()) {
                    if let Ok(recipient) = parse_recipient(&recipient_str) {
                        result.push((recipient, recipient_str));
                    }
                }
            }
        }
    }

    Ok(result)
}

/// Finds an age identity by recipient string (matched exactly).
pub fn find_identity_by_recipient(key_store: &PathBuf, recipient_str: &str) -> Result<Identity> {
    let identities = load_identities_from_store(key_store)?;
    let wanted = recipient_str.trim();
    identities
        .into_iter()
        .find(|(_, recipient)| recipient == wanted)
        .map(|(identity, _)| identity)
        .ok_or_else(|| anyhow::anyhow!("No age identity found for recipient: {}", recipient_str))
}

/// Finds an age identity by fingerprint (derived from recipient string).
pub fn find_identity_by_fingerprint(key_store: &PathBuf, fingerprint: &str) -> Result<Identity> {
    let identities = load_identities_from_store(key_store)?;
    let wanted = fingerprint.trim().to_lowercase();
    identities
        .into_iter()
        .find(|(_, recipient)| fingerprint_for_recipient(recipient) == wanted)
        .map(|(identity, _)| identity)
        .ok_or_else(|| anyhow::anyhow!("No age identity found for fingerprint: {}", fingerprint))
}

/// Finds a recipient string by fingerprint in the key store.
pub fn find_recipient_by_fingerprint(key_store: &PathBuf, fingerprint: &str) -> Result<String> {
    let recipients = load_recipients_from_store(key_store)?;
    let wanted = fingerprint.trim().to_lowercase();
    recipients
        .into_iter()
        .find(|(_, recipient_str)| fingerprint_for_recipient(recipient_str) == wanted)
        .map(|(_, recipient_str)| recipient_str)
        .ok_or_else(|| anyhow::anyhow!("No recipient found for fingerprint: {}", fingerprint))
}
