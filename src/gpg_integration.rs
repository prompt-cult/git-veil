use crate::armour::{PRIVATE_KEY_BEGIN, PRIVATE_KEY_END};
use crate::fs_atomic::write_atomic;
use crate::pubkey::extract_email_from_user_id;
use anyhow::{Context, Result};
use pgp::composed::{Deserializable, SignedPublicKey, SignedSecretKey};
use pgp::types::{KeyDetails, Password};
use rand::thread_rng;
use std::fs;
use std::path::PathBuf;

/// Returns the default key store directory (`$HOME/.git-gpg`).
///
/// Errors when `HOME` is unset or empty instead of silently falling back to
/// a world-writable location such as `/tmp`, where an attacker on a
/// multi-user system could plant or tamper with key material.
pub fn default_gpg_home() -> Result<PathBuf> {
    match std::env::var("HOME") {
        Ok(home) if !home.is_empty() => Ok(PathBuf::from(home).join(".git-gpg")),
        _ => anyhow::bail!(
            "HOME is not set; cannot locate the key store ($HOME/.git-gpg); pass --gpg-home"
        ),
    }
}

/// Imports an armoured public key to the key store (public-keys.pgp).
pub fn import_key_to_gpg_home(gpg_home: &PathBuf, armored_key: &str) -> Result<()> {
    fs::create_dir_all(gpg_home).context("Failed to create key store directory")?;
    let public_keys_path = gpg_home.join("public-keys.pgp");

    let mut existing = if public_keys_path.exists() {
        fs::read_to_string(&public_keys_path)?
    } else {
        String::new()
    };

    if !existing.is_empty() && !existing.ends_with('\n') {
        existing.push('\n');
    }
    existing.push_str(armored_key);
    // Atomic append = read-existing (above) + write_atomic(whole content).
    // The O(n) rewrite is the accepted trade — see fs_atomic::append_atomic —
    // a torn key store must never be possible.
    write_atomic(&public_keys_path, existing.as_bytes())
        .context("Failed to write public-keys.pgp")?;
    Ok(())
}

/// Splits file content into individual armoured private key blocks.
///
/// The secret key store may hold several keys, each as its own armoured
/// block. Garbage between complete blocks is ignored, but a block with a
/// BEGIN marker and no END marker means the store is corrupt (e.g. truncated
/// by a partial write or bad merge), which is a hard error: silently
/// dropping the tail would let an attacker remove keys by truncation.
pub(crate) fn split_armored_private_key_blocks(
    content: &str,
    secret_keys_path: &std::path::Path,
) -> Result<Vec<String>> {
    let mut blocks = Vec::new();
    let mut rest = content;
    while let Some(start) = rest.find(PRIVATE_KEY_BEGIN) {
        let after = &rest[start..];
        let end = match after.find(PRIVATE_KEY_END) {
            Some(e) => e + PRIVATE_KEY_END.len(),
            None => anyhow::bail!(
                "Unterminated private key block in {} (corrupt secret key store)",
                secret_keys_path.display()
            ),
        };
        blocks.push(after[..end].to_string());
        rest = &after[end..];
    }
    Ok(blocks)
}

/// Loads and parses every private key in the key store.
fn load_secret_keys(gpg_home: &PathBuf) -> Result<Vec<SignedSecretKey>> {
    let secret_keys_path = gpg_home.join("secret-keys.pgp");
    let content = fs::read_to_string(&secret_keys_path)
        .context("Failed to read secret-keys.pgp")?;

    let blocks = split_armored_private_key_blocks(&content, &secret_keys_path)?;
    if blocks.is_empty() {
        anyhow::bail!("No private key blocks found in {}", secret_keys_path.display());
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

/// Finds a private key by email in the key store.
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

/// Finds a private key by fingerprint in the key store.
pub fn find_private_key_by_fingerprint(gpg_home: &PathBuf, fingerprint: &str) -> Result<SignedSecretKey> {
    let keys = load_secret_keys(gpg_home)?;

    let wanted = fingerprint.to_uppercase();
    keys.into_iter()
        .find(|key| key.fingerprint().to_string().to_uppercase() == wanted)
        .ok_or_else(|| anyhow::anyhow!("No secret key found for fingerprint: {}", fingerprint))
}

/// Decrypts ciphertext using a private key.
///
/// `passphrase` unlocks a passphrase-protected private key; `None` means an
/// empty passphrase (unprotected keys). Interactive tty prompting is
/// deliberately deferred — callers source the passphrase from
/// `GITGPG_PASSPHRASE` or `--passphrase-stdin` (see main.rs).
pub fn decrypt_with_gpg_key(
    ciphertext: &str,
    private_key: &SignedSecretKey,
    passphrase: Option<&str>,
) -> Result<Vec<u8>> {
    use pgp::composed::Message;

    let passphrase = passphrase.map(Password::from).unwrap_or_else(Password::empty);
    let (message, _headers) = Message::from_string(ciphertext)
        .context("Failed to parse encrypted message")?;

    // Name the key in the failure message: the two indistinguishable-at-this-
    // layer causes are (a) the ciphertext was never encrypted to this key and
    // (b) the key needs a passphrase that was not supplied (or was wrong).
    // The underlying pgp cause stays in the anyhow chain; main prints it as a
    // "Caused by" section. No plaintext or passphrase material is ever echoed.
    let key_email = private_key
        .details
        .users
        .iter()
        .find_map(|u| extract_email_from_user_id(&String::from_utf8_lossy(u.id.id())))
        .unwrap_or_else(|| "<unknown>".to_string());

    let mut decrypted = message.decrypt(&passphrase, private_key)
        .with_context(|| format!(
            "decryption failed: this ciphertext was not encrypted to your key '{}' (it is not a listed recipient), or your key needs a passphrase (set GITGPG_PASSPHRASE or use --passphrase-stdin)",
            key_email
        ))?;
    
    let plaintext = decrypted.as_data_vec()
        .context("Failed to extract plaintext")?;
    
    Ok(plaintext)
}

/// Encrypts plaintext to a single public key.
///
/// Convenience wrapper around [`encrypt_to_gpg_keys`] for the common
/// single-recipient case.
pub fn encrypt_to_gpg_key(plaintext: &[u8], public_key: &SignedPublicKey) -> Result<String> {
    encrypt_to_gpg_keys(plaintext, std::slice::from_ref(public_key))
}

/// Encrypts plaintext to ALL the given public keys as ONE OpenPGP message.
///
/// Each recipient gets its own PKESK packet wrapping the same session key,
/// so every listed key can decrypt the identical ciphertext. For each
/// recipient the encryption subkey is selected by key flags exactly as for
/// a single recipient. SEIPD v1 with AES-256 and an empty literal filename.
pub fn encrypt_to_gpg_keys(plaintext: &[u8], public_keys: &[SignedPublicKey]) -> Result<String> {
    use pgp::composed::MessageBuilder;
    use pgp::crypto::sym::SymmetricKeyAlgorithm;

    let mut rng = thread_rng();

    let builder = MessageBuilder::from_bytes("", plaintext.to_vec());
    let mut builder = builder.seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);

    for public_key in public_keys {
        // Find encryption subkey
        let encryption_subkey = public_key.public_subkeys.iter()
            .find(|sk| sk.signatures.iter()
                .any(|sig| sig.key_flags().encrypt_comms() || sig.key_flags().encrypt_storage()))
            .context("No encryption subkey found in public key")?;

        builder.encrypt_to_key(&mut rng, &encryption_subkey.key)
            .context("Failed to encrypt to key")?;
    }

    let armored = builder.to_armored_string(&mut rng, Default::default())
        .context("Failed to armor encrypted message")?;

    Ok(armored)
}
