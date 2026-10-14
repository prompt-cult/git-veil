//! X25519 encryption and decryption over the age format
//! (age-encryption.org/v1, X25519 per RFC 7748).
//!
//! Terminology (see "Terminology" in docs/design.md): the core speaks
//! RFC-standard cryptography only. The one boundary with the age crate's
//! own vocabulary is this import, where the upstream type names are aliased
//! to the crypto terms used everywhere else.
//!
//! - `age::x25519::Recipient` (the bech32 X25519 public key) is
//!   [`X25519PublicKey`]
//! - `age::x25519::Identity` (the bech32 X25519 private key) is
//!   [`X25519PrivateKey`]

pub(crate) use age::x25519::{Identity as X25519PrivateKey, Recipient as X25519PublicKey};
use age::{Decryptor, Encryptor};
use anyhow::{Context, Result};
use std::collections::HashSet;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::exit_codes::{coded, ExitCode};
use crate::fs_atomic::{write_atomic, write_atomic_mode};

/// Builds the fail-closed error for a corrupt key store line.
///
/// git-veil is a security tool, so it never silently drops key material
/// it cannot parse. The error names the file, the 1-based line number, and
/// the offending line itself, so the user can delete exactly that line
/// deliberately and re-run.
pub(crate) fn corrupt_store_line_error(
    _path: &Path,
    _line_number: usize,
    _line: &str,
    _cause: anyhow::Error,
) -> anyhow::Error {
    coded(
        ExitCode::KeyParseFailure,
        "corrupt key store line. Delete or repair that line and re-run. git-veil never silently drops key material"
            .to_string(),
    )
}

/// Yields the meaningful lines of a key store file with their 1-based line
/// numbers. Blank lines and `#` comments are skipped. Everything else goes
/// to the caller's parser. A parser failure is a hard refusal via
/// `corrupt_store_line_error`, never a silent skip.
pub(crate) fn for_each_store_line(
    path: &Path,
    content: &str,
    mut handle: impl FnMut(usize, &str) -> Result<()>,
) -> Result<()> {
    for (index, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line_number = index + 1;
        if let Err(err) = handle(line_number, line) {
            return Err(corrupt_store_line_error(path, line_number, line, err));
        }
    }
    Ok(())
}

/// Returns the default key store directory.
///
/// `$GIT_VEIL_HOME` wins, then `$HOME/.git-veil`. Errors when neither is
/// set or both are empty, instead of silently falling back to a
/// world-writable location such as `/tmp`, where an attacker on a
/// multi-user system could plant or tamper with key material. An explicit
/// `--key-store` on the CLI always overrides both.
pub fn default_key_store() -> Result<PathBuf> {
    std::env::var("GIT_VEIL_HOME")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .filter(|s| !s.is_empty())
                .map(|home| PathBuf::from(home).join(".git-veil"))
        })
        .ok_or_else(|| {
            anyhow::anyhow!("Neither GIT_VEIL_HOME nor HOME is set. Pass the key store path.")
        })
}

/// Parses a bech32 X25519 public key encoding (`age1...`) into an
/// [`X25519PublicKey`].
pub fn parse_x25519_public_key(s: &str) -> Result<X25519PublicKey> {
    s.trim().parse::<X25519PublicKey>().map_err(|e| {
        coded(
            ExitCode::KeyParseFailure,
            format!("Failed to parse the X25519 public key encoding: {}", e),
        )
    })
}

/// Parses a bech32 X25519 private key encoding (`AGE-SECRET-KEY-1...`) into
/// an [`X25519PrivateKey`].
pub fn parse_x25519_private_key(s: &str) -> Result<X25519PrivateKey> {
    s.trim().parse::<X25519PrivateKey>().map_err(|e| {
        coded(
            ExitCode::KeyParseFailure,
            format!("Failed to parse the X25519 private key encoding: {}", e),
        )
    })
}

/// Returns the bech32 encoding of the X25519 public key derived from a
/// private key.
pub fn x25519_public_key_encoding(private_key: &X25519PrivateKey) -> String {
    private_key.to_public().to_string()
}

/// Generates a new X25519 private key.
pub fn generate_x25519_private_key() -> X25519PrivateKey {
    X25519PrivateKey::generate()
}

/// Encrypts plaintext to all the given X25519 public keys as one age
/// message.
///
/// Each public key gets its own stanza wrapping the same file key, so every
/// listed key can decrypt the identical ciphertext. Output is the standard
/// age format for text-safe storage in `<name>.secret` files.
pub fn encrypt_to_x25519_public_keys(
    plaintext: &[u8],
    public_keys: &[X25519PublicKey],
) -> Result<Vec<u8>> {
    let encryptor =
        Encryptor::with_recipients(public_keys.iter().map(|k| k as &dyn age::Recipient))
            .context("Failed to create age encryptor. The keyring has no public keys")?;

    let mut encrypted = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .context("Failed to create age encryptor")?;
    writer
        .write_all(plaintext)
        .context("Failed to write plaintext to age encryptor")?;
    writer
        .finish()
        .context("Failed to finalize age encryption")?;

    Ok(encrypted)
}

/// Encrypts plaintext to a single X25519 public key (convenience wrapper).
pub fn encrypt_to_x25519_public_key(
    plaintext: &[u8],
    public_key: &X25519PublicKey,
) -> Result<Vec<u8>> {
    encrypt_to_x25519_public_keys(plaintext, std::slice::from_ref(public_key))
}

/// Decrypts age ciphertext with an X25519 private key.
pub fn decrypt_with_x25519_private_key(
    ciphertext: &[u8],
    private_key: &X25519PrivateKey,
) -> Result<Vec<u8>> {
    let decryptor = Decryptor::new(ciphertext).context("Failed to parse age ciphertext")?;

    let mut decrypted = Vec::new();
    let mut reader = decryptor.decrypt(std::iter::once(private_key as &dyn age::Identity))
        .map_err(|_| coded(
            ExitCode::DecryptionFailed,
            "decryption failed. This ciphertext was not encrypted to your key and no stanza in it is addressed to your X25519 public key"
        ))?;
    reader
        .read_to_end(&mut decrypted)
        .context("Failed to extract plaintext")?;

    Ok(decrypted)
}

/// Imports a bech32 X25519 private key encoding into the key store
/// (identities.txt).
///
/// The store is private key material, so it is created mode 0600
/// regardless of the process umask.
pub fn import_x25519_private_key_to_store(key_store: &Path, private_key_str: &str) -> Result<()> {
    fs::create_dir_all(key_store).context("Failed to create key store directory")?;
    let private_keys_path = key_store.join("identities.txt");

    let mut existing = if private_keys_path.exists() {
        fs::read_to_string(&private_keys_path)?
    } else {
        String::new()
    };

    if !existing.is_empty() && !existing.ends_with('\n') {
        existing.push('\n');
    }
    existing.push_str(private_key_str.trim());
    existing.push('\n');
    write_atomic_mode(&private_keys_path, existing.as_bytes(), 0o600)
        .context("Failed to write identities.txt")?;
    Ok(())
}

/// Imports a bech32 X25519 public key encoding into the key store
/// (recipients.txt).
pub fn import_x25519_public_key_to_store(key_store: &Path, public_key_str: &str) -> Result<()> {
    fs::create_dir_all(key_store).context("Failed to create key store directory")?;
    let public_keys_path = key_store.join("recipients.txt");

    let mut existing = if public_keys_path.exists() {
        fs::read_to_string(&public_keys_path)?
    } else {
        String::new()
    };

    if !existing.is_empty() && !existing.ends_with('\n') {
        existing.push('\n');
    }
    existing.push_str(public_key_str.trim());
    existing.push('\n');
    write_atomic(&public_keys_path, existing.as_bytes())
        .context("Failed to write recipients.txt")?;
    Ok(())
}

/// Loads all X25519 private keys from the key store.
///
/// The source is `<key_store>/identities.txt`, one private key per line.
/// Returns an empty Vec if the store is absent (fresh machine).
///
/// A non-comment line that does not parse is a hard refusal (code 62)
/// naming the corrupt line. Key material is never silently skipped.
pub fn load_x25519_private_keys_from_store(
    key_store: &Path,
) -> Result<Vec<(X25519PrivateKey, String)>> {
    let private_keys_path = key_store.join("identities.txt");
    let mut result = Vec::new();

    if private_keys_path.exists() {
        let content =
            fs::read_to_string(&private_keys_path).context("Failed to read identities.txt")?;
        for_each_store_line(&private_keys_path, &content, |_, line| {
            let private_key = parse_x25519_private_key(line)?;
            let public_key = x25519_public_key_encoding(&private_key);
            result.push((private_key, public_key));
            Ok(())
        })?;
    }

    Ok(result)
}

/// Loads all X25519 public keys from the key store.
///
/// Like every key store read, a non-comment line that does not parse is a
/// hard refusal (code 62) naming the corrupt line.
pub fn load_x25519_public_keys_from_store(
    key_store: &Path,
) -> Result<Vec<(X25519PublicKey, String)>> {
    let public_keys_path = key_store.join("recipients.txt");
    let mut result = Vec::new();
    let mut seen = HashSet::new();

    if public_keys_path.exists() {
        let content =
            fs::read_to_string(&public_keys_path).context("Failed to read recipients.txt")?;
        for_each_store_line(&public_keys_path, &content, |_, line| {
            let public_key = parse_x25519_public_key(line)?;
            if seen.insert(line.to_string()) {
                result.push((public_key, line.to_string()));
            }
            Ok(())
        })?;
    }

    // Also derive public keys from the imported private keys.
    let private_keys_path = key_store.join("identities.txt");
    if private_keys_path.exists() {
        let content =
            fs::read_to_string(&private_keys_path).context("Failed to read identities.txt")?;
        for_each_store_line(&private_keys_path, &content, |_, line| {
            let private_key = parse_x25519_private_key(line)?;
            let public_key_str = x25519_public_key_encoding(&private_key);
            if seen.insert(public_key_str.clone()) {
                let public_key = parse_x25519_public_key(&public_key_str)?;
                result.push((public_key, public_key_str));
            }
            Ok(())
        })?;
    }

    Ok(result)
}

/// Finds an X25519 private key by its public key encoding (matched
/// exactly).
pub fn find_x25519_private_key_by_public_key(
    key_store: &Path,
    public_key_str: &str,
) -> Result<X25519PrivateKey> {
    let private_keys = load_x25519_private_keys_from_store(key_store)?;
    let wanted = public_key_str.trim();
    private_keys
        .into_iter()
        .find(|(_, public_key)| public_key == wanted)
        .map(|(private_key, _)| private_key)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No X25519 private key in the key store matches the public key: {}",
                public_key_str
            )
        })
}
