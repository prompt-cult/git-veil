use anyhow::{Context, Result};
use age::{Decryptor, Encryptor};
use age::x25519::{Identity, Recipient};
use std::collections::HashSet;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::exit_codes::{coded, ExitCode};
use crate::fs_atomic::{write_atomic, write_atomic_mode};

/// Builds the fail-closed error for a corrupt key store line.
///
/// git-veil is a security tool and never silently drops key material it
/// cannot parse: the error names the file, the 1-based line number, and the
/// offending line itself, so the user can delete exactly that line
/// deliberately and re-run.
pub(crate) fn corrupt_store_line_error(
    path: &Path,
    line_number: usize,
    line: &str,
    cause: anyhow::Error,
) -> anyhow::Error {
    coded(
        ExitCode::KeyParseFailure,
        format!(
            "corrupt key store line {} in {}: \"{}\" ({}); delete or repair that line and re-run — git-veil never silently drops key material",
            line_number,
            path.display(),
            line,
            cause
        ),
    )
}

/// Yields the meaningful lines of a key store file with their 1-based line
/// numbers: blank lines and `#` comments are skipped; everything else is
/// handed to the caller's parser, whose failure is a hard refusal (never a
/// silent skip) via `corrupt_store_line_error`.
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
/// Resolution order: `$GIT_VEIL_HOME` wins, then `$HOME/.git-veil`.
/// Errors when neither is set or both are empty, instead of silently
/// falling back to a world-writable location such as `/tmp`, where an
/// attacker on a multi-user system could plant or tamper with key
/// material. An explicit `--key-store` on the CLI always overrides both.
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
        .ok_or_else(|| anyhow::anyhow!(
            "Neither GIT_VEIL_HOME nor HOME is set; pass --key-store"
        ))
}

/// Parses an age recipient string (`age1...`) into a Recipient.
pub fn parse_recipient(s: &str) -> Result<Recipient> {
    s.trim()
        .parse::<Recipient>()
        .map_err(|e| coded(ExitCode::KeyParseFailure, format!("Failed to parse age recipient: {}", e)))
}

/// Parses an age identity string (`AGE-SECRET-KEY-1...`) into an Identity.
pub fn parse_identity(s: &str) -> Result<Identity> {
    s.trim()
        .parse::<Identity>()
        .map_err(|e| coded(ExitCode::KeyParseFailure, format!("Failed to parse age identity: {}", e)))
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
        .map_err(|_| coded(
            ExitCode::DecryptionFailed,
            "decryption failed: this ciphertext was not encrypted to your key (it is not a listed recipient)"
        ))?;
    reader.read_to_end(&mut decrypted)
        .context("Failed to extract plaintext")?;

    Ok(decrypted)
}

/// Imports an age identity string into the key store (identities.txt).
///
/// The store is private key material, so it is created mode 0600
/// regardless of the process umask.
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
    write_atomic_mode(&identities_path, existing.as_bytes(), 0o600)
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
///
/// A non-comment line that does not parse is a hard refusal (code 62)
/// naming the corrupt line — key material is never silently skipped.
pub fn load_identities_from_store(key_store: &Path) -> Result<Vec<(Identity, String)>> {
    let identities_path = key_store.join("identities.txt");
    let mut result = Vec::new();

    if identities_path.exists() {
        let content = fs::read_to_string(&identities_path)
            .context("Failed to read identities.txt")?;
        for_each_store_line(&identities_path, &content, |_, line| {
            let identity = parse_identity(line)?;
            let recipient = recipient_from_identity(&identity);
            result.push((identity, recipient));
            Ok(())
        })?;
    }

    Ok(result)
}

/// Loads all recipient strings from the key store.
///
/// Like every key store read, a non-comment line that does not parse is a
/// hard refusal (code 62) naming the corrupt line.
pub fn load_recipients_from_store(key_store: &Path) -> Result<Vec<(Recipient, String)>> {
    let recipients_path = key_store.join("recipients.txt");
    let mut result = Vec::new();
    let mut seen = HashSet::new();

    if recipients_path.exists() {
        let content = fs::read_to_string(&recipients_path)
            .context("Failed to read recipients.txt")?;
        for_each_store_line(&recipients_path, &content, |_, line| {
            let recipient = parse_recipient(line)?;
            if seen.insert(line.to_string()) {
                result.push((recipient, line.to_string()));
            }
            Ok(())
        })?;
    }

    // Also derive recipients from imported identities
    let identities_path = key_store.join("identities.txt");
    if identities_path.exists() {
        let content = fs::read_to_string(&identities_path)
            .context("Failed to read identities.txt")?;
        for_each_store_line(&identities_path, &content, |_, line| {
            let identity = parse_identity(line)?;
            let recipient_str = recipient_from_identity(&identity);
            if seen.insert(recipient_str.clone()) {
                let recipient = parse_recipient(&recipient_str)?;
                result.push((recipient, recipient_str));
            }
            Ok(())
        })?;
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
