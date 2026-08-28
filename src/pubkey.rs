use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use pgp::composed::{SignedPublicKey, Deserializable};
use pgp::types::KeyDetails;
use pgp::composed::ArmorOptions;

/// Parses an armored public key string into a SignedPublicKey.
pub fn parse_armored_public_key(armored: &str) -> Result<SignedPublicKey> {
    let (key, _headers) = SignedPublicKey::from_string(armored)
        .context("Failed to parse armored public key")?;
    Ok(key)
}

/// Extracts user identity strings from a public key.
pub fn extract_key_identities(key: &SignedPublicKey) -> Vec<String> {
    key.details
        .users
        .iter()
        .map(|user| String::from_utf8_lossy(user.id.id()).into_owned())
        .collect()
}

/// Extracts the fingerprint from a public key as an uppercase hex string.
pub fn extract_key_fingerprint(key: &SignedPublicKey) -> String {
    key.fingerprint().to_string()
}

/// Extracts the email address from a user-ID string.
///
/// If the ID contains an angle-bracket address (`Name <addr>`), the address
/// between the brackets is returned (trimmed, lowercased). Otherwise, if the
/// whole trimmed ID itself looks like a bare address (contains '@' and no
/// whitespace), it is returned lowercased. Otherwise there is no usable
/// address and `None` is returned.
pub fn extract_email_from_user_id(user_id: &str) -> Option<String> {
    let trimmed = user_id.trim();
    if let (Some(start), Some(end)) = (trimmed.find('<'), trimmed.find('>')) {
        if start < end {
            return Some(trimmed[start + 1..end].trim().to_lowercase());
        }
    }
    if trimmed.contains('@') && !trimmed.contains(char::is_whitespace) {
        return Some(trimmed.to_lowercase());
    }
    None
}

/// Checks if an email address is present in any of the key's user identities.
///
/// Matching is exact equality (case-insensitive) between the requested email
/// and the address extracted from each user-ID — never substring matching.
pub fn check_email_in_identities(key: &SignedPublicKey, email: &str) -> bool {
    let wanted = email.trim().to_lowercase();
    let identities = extract_key_identities(key);
    identities
        .iter()
        .filter_map(|id| extract_email_from_user_id(id))
        .any(|addr| addr == wanted)
}

/// Encodes a public key to base64 (after armoring it).
pub fn base64_encode_public_key(key: &SignedPublicKey) -> Result<String> {
    let armored = key
        .to_armored_string(ArmorOptions::default())
        .context("Failed to armor public key for keyring entry")?;
    Ok(STANDARD.encode(armored.as_bytes()))
}

/// Decodes a base64-encoded public key back to a SignedPublicKey.
pub fn base64_decode_public_key(encoded: &str) -> Result<SignedPublicKey> {
    let bytes = STANDARD.decode(encoded).context("Failed to decode base64")?;
    let armored = String::from_utf8(bytes).context("Invalid UTF-8 in decoded key")?;
    parse_armored_public_key(&armored)
}
