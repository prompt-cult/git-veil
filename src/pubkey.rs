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
        .map(|user| user.id.to_string())
        .collect()
}

/// Extracts the fingerprint from a public key as an uppercase hex string.
pub fn extract_key_fingerprint(key: &SignedPublicKey) -> String {
    key.fingerprint().to_string()
}

/// Checks if an email address is present in any of the key's user identities.
pub fn check_email_in_identities(key: &SignedPublicKey, email: &str) -> bool {
    let identities = extract_key_identities(key);
    identities.iter().any(|id| id.contains(email))
}

/// Encodes a public key to base64 (after armoring it).
pub fn base64_encode_public_key(key: &SignedPublicKey) -> String {
    let armored = key.to_armored_string(ArmorOptions::default()).unwrap_or_default();
    STANDARD.encode(armored.as_bytes())
}

/// Decodes a base64-encoded public key back to a SignedPublicKey.
pub fn base64_decode_public_key(encoded: &str) -> Result<SignedPublicKey> {
    let bytes = STANDARD.decode(encoded).context("Failed to decode base64")?;
    let armored = String::from_utf8(bytes).context("Invalid UTF-8 in decoded key")?;
    parse_armored_public_key(&armored)
}
