use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::thread_rng;

use crate::keyring::END_MARKER;

/// Generates a new Ed25519 signing keypair.
///
/// Returns (signing_key, verifying_key_string) where verifying_key_string is
/// a hex-encoded Ed25519 public key.
pub fn generate_signing_keypair() -> (SigningKey, String) {
    let mut rng = thread_rng();
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, hex::encode(verifying_key.to_bytes()))
}

/// Signs keyring content with an Ed25519 signing key and returns a base64-encoded signature.
pub fn sign_keyring_content(keyring_content: &str, signing_key: &SigningKey) -> Result<String> {
    let signature: Signature = signing_key.sign(keyring_content.as_bytes());
    Ok(STANDARD.encode(signature.to_bytes()))
}

/// Verifies a keyring signature against the content using an Ed25519 verifying key.
pub fn verify_keyring_signature(
    keyring_content: &str,
    signature_b64: &str,
    verifying_key: &VerifyingKey,
) -> Result<()> {
    let sig_bytes = STANDARD
        .decode(signature_b64.trim())
        .context("Failed to decode base64 signature")?;
    let signature =
        Signature::from_slice(&sig_bytes).context("Failed to parse Ed25519 signature")?;
    verifying_key
        .verify(keyring_content.as_bytes(), &signature)
        .context("Signature verification failed")?;
    Ok(())
}

/// Parses a hex-encoded Ed25519 verifying key.
pub fn parse_verifying_key(hex_str: &str) -> Result<VerifyingKey> {
    let bytes = hex::decode(hex_str.trim()).context("Failed to decode hex verifying key")?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Ed25519 verifying key must be 32 bytes"))?;
    VerifyingKey::from_bytes(&arr)
        .map_err(|e| anyhow::anyhow!("Failed to parse Ed25519 verifying key: {}", e))
}

/// Parses a hex-encoded Ed25519 signing key.
pub fn parse_signing_key(hex_str: &str) -> Result<SigningKey> {
    let bytes = hex::decode(hex_str.trim()).context("Failed to decode hex signing key")?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Ed25519 signing key must be 32 bytes"))?;
    Ok(SigningKey::from_bytes(&arr))
}

/// Derives a fingerprint from an Ed25519 verifying key.
pub fn fingerprint_for_verifying_key(verifying_key: &VerifyingKey) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    verifying_key.to_bytes().hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

/// Signs keyring content and returns the signature block for the keyring file.
pub fn create_signature_block(keyring_content: &str, signing_key: &SigningKey) -> Result<String> {
    let sig_b64 = sign_keyring_content(keyring_content, signing_key)?;
    Ok(format!(
        "-----BEGIN GIT-VEIL SIGNATURE-----\n{}\n-----END GIT-VEIL SIGNATURE-----\n",
        sig_b64
    ))
}

/// Extracts the signature section from a keyring text.
///
/// The signature is the last GIT-VEIL SIGNATURE block, after the END GIT-VEIL
/// KEYRING marker. Searches backwards from the end so a stray marker inside
/// the keyring body cannot desynchronise the verify path.
pub fn extract_signature_from_keyring(keyring_text: &str) -> Result<String> {
    let sig_begin = "-----BEGIN GIT-VEIL SIGNATURE-----";
    let sig_end = "-----END GIT-VEIL SIGNATURE-----";
    let sig_begin_idx = keyring_text
        .rfind(sig_begin)
        .context("No signature found in keyring")?;
    let sig_end_idx = keyring_text
        .rfind(sig_end)
        .context("No signature end marker found in keyring")?;
    if sig_begin_idx >= sig_end_idx {
        anyhow::bail!("Malformed signature block: BEGIN marker found at or after END marker");
    }
    // Extract the base64 signature between the markers
    let block = &keyring_text[sig_begin_idx + sig_begin.len()..sig_end_idx];
    let sig_b64 = block.trim();
    Ok(sig_b64.to_string())
}

/// Extracts the content to verify (everything up to and including END GIT-VEIL KEYRING marker).
pub fn extract_content_to_verify_from_keyring(keyring_text: &str) -> Result<String> {
    let end_idx = keyring_text
        .find(END_MARKER)
        .context("No END GIT-VEIL KEYRING marker found")?;
    Ok(keyring_text[..end_idx + END_MARKER.len()].to_string())
}
