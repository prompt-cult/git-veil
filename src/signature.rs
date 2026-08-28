use anyhow::{Context, Result};
use pgp::composed::{SignedSecretKey, SignedPublicKey, Deserializable, DetachedSignature};
use pgp::crypto::hash::HashAlgorithm;
use pgp::types::Password;
use rand::thread_rng;
use std::io::Cursor;

use crate::keyring::{SIG_BEGIN, SIG_END};

/// Signs keyring content with a private key and returns an armored signature.
///
/// `passphrase` unlocks a passphrase-protected signing key; `None` means an
/// empty passphrase (unprotected keys).
pub fn sign_keyring_content(
    keyring_content: &str,
    signing_key: &SignedSecretKey,
    passphrase: Option<&str>,
) -> Result<String> {
    let mut rng = thread_rng();
    let passphrase = passphrase.map(Password::from).unwrap_or_else(Password::empty);

    // Get the primary key for signing
    let primary_key = &signing_key.primary_key;

    let cursor = Cursor::new(keyring_content.as_bytes());
    let signature = DetachedSignature::sign_binary_data(
        &mut rng,
        primary_key,
        &passphrase,
        HashAlgorithm::Sha256,
        cursor,
    ).context("Failed to create detached signature (wrong passphrase? if this key is passphrase-protected, supply it via GITGPG_PASSPHRASE or --passphrase-stdin)")?;
    
    let armored = signature.to_armored_string(Default::default())
        .context("Failed to armor signature")?;
    
    Ok(armored)
}

/// Verifies a keyring signature against the content using a public key.
pub fn verify_keyring_signature(keyring_content: &str, signature: &str, signing_key: &SignedPublicKey) -> Result<()> {
    let (sig, _headers) = DetachedSignature::from_string(signature)
        .context("Failed to parse signature")?;
    
    sig.verify(&signing_key.primary_key, keyring_content.as_bytes())
        .context("Signature verification failed")?;
    
    Ok(())
}

/// Extracts the signature section from a keyring text.
///
/// The detached signature is BY CONVENTION the LAST PGP signature block,
/// after the END GIT-GPG KEYRING marker. Extraction therefore searches
/// backwards from the end of the text so a stray signature marker inside
/// the keyring body cannot desynchronise the verify path.
/// (`Keyring::parse` extracts the signature independently; its positional
/// format — after the END marker — is unaffected.)
pub fn extract_signature_from_keyring(keyring_text: &str) -> Result<String> {
    let sig_begin = keyring_text
        .rfind(SIG_BEGIN)
        .context("No PGP signature found in keyring")?;
    let sig_end = keyring_text
        .rfind(SIG_END)
        .context("No PGP signature end marker found")?;
    if sig_begin >= sig_end {
        anyhow::bail!(
            "Malformed PGP signature block: BEGIN marker found at or after END marker"
        );
    }
    Ok(keyring_text[sig_begin..sig_end + SIG_END.len()].to_string())
}

/// Extracts the content to verify (everything up to and including END GIT-GPG KEYRING marker).
pub fn extract_content_to_verify_from_keyring(keyring_text: &str) -> Result<String> {
    let end_marker = "-----END GIT-GPG KEYRING-----";
    let end_idx = keyring_text
        .find(end_marker)
        .context("No END GIT-GPG KEYRING marker found")?;
    Ok(keyring_text[..end_idx + end_marker.len()].to_string())
}
