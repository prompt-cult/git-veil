//! The single fingerprint derivation.
//!
//! Every fingerprint in git-veil is computed exactly one way.
//!
//! ```text
//! FP = SHA-256( UTF8(label) + ":" + UTF8(public-key-encoding) )
//! ```
//!
//! printed as 64 lowercase hexadecimal characters. The label is the
//! principal label for a keyring principal, or the repository id for the
//! owner key. The public key encoding is the bech32 X25519 public key
//! (age1...) or the 64 hex character Ed25519 verifying key.
//!
//! The derivation is a pure function over public values with a fixed,
//! documented shape, so a user on a clean host reproduces the exact value
//! with stock OS tools (see docs/design.md, "Fingerprints").
//!
//! ```text
//! printf '%s:%s' 'principal-label' "$(age-keygen -y private-key.txt)" | sha256sum
//! printf '%s:%s' 'repo-id' "$(head -n 1 owner.verifying)" | sha256sum
//! ```
//!
//! Fingerprints are computed on demand and never stored in the keyring.
//! A 16 hex character pin or trust record is a legacy artefact from a
//! retired derivation, and every gated command refuses it as hostile
//! ([`is_legacy_pin_shape`]).

use sha2::{Digest, Sha256};

/// Computes the binding fingerprint of a labelled public key. The input is
/// SHA-256 over the UTF-8 label, exactly one colon separator, and the UTF-8
/// public key encoding, printed as 64 lowercase hex characters.
///
/// The inputs are used verbatim, with no trimming and no case folding, so
/// the result matches the stock-tool one-liners byte for byte.
pub fn fingerprint_for_public_key(label: &str, public_key_encoding: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(label.as_bytes());
    hasher.update(b":");
    hasher.update(public_key_encoding.as_bytes());
    hex::encode(hasher.finalize())
}

/// The owner key fingerprint is the single derivation with the repository
/// id as the label and the canonical lowercase hex of the Ed25519
/// verifying key bytes as the public key encoding. Deriving the hex from
/// the key bytes, never from a file string, keeps every channel (pin,
/// committed metadata, pin file) in agreement regardless of file casing.
pub fn owner_key_fingerprint(repo_id: &str, verifying_key: &ed25519_dalek::VerifyingKey) -> String {
    fingerprint_for_public_key(repo_id, &hex::encode(verifying_key.to_bytes()))
}

/// True when `value` is exactly 16 ASCII hexadecimal characters, the
/// shape of a retired fingerprint. Such values predate the SHA-256
/// derivation and are refused as hostile by every gated command. The
/// recovery is re-establishing the pin as described in the trust
/// documentation.
pub fn is_legacy_pin_shape(value: &str) -> bool {
    value.len() == 16 && value.chars().all(|c| c.is_ascii_hexdigit())
}
