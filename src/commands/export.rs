use anyhow::{Context, Result};
use std::path::Path;

use crate::age_crypto::load_x25519_public_keys_from_store;
use crate::fs_atomic::write_atomic;

/// Resolves `identifier` - an exact X25519 public key encoding - against
/// every public key in the local key store and returns its encoding.
///
/// Matching is exact equality on the public key string; no
/// fingerprint-as-identifier mode remains (issue #41). The store may hold
/// public keys imported via `trust` or derived from imported private keys;
/// it deduplicates by public key encoding, so at most one entry matches.
pub fn export_public_key(key_store: &Path, identifier: &str) -> Result<String> {
    let public_keys = load_x25519_public_keys_from_store(key_store)?;
    let wanted = identifier.trim();

    let matched: Vec<&String> = public_keys
        .iter()
        .map(|(_, public_key_str)| public_key_str)
        .filter(|public_key_str| *public_key_str == wanted)
        .collect();

    let Some(public_key_str) = matched.first() else {
        anyhow::bail!(
            "no matching key found in the key store. Export only finds keys this machine knows"
        );
    };

    let mut result = (*public_key_str).clone();
    if !result.ends_with('\n') {
        result.push('\n');
    }
    Ok(result)
}

/// Exports the X25519 public key encoding for `identifier` from the local
/// key store: to stdout, or atomically to `output` when given.
pub fn cmd_export(key_store: &Path, identifier: &str, output: Option<&Path>) -> Result<()> {
    let armored = export_public_key(key_store, identifier)?;
    match output {
        Some(path) => write_atomic(path, armored.as_bytes())
            .with_context(|| format!("Failed to write exported key to {}", path.display()))?,
        None => print!("{}", armored),
    }
    Ok(())
}
