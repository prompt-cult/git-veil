use anyhow::{Context, Result};
use pgp::composed::{ArmorOptions, SignedPublicKey};
use pgp::types::KeyDetails;
use std::path::{Path, PathBuf};

use crate::fs_atomic::write_atomic;
use crate::openpgp::load_public_keys_from_store;
use crate::pubkey::extract_email_from_user_id;

/// Resolves `identifier` (an email address or a key fingerprint, matched
/// case-insensitively) against every public key in the local key store and
/// returns it as an armoured PUBLIC key block.
///
/// Matching is exact equality: the identifier equals a fingerprint, or it
/// equals the address extracted from one of the key's user-IDs — never
/// substring matching (the same semantics as find_private_key_by_email).
/// The store may hold the key only as a private half (imported via
/// `git-veil import`); the output is always re-armoured from the PUBLIC
/// half, so private key material can never leak through export.
///
/// Errors: no matching key (naming the store paths) or an ambiguous match —
/// several distinct keys share the requested email — listing every matching
/// fingerprint so the caller can disambiguate by fingerprint.
pub fn export_public_key(key_store: &PathBuf, identifier: &str) -> Result<String> {
    let keys = load_public_keys_from_store(key_store)?;
    let wanted_email = identifier.trim().to_lowercase();
    let wanted_fingerprint = identifier.trim().to_uppercase();

    let matched: Vec<&SignedPublicKey> = keys
        .iter()
        .filter(|key| {
            key.fingerprint().to_string().to_uppercase() == wanted_fingerprint
                || key.details.users.iter().any(|u| {
                    extract_email_from_user_id(&String::from_utf8_lossy(u.id.id()))
                        .is_some_and(|addr| addr == wanted_email)
                })
        })
        .collect();

    if matched.is_empty() {
        anyhow::bail!(
            "No key matching '{}' found in the key store {} (public-keys.pgp, secret-keys.pgp); export only finds keys this machine knows — collaborators must run export on their own machine",
            identifier,
            key_store.display()
        );
    }
    if matched.len() > 1 {
        let fingerprints: Vec<String> = matched
            .iter()
            .map(|key| key.fingerprint().to_string())
            .collect();
        anyhow::bail!(
            "Multiple keys match '{}' in the key store {}; pass a fingerprint instead of an email. Matching fingerprints:\n  {}",
            identifier,
            key_store.display(),
            fingerprints.join("\n  ")
        );
    }

    let mut armored = matched[0]
        .to_armored_string(ArmorOptions::default())
        .context("Failed to armor public key")?;
    if !armored.ends_with('\n') {
        armored.push('\n');
    }
    Ok(armored)
}

/// Exports the armoured PUBLIC key for `identifier` from the local key
/// store: to stdout, or atomically to `output` when given.
///
/// This is the external-tool-free key handoff: each collaborator runs
/// export on
/// their OWN machine and hands the .pub file to the owner, who adds it to
/// the keyring with tell. export does not touch the repository.
pub fn cmd_export(key_store: &PathBuf, identifier: &str, output: Option<&Path>) -> Result<()> {
    let armored = export_public_key(key_store, identifier)?;
    match output {
        Some(path) => write_atomic(path, armored.as_bytes())
            .with_context(|| format!("Failed to write exported key to {}", path.display()))?,
        None => print!("{}", armored),
    }
    Ok(())
}
