//! Discovery of user-owned keys.
//!
//! git-veil never generates key material. A key the tool made would be a
//! key the user never backed up, and when the user's disk dies their
//! ciphertext dies with it. When a key is missing, discovery fails with
//! the documented exit code and prints the recipe to create it, with the
//! backup instruction, instead of manufacturing one.

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use std::fs;
use std::path::Path;

use crate::age_crypto::{
    find_x25519_private_key_by_public_key, for_each_store_line, X25519PrivateKey,
};
use crate::exit_codes::{coded, exit_code_of, ExitCode};
use crate::fingerprint::fingerprint_for_public_key;
use crate::signing::parse_signing_key;

/// The guidance printed when no signing key exists.
fn signing_key_recipe(_key_store: &Path) -> String {
    "git-veil never generates keys. A key the tool made would be a key you never \
     backed up. Create an Ed25519 signing key yourself and back it up. See the \
     key creation documentation. The seed goes into signing-keys.txt as one 64 \
     hex character line and the matching verifying key goes into the committed \
     .git-veil/owner.verifying file. Without the seed you cannot re-sign the keyring."
        .to_string()
}

/// Loads every signing key seed from `<key_store>/signing-keys.txt`.
///
/// One 64-hex-character Ed25519 seed per line. `#` comments and blank
/// lines are skipped. A missing file is an empty list (fresh machine),
/// not an error. A present-but-garbage line is an error. Never guess
/// which line the user meant.
pub fn load_signing_keys(key_store: &Path) -> Result<Vec<SigningKey>> {
    let path = key_store.join("signing-keys.txt");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content =
        fs::read_to_string(&path).with_context(|| format!("Failed to read {}", path.display()))?;
    let mut keys = Vec::new();
    for_each_store_line(&path, &content, |_, line| {
        keys.push(parse_signing_key(line)?);
        Ok(())
    })?;
    Ok(keys)
}

/// Selects the Ed25519 signing key for keyring curation (add-key/remove-key).
///
/// The trusted key is used: the one whose owner key fingerprint under the
/// single derivation (repository id as the label, see src/fingerprint.rs)
/// equals `pinned_fingerprint`. The keyring must be signed with exactly
/// the key the pin names, which is what verify-keys checks against, so
/// the pin, not list order, selects the key.
///
/// No usable key exits with code 20 and the create-and-back-up recipe.
pub fn discover_signing_key(
    key_store: &Path,
    repo_id: &str,
    pinned_fingerprint: &str,
) -> Result<SigningKey> {
    let keys = load_signing_keys(key_store)?;

    if keys.is_empty() {
        return Err(coded(
            ExitCode::NoSigningKey,
            format!(
                "no Ed25519 signing key found in signing-keys.txt\n\n{}",
                signing_key_recipe(key_store)
            ),
        ));
    }

    let wanted = pinned_fingerprint.trim().to_lowercase();
    if let Some(key) = keys.iter().find(|k| {
        fingerprint_for_public_key(repo_id, &hex::encode(k.verifying_key().to_bytes())) == wanted
    }) {
        return Ok(key.clone());
    }
    Err(coded(
        ExitCode::NoSigningKey,
        format!(
            "the key store holds {} signing keys but none matches the trusted key fingerprint pinned for this repository. Add the matching seed to signing-keys.txt. See the trust documentation.\n\n{}",
            keys.len(),
            signing_key_recipe(key_store)
        ),
    ))
}

/// Explicit signing-key selection by the full verifying key.
///
/// The only selection form is the 64 hex character Ed25519 verifying key.
/// It is the public half, never the seed. A seed on a command line lands in
/// shell history, `ps` output, scrollback and agent transcripts, so the
/// private key must never appear there. A 1-based index into
/// signing-keys.txt is not a selection form either, because reordering
/// the file would silently rename what an index selected. The
/// 16-hex-character fingerprint form is not a selection form.
///
/// Zero matches exits with code 20. More than one match, from a
/// degenerate duplicated store, exits with code 70. Silently picking one
/// is not acceptable.
pub fn discover_signing_key_explicit(
    key_store: &Path,
    verifying_key_hex: &str,
) -> Result<SigningKey> {
    let keys = load_signing_keys(key_store)?;
    let wanted = verifying_key_hex.trim().to_lowercase();
    let matches: Vec<&SigningKey> = keys
        .iter()
        .filter(|k| hex::encode(k.verifying_key().to_bytes()) == wanted)
        .collect();
    match matches.as_slice() {
        [key] => Ok((*key).clone()),
        [] => Err(coded(
            ExitCode::NoSigningKey,
            format!(
                "no signing key in signing-keys.txt has the requested verifying key. Add the matching seed to signing-keys.txt. See the trust documentation.\n\n{}",
                signing_key_recipe(key_store)
            ),
        )),
        _ => Err(coded(
            ExitCode::Refused,
            format!(
                "{} signing keys in signing-keys.txt share one verifying key. The key store is degenerate and must be deduplicated.",
                matches.len()
            ),
        )),
    }
}

/// Finds the X25519 private key whose public key encoding is
/// `public_key_str` in the key store, exiting with code 21 and the
/// creation recipe when it is absent.
///
/// A corrupt identities.txt is not reported as a missing private key. The
/// store loader's coded refusal (code 62, naming the corrupt line) passes
/// through unchanged.
pub fn discover_x25519_private_key(
    key_store: &Path,
    public_key_str: &str,
) -> Result<X25519PrivateKey> {
    find_x25519_private_key_by_public_key(key_store, public_key_str).map_err(|err| {
        if exit_code_of(&err) != ExitCode::GeneralError as i32 {
            // A specific failure (e.g. a corrupt store line) keeps its code
            return err;
        }
        coded(
            ExitCode::NoX25519PrivateKey,
            "no X25519 private key in the key store matches your keyring entry. git-veil never \
             generates keys. A key the tool made would be one you never backed up. \
             Create your own X25519 private key (age identity) and back it up, then import it. \
             See the key creation documentation. Without a backup of your X25519 private key, \
             anything encrypted to you is unrecoverable."
                .to_string(),
        )
    })
}
