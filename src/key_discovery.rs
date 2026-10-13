//! Discovery of user-owned keys.
//!
//! git-veil NEVER generates key material: a key the tool made would be a
//! key the user never backed up, and when the user's disk dies their
//! ciphertext dies with it. When a key is missing, discovery fails with
//! the documented exit code and prints the recipe to create it — with the
//! backup instruction — instead of manufacturing one.

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use std::fs;
use std::path::Path;

use crate::age_crypto::{find_identity_by_recipient, for_each_store_line};
use crate::exit_codes::{coded, exit_code_of, ExitCode};
use crate::fingerprint::fingerprint_for_public_key;
use crate::signing::parse_signing_key;

/// The guidance printed when no signing key exists.
fn signing_key_recipe(_key_store: &Path) -> String {
    "git-veil never generates keys. A key the tool made would be a key you never \
     backed up. Create an Ed25519 signing key yourself and back it up. See the \
     key creation documentation. The seed goes into signing-keys.txt as one 64 \
     hex character line and the matching verifying key goes into the committed \
     owner.verifying file. Without the seed you cannot re-sign the keyring."
        .to_string()
}

/// Loads every signing key seed from `<key_store>/signing-keys.txt`.
///
/// One 64-hex-character Ed25519 seed per line; `#` comments and blank
/// lines are skipped. A missing file is an empty list (fresh machine),
/// not an error; a present-but-garbage line IS an error — never guess
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

/// Selects the Ed25519 signing key for keyring curation (tell/removeperson).
///
/// The TRUSTED key is used — the one whose owner key fingerprint under
/// the single derivation (repository id as the label, see
/// src/fingerprint.rs) equals `pinned_fingerprint`. The keyring must be
/// signed with exactly the key the pin names (that is what verify_keyring
/// checks against), so the pin, not list order, selects the key.
///
/// No usable key → exit code 20 with the create-and-back-up recipe.
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
/// The ONLY selection form: the 64 hex character Ed25519 verifying key —
/// the public half, never the seed. The 1-based index into
/// signing-keys.txt was removed (reordering the file silently renamed what
/// an index selected), the full 64-hex seed was removed (the private
/// key must never appear on a command line, where it lands in shell
/// history, `ps` output, scrollback and agent transcripts), and the
/// 16-hex-character fingerprint form was retired with the derivation
/// change (issue #41).
///
/// Zero matches → exit code 20. More than one match (a degenerate
/// duplicated store) → exit code 70; silently picking one is not
/// acceptable.
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

/// Finds the age identity for `recipient_str` in the key store, exiting
/// with code 21 and the creation recipe when it is absent.
///
/// A corrupt identities.txt is NOT reported as a missing identity: the
/// store loader's coded refusal (code 62, naming the corrupt line) passes
/// through unchanged.
pub fn discover_identity(key_store: &Path, recipient_str: &str) -> Result<age::x25519::Identity> {
    find_identity_by_recipient(key_store, recipient_str).map_err(|err| {
        if exit_code_of(&err) != ExitCode::GeneralError as i32 {
            // A specific failure (e.g. a corrupt store line) keeps its code
            return err;
        }
        coded(
            ExitCode::NoAgeIdentity,
            "no age identity in the key store matches your keyring entry. git-veil never \
             generates keys. An identity the tool made would be one you never backed up. \
             Create your own age identity and back it up, then import it. See the key \
             creation documentation. Without a backup of your age secret, anything encrypted \
             to you is unrecoverable."
                .to_string(),
        )
    })
}
