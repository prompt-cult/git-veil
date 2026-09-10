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
use crate::signing::{fingerprint_for_verifying_key, parse_signing_key};

/// The recipe printed when no signing key exists (formatted with the
/// actual key store path by [`discover_signing_key`]).
fn signing_key_recipe(key_store: &Path) -> String {
    format!(
        "git-veil never generates keys: a key the tool made would be a key you never\n\
         backed up. Create an Ed25519 signing key yourself, and BACK IT UP:\n\
         \n\
         \x20 umask 077\n\
         \x20 mkdir -p \"{store}\"\n\
         \x20 openssl genpkey -algorithm ED25519 -out \"{store}/ed25519.pem\"\n\
         \x20 openssl pkey -in \"{store}/ed25519.pem\" -outform DER \\\n\
         \x20   | tail -c 32 | xxd -p -c 32 > \"{store}/signing-keys.txt\"\n\
         \n\
         signing-keys.txt holds one 64-hex-character Ed25519 seed per line (the\n\
         last 32 bytes of the key's DER encoding). The matching verifying key,\n\
         for pinning with git-veil trust:\n\
         \n\
         \x20 openssl pkey -in \"{store}/ed25519.pem\" -pubout -outform DER \\\n\
         \x20   | tail -c 32 | xxd -p -c 32 > owner.verifying\n\
         \n\
         Lose the seed and you can no longer re-sign the keyring; back it up now.",
        store = key_store.display()
    )
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
/// Selection order:
///
/// 1. An explicit `--signing-key` value wins: a 1-based index into
///    signing-keys.txt, or a full 64-hex-character seed.
/// 2. Otherwise the TRUSTED key is used — the one whose verifying-key
///    fingerprint equals `pinned_fingerprint`. The keyring must be signed
///    with exactly the key the pin names (that is what verify_keyring
///    checks against), so the pin, not list order, selects the key.
/// 3. No usable key → exit code 20 with the create-and-back-up recipe.
pub fn discover_signing_key(
    key_store: &Path,
    explicit: Option<&str>,
    pinned_fingerprint: Option<&str>,
) -> Result<SigningKey> {
    let keys = load_signing_keys(key_store)?;

    if let Some(selection) = explicit.map(str::trim).filter(|s| !s.is_empty()) {
        // A 64-char hex string is a seed, never an index (a numeric seed
        // would otherwise be misread as a position).
        if selection.len() == 64 && hex::decode(selection).is_ok() {
            return parse_signing_key(selection);
        }
        let index: usize = selection.parse().context(
            "--signing-key must be a 1-based index into signing-keys.txt or a 64-hex-character seed",
        )?;
        if index == 0 {
            anyhow::bail!("--signing-key index is 1-based; got 0");
        }
        return keys.get(index - 1).cloned().ok_or_else(|| {
            anyhow::anyhow!(
                "signing-keys.txt holds {} key(s); no key at index {}",
                keys.len(),
                index
            )
        });
    }

    if keys.is_empty() {
        return Err(coded(
            ExitCode::NoSigningKey,
            format!(
                "no Ed25519 signing key found in {}/signing-keys.txt\n\n{}",
                key_store.display(),
                signing_key_recipe(key_store)
            ),
        ));
    }

    if let Some(fingerprint) = pinned_fingerprint.map(str::trim).filter(|s| !s.is_empty()) {
        let wanted = fingerprint.to_lowercase();
        if let Some(key) = keys
            .iter()
            .find(|k| fingerprint_for_verifying_key(&k.verifying_key()) == wanted)
        {
            return Ok(key.clone());
        }
        return Err(coded(
            ExitCode::NoSigningKey,
            format!(
                "the key store {} holds {} signing key(s), but none matches the trusted fingerprint {} pinned for this repository; add the matching seed to signing-keys.txt, or re-pin with git-veil trust\n\n{}",
                key_store.display(),
                keys.len(),
                wanted,
                signing_key_recipe(key_store)
            ),
        ));
    }

    // No pin to honour (callers that verify trust first never reach this
    // arm): fall back to the first key.
    Ok(keys
        .into_iter()
        .next()
        .expect("non-empty keys checked above"))
}

/// Finds the age identity for `recipient_str` in the key store, exiting
/// with code 21 and the creation recipe when it is absent.
///
/// A corrupt identities.txt is NOT reported as a missing identity: the
/// store loader's coded refusal (code 62, naming the corrupt line) passes
/// through unchanged.
pub fn discover_identity(key_store: &Path, recipient_str: &str) -> Result<age::x25519::Identity> {
    let key_store = key_store.to_path_buf();
    find_identity_by_recipient(&key_store, recipient_str).map_err(|err| {
        if exit_code_of(&err) != ExitCode::GeneralError as i32 {
            // A specific failure (e.g. a corrupt store line) keeps its code
            return err;
        }
        coded(
            ExitCode::NoAgeIdentity,
            format!(
                "no age identity for your keyring entry ({}) found in {}/identities.txt\n\n\
                 git-veil never generates keys: an identity the tool made would be one you\n\
                 never backed up. Create your own age identity and BACK IT UP:\n\
                 \n\
                 \x20 umask 077\n\
                 \x20 age-keygen -o my-age-identity.txt    # or: rage-keygen\n\
                 \x20 git-veil import my-age-identity.txt\n\
                 \n\
                 Without a backup of the AGE-SECRET-KEY-1... line, ciphertexts encrypted to\n\
                 you are unrecoverable.",
                recipient_str,
                key_store.display()
            ),
        )
    })
}
