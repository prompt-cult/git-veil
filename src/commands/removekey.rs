use anyhow::{Context, Result};
use pgp::composed::{Deserializable, SignedPublicKey, SignedSecretKey};
use std::collections::BTreeSet;
use std::path::PathBuf;

use crate::fs_atomic::write_atomic;
use crate::openpgp::{split_armored_private_key_blocks, split_armored_public_key_blocks};
use crate::pubkey::extract_email_from_user_id;
use pgp::types::KeyDetails;

/// One armoured key block parsed out of a key store, with the matching
/// fields (fingerprint and user-ID emails) lifted out for lookup.
struct StoreBlock {
    text: String,
    fingerprint: String,
    emails: Vec<String>,
}

/// A key store file parsed into blocks. `exists` is false when the store
/// file is absent (fresh machine) — absent stores are never created.
struct StoreContents {
    path: PathBuf,
    exists: bool,
    blocks: Vec<StoreBlock>,
}

fn lift_users(users: &[pgp::types::SignedUser]) -> Vec<String> {
    users
        .iter()
        .map(|u| String::from_utf8_lossy(u.id.id()).into_owned())
        .collect()
}

/// Loads and parses the armoured PRIVATE key store (secret-keys.pgp).
///
/// An absent store yields `exists: false`. A store with an unterminated
/// block, or a block that does not parse, is a hard error: removekey must
/// never rewrite a store it cannot fully understand, and the caller must
/// refuse (and leave the file untouched) rather than drop anything.
fn load_private_store(path: &PathBuf) -> Result<StoreContents> {
    if !path.exists() {
        return Ok(StoreContents {
            path: path.clone(),
            exists: false,
            blocks: Vec::new(),
        });
    }
    let content = std::fs::read_to_string(path).context("Failed to read secret-keys.pgp")?;
    let texts = split_armored_private_key_blocks(&content, path)?;
    let mut blocks = Vec::new();
    for text in texts {
        let (key, _headers) = SignedSecretKey::from_string(&text).with_context(|| {
            format!(
                "Failed to parse private key block in {} (corrupt key store); refusing to modify it — repair the store manually",
                path.display()
            )
        })?;
        blocks.push(StoreBlock {
            text,
            fingerprint: key.fingerprint().to_string().to_uppercase(),
            emails: lift_users(&key.details.users),
        });
    }
    Ok(StoreContents {
        path: path.clone(),
        exists: true,
        blocks,
    })
}

/// Loads and parses the armoured PUBLIC key store (public-keys.pgp).
/// Same contract as [`load_private_store`].
fn load_public_store(path: &PathBuf) -> Result<StoreContents> {
    if !path.exists() {
        return Ok(StoreContents {
            path: path.clone(),
            exists: false,
            blocks: Vec::new(),
        });
    }
    let content = std::fs::read_to_string(path).context("Failed to read public-keys.pgp")?;
    let texts = split_armored_public_key_blocks(&content, path)?;
    let mut blocks = Vec::new();
    for text in texts {
        let (key, _headers) = SignedPublicKey::from_string(&text).with_context(|| {
            format!(
                "Failed to parse public key block in {} (corrupt key store); refusing to modify it — repair the store manually",
                path.display()
            )
        })?;
        blocks.push(StoreBlock {
            text,
            fingerprint: key.fingerprint().to_string().to_uppercase(),
            emails: lift_users(&key.details.users),
        });
    }
    Ok(StoreContents {
        path: path.clone(),
        exists: true,
        blocks,
    })
}

/// Matching is exact equality (the same semantics as export and
/// find_private_key_by_email): the identifier equals the key's fingerprint
/// (case-insensitively), or equals the address extracted from one of the
/// key's user-IDs — never substring matching.
fn block_matches(block: &StoreBlock, wanted_fingerprint: &str, wanted_email: &str) -> bool {
    block.fingerprint == wanted_fingerprint
        || block
            .emails
            .iter()
            .any(|email| extract_email_from_user_id(email).is_some_and(|addr| addr == wanted_email))
}

/// Fingerprints are matched and stored uppercase; the rest of the tool
/// (export, list-keys) prints them lowercase hex, so displayed strings
/// follow that convention.
fn display_fingerprint(block: &StoreBlock) -> String {
    block.fingerprint.to_lowercase()
}

/// Removes key material from the LOCAL key store: every armoured block in
/// `<key_store>/secret-keys.pgp` and `<key_store>/public-keys.pgp` whose key's
/// fingerprint matches `identifier`, or whose exact case-insensitive email
/// matches, is dropped.
///
/// This is DESTRUCTIVE and local-only: it does NOT touch any repository,
/// keyring or trust state, and it does NOT revoke the key — old ciphertext
/// encrypted to it stays decryptable by whoever holds it. Revoking a
/// departing collaborator is removeperson + re-hide (docs/departing.md).
///
/// Guards, mirroring clean:
/// - if the target key is the only private key in secret-keys.pgp, the
///   removal refuses without `--yes` (without it nothing can be decrypted);
/// - an email matching several distinct keys is ambiguous: the fingerprints
///   are listed and nothing is removed without `--yes` (which removes ALL
///   of them — passing the fingerprint is the safer way to remove one).
///
/// The rewrite is atomic and lossless for the retained blocks: both stores
/// are fully read and parsed BEFORE any decision, a corrupt (e.g.
/// truncated) store refuses the whole command untouched (repair it by hand
/// — a corrupt store is never deleted), and only then are the remaining
/// blocks re-serialised and written back via write_atomic.
pub fn cmd_removekey(key_store: &PathBuf, identifier: &str, yes: bool) -> Result<()> {
    let secret_path = key_store.join("secret-keys.pgp");
    let public_path = key_store.join("public-keys.pgp");

    // Read and parse BOTH stores before any decision or write: a corrupt
    // store refuses the whole command before anything can be removed.
    let secret_store = load_private_store(&secret_path)?;
    let public_store = load_public_store(&public_path)?;

    let wanted_email = identifier.trim().to_lowercase();
    let wanted_fingerprint = identifier.trim().to_uppercase();

    let secret_matches: Vec<usize> = secret_store
        .blocks
        .iter()
        .enumerate()
        .filter(|(_, block)| block_matches(block, &wanted_fingerprint, &wanted_email))
        .map(|(i, _)| i)
        .collect();
    let public_matches: Vec<usize> = public_store
        .blocks
        .iter()
        .enumerate()
        .filter(|(_, block)| block_matches(block, &wanted_fingerprint, &wanted_email))
        .map(|(i, _)| i)
        .collect();

    if secret_matches.is_empty() && public_matches.is_empty() {
        anyhow::bail!(
            "No key matching '{}' found in the key store {} (secret-keys.pgp, public-keys.pgp); removekey only removes keys this machine's local store holds",
            identifier,
            key_store.display()
        );
    }

    // Danger guard: the target is the only private key in secret-keys.pgp.
    if !secret_matches.is_empty() && secret_store.blocks.len() == 1 && !yes {
        anyhow::bail!(
            "Refusing to remove '{}': this is your only private key; without it you cannot decrypt anything — pass --yes to confirm",
            identifier
        );
    }

    // Ambiguity guard: several DISTINCT keys match the identifier.
    let mut matched_fingerprints: BTreeSet<String> = BTreeSet::new();
    for i in &secret_matches {
        matched_fingerprints.insert(display_fingerprint(&secret_store.blocks[*i]));
    }
    for i in &public_matches {
        matched_fingerprints.insert(display_fingerprint(&public_store.blocks[*i]));
    }
    if matched_fingerprints.len() > 1 && !yes {
        anyhow::bail!(
            "Multiple keys match '{}' in the key store {}; pass a fingerprint instead of an email, or re-run with --yes to remove ALL of them. Matching fingerprints:\n  {}",
            identifier,
            key_store.display(),
            matched_fingerprints
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join("\n  ")
        );
    }

    // Rewrite only the stores that hold matching blocks; the retained blocks
    // are written back verbatim in the store's canonical format.
    for (store, matches) in [
        (&secret_store, &secret_matches),
        (&public_store, &public_matches),
    ] {
        if matches.is_empty() {
            if store.exists {
                println!("Removed from {}: none found", store.path.display());
            } else {
                println!("Removed from {}: store absent", store.path.display());
            }
            continue;
        }
        let removed: Vec<String> = matches
            .iter()
            .map(|i| display_fingerprint(&store.blocks[*i]))
            .collect();
        let mut retained = String::new();
        for (i, block) in store.blocks.iter().enumerate() {
            if !matches.contains(&i) {
                retained.push_str(&block.text);
                retained.push('\n');
            }
        }
        write_atomic(&store.path, retained.as_bytes())
            .with_context(|| format!("Failed to rewrite {}", store.path.display()))?;
        println!(
            "Removed from {}: {}",
            store.path.display(),
            removed.join(", ")
        );
    }

    Ok(())
}
