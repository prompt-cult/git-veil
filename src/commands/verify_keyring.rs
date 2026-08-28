use anyhow::{Context, Result};
use pgp::composed::SignedPublicKey;
use std::fs;
use std::path::{Path, PathBuf};

use crate::armour::{SIG_BEGIN};
use crate::gpg_integration::split_armored_public_key_blocks;
use crate::{derive_repo_id, extract_key_fingerprint, get_remote_push_url, parse_armored_public_key, verify_keyring_signature, TrustPinStore, TrustStore, Keyring, extract_content_to_verify_from_keyring, extract_signature_from_keyring};

/// Loads the public key matching `fingerprint` from the key store
/// (public-keys.pgp).
fn load_public_key_by_fingerprint(gpg_home: &PathBuf, fingerprint: &str) -> Result<SignedPublicKey> {
    let public_keys_path = gpg_home.join("public-keys.pgp");
    let content = fs::read_to_string(&public_keys_path)
        .context("Failed to read public-keys.pgp")?;

    let wanted = fingerprint.to_uppercase();
    for block in split_armored_public_key_blocks(&content, &public_keys_path)? {
        let key = parse_armored_public_key(&block)?;
        if extract_key_fingerprint(&key).to_uppercase() == wanted {
            return Ok(key);
        }
    }

    anyhow::bail!(
        "Trusted key with fingerprint {} not found in {}",
        wanted,
        public_keys_path.display()
    )
}

/// Verifies the keyring signature against the trusted signing key, without printing.
///
/// A keyring with no signature is only acceptable when it has zero entries
/// (the fresh-init state); a keyring containing entries must carry a valid
/// signature made by the trusted key.
///
/// Returns the repository ID, the trusted signer fingerprint, and the parsed keyring.
pub fn verify_keyring_against_trust(repo_root: &Path, remote_name: &str, gpg_home: &PathBuf) -> Result<(String, String, Keyring)> {
    let push_url = get_remote_push_url(repo_root, remote_name)?;
    let repo_id = derive_repo_id(&push_url)?;

    // Load trust store
    let trust_path = repo_root.join(".git-gpg/trust.json");
    let trust_store = TrustStore::load_from_file(&trust_path)?;
    // Covers both the no-trust.json case (empty store) and the
    // missing-repo_id case (store without this repo's entry): both name the
    // repo_id and the remote that produced it, plus the remedy.
    let trusted_fingerprint = match trust_store.get_trusted_fingerprint(&repo_id) {
        Some(fingerprint) => fingerprint,
        None => anyhow::bail!(
            "no trust established for {} (from remote '{}'); run git-gpg trust {} <keyfile> to pin this repository's key on this machine",
            repo_id,
            remote_name,
            repo_id
        ),
    };

    // trust.json is committed to the repo and therefore attacker-writable;
    // it is never a sufficient anchor on its own. Require the per-machine
    // pin written by cmd_trust, and fail closed on any disagreement.
    match TrustPinStore::read_pin(gpg_home, &repo_id)? {
        Some(pinned) if pinned.eq_ignore_ascii_case(trusted_fingerprint) => {}
        Some(pinned) => anyhow::bail!(
            "trust for {} (from remote '{}') changed on this machine's record ({} → {}); if you intended this, re-run git-gpg trust {} <keyfile>",
            repo_id,
            remote_name,
            pinned,
            trusted_fingerprint,
            repo_id
        ),
        None => anyhow::bail!(
            "no local pin for {} (from remote '{}'); run git-gpg trust {} <keyfile> to pin this repository's key on this machine",
            repo_id,
            remote_name,
            repo_id
        ),
    }

    // Load signing public key
    let public_key = load_public_key_by_fingerprint(gpg_home, trusted_fingerprint)?;

    // Load keyring
    let keyring_path = repo_root.join(".git-gpg/keyring");
    let keyring_text = fs::read_to_string(&keyring_path)
        .context("Failed to read keyring file")?;
    let keyring = Keyring::parse(&keyring_text)?;

    if keyring_text.contains(SIG_BEGIN) {
        // Extract content and signature
        let content_to_verify = extract_content_to_verify_from_keyring(&keyring_text)?;
        let signature = extract_signature_from_keyring(&keyring_text)?;

        // Verify signature
        verify_keyring_signature(&content_to_verify, &signature, &public_key)?;
    } else if !keyring.entries.is_empty() {
        anyhow::bail!(
            "Keyring contains {} entries but has no signature; refusing to trust unverified keyring",
            keyring.entries.len()
        );
    }

    Ok((repo_id, trusted_fingerprint.to_string(), keyring))
}

/// Verifies the keyring signature against the trusted signing key.
pub fn cmd_verify_keyring(repo_root: &Path, remote_name: &str, gpg_home: &PathBuf) -> Result<()> {
    let (repo_id, fingerprint, keyring) =
        verify_keyring_against_trust(repo_root, remote_name, gpg_home)?;

    println!("✓ Keyring signature verified");
    println!("Signed by fingerprint: {}", fingerprint);
    println!("Repository ID: {}", repo_id);
    println!("Keys in keyring: {}", keyring.entries.len());
    Ok(())
}
