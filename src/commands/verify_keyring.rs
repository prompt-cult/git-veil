use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use crate::{
    derive_repo_id, extract_content_to_verify_from_keyring,
    extract_signature_from_keyring, fingerprint_for_verifying_key,
    get_remote_push_url, parse_verifying_key,
    verify_keyring_signature, Keyring, TrustPinStore, TrustStore,
};

/// Loads the Ed25519 verifying key matching `fingerprint` from the key store.
fn load_verifying_key_by_fingerprint(
    key_store: &PathBuf,
    fingerprint: &str,
) -> Result<ed25519_dalek::VerifyingKey> {
    let verifying_keys_path = key_store.join("verifying-keys.txt");
    let content =
        fs::read_to_string(&verifying_keys_path).context("Failed to read verifying-keys.txt")?;

    let wanted = fingerprint.trim().to_lowercase();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Ok(key) = parse_verifying_key(line) {
            if fingerprint_for_verifying_key(&key) == wanted {
                return Ok(key);
            }
        }
    }

    anyhow::bail!(
        "Trusted key with fingerprint {} not found in {}",
        wanted,
        verifying_keys_path.display()
    )
}

/// Verifies the keyring signature against the trusted signing key, without printing.
///
/// A keyring with no signature is only acceptable when it has zero entries
/// (the fresh-init state); a keyring containing entries must carry a valid
/// signature made by the trusted key.
///
/// Returns the repository ID, the trusted signer fingerprint, and the parsed keyring.
pub fn verify_keyring_against_trust(
    repo_root: &Path,
    remote_name: &str,
    key_store: &PathBuf,
) -> Result<(String, String, Keyring)> {
    let push_url = get_remote_push_url(repo_root, remote_name)?;
    let repo_id = derive_repo_id(&push_url)?;

    // Load trust store
    let trust_path = repo_root.join(".git-veil/trust.json");
    let trust_store = TrustStore::load_from_file(&trust_path)?;
    // Covers both the no-trust.json case (empty store) and the
    // missing-repo_id case (store without this repo's entry): both name the
    // repo_id and the remote that produced it, plus the remedy.
    let trusted_fingerprint = match trust_store.get_trusted_fingerprint(&repo_id) {
        Some(fingerprint) => fingerprint,
        None => anyhow::bail!(
            "no trust established for {} (from remote '{}'); run git-veil trust {} <keyfile> to pin this repository's key on this machine",
            repo_id,
            remote_name,
            repo_id
        ),
    };

    // trust.json is committed to the repo and therefore attacker-writable;
    // it is never a sufficient anchor on its own. Require the per-machine
    // pin written by cmd_trust, and fail closed on any disagreement.
    match TrustPinStore::read_pin(key_store, &repo_id)? {
        Some(pinned) if pinned.eq_ignore_ascii_case(trusted_fingerprint) => {}
        Some(pinned) => anyhow::bail!(
            "trust for {} (from remote '{}') changed on this machine's record ({} → {}); if you intended this, re-run git-veil trust {} <keyfile>",
            repo_id,
            remote_name,
            pinned,
            trusted_fingerprint,
            repo_id
        ),
        None => anyhow::bail!(
            "no local pin for {} (from remote '{}'); run git-veil trust {} <keyfile> to pin this repository's key on this machine",
            repo_id,
            remote_name,
            repo_id
        ),
    }

    // Load signing (verifying) public key
    let verifying_key = load_verifying_key_by_fingerprint(key_store, trusted_fingerprint)?;

    // Load keyring
    let keyring_path = repo_root.join(".git-veil/keyring");
    let keyring_text = fs::read_to_string(&keyring_path).context("Failed to read keyring file")?;
    let keyring = Keyring::parse(&keyring_text)?;

    let sig_begin = "-----BEGIN GIT-VEIL SIGNATURE-----";
    if keyring_text.contains(sig_begin) {
        // Extract content and signature
        let content_to_verify = extract_content_to_verify_from_keyring(&keyring_text)?;
        let signature_b64 = extract_signature_from_keyring(&keyring_text)?;

        // Verify signature
        verify_keyring_signature(&content_to_verify, &signature_b64, &verifying_key)?;
    } else if !keyring.entries.is_empty() {
        anyhow::bail!(
            "Keyring contains {} entries but has no signature; refusing to trust unverified keyring",
            keyring.entries.len()
        );
    }

    Ok((repo_id, trusted_fingerprint.to_string(), keyring))
}

/// Verifies the keyring signature against the trusted signing key.
pub fn cmd_verify_keyring(repo_root: &Path, remote_name: &str, key_store: &PathBuf) -> Result<()> {
    let (repo_id, fingerprint, keyring) =
        verify_keyring_against_trust(repo_root, remote_name, key_store)?;

    println!("✓ Keyring signature verified");
    println!("Signed by fingerprint: {}", fingerprint);
    println!("Repository ID: {}", repo_id);
    println!("Keys in keyring: {}", keyring.entries.len());
    Ok(())
}
