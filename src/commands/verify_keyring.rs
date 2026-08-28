use anyhow::{Context, Result};
use pgp::composed::SignedPublicKey;
use std::fs;
use std::path::{Path, PathBuf};

use crate::{derive_repo_id, extract_key_fingerprint, get_remote_push_url, parse_armored_public_key, verify_keyring_signature, TrustPinStore, TrustStore, Keyring, SIG_BEGIN, extract_content_to_verify_from_keyring, extract_signature_from_keyring};

const PUBKEY_BEGIN: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
const PUBKEY_END: &str = "-----END PGP PUBLIC KEY BLOCK-----";

/// Loads the public key matching `fingerprint` from the gpg home pubring.
fn load_public_key_by_fingerprint(gpg_home: &PathBuf, fingerprint: &str) -> Result<SignedPublicKey> {
    let pubring_path = gpg_home.join("pubring.pgp");
    let content = fs::read_to_string(&pubring_path)
        .context("Failed to read pubring.pgp")?;

    let wanted = fingerprint.to_uppercase();
    let mut rest = content.as_str();
    while let Some(begin) = rest.find(PUBKEY_BEGIN) {
        let after = &rest[begin..];
        let end = after
            .find(PUBKEY_END)
            .context("Malformed public key block in pubring.pgp")?
            + PUBKEY_END.len();
        let key = parse_armored_public_key(&after[..end])?;
        if extract_key_fingerprint(&key).to_uppercase() == wanted {
            return Ok(key);
        }
        rest = &after[end..];
    }

    anyhow::bail!(
        "Trusted key with fingerprint {} not found in {}",
        wanted,
        pubring_path.display()
    )
}

/// Verifies the keyring signature against the trusted signing key, without printing.
///
/// A keyring with no signature is only acceptable when it has zero entries
/// (the fresh-init state); a keyring containing entries must carry a valid
/// signature made by the trusted key.
///
/// Returns the repository ID and the parsed keyring.
pub fn verify_keyring_against_trust(repo_root: &Path, remote_name: &str, gpg_home: &PathBuf) -> Result<(String, Keyring)> {
    let push_url = get_remote_push_url(repo_root, remote_name)?;
    let repo_id = derive_repo_id(&push_url)?;

    // Load trust store
    let trust_path = repo_root.join(".git-gpg/trust.json");
    let trust_store = TrustStore::load_from_file(&trust_path)?;
    let trusted_fingerprint = trust_store.get_trusted_fingerprint(&repo_id)
        .context("No trust established for this repository")?;

    // trust.json is committed to the repo and therefore attacker-writable;
    // it is never a sufficient anchor on its own. Require the per-machine
    // pin written by cmd_trust, and fail closed on any disagreement.
    match TrustPinStore::read_pin(gpg_home, &repo_id)? {
        Some(pinned) if pinned.eq_ignore_ascii_case(trusted_fingerprint) => {}
        Some(pinned) => anyhow::bail!(
            "trust for {} changed on this machine's record ({} → {}); if you intended this, re-run git gpg trust",
            repo_id,
            pinned,
            trusted_fingerprint
        ),
        None => anyhow::bail!(
            "no local pin for {}; run git gpg trust to pin this repository's key before use",
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

    Ok((repo_id, keyring))
}

/// Verifies the keyring signature against the trusted signing key.
pub fn cmd_verify_keyring(repo_root: &Path, remote_name: &str, gpg_home: &PathBuf) -> Result<()> {
    let (repo_id, keyring) = verify_keyring_against_trust(repo_root, remote_name, gpg_home)?;

    println!("✓ Keyring signature verified");
    println!("Repository ID: {}", repo_id);
    println!("Keys in keyring: {}", keyring.entries.len());
    Ok(())
}
