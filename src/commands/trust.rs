use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use crate::{derive_repo_id, get_remote_push_url, parse_armored_public_key, extract_key_fingerprint, check_email_in_identities, import_key_to_gpg_home, validate_public_key_for_use, KeyUse, TrustPinStore, TrustStore};

/// Establishes trust for a repository by verifying the owner's signing key.
pub fn cmd_trust(repo_root: &Path, repo_id: &str, signing_key_path: &str, remote_name: &str, gpg_home: &PathBuf) -> Result<()> {
    // Get push URL and derive repo ID
    let push_url = get_remote_push_url(repo_root, remote_name)?;
    let computed_repo_id = derive_repo_id(&push_url)?;

    // Verify provided repo_id matches computed
    if repo_id != computed_repo_id {
        anyhow::bail!(
            "Repository ID mismatch: provided '{}' does not match computed '{}'",
            repo_id,
            computed_repo_id
        );
    }

    // Read and parse signing key (relative paths resolve against repo_root)
    let key_content = fs::read_to_string(repo_root.join(signing_key_path))
        .context("Failed to read signing key file")?;
    let public_key = parse_armored_public_key(&key_content)?;

    // Extract fingerprint
    let fingerprint = extract_key_fingerprint(&public_key);

    // Verify repo-id email is in key identities
    let repo_email = repo_id.splitn(2, '+').nth(1).unwrap_or("");
    if !check_email_in_identities(&public_key, repo_email) {
        anyhow::bail!(
            "Signing key does not contain email from repo ID: {}",
            repo_email
        );
    }

    // Key-validity policy: the anchor of trust must not be expired, revoked
    // or unsigned key material. Fail-closed before anything is blessed,
    // imported or pinned.
    if let Err(cause) = validate_public_key_for_use(&public_key, KeyUse::Certify) {
        anyhow::bail!("Refusing to trust key: {}", cause);
    }

    // Import key to GPG home
    import_key_to_gpg_home(gpg_home, &key_content)?;

    // Update trust store
    let trust_path = repo_root.join(".git-gpg/trust.json");
    let mut trust_store = TrustStore::load_from_file(&trust_path)?;
    trust_store.add_trust(repo_id.to_string(), fingerprint.clone());
    trust_store.save_to_file(&trust_path)?;

    // Pin the fingerprint on this machine, outside the repo: trust.json is
    // committed (attacker-writable), so the local pin is the real anchor.
    TrustPinStore::write_pin(gpg_home, repo_id, &fingerprint)
        .context("Failed to write local trust pin")?;

    println!("✓ Trusted key for {} (fingerprint: {})", repo_id, fingerprint);
    println!(
        "✓ Pinned {} for {} on this machine",
        fingerprint, repo_id
    );
    Ok(())
}
