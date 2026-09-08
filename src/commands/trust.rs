use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use crate::{
    derive_repo_id, fingerprint_for_verifying_key, get_remote_push_url,
    import_recipient_to_store, parse_verifying_key,
    TrustPinStore, TrustStore,
};

/// Establishes trust for a repository by verifying the owner's signing key.
///
/// The `signing_key_path` file contains the owner's Ed25519 verifying key
/// (hex-encoded public key) on the first line, and optionally the owner's age
/// recipient string on the second line.
pub fn cmd_trust(
    repo_root: &Path,
    repo_id: &str,
    signing_key_path: &str,
    remote_name: &str,
    key_store: &PathBuf,
) -> Result<()> {
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

    // Read signing key file (relative paths resolve against repo_root)
    let key_content = fs::read_to_string(repo_root.join(signing_key_path))
        .context("Failed to read signing key file")?;

    // First line is the Ed25519 verifying key (hex)
    let mut lines = key_content.lines();
    let verifying_key_hex = lines.next().context("Signing key file is empty")?.trim();
    let verifying_key = parse_verifying_key(verifying_key_hex)?;
    let fingerprint = fingerprint_for_verifying_key(&verifying_key);

    // Second line (optional) is the owner's age recipient string
    if let Some(recipient_line) = lines.next() {
        let recipient_str = recipient_line.trim();
        if !recipient_str.is_empty() && recipient_str.starts_with("age1") {
            import_recipient_to_store(key_store, recipient_str)?;
        }
    }

    // Import the verifying key to the key store
    let verifying_keys_path = key_store.join("verifying-keys.txt");
    fs::create_dir_all(key_store).context("Failed to create key store directory")?;
    let mut existing = if verifying_keys_path.exists() {
        fs::read_to_string(&verifying_keys_path)?
    } else {
        String::new()
    };
    if !existing.is_empty() && !existing.ends_with('\n') {
        existing.push('\n');
    }
    existing.push_str(verifying_key_hex);
    existing.push('\n');
    crate::fs_atomic::write_atomic(&verifying_keys_path, existing.as_bytes())
        .context("Failed to write verifying-keys.txt")?;

    // Re-trust visibility: if a pin already exists for this repo and names a
    // DIFFERENT fingerprint, this machine's record of the repository's trust
    // anchor is about to CHANGE — say so loudly before rewriting it.
    if let Some(previous) = TrustPinStore::read_pin(key_store, repo_id)? {
        if !previous.eq_ignore_ascii_case(&fingerprint) {
            println!(
                "replacing the previously pinned fingerprint {} for {} with {}",
                previous, repo_id, fingerprint
            );
        }
    }

    // Update trust store
    let trust_path = repo_root.join(".git-veil/trust.json");
    let mut trust_store = TrustStore::load_from_file(&trust_path)?;
    trust_store.add_trust(repo_id.to_string(), fingerprint.clone());
    trust_store.save_to_file(&trust_path)?;

    // Pin the fingerprint on this machine, outside the repo: trust.json is
    // committed (attacker-writable), so the local pin is the real anchor.
    //
    // Ordering invariant: trust.json is written BEFORE the pin. verify
    // compares the committed trust.json fingerprint against this pin and
    // fails closed on a missing or mismatched pin, so if the process dies
    // between the two writes the result is fail-closed (mismatch), never a
    // state where a changed anchor verifies without an explicit re-pin.
    TrustPinStore::write_pin(key_store, repo_id, &fingerprint)
        .context("Failed to write local trust pin")?;

    println!(
        "Trusted key for {} (fingerprint: {})",
        repo_id, fingerprint
    );
    println!("Pinned {} for {} on this machine", fingerprint, repo_id);
    Ok(())
}
