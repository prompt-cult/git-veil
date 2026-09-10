use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use crate::fs_atomic::write_atomic;
use crate::key_discovery::discover_signing_key;
use crate::{
    create_signature_block, extract_content_to_verify_from_keyring,
    verify_keyring_against_trust, Keyring,
};
use crate::exit_codes::{coded, ExitCode};

/// Removes a collaborator's entry from the keyring and re-signs it.
pub fn cmd_removeperson(
    repo_root: &Path,
    email_to_remove: &str,
    remote_name: &str,
    key_store: &PathBuf,
    signing_key_selection: Option<&str>,
) -> Result<()> {
    // Verify trust is established AND the existing keyring signature
    // against the trusted key BEFORE any mutation. An unsigned keyring is
    // only acceptable when it has zero entries (the fresh-init state); a
    // keyring containing entries must already carry a valid signature
    // from the trusted key, otherwise removeperson would launder trust
    // by re-signing attacker-supplied content.
    let (_, trusted_fingerprint, _) =
        verify_keyring_against_trust(repo_root, remote_name, key_store)?;

    // Load keyring
    let keyring_path = repo_root.join(".git-veil/keyring");
    let keyring_content =
        fs::read_to_string(&keyring_path).context("Failed to read keyring file")?;
    let mut keyring = Keyring::parse(&keyring_content)?;

    // Find the entry by exact email
    if keyring.find_by_email(email_to_remove).is_none() {
        return Err(coded(
            ExitCode::IdentityNotInKeyring,
            format!(
                "'{}' not found in keyring; check the email against git-veil list-keys",
                email_to_remove
            ),
        ));
    }

    // Remove entry (this clears signature)
    keyring.remove_entry(email_to_remove);

    // Serialize keyring without signature
    let keyring_without_sig = keyring.serialize();

    // Re-sign with the TRUSTED key: removeperson curates the keyring exactly
    // like tell does, so it must sign with the key verify_keyring checks
    // against, never with any collaborator's key. Discovery selects the
    // signing key whose verifying key matches the pinned fingerprint.
    let signing_key = discover_signing_key(key_store, signing_key_selection, Some(&trusted_fingerprint))?;

    // Sign keyring content: sign exactly the bytes that verify_keyring will
    // extract, using the same canonicalization function so the two sides of
    // the sign/verify contract cannot drift apart. An empty keyring is a
    // legitimate result (revoking the last collaborator); verify_keyring
    // accepts a signed keyring regardless of entry count.
    let content_to_sign = extract_content_to_verify_from_keyring(&keyring_without_sig)?;
    let sig_block = create_signature_block(&content_to_sign, &signing_key)?;
    keyring.signature = Some(sig_block);

    // Save keyring
    write_atomic(&keyring_path, keyring.serialize().as_bytes())
        .context("Failed to write keyring file")?;

    println!("✓ Removed {} from keyring", email_to_remove);
    Ok(())
}
