use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

use crate::allowance::AllowanceStore;
use crate::exit_codes::{coded, ExitCode};
use crate::fs_atomic::write_atomic;
use crate::key_discovery::{discover_signing_key, discover_signing_key_explicit};
use crate::trust_store::RingPassStore;
use crate::{
    create_signature_block, extract_content_to_verify_from_keyring, keyring_content_digest,
    verify_keyring_against_trust, Keyring,
};

/// Removes a collaborator's entry from the keyring and re-signs it.
pub fn cmd_remove_key(
    repo_root: &Path,
    email_to_remove: &str,
    remote_name: &str,
    key_store: &Path,
    signing_key_selection: Option<&str>,
) -> Result<()> {
    // Verify trust is established and the existing keyring signature
    // against the trusted key before any mutation. An unsigned keyring is
    // only acceptable when it has zero entries (the fresh-init state). A
    // keyring containing entries must already carry a valid signature
    // from the trusted key, otherwise remove-key would launder trust by
    // re-signing attacker-supplied content.
    let (repo_id, trusted_fingerprint, _) =
        verify_keyring_against_trust(repo_root, remote_name, key_store)?;

    // Load keyring
    let keyring_path = repo_root.join(".git-veil/keyring");
    let keyring_content =
        fs::read_to_string(&keyring_path).context("Failed to read keyring file")?;
    let mut keyring = Keyring::parse(&keyring_content)?;

    // Find the entry by exact email
    if keyring.find_by_email(email_to_remove).is_none() {
        return Err(coded(
            ExitCode::PrincipalNotInKeyring,
            "that principal is not in the keyring. Check the email against the keyring listing.",
        ));
    }

    // Remove entry (this clears signature)
    keyring.remove_entry(email_to_remove);

    // Bump the monotonic freshness counter before signing. The bump is
    // part of the signed payload, so a later `git revert` of this commit
    // restores an old version too and the per-machine baseline refuses it
    // (docs/src/design.md "Keyring format and freshness").
    keyring.bump_version()?;

    // Serialize keyring without signature
    let keyring_without_sig = keyring.serialize();

    // Re-sign with the trusted key. Remove-key curates the keyring
    // exactly like add-key does, so it must sign with the key verify-keys
    // checks against, never with any collaborator's key. Discovery
    // selects the signing key whose owner key fingerprint matches the
    // pinned fingerprint.
    let signing_key = match signing_key_selection {
        Some(verifying_key_hex) => discover_signing_key_explicit(key_store, verifying_key_hex)?,
        None => discover_signing_key(key_store, &repo_id, &trusted_fingerprint)?,
    };

    // Sign keyring content: sign exactly the bytes that verify-keys will
    // extract, using the same canonicalization function so the two sides of
    // the sign/verify contract cannot drift apart. An empty keyring is a
    // legitimate result (revoking the last collaborator). verify-keys
    // accepts a signed keyring regardless of entry count.
    let content_to_sign = extract_content_to_verify_from_keyring(&keyring_without_sig)?;
    let sig_block = create_signature_block(&content_to_sign, &signing_key)?;
    keyring.signature = Some(sig_block);

    // Save keyring
    write_atomic(&keyring_path, keyring.serialize().as_bytes())
        .context("Failed to write keyring file")?;

    // Stamp the ring-change pass as due (docs/src/design.md "The ring-change
    // ceremony"). The stamp records the version and the signed-content
    // digest just written, in this machine's key store: the whole-manifest
    // pass runs only against this exact ring, only on this machine, and
    // one pass consumes it. No committed repo content can forge it.
    let version = keyring.version.expect("bump_version set the version");
    let digest = keyring_content_digest(&content_to_sign);
    RingPassStore::write(key_store, &repo_id, version, &digest)?;

    // Purge the removed principal's allowance records in the key store
    // this machine runs against (docs/src/design.md "Allowance"). The pin was
    // verified equal to the committed fingerprint above, so it keys the
    // same record the principal's commands wrote. Scope, stated honestly:
    // this machine's key store only.
    if AllowanceStore::purge(key_store, &repo_id, &trusted_fingerprint, email_to_remove)? {
        println!("removed allowance record for {}", email_to_remove);
    }

    println!("removed {} from the keyring", email_to_remove);

    // One plain line for the due pass: the fact, the verb, and the
    // follow-up command. After a removal the pass is the rotation step:
    // without it, existing ciphertext stays decryptable by the removed
    // principal.
    println!("note: the keyring has changed. To re-encrypt to the updated keyring, run the rotate command.");
    Ok(())
}
