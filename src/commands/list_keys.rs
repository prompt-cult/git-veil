use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use crate::{verify_keyring_against_trust, Keyring};

/// Lists all keys in the keyring, gated on keyring signature verification.
///
/// The keyring is verified against the trust pin (the same gate as
/// verify-keyring) BEFORE it is presented. On success the listing is prefixed
/// with a verification banner. On failure the unverified content is still
/// printed (an auditor must SEE the tampered content) but under a loud
/// invalid-signature banner, and the command exits with an error so scripts
/// never mistake an audit of a tampered ring for a clean one. A repo with no
/// trust established or no local pin fails closed like every other gated
/// command.
pub fn cmd_list_keys(repo_root: &Path, remote_name: &str, gpg_home: &PathBuf) -> Result<()> {
    match verify_keyring_against_trust(repo_root, remote_name, gpg_home) {
        Ok((_repo_id, _fingerprint, keyring)) => {
            println!("✓ Keyring signature verified (signed by pinned trusted key)");
            print_keyring(&keyring);
            Ok(())
        }
        Err(verification_error) => {
            println!("⚠ KEYRING SIGNATURE INVALID — listing unverified content");
            println!("Verification failure: {}", verification_error);

            let keyring_path = repo_root.join(".git-gpg/keyring");
            match fs::read_to_string(&keyring_path)
                .context("Failed to read keyring file")
                .and_then(|text| Keyring::parse(&text).context("Failed to parse keyring file"))
            {
                Ok(keyring) => print_keyring(&keyring),
                Err(display_error) => {
                    println!("Unverified keyring content could not be displayed: {}", display_error)
                }
            }

            // The verification failure itself is the exit error: scripts and
            // auditors see the real reason (no trust, pin mismatch, bad
            // signature), never a clean exit code.
            Err(verification_error)
        }
    }
}

fn print_keyring(keyring: &Keyring) {
    if keyring.entries.is_empty() {
        println!("No keys in keyring");
    } else {
        println!("Keys in keyring:");
        for entry in &keyring.entries {
            println!("  {} ({})", entry.email, entry.fingerprint);
        }
        println!("\nTotal: {} keys", keyring.entries.len());
    }
}
