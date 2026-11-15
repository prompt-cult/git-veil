use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

use crate::fingerprint::fingerprint_for_public_key;
use crate::{verify_keyring_against_trust, Keyring};

/// Lists all keys in the keyring, gated on keyring signature
/// verification.
///
/// The keyring is verified against the trust pin, the same gate as
/// verify-keys, before it is presented. Success prints bare data and
/// nothing else: one `principal fingerprint` pair per line on stdout,
/// no banner, no header, no footer. Exit 0 is the verification
/// statement. On failure the unverified content is still printed, so
/// an auditor can see the tampered content, but the warning and the
/// failure reason go to stderr and the command exits with an error so
/// scripts never mistake an audit of a tampered ring for a clean one.
/// A repo with no trust established or no local pin fails closed like
/// every other gated command.
pub fn cmd_list_keys(repo_root: &Path, remote_name: &str, key_store: &Path) -> Result<()> {
    match verify_keyring_against_trust(repo_root, remote_name, key_store) {
        Ok((_repo_id, _fingerprint, keyring)) => {
            print_keyring(&keyring);
            Ok(())
        }
        Err(verification_error) => {
            eprintln!("WARNING: keyring signature invalid. Listing unverified content.");
            eprintln!("Verification failure: {}", verification_error);

            let keyring_path = repo_root.join(".git-veil/keyring");
            match fs::read_to_string(&keyring_path)
                .context("Failed to read keyring file")
                .and_then(|text| Keyring::parse(&text).context("Failed to parse keyring file"))
            {
                Ok(keyring) => print_keyring(&keyring),
                Err(display_error) => {
                    eprintln!(
                        "Unverified keyring content could not be displayed: {}",
                        display_error
                    )
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
    for entry in &keyring.entries {
        // The binding fingerprint is computed at print time. The
        // keyring stores only the principal and the public key.
        println!(
            "{} {}",
            entry.email,
            fingerprint_for_public_key(&entry.email, &entry.public_key)
        );
    }
}
