use anyhow::{Context, Result};
use pgp::composed::{Deserializable, SignedSecretKey};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::fs_atomic::write_atomic;
use crate::gpg_integration::split_armored_private_key_blocks;
use crate::pubkey::extract_email_from_user_id;
use pgp::types::KeyDetails;

fn primary_user_id(key: &SignedSecretKey) -> String {
    key.details
        .users
        .first()
        .map(|u| String::from_utf8_lossy(u.id.id()).into_owned())
        .unwrap_or_else(|| "<no user id>".to_string())
}

/// Imports armoured private key blocks from one or more files into the
/// tool-owned key store (<gpg_home>/secret-keys.pgp).
///
/// Relative key-file paths resolve against `repo_root`. Each file must
/// contain at least one parseable private key block, or the command refuses
/// it. Keys whose fingerprint is already present in the secret key store are
/// skipped rather than duplicated. On success the store is written as
/// newline-separated armoured private key blocks, the exact multi-block
/// format the reader in gpg_integration.rs supports.
pub fn cmd_import(repo_root: &Path, files: &[String], gpg_home: &PathBuf) -> Result<()> {
    if files.is_empty() {
        anyhow::bail!("no key files given; pass one or more armoured private key files, e.g. git-veil import alice.pgp");
    }
    let secret_keys_path = gpg_home.join("secret-keys.pgp");

    let mut secret_keys_content = if secret_keys_path.exists() {
        fs::read_to_string(&secret_keys_path).context("Failed to read secret-keys.pgp")?
    } else {
        String::new()
    };

    // Fingerprints already present in the secret key store (uppercase hex for
    // case-insensitive comparison).
    let mut known: HashSet<String> = HashSet::new();
    for block in split_armored_private_key_blocks(&secret_keys_content, &secret_keys_path)? {
        if let Ok((key, _)) = SignedSecretKey::from_string(&block) {
            known.insert(key.fingerprint().to_string().to_uppercase());
        }
    }

    let mut imported = 0usize;
    let mut skipped = 0usize;

    for file in files {
        let resolved = repo_root.join(file);
        let content = fs::read_to_string(&resolved)
            .with_context(|| format!("Failed to read key file {}", file))?;
        let blocks = split_armored_private_key_blocks(&content, &resolved)?;
        if blocks.is_empty() {
            anyhow::bail!("No private key blocks found in {}", file);
        }

        let mut parseable = 0usize;
        for block in &blocks {
            let key = match SignedSecretKey::from_string(block) {
                Ok((key, _headers)) => key,
                Err(err) => {
                    println!("! skipped unparseable block in {}: {}", file, err);
                    continue;
                }
            };
            parseable += 1;

            let fingerprint = key.fingerprint().to_string().to_uppercase();
            let user_id = primary_user_id(&key);
            // Print the extracted email when the UID carries one; otherwise
            // fall back to the raw UID so the output stays informative.
            let display = extract_email_from_user_id(&user_id)
                .unwrap_or_else(|| user_id.clone());

            if known.contains(&fingerprint) {
                skipped += 1;
                println!("= skipped (already imported): {} ({})", display, fingerprint);
            } else {
                if !secret_keys_content.is_empty() && !secret_keys_content.ends_with('\n') {
                    secret_keys_content.push('\n');
                }
                secret_keys_content.push_str(block);
                secret_keys_content.push('\n');
                known.insert(fingerprint.clone());
                imported += 1;
                println!("+ imported: {} ({})", display, fingerprint);
            }
        }

        if parseable == 0 {
            anyhow::bail!("No parseable private key blocks in {}", file);
        }
    }

    fs::create_dir_all(gpg_home).context("Failed to create key store directory")?;
    // Atomic append = read-existing (above) + write_atomic(whole content).
    // The O(n) rewrite of the accumulated store is the accepted trade at
    // this scale (a handful of armoured blocks); a torn secret-keys store
    // would brick ALL private-key access (fail-closed), so a partial
    // write must never be possible.
    write_atomic(&secret_keys_path, secret_keys_content.as_bytes())
        .context("Failed to write secret-keys.pgp")?;

    println!("Summary: {} imported, {} skipped", imported, skipped);
    Ok(())
}
