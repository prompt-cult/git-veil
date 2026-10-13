use anyhow::{Context, Result};
use std::collections::HashSet;
use std::fs;
use std::path::Path;

use crate::age_crypto::{
    for_each_store_line, parse_x25519_private_key, x25519_public_key_encoding,
};
use crate::fs_atomic::write_atomic_mode;

/// Imports bech32 X25519 private keys from one or more files into the
/// tool-owned key store (<key_store>/identities.txt).
///
/// Relative key-file paths resolve against `repo_root`. Each file must
/// contain at least one parseable X25519 private key line, or the command
/// refuses it. A private key whose public key is already present in the
/// store is skipped rather than duplicated. On success the store is
/// written as newline-separated private key encodings.
pub fn cmd_import(repo_root: &Path, files: &[String], key_store: &Path) -> Result<()> {
    if files.is_empty() {
        anyhow::bail!("no key files given. Pass one or more X25519 private key files.");
    }
    let private_keys_path = key_store.join("identities.txt");

    let mut private_keys_content = if private_keys_path.exists() {
        fs::read_to_string(&private_keys_path).context("Failed to read identities.txt")?
    } else {
        String::new()
    };

    // Public key encodings already present in the private key store. A
    // corrupt store line refuses the import outright (code 62, naming the
    // line) - never append to a store we could not fully parse.
    let mut known: HashSet<String> = HashSet::new();
    if private_keys_path.exists() {
        for_each_store_line(&private_keys_path, &private_keys_content, |_, line| {
            let private_key = parse_x25519_private_key(line)?;
            let public_key = x25519_public_key_encoding(&private_key);
            known.insert(public_key);
            Ok(())
        })?;
    }

    let mut imported = 0usize;
    let mut skipped = 0usize;

    for file in files {
        let resolved = repo_root.join(file);
        let content = fs::read_to_string(&resolved)
            .with_context(|| format!("Failed to read key file {}", file))?;

        let mut parseable = 0usize;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let private_key = match parse_x25519_private_key(line) {
                Ok(private_key) => private_key,
                Err(err) => {
                    // Source file, not the store: junk lines in an imported
                    // file are skipped, but never silently - the note (and
                    // the parse error) goes to stderr.
                    eprintln!("! skipped unparseable line in {}: {}", file, err);
                    continue;
                }
            };
            parseable += 1;

            let public_key = x25519_public_key_encoding(&private_key);

            if known.contains(&public_key) {
                skipped += 1;
                println!("= skipped because already imported: {}", public_key);
            } else {
                if !private_keys_content.is_empty() && !private_keys_content.ends_with('\n') {
                    private_keys_content.push('\n');
                }
                private_keys_content.push_str(line);
                private_keys_content.push('\n');
                known.insert(public_key.clone());
                imported += 1;
                println!("+ imported: {}", public_key);
            }
        }

        if parseable == 0 {
            anyhow::bail!("No parseable X25519 private key lines in {}", file);
        }
    }

    fs::create_dir_all(key_store).context("Failed to create key store directory")?;
    // Private key material: created 0600 regardless of the process umask.
    write_atomic_mode(&private_keys_path, private_keys_content.as_bytes(), 0o600)
        .context("Failed to write identities.txt")?;

    println!("Summary: {} imported, {} skipped", imported, skipped);
    Ok(())
}
