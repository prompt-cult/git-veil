use anyhow::{Context, Result};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::age_crypto::{
    fingerprint_for_recipient, for_each_store_line, parse_identity, recipient_from_identity,
};
use crate::fs_atomic::write_atomic_mode;

/// Imports age identity strings from one or more files into the
/// tool-owned key store (<key_store>/identities.txt).
///
/// Relative key-file paths resolve against `repo_root`. Each file must
/// contain at least one parseable age identity line, or the command refuses
/// it. Identities whose fingerprint is already present in the store are
/// skipped rather than duplicated. On success the store is written as
/// newline-separated identity strings.
pub fn cmd_import(repo_root: &Path, files: &[String], key_store: &PathBuf) -> Result<()> {
    if files.is_empty() {
        anyhow::bail!("no key files given; pass one or more age identity files, e.g. git-veil import alice.age");
    }
    let identities_path = key_store.join("identities.txt");

    let mut identities_content = if identities_path.exists() {
        fs::read_to_string(&identities_path).context("Failed to read identities.txt")?
    } else {
        String::new()
    };

    // Fingerprints already present in the identity store. A corrupt store
    // line refuses the import outright (code 62, naming the line) — never
    // append to a store we could not fully parse.
    let mut known: HashSet<String> = HashSet::new();
    if identities_path.exists() {
        for_each_store_line(&identities_path, &identities_content, |_, line| {
            let identity = parse_identity(line)?;
            let recipient = recipient_from_identity(&identity);
            known.insert(fingerprint_for_recipient(&recipient));
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
            let identity = match parse_identity(line) {
                Ok(identity) => identity,
                Err(err) => {
                    // Source file, not the store: junk lines in an imported
                    // file are skipped, but never silently — the note (and
                    // the parse error) goes to stderr.
                    eprintln!("! skipped unparseable line in {}: {}", file, err);
                    continue;
                }
            };
            parseable += 1;

            let recipient = recipient_from_identity(&identity);
            let fingerprint = fingerprint_for_recipient(&recipient);

            if known.contains(&fingerprint) {
                skipped += 1;
                println!(
                    "= skipped (already imported): {} ({})",
                    recipient, fingerprint
                );
            } else {
                if !identities_content.is_empty() && !identities_content.ends_with('\n') {
                    identities_content.push('\n');
                }
                identities_content.push_str(line);
                identities_content.push('\n');
                known.insert(fingerprint.clone());
                imported += 1;
                println!("+ imported: {} ({})", recipient, fingerprint);
            }
        }

        if parseable == 0 {
            anyhow::bail!("No parseable age identity lines in {}", file);
        }
    }

    fs::create_dir_all(key_store).context("Failed to create key store directory")?;
    // Private key material: created 0600 regardless of the process umask.
    write_atomic_mode(&identities_path, identities_content.as_bytes(), 0o600)
        .context("Failed to write identities.txt")?;

    println!("Summary: {} imported, {} skipped", imported, skipped);
    Ok(())
}
