use anyhow::{Context, Result};
use std::collections::BTreeSet;
use std::path::PathBuf;

use crate::fs_atomic::write_atomic;
use crate::age_crypto::{parse_identity, recipient_from_identity, fingerprint_for_recipient};

/// One key line parsed out of a key store file.
struct StoreLine {
    text: String,
    fingerprint: String,
    recipient: String,
}

/// A key store file parsed into lines. `exists` is false when the store
/// file is absent (fresh machine) — absent stores are never created.
struct StoreContents {
    path: PathBuf,
    exists: bool,
    lines: Vec<StoreLine>,
}

/// Loads and parses the identities store (identities.txt).
fn load_identity_store(path: &PathBuf) -> Result<StoreContents> {
    if !path.exists() {
        return Ok(StoreContents {
            path: path.clone(),
            exists: false,
            lines: Vec::new(),
        });
    }
    let content = std::fs::read_to_string(path).context("Failed to read identities.txt")?;
    let mut lines = Vec::new();
    for line in content.lines() {
        let line_str = line.trim();
        if line_str.is_empty() || line_str.starts_with('#') {
            continue;
        }
        if let Ok(identity) = parse_identity(line_str) {
            let recipient = recipient_from_identity(&identity);
            let fingerprint = fingerprint_for_recipient(&recipient);
            lines.push(StoreLine {
                text: line_str.to_string(),
                fingerprint,
                recipient,
            });
        }
    }
    Ok(StoreContents {
        path: path.clone(),
        exists: true,
        lines,
    })
}

/// Loads and parses the recipients store (recipients.txt).
fn load_recipient_store(path: &PathBuf) -> Result<StoreContents> {
    if !path.exists() {
        return Ok(StoreContents {
            path: path.clone(),
            exists: false,
            lines: Vec::new(),
        });
    }
    let content = std::fs::read_to_string(path).context("Failed to read recipients.txt")?;
    let mut lines = Vec::new();
    for line in content.lines() {
        let line_str = line.trim();
        if line_str.is_empty() || line_str.starts_with('#') {
            continue;
        }
        let fingerprint = fingerprint_for_recipient(line_str);
        lines.push(StoreLine {
            text: line_str.to_string(),
            fingerprint,
            recipient: line_str.to_string(),
        });
    }
    Ok(StoreContents {
        path: path.clone(),
        exists: true,
        lines,
    })
}

/// Matching: the identifier equals the key's fingerprint (case-insensitively),
/// or equals the recipient string.
fn line_matches(line: &StoreLine, wanted_fingerprint: &str, wanted_recipient: &str) -> bool {
    line.fingerprint == wanted_fingerprint || line.recipient == wanted_recipient
}

/// Removes key material from the LOCAL key store: every line in
/// `<key_store>/identities.txt` and `<key_store>/recipients.txt` whose
/// fingerprint matches `identifier`, or whose recipient string matches, is dropped.
pub fn cmd_removekey(key_store: &PathBuf, identifier: &str, yes: bool) -> Result<()> {
    let identities_path = key_store.join("identities.txt");
    let recipients_path = key_store.join("recipients.txt");

    let identity_store = load_identity_store(&identities_path)?;
    let recipient_store = load_recipient_store(&recipients_path)?;

    let wanted_recipient = identifier.trim();
    let wanted_fingerprint = identifier.trim().to_lowercase();

    let identity_matches: Vec<usize> = identity_store
        .lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line_matches(line, &wanted_fingerprint, wanted_recipient))
        .map(|(i, _)| i)
        .collect();
    let recipient_matches: Vec<usize> = recipient_store
        .lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line_matches(line, &wanted_fingerprint, wanted_recipient))
        .map(|(i, _)| i)
        .collect();

    if identity_matches.is_empty() && recipient_matches.is_empty() {
        anyhow::bail!(
            "No key matching '{}' found in the key store {} (identities.txt, recipients.txt); removekey only removes keys this machine's local store holds",
            identifier,
            key_store.display()
        );
    }

    // Danger guard: the target is the only identity in identities.txt.
    if !identity_matches.is_empty() && identity_store.lines.len() == 1 && !yes {
        anyhow::bail!(
            "Refusing to remove '{}': this is your only identity; without it you cannot decrypt anything — pass --yes to confirm",
            identifier
        );
    }

    // Ambiguity guard: several DISTINCT keys match the identifier.
    let mut matched_fingerprints: BTreeSet<String> = BTreeSet::new();
    for i in &identity_matches {
        matched_fingerprints.insert(identity_store.lines[*i].fingerprint.clone());
    }
    for i in &recipient_matches {
        matched_fingerprints.insert(recipient_store.lines[*i].fingerprint.clone());
    }
    if matched_fingerprints.len() > 1 && !yes {
        anyhow::bail!(
            "Multiple keys match '{}' in the key store {}; pass a fingerprint instead, or re-run with --yes to remove ALL of them. Matching fingerprints:\n  {}",
            identifier,
            key_store.display(),
            matched_fingerprints
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join("\n  ")
        );
    }

    // Rewrite only the stores that hold matching lines.
    for (store, matches) in [
        (&identity_store, &identity_matches),
        (&recipient_store, &recipient_matches),
    ] {
        if matches.is_empty() {
            if store.exists {
                println!("Removed from {}: none found", store.path.display());
            } else {
                println!("Removed from {}: store absent", store.path.display());
            }
            continue;
        }
        let removed: Vec<String> = matches
            .iter()
            .map(|i| store.lines[*i].fingerprint.clone())
            .collect();
        let mut retained = String::new();
        for (i, line) in store.lines.iter().enumerate() {
            if !matches.contains(&i) {
                retained.push_str(&line.text);
                retained.push('\n');
            }
        }
        write_atomic(&store.path, retained.as_bytes())
            .with_context(|| format!("Failed to rewrite {}", store.path.display()))?;
        println!(
            "Removed from {}: {}",
            store.path.display(),
            removed.join(", ")
        );
    }

    Ok(())
}
