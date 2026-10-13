use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

use crate::age_crypto::{
    for_each_store_line, parse_identity, parse_recipient, recipient_from_identity,
};
use crate::fs_atomic::write_atomic;

/// One key line parsed out of a key store file.
struct StoreLine {
    text: String,
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
///
/// A non-comment line that is not a parseable identity is a hard error
/// naming the corrupt line: the store is refused untouched. Silently
/// skipping corrupt lines would let a successful removal rewrite the store
/// without them — deleting key material removekey was never asked to touch
/// (the same fail-closed rule every key store read applies).
fn load_identity_store(path: &Path) -> Result<StoreContents> {
    if !path.exists() {
        return Ok(StoreContents {
            path: path.to_path_buf(),
            exists: false,
            lines: Vec::new(),
        });
    }
    let content = std::fs::read_to_string(path).context("Failed to read identities.txt")?;
    let mut lines = Vec::new();
    for_each_store_line(path, &content, |_, line_str| {
        let identity = parse_identity(line_str)?;
        let recipient = recipient_from_identity(&identity);
        lines.push(StoreLine {
            text: line_str.to_string(),
            recipient,
        });
        Ok(())
    })?;
    Ok(StoreContents {
        path: path.to_path_buf(),
        exists: true,
        lines,
    })
}

/// Loads and parses the recipients store (recipients.txt).
///
/// The same fail-closed rule as every key store read: a non-comment line
/// that is not a parseable recipient is a hard error naming the corrupt
/// line — the store is refused untouched, never rewritten from a partial
/// parse.
fn load_recipient_store(path: &Path) -> Result<StoreContents> {
    if !path.exists() {
        return Ok(StoreContents {
            path: path.to_path_buf(),
            exists: false,
            lines: Vec::new(),
        });
    }
    let content = std::fs::read_to_string(path).context("Failed to read recipients.txt")?;
    let mut lines = Vec::new();
    for_each_store_line(path, &content, |_, line_str| {
        parse_recipient(line_str)?;
        lines.push(StoreLine {
            text: line_str.to_string(),
            recipient: line_str.to_string(),
        });
        Ok(())
    })?;
    Ok(StoreContents {
        path: path.to_path_buf(),
        exists: true,
        lines,
    })
}

/// Removes key material from the LOCAL key store: every line in
/// `<key_store>/identities.txt` and `<key_store>/recipients.txt` whose
/// recipient string exactly matches `identifier` is dropped. Keys are
/// selected by public key string only; no fingerprint-as-identifier mode
/// remains (issue #41).
pub fn cmd_removekey(key_store: &Path, identifier: &str, yes: bool) -> Result<()> {
    let identities_path = key_store.join("identities.txt");
    let recipients_path = key_store.join("recipients.txt");

    let identity_store = load_identity_store(&identities_path)?;
    let recipient_store = load_recipient_store(&recipients_path)?;

    let wanted_recipient = identifier.trim();

    let identity_matches: Vec<usize> = identity_store
        .lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.recipient == wanted_recipient)
        .map(|(i, _)| i)
        .collect();
    let recipient_matches: Vec<usize> = recipient_store
        .lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.recipient == wanted_recipient)
        .map(|(i, _)| i)
        .collect();

    if identity_matches.is_empty() && recipient_matches.is_empty() {
        anyhow::bail!(
            "no matching key found in the key store. removekey only removes keys this machine local store holds"
        );
    }

    // Danger guard: the target is the only identity in identities.txt.
    if !identity_matches.is_empty() && identity_store.lines.len() == 1 && !yes {
        anyhow::bail!(
            "refusing to remove the only identity. Without it you cannot decrypt anything. Confirm to continue"
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
            .map(|i| store.lines[*i].recipient.clone())
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
