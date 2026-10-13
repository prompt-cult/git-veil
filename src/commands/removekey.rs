use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

use crate::age_crypto::{
    for_each_store_line, parse_x25519_private_key, parse_x25519_public_key,
    x25519_public_key_encoding,
};
use crate::fs_atomic::write_atomic;

/// One key line parsed out of a key store file.
struct StoreLine {
    text: String,
    public_key: String,
}

/// A key store file parsed into lines. `exists` is false when the store
/// file is absent (fresh machine) — absent stores are never created.
struct StoreContents {
    path: PathBuf,
    exists: bool,
    lines: Vec<StoreLine>,
}

/// Loads and parses the private key store (identities.txt).
///
/// A non-comment line that is not a parseable X25519 private key is a hard
/// error naming the corrupt line: the store is refused untouched. Silently
/// skipping corrupt lines would let a successful removal rewrite the store
/// without them — deleting key material removekey was never asked to touch
/// (the same fail-closed rule every key store read applies).
fn load_private_key_store(path: &Path) -> Result<StoreContents> {
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
        let private_key = parse_x25519_private_key(line_str)?;
        let public_key = x25519_public_key_encoding(&private_key);
        lines.push(StoreLine {
            text: line_str.to_string(),
            public_key,
        });
        Ok(())
    })?;
    Ok(StoreContents {
        path: path.to_path_buf(),
        exists: true,
        lines,
    })
}

/// Loads and parses the public key store (recipients.txt).
///
/// The same fail-closed rule as every key store read: a non-comment line
/// that is not a parseable X25519 public key is a hard error naming the
/// corrupt line — the store is refused untouched, never rewritten from a
/// partial parse.
fn load_public_key_store(path: &Path) -> Result<StoreContents> {
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
        parse_x25519_public_key(line_str)?;
        lines.push(StoreLine {
            text: line_str.to_string(),
            public_key: line_str.to_string(),
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
/// X25519 public key encoding exactly matches `identifier` is dropped.
/// Keys are selected by public key string only; no
/// fingerprint-as-identifier mode remains (issue #41).
pub fn cmd_removekey(key_store: &Path, identifier: &str, yes: bool) -> Result<()> {
    let private_keys_path = key_store.join("identities.txt");
    let public_keys_path = key_store.join("recipients.txt");

    let private_key_store = load_private_key_store(&private_keys_path)?;
    let public_key_store = load_public_key_store(&public_keys_path)?;

    let wanted_public_key = identifier.trim();

    let private_key_matches: Vec<usize> = private_key_store
        .lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.public_key == wanted_public_key)
        .map(|(i, _)| i)
        .collect();
    let public_key_matches: Vec<usize> = public_key_store
        .lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.public_key == wanted_public_key)
        .map(|(i, _)| i)
        .collect();

    if private_key_matches.is_empty() && public_key_matches.is_empty() {
        anyhow::bail!(
            "no matching key found in the key store. removekey only removes keys this machine local store holds"
        );
    }

    // Danger guard: the target is the only private key in identities.txt.
    if !private_key_matches.is_empty() && private_key_store.lines.len() == 1 && !yes {
        anyhow::bail!(
            "refusing to remove the only private key. Without it you cannot decrypt anything. Confirm to continue"
        );
    }

    // Rewrite only the stores that hold matching lines.
    for (store, matches) in [
        (&private_key_store, &private_key_matches),
        (&public_key_store, &public_key_matches),
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
            .map(|i| store.lines[*i].public_key.clone())
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
