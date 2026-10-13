use anyhow::{Context, Result};
use std::path::Path;

use crate::age_crypto::load_recipients_from_store;
use crate::fs_atomic::write_atomic;

/// Resolves `identifier` — an exact age recipient string — against every
/// recipient in the local key store and returns it as a recipient string.
///
/// Matching is exact equality on the public key string; no
/// fingerprint-as-identifier mode remains (issue #41). The store may hold
/// recipients imported via `trust` or derived from imported identities;
/// it deduplicates by recipient string, so at most one entry matches.
pub fn export_public_key(key_store: &Path, identifier: &str) -> Result<String> {
    let recipients = load_recipients_from_store(key_store)?;
    let wanted = identifier.trim();

    let matched: Vec<&String> = recipients
        .iter()
        .map(|(_, recipient_str)| recipient_str)
        .filter(|recipient_str| *recipient_str == wanted)
        .collect();

    let Some(recipient_str) = matched.first() else {
        anyhow::bail!(
            "no matching key found in the key store. Export only finds keys this machine knows"
        );
    };

    let mut result = (*recipient_str).clone();
    if !result.ends_with('\n') {
        result.push('\n');
    }
    Ok(result)
}

/// Exports the age recipient string for `identifier` from the local key
/// store: to stdout, or atomically to `output` when given.
pub fn cmd_export(key_store: &Path, identifier: &str, output: Option<&Path>) -> Result<()> {
    let armored = export_public_key(key_store, identifier)?;
    match output {
        Some(path) => write_atomic(path, armored.as_bytes())
            .with_context(|| format!("Failed to write exported key to {}", path.display()))?,
        None => print!("{}", armored),
    }
    Ok(())
}
