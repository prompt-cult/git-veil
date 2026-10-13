use anyhow::{Context, Result};
use std::path::Path;

use crate::age_crypto::{fingerprint_for_recipient, load_recipients_from_store};
use crate::fs_atomic::write_atomic;

/// Resolves `identifier` (an age recipient string or a fingerprint, matched
/// case-insensitively) against every recipient in the local key store and
/// returns it as a recipient string.
///
/// Matching is exact equality: the identifier equals a recipient string, or
/// equals the fingerprint derived from one. The store may hold recipients
/// imported via `trust` or derived from imported identities.
pub fn export_public_key(key_store: &Path, identifier: &str) -> Result<String> {
    let recipients = load_recipients_from_store(key_store)?;
    let wanted_fingerprint = identifier.trim().to_lowercase();

    let matched: Vec<&String> = recipients
        .iter()
        .map(|(_, recipient_str)| recipient_str)
        .filter(|recipient_str| {
            *recipient_str == identifier.trim()
                || fingerprint_for_recipient(recipient_str) == wanted_fingerprint
        })
        .collect();

    if matched.is_empty() {
        anyhow::bail!(
            "no matching key found in the key store. Export only finds keys this machine knows"
        );
    }
    if matched.len() > 1 {
        anyhow::bail!("multiple keys match in the key store. Pass a fingerprint to select one");
    }

    let mut result = matched[0].clone();
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
