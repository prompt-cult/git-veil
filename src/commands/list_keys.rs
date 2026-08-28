use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

use crate::Keyring;

/// Lists all keys in the keyring.
pub fn cmd_list_keys(repo_root: &Path) -> Result<()> {
    let keyring_path = repo_root.join(".git-gpg/keyring");
    let keyring_text = fs::read_to_string(&keyring_path)
        .context("Failed to read keyring file")?;
    let keyring = Keyring::parse(&keyring_text)?;

    if keyring.entries.is_empty() {
        println!("No keys in keyring");
    } else {
        println!("Keys in keyring:");
        for entry in &keyring.entries {
            println!("  {} ({})", entry.email, entry.fingerprint);
        }
        println!("\nTotal: {} keys", keyring.entries.len());
    }
    Ok(())
}
