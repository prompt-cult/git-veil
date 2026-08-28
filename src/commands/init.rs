use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

use crate::fs_atomic::write_atomic;
use crate::{Keyring, TrackedFiles, TrustStore};

/// Initialises a new git-veil repository structure under `repo_root`.
///
/// Creates only the internal state directory `.git-veil/` (keyring,
/// trust.json, tracked.json). It never touches `.gitignore`: ciphertext is
/// stored in place beside the plaintext as `<name>.secret`, and those files
/// are meant to be COMMITTED, so gitignoring them would defeat the
/// fresh-clone decryptability contract.
pub fn cmd_init(repo_root: &Path) -> Result<()> {
    let git_veil_dir = repo_root.join(".git-veil");

    // Fresh init only: a re-init over an established trust anchor would
    // silently destroy the user's trust.json and tracked-file manifest, so
    // refuse while real trust state exists. A `.git-veil/` directory with an
    // absent or empty trust.json is a degenerate half-initialised state and
    // keeps the old reset behaviour.
    let trust_path = git_veil_dir.join("trust.json");
    if git_veil_dir.is_dir() && trust_path.exists() {
        let existing_trust = TrustStore::load_from_file(&trust_path)
            .context("Failed to read existing trust.json")?;
        if !existing_trust.trusted_keys.is_empty() {
            anyhow::bail!(
                "git-veil is already initialized here; refusing to reset existing trust state \
                 — remove .git-veil/ explicitly if you really want a fresh start"
            );
        }
    }

    // Create the internal state directory
    fs::create_dir_all(&git_veil_dir).context("Failed to create .git-veil directory")?;

    // Create empty keyring
    let keyring = Keyring::new();
    let keyring_content = keyring.serialize();
    write_atomic(&git_veil_dir.join("keyring"), keyring_content.as_bytes())
        .context("Failed to create keyring file")?;

    // Create empty trust.json via the type's own API (single source of truth
    // for the on-disk format)
    TrustStore::default()
        .save_to_file(&git_veil_dir.join("trust.json"))
        .context("Failed to create trust.json")?;

    // Create empty tracked.json via the type's own API (single source of
    // truth for the on-disk format)
    TrackedFiles::default()
        .save(&git_veil_dir.join("tracked.json"))
        .context("Failed to create tracked.json")?;

    println!("✓ git-veil initialized");
    Ok(())
}
