use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

use crate::{Keyring, TrackedFiles, TrustStore};

/// Initialises a new git-gpg repository structure under `repo_root`.
///
/// Creates only the internal state directory `.git-gpg/` (keyring,
/// trust.json, tracked.json). It never touches `.gitignore`: ciphertext is
/// stored in place beside the plaintext as `<name>.secret`, and those files
/// are meant to be COMMITTED, so gitignoring them would defeat the
/// fresh-clone decryptability contract.
pub fn cmd_init(repo_root: &Path) -> Result<()> {
    let git_gpg_dir = repo_root.join(".git-gpg");

    // Create the internal state directory
    fs::create_dir_all(&git_gpg_dir).context("Failed to create .git-gpg directory")?;

    // Create empty keyring
    let keyring = Keyring::new();
    let keyring_content = keyring.serialize();
    fs::write(git_gpg_dir.join("keyring"), keyring_content)
        .context("Failed to create keyring file")?;

    // Create empty trust.json via the type's own API (single source of truth
    // for the on-disk format)
    TrustStore::default()
        .save_to_file(&git_gpg_dir.join("trust.json"))
        .context("Failed to create trust.json")?;

    // Create empty tracked.json via the type's own API (single source of
    // truth for the on-disk format)
    TrackedFiles::default()
        .save(&git_gpg_dir.join("tracked.json"))
        .context("Failed to create tracked.json")?;

    println!("✓ git-gpg initialized");
    Ok(())
}
