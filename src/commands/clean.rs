use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

/// Removes the .git-gpg internal state directory.
///
/// Single responsibility: destroy git-gpg's internal state (.git-gpg/).
/// `.gitignore` is never rewritten — init no longer adds any entry, and the
/// in-place `<name>.secret` ciphertext files are ordinary committable files
/// that a clean must not disown.
pub fn cmd_clean(repo_root: &Path) -> Result<()> {
    let git_gpg_dir = repo_root.join(".git-gpg");

    if git_gpg_dir.exists() {
        fs::remove_dir_all(&git_gpg_dir)
            .context("Failed to remove .git-gpg directory")?;
    }

    println!("✓ Cleaned");
    Ok(())
}
