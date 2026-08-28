use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

use crate::commands::hide::encrypted_path_for;
use crate::TrackedFiles;

/// Removes the .git-gpg internal state directory.
///
/// Single responsibility: destroy git-gpg's internal state (.git-gpg/).
/// `.gitignore` is never rewritten — init no longer adds any entry, and the
/// in-place `<name>.secret` ciphertext files are ordinary committable files
/// that a clean must not disown.
///
/// Because hide deletes the plaintexts, the `<name>.secret` ciphertexts
/// beside them can be the ONLY remaining copy of a secret, and the tracked
/// state that references them dies with the clean. A clean that would
/// destroy such data therefore refuses unless `--yes` confirms it.
pub fn cmd_clean(repo_root: &Path, yes: bool) -> Result<()> {
    let git_gpg_dir = repo_root.join(".git-gpg");

    // Compute the danger condition BEFORE removing anything: tracked state
    // (the manifest itself is being destroyed) and any in-place ciphertext
    // beside the tracked paths (possibly the only remaining copy).
    let tracked = TrackedFiles::load(&git_gpg_dir.join("tracked.json"))?;
    let mut ciphertext_paths = Vec::new();
    for file in &tracked.files {
        let encrypted_path = encrypted_path_for(repo_root, file);
        if encrypted_path.exists() {
            ciphertext_paths.push(encrypted_path);
        }
    }

    if (!tracked.files.is_empty() || !ciphertext_paths.is_empty()) && !yes {
        let mut message = String::from(
            "Refusing to clean: this would destroy git-gpg state holding secret material.\n",
        );
        message.push_str(&format!(
            "Tracked files whose manifest entries would be destroyed: {}\n",
            tracked.files.len()
        ));
        if ciphertext_paths.is_empty() {
            message.push_str(
                "No ciphertext exists beside the tracked paths, but the tracked-file \
                 manifest itself would be destroyed.\n",
            );
        } else {
            message.push_str(
                "Ciphertext file(s) that would be orphaned (possibly the only remaining copy):\n",
            );
            for path in &ciphertext_paths {
                message.push_str(&format!("  - {}\n", path.display()));
            }
        }
        message.push_str("Re-run with --yes to confirm you want to destroy this data.");
        anyhow::bail!("{}", message);
    }

    if git_gpg_dir.exists() {
        fs::remove_dir_all(&git_gpg_dir)
            .context("Failed to remove .git-gpg directory")?;
    }

    println!("✓ Cleaned");
    Ok(())
}
