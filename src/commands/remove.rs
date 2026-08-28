use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use crate::tracked_files::validate_tracked_path;
use crate::TrackedFiles;

/// Removes files from the tracked files list.
///
/// Unlike cmd_add, the tracked plaintext may not exist: hide deletes it and
/// leaves only the `.secret` ciphertext beside it, so removal must NOT
/// require the plaintext to be on disk (forcing the user to reveal a secret
/// just to untrack it would defeat the purpose). Resolution therefore mirrors
/// cmd_unhide: an absolute path is stripped lexically against the canonical
/// repository root, a relative path is taken as repo-relative, and both go
/// through the shared `validate_tracked_path` boundary check. Paths outside
/// the repository are still rejected.
///
/// Removal only edits tracked.json — it does NOT delete any ciphertext
/// `<name>.secret` file (untracking is not decrypting); unhide/reveal handle
/// the ciphertext.
pub fn cmd_remove(repo_root: &Path, files: Vec<String>) -> Result<()> {
    let tracked_path = repo_root.join(".git-gpg/tracked.json");
    let mut tracked = TrackedFiles::load(&tracked_path)?;

    let canonical_root = fs::canonicalize(repo_root)
        .context("Failed to canonicalise repository root")?;

    let mut count = 0;
    for file in &files {
        let path = PathBuf::from(file);

        // The plaintext may not exist (it is hidden), so resolve lexically:
        // absolute paths are stripped against the canonical repo root,
        // relative paths are already repo-relative.
        let relative: PathBuf = if path.is_absolute() {
            path.strip_prefix(&canonical_root)
                .with_context(|| format!("File is outside the repository: {}", file))?
                .to_path_buf()
        } else {
            path
        };

        if relative.as_os_str().is_empty() {
            anyhow::bail!("Cannot remove the repository root itself: {}", file);
        }
        validate_tracked_path(&relative)
            .with_context(|| format!("Invalid path for tracked file: {}", file))?;
        if !tracked.files.contains(&relative) {
            anyhow::bail!("File not tracked: {}", file);
        }
        tracked.remove(&relative);
        count += 1;
    }

    tracked.save(&tracked_path)?;
    println!("Removed {} file(s)", count);
    Ok(())
}
