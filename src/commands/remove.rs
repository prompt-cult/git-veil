use anyhow::Result;
use std::path::Path;

use crate::tracked_files::{PathResolveMode, resolve_repo_relative_input, TrackedFiles};

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

    let mut count = 0;
    for file in &files {
        let relative = resolve_repo_relative_input(
            repo_root,
            file,
            PathResolveMode::LexicalStripValidateResolved,
            "remove",
        )?;

        if !tracked.files.contains(&relative) {
            anyhow::bail!("file not tracked: {}; run git-gpg add '{}' to track it", file, file);
        }
        tracked.remove(&relative);
        count += 1;
    }

    tracked.save(&tracked_path)?;
    println!("Removed {} file(s)", count);
    Ok(())
}
