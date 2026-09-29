use anyhow::{Context, Result};
use std::path::Path;

use crate::commands::hide::encrypted_path_for;
use crate::tracked_files::{resolve_repo_relative_input, PathResolveMode, TrackedFiles};

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
/// By default the sibling `<name>.secret` ciphertext is deleted in the same
/// step. This is the fail-closed default: a de-tracked but committed
/// ciphertext would otherwise be silently skipped by the next hide, leaving
/// it decryptable by collaborators removed in a later rotation (see
/// "Orphaned ciphertext" in docs/design.md — hide refuses such orphans with
/// exit 42). The ciphertext is committed content, so deletion is recoverable
/// from git history. `--keep-ciphertext` preserves the old leave-in-place
/// behaviour for callers that want it; hide will then refuse the orphan
/// until it is staged-deleted or the path is re-tracked.
pub fn cmd_remove(repo_root: &Path, files: Vec<String>, keep_ciphertext: bool) -> Result<()> {
    let tracked_path = repo_root.join(".git-veil/tracked.json");
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
            anyhow::bail!(
                "file not tracked: {}; run git-veil add '{}' to track it",
                file,
                file
            );
        }
        tracked.remove(&relative);
        count += 1;

        if !keep_ciphertext {
            let ciphertext = encrypted_path_for(repo_root, &relative);
            if ciphertext.exists() {
                std::fs::remove_file(&ciphertext).with_context(|| {
                    format!("Failed to delete ciphertext: {}", ciphertext.display())
                })?;
                println!(
                    "Deleted ciphertext: {} (committed copies stay recoverable via git history)",
                    ciphertext.display()
                );
            }
        }
    }

    tracked.save(&tracked_path)?;
    println!("Removed {} file(s)", count);
    Ok(())
}
