use anyhow::Result;
use std::path::Path;

use crate::tracked_files::{resolve_repo_relative_input, PathResolveMode, TrackedFiles};

/// Adds files to the tracked files list.
///
/// Paths are stored relative to the repository root. The file is
/// canonicalised first, so a symlink whose target resolves outside the repo
/// is rejected (the target could otherwise be read and deleted by hide).
/// Relative user-supplied paths resolve against `repo_root`.
pub fn cmd_add(repo_root: &Path, files: Vec<String>) -> Result<()> {
    let tracked_path = repo_root.join(".git-veil/tracked.json");
    let mut tracked = TrackedFiles::load(&tracked_path)?;

    let mut count = 0;
    for file in &files {
        let relative = resolve_repo_relative_input(
            repo_root,
            file,
            PathResolveMode::CanonicaliseRequireExists,
            "track",
        )?;
        tracked.add(relative);
        count += 1;
    }

    tracked.save(&tracked_path)?;
    println!("Added {} file(s)", count);
    Ok(())
}
