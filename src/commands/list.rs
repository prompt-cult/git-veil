use anyhow::Result;
use std::path::Path;

use crate::TrackedFiles;

/// Lists all tracked files.
pub fn cmd_list(repo_root: &Path) -> Result<()> {
    let tracked_path = repo_root.join(".git-veil/tracked.json");
    let tracked = TrackedFiles::load(&tracked_path)?;

    if tracked.files.is_empty() {
        println!("No files tracked");
    } else {
        println!("Tracked files:");
        for file in &tracked.files {
            println!("  - {}", file.display());
        }
    }
    Ok(())
}
