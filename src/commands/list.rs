use anyhow::Result;
use std::path::PathBuf;

use crate::TrackedFiles;

/// Lists all tracked files.
pub fn cmd_list() -> Result<()> {
    let tracked_path = PathBuf::from(".git-gpg/tracked.json");
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
