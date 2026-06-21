use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;

use crate::TrackedFiles;

/// Removes files from the tracked files list.
pub fn cmd_remove(files: Vec<String>) -> Result<()> {
    let tracked_path = PathBuf::from(".git-gpg/tracked.json");
    let mut tracked = TrackedFiles::load(&tracked_path)?;
    
    let mut count = 0;
    for file in &files {
        let path = PathBuf::from(file);
        let canonical = fs::canonicalize(&path)
            .with_context(|| format!("File not found: {}", file))?;
        
        if !tracked.files.contains(&canonical) {
            anyhow::bail!("File not tracked: {}", file);
        }
        
        tracked.remove(&canonical);
        count += 1;
    }
    
    tracked.save(&tracked_path)?;
    println!("Removed {} file(s)", count);
    Ok(())
}
