use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;

use crate::TrackedFiles;

/// Adds files to the tracked files list.
pub fn cmd_add(files: Vec<String>) -> Result<()> {
    let tracked_path = PathBuf::from(".git-gpg/tracked.json");
    let mut tracked = TrackedFiles::load(&tracked_path)?;
    
    let mut count = 0;
    for file in &files {
        let path = PathBuf::from(file);
        let canonical = fs::canonicalize(&path)
            .with_context(|| format!("File not found: {}", file))?;
        tracked.add(canonical);
        count += 1;
    }
    
    tracked.save(&tracked_path)?;
    println!("Added {} file(s)", count);
    Ok(())
}
