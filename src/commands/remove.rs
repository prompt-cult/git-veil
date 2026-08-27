use anyhow::{Context, Result};
use std::env;
use std::fs;
use std::path::PathBuf;

use crate::tracked_files::validate_tracked_path;
use crate::TrackedFiles;

/// Removes files from the tracked files list.
///
/// Paths are stored relative to the repository root, so the user-supplied
/// path is canonicalised and stripped against the repo root the same way
/// cmd_add resolves it.
pub fn cmd_remove(files: Vec<String>) -> Result<()> {
    let tracked_path = PathBuf::from(".git-gpg/tracked.json");
    let mut tracked = TrackedFiles::load(&tracked_path)?;

    let repo_root = env::current_dir().context("Failed to get current directory")?;
    let repo_root = fs::canonicalize(&repo_root)
        .context("Failed to canonicalise repository root")?;

    let mut count = 0;
    for file in &files {
        let path = PathBuf::from(file);
        let canonical = fs::canonicalize(&path)
            .with_context(|| format!("File not found: {}", file))?;
        let relative = canonical
            .strip_prefix(&repo_root)
            .with_context(|| format!(
                "File is outside the repository: {} (resolves to {})",
                file,
                canonical.display()
            ))?;
        if relative.as_os_str().is_empty() {
            anyhow::bail!("Cannot remove the repository root itself: {}", file);
        }
        validate_tracked_path(relative)
            .with_context(|| format!("Invalid path for tracked file: {}", file))?;
        if !tracked.files.contains(&relative.to_path_buf()) {
            anyhow::bail!("File not tracked: {}", file);
        }
        tracked.remove(&relative.to_path_buf());
        count += 1;
    }

    tracked.save(&tracked_path)?;
    println!("Removed {} file(s)", count);
    Ok(())
}
