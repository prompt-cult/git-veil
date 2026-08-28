use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

/// Removes the .git-gpg directory and cleans up .gitignore.
pub fn cmd_clean(repo_root: &Path) -> Result<()> {
    let git_gpg_dir = repo_root.join(".git-gpg");

    if git_gpg_dir.exists() {
        fs::remove_dir_all(&git_gpg_dir)
            .context("Failed to remove .git-gpg directory")?;
    }

    // Remove .git-gpg/secrets from .gitignore
    let gitignore_path = repo_root.join(".gitignore");
    if gitignore_path.exists() {
        let content = fs::read_to_string(&gitignore_path)?;
        let updated: Vec<&str> = content.lines()
            .filter(|line| !line.trim().starts_with(".git-gpg"))
            .collect();
        let new_content = updated.join("\n");
        fs::write(&gitignore_path, new_content)
            .context("Failed to update .gitignore")?;
    }

    println!("✓ Cleaned");
    Ok(())
}
