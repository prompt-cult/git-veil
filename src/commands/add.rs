use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;

use crate::tracked_files::{resolve_repo_relative_input, PathResolveMode, TrackedFiles};

/// Adds files to the tracked files list.
///
/// Paths are stored relative to the repository root. The file is
/// canonicalised first, so a symlink whose target resolves outside the repo
/// is rejected (the target could otherwise be read and deleted by hide).
/// Relative user-supplied paths resolve against `repo_root`.
///
/// Like git-secret, files not already in .gitignore are auto-added to it.
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
        let relative_str = relative.to_string_lossy().to_string();

        ensure_gitignored(repo_root, &relative_str)?;

        // A .secret swallowed by a broad ignore rule (e.g. a parent
        // directory like .tmp/) would silently never reach the repository:
        // add succeeds, but the ciphertext beside the plaintext is
        // untrackable. Warn now; hide refuses outright before encrypting.
        let secret_relative = format!("{}.secret", relative_str);
        if is_gitignored(repo_root, &secret_relative)? {
            println!(
                "warning: the ciphertext path '{}' is git-ignored (error code 40); it will never reach the repository — fix .gitignore before hiding",
                secret_relative
            );
        }

        tracked.add(relative);
        count += 1;
    }

    tracked.save(&tracked_path)?;
    println!("Added {} file(s)", count);
    Ok(())
}

/// Runs `git check-ignore` for one repo-relative path: true when git
/// ignores it. Shared by the add-time warning and hide's fail-closed
/// ciphertext gate so the two sides cannot drift apart.
pub(crate) fn is_gitignored(repo_root: &Path, relative_path: &str) -> Result<bool> {
    Ok(Command::new("git")
        .current_dir(repo_root)
        .args(["check-ignore", relative_path])
        .output()
        .context("Failed to run git check-ignore")?
        .status
        .success())
}

/// Checks if a file is gitignored. If not, appends it to .gitignore.
fn ensure_gitignored(repo_root: &Path, relative_path: &str) -> Result<()> {
    if !is_gitignored(repo_root, relative_path)? {
        let gitignore_path = repo_root.join(".gitignore");
        let mut content = std::fs::read_to_string(&gitignore_path)
            .unwrap_or_default();
        if !content.ends_with('\n') && !content.is_empty() {
            content.push('\n');
        }
        content.push_str(relative_path);
        content.push('\n');
        std::fs::write(&gitignore_path, content)
            .with_context(|| format!("Failed to write .gitignore"))?;
        println!("file not in .gitignore, adding: {}", relative_path);
    }

    Ok(())
}
