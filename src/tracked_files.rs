use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

const SECRETS_DIR: &str = ".git-gpg/secrets";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TrackedFiles {
    pub files: Vec<PathBuf>,
}

/// Validates that a tracked path is a safe repo-relative path.
///
/// Tracked paths must be relative, must contain no `..` (or other
/// non-normal) components, and — as defence in depth — must stay inside
/// `.git-gpg/secrets` when joined under it. This is the shared boundary
/// check used when loading tracked.json and before any path use in
/// hide/reveal, so a malicious tracked.json (committed by any repo writer)
/// cannot make git-gpg read or write outside the repository.
pub fn validate_tracked_path(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() {
        anyhow::bail!("Tracked path is empty");
    }
    if path.is_absolute() {
        anyhow::bail!(
            "Tracked path must be relative, got absolute path: {}",
            path.display()
        );
    }
    for component in path.components() {
        match component {
            Component::Normal(_) => {}
            other => anyhow::bail!(
                "Tracked path contains forbidden {:?} component: {}",
                other,
                path.display()
            ),
        }
    }
    let joined = PathBuf::from(SECRETS_DIR).join(path);
    if !joined.starts_with(SECRETS_DIR) {
        anyhow::bail!(
            "Tracked path escapes the secrets directory: {}",
            path.display()
        );
    }
    Ok(())
}

impl TrackedFiles {
    pub fn load(path: &PathBuf) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = fs::read_to_string(path)
            .context("Failed to read tracked files")?;
        let tracked: TrackedFiles = serde_json::from_str(&content)
            .context("Failed to parse tracked files JSON")?;
        for file in &tracked.files {
            validate_tracked_path(file)
                .with_context(|| format!("Invalid tracked file entry: {}", file.display()))?;
        }
        Ok(tracked)
    }

    pub fn save(&self, path: &PathBuf) -> Result<()> {
        let content = serde_json::to_string_pretty(self)
            .context("Failed to serialize tracked files")?;
        fs::write(path, content).context("Failed to write tracked files")?;
        Ok(())
    }

    pub fn add(&mut self, file: PathBuf) {
        if !self.files.contains(&file) {
            self.files.push(file);
        }
    }

    pub fn remove(&mut self, file: &PathBuf) {
        self.files.retain(|f| f != file);
    }
}

/// Gets the email configured in git config user.email.
pub fn get_git_config_email(repo_root: &Path) -> Result<String> {
    let output = Command::new("git")
        .args(["config", "user.email"])
        .current_dir(repo_root)
        .output()
        .context("Failed to execute git config user.email")?;

    if !output.status.success() {
        anyhow::bail!("git config user.email is not set");
    }

    let email = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if email.is_empty() {
        anyhow::bail!("git config user.email is empty");
    }

    Ok(email)
}
