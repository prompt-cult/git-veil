use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TrackedFiles {
    pub files: Vec<PathBuf>,
}

/// Validates that a tracked path is a safe repo-relative path.
///
/// Tracked paths must be relative, must contain no `..` (or other
/// non-normal) components, and — as defence in depth — must stay inside
/// the repository root when joined under it (ciphertext lives beside the
/// plaintext as `<name>.secret`, so every tracked path is used both for
/// reads and for sibling writes). This is the shared boundary check used
/// when loading tracked.json and before any path use in hide/reveal, so a
/// malicious tracked.json (committed by any repo writer) cannot make git-gpg
/// read or write outside the repository.
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
    if !stays_inside_repo_root(path) {
        anyhow::bail!(
            "Tracked path escapes the repository root: {}",
            path.display()
        );
    }
    Ok(())
}

/// Defence in depth: lexically joins `path` under a repository root and
/// resolves `.`/`..` components; the result must still be inside that root.
/// The component check in `validate_tracked_path` already rejects `..`, so
/// this names and enforces the repo-root containment guarantee on its own:
/// if the component rule is ever relaxed, this check still holds the line.
fn stays_inside_repo_root(path: &Path) -> bool {
    // A single representative root suffices: containment under an absolute
    // root is a lexical property independent of the root's exact name.
    let repo_root = PathBuf::from("/repo");
    let mut normalized = PathBuf::new();
    for component in repo_root.join(path).components() {
        match component {
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::Prefix(_) => return false,
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return false;
                }
            }
            Component::Normal(_) => normalized.push(component.as_os_str()),
        }
    }
    normalized.starts_with(&repo_root)
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
