use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TrackedFiles {
    pub files: Vec<PathBuf>,
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
pub fn get_git_config_email() -> Result<String> {
    let output = Command::new("git")
        .args(["config", "user.email"])
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
