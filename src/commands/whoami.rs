use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

use crate::get_git_config_email;

/// Shows the current user's identity.
pub fn cmd_whoami(repo_root: &Path, email_override: Option<&str>, key_store: &PathBuf) -> Result<()> {
    let email = match email_override {
        Some(e) => e.to_string(),
        None => get_git_config_email(repo_root).context(
            "git config user.email is not set; run git config user.email '<you@example.com>' or pass --email",
        )?,
    };

    println!("Your identity: {}", email);
    println!("Key store: {}", key_store.display());
    Ok(())
}
