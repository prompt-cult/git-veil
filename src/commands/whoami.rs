use anyhow::{Context, Result};
use std::path::PathBuf;

use crate::{get_git_config_email, default_gpg_home};

/// Shows the current user's identity.
pub fn cmd_whoami(email_override: Option<&str>, gpg_home: &PathBuf) -> Result<()> {
    let email = match email_override {
        Some(e) => e.to_string(),
        None => get_git_config_email().context("git config user.email is not set")?,
    };
    
    println!("Your identity: {}", email);
    println!("GPG home: {}", gpg_home.display());
    Ok(())
}
