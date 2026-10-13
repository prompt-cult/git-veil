use anyhow::{Context, Result};
use std::path::Path;

use crate::get_git_config_email;

/// Shows the current user's principal.
pub fn cmd_whoami(repo_root: &Path, email_override: Option<&str>, _key_store: &Path) -> Result<()> {
    let email = match email_override {
        Some(e) => e.to_string(),
        None => get_git_config_email(repo_root).context(
            "git config user.email is not set. Set the git email or pass the email flag",
        )?,
    };

    // The principal label is committed in the public keyring — a public
    // repository fact, not secret material — so naming it is the whole
    // point of asking (issue #42).
    println!("Your principal: {}", email);
    Ok(())
}
