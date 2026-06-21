use anyhow::{Context, Result};
use std::env;

use crate::{derive_repo_id, get_remote_push_url};

/// Shows the repository ID derived from the git remote push URL.
pub fn cmd_show_repo_id(remote_name: &str) -> Result<()> {
    let repo_path = env::current_dir().context("Failed to get current directory")?;
    let push_url = get_remote_push_url(&repo_path, remote_name)?;
    let repo_id = derive_repo_id(&push_url)?;
    
    println!("Repository ID: {}", repo_id);
    println!("Remote: {}", remote_name);
    println!("Push URL: {}", push_url);
    Ok(())
}
