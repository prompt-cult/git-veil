use anyhow::Result;
use std::path::Path;

use crate::{derive_repo_id, get_remote_push_url};

/// Shows the repository ID derived from the git remote push URL.
pub fn cmd_show_repo_id(repo_root: &Path, remote_name: &str) -> Result<()> {
    let push_url = get_remote_push_url(repo_root, remote_name)?;
    let repo_id = derive_repo_id(&push_url)?;

    println!("Repository ID: {}", repo_id);
    println!("Remote: {}", remote_name);
    println!("Push URL: {}", push_url);
    Ok(())
}
