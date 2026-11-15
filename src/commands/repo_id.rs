use anyhow::Result;
use std::path::Path;

use crate::{derive_repo_id, get_remote_push_url};

/// Shows the repository ID derived from the git remote push URL: one
/// bare value on stdout. The remote name and push URL behind it are
/// `git remote`'s to show.
pub fn cmd_repo_id(repo_root: &Path, remote_name: &str) -> Result<()> {
    let push_url = get_remote_push_url(repo_root, remote_name)?;
    let repo_id = derive_repo_id(&push_url)?;

    println!("{}", repo_id);
    Ok(())
}
