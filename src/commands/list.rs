use anyhow::Result;
use std::path::Path;

use crate::TrackedFiles;

/// Lists all tracked files, one path per line on stdout.
///
/// Bare data, no header, no bullets: the output pipes into `xargs`,
/// `while read` and friends. An empty list prints nothing; exit 0 is
/// the only statement that nothing is tracked.
pub fn cmd_list(repo_root: &Path) -> Result<()> {
    let tracked_path = repo_root.join(".git-veil/tracked.json");
    let tracked = TrackedFiles::load(&tracked_path)?;

    for file in &tracked.files {
        println!("{}", file.display());
    }
    Ok(())
}
