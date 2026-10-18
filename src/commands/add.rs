use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;

use crate::allowance::AllowanceStore;
use crate::commands::allow::resolve_allowance_anchor;
use crate::tracked_files::{
    get_git_config_email, resolve_repo_relative_input, PathResolveMode, TrackedFiles,
};

/// Adds files to the tracked files list.
///
/// Paths are stored relative to the repository root. The file is
/// canonicalised first, so a symlink whose target resolves outside the repo
/// is rejected (the target could otherwise be read and deleted by hide).
/// Relative user-supplied paths resolve against `repo_root`.
///
/// Like git-secret, files not already in .gitignore are auto-added to it.
///
/// The manifest nomination is also the user's standing instruction, so each
/// path is recorded in the machine-local allowance store in the key store
/// (src/allowance.rs): tracked.json is committed and attacker-writable, so
/// hide refuses to first-encrypt a path that neither has a committed
/// ciphertext nor was allowed on this machine. See "Allowance" in
/// docs/design.md.
pub fn cmd_add(
    repo_root: &Path,
    files: Vec<String>,
    remote_name: &str,
    key_store: &std::path::Path,
) -> Result<()> {
    let tracked_path = repo_root.join(".git-veil/tracked.json");
    let mut tracked = TrackedFiles::load(&tracked_path)?;

    let (repo_id, pin) = resolve_allowance_anchor(repo_root, remote_name, key_store)?;
    let principal = get_git_config_email(repo_root).context(
        "add records the allowance with the manifest nomination, which needs your git config user.email",
    )?;

    let mut count = 0;
    for file in &files {
        let relative = resolve_repo_relative_input(
            repo_root,
            file,
            PathResolveMode::CanonicaliseRequireExists,
            "track",
        )?;
        let relative_str = relative.to_string_lossy().to_string();

        ensure_gitignored(repo_root, &relative_str)?;

        // A .secret swallowed by a broad ignore rule, such as a parent
        // directory like .tmp/, would silently never reach the repository.
        // Add succeeds, but the ciphertext beside the plaintext is
        // untrackable. Warn now. Hide refuses outright before encrypting.
        let secret_relative = format!("{}.secret", relative_str);
        if is_gitignored(repo_root, &secret_relative)? {
            println!(
                "warning: a ciphertext path is git-ignored with error code 40 so it will never reach the repository. Fix .gitignore before hiding"
            );
        }

        tracked.add(relative.clone());
        AllowanceStore::record(key_store, &repo_id, &pin, &principal, &relative)?;
        count += 1;
    }

    tracked.save(&tracked_path)?;
    println!("added {} files", count);
    Ok(())
}

/// Runs `git check-ignore` for one repo-relative path: true when git
/// ignores it. Shared by the add-time warning and hide's fail-closed
/// ciphertext gate so the two sides cannot drift apart.
pub(crate) fn is_gitignored(repo_root: &Path, relative_path: &str) -> Result<bool> {
    Ok(Command::new("git")
        .current_dir(repo_root)
        .args(["check-ignore", relative_path])
        .output()
        .context("Failed to run git check-ignore")?
        .status
        .success())
}

/// True when the repo-relative path is tracked in the git index, staged
/// or committed. Shared by reveal and unhide's tracked-plaintext
/// refusal (exit 43, docs/design.md "Ignore safety" gate 4). A
/// git-tracked plaintext is ordinary repository content, not a
/// secret, and overwriting it from attacker-committed ciphertext is
/// the reveal-clobber channel.
///
/// The check is case-insensitive as a fallback. On the macOS and
/// Windows default filesystems a case-variant spelling of a tracked
/// path resolves to the same file, so an exact-match miss must still
/// refuse when any case-variant of the path is in the index. A miss
/// there would let a committed payload ciphertext overwrite a tracked
/// source file through reveal. On case-sensitive filesystems the
/// fallback can in principle false-positive two genuinely distinct
/// case-variant files. For a secrets tool refusing beats overwriting,
/// and the refusal names the path.
pub(crate) fn is_tracked_in_git(repo_root: &Path, relative_path: &Path) -> bool {
    let exact = Command::new("git")
        .current_dir(repo_root)
        .args(["ls-files", "--error-unmatch", "--"])
        .arg(relative_path)
        .output();
    match exact {
        Ok(out) if out.status.success() => return true,
        _ => {}
    }
    // Case-insensitive fallback over the full index listing.
    Command::new("git")
        .current_dir(repo_root)
        .args(["ls-files", "-z"])
        .output()
        .map(|out| {
            let wanted = relative_path.to_string_lossy();
            out.stdout
                .split(|b| *b == 0)
                .any(|entry| entry.eq_ignore_ascii_case(wanted.as_bytes()))
        })
        .unwrap_or(false)
}

/// Checks if a file is gitignored. If not, appends it to .gitignore.
fn ensure_gitignored(repo_root: &Path, relative_path: &str) -> Result<()> {
    if !is_gitignored(repo_root, relative_path)? {
        let gitignore_path = repo_root.join(".gitignore");
        let mut content = std::fs::read_to_string(&gitignore_path).unwrap_or_default();
        if !content.ends_with('\n') && !content.is_empty() {
            content.push('\n');
        }
        content.push_str(relative_path);
        content.push('\n');
        std::fs::write(&gitignore_path, content)
            .with_context(|| "Failed to write .gitignore".to_string())?;
        println!("file not in .gitignore, adding: {}", relative_path);
    }

    Ok(())
}
