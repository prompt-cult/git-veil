use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;

use crate::intent::LocalAdds;
use crate::tracked_files::{resolve_repo_relative_input, PathResolveMode, TrackedFiles};
use crate::{derive_repo_id, get_remote_push_url};

/// Adds files to the tracked files list.
///
/// Paths are stored relative to the repository root. The file is
/// canonicalised first, so a symlink whose target resolves outside the repo
/// is rejected (the target could otherwise be read and deleted by hide).
/// Relative user-supplied paths resolve against `repo_root`.
///
/// Like git-secret, files not already in .gitignore are auto-added to it.
///
/// Each path is also recorded in the machine-local intent log in the key
/// store (src/intent.rs): tracked.json is committed and attacker-writable,
/// so hide refuses to first-encrypt a path that neither has a committed
/// ciphertext nor was added on this machine. See "Encryption intent" in
/// docs/design.md.
pub fn cmd_add(
    repo_root: &Path,
    files: Vec<String>,
    remote_name: &str,
    key_store: &std::path::Path,
) -> Result<()> {
    let tracked_path = repo_root.join(".git-veil/tracked.json");
    let mut tracked = TrackedFiles::load(&tracked_path)?;

    let push_url = get_remote_push_url(repo_root, remote_name)?;
    let repo_id = derive_repo_id(&push_url)?;

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

        // A .secret swallowed by a broad ignore rule (e.g. a parent
        // directory like .tmp/) would silently never reach the repository:
        // add succeeds, but the ciphertext beside the plaintext is
        // untrackable. Warn now; hide refuses outright before encrypting.
        let secret_relative = format!("{}.secret", relative_str);
        if is_gitignored(repo_root, &secret_relative)? {
            println!(
                "warning: the ciphertext path '{}' is git-ignored (error code 40); it will never reach the repository — fix .gitignore before hiding",
                secret_relative
            );
        }

        tracked.add(relative.clone());
        LocalAdds::record(key_store, &repo_id, &relative)?;
        count += 1;
    }

    tracked.save(&tracked_path)?;
    println!("Added {} file(s)", count);
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

/// True when the repo-relative path is tracked in the git index (staged or
/// committed). Shared by reveal and unhide's tracked-plaintext refusal
/// (exit 43, docs/design.md "Ignore safety" gate 4): a git-tracked plaintext
/// is ordinary repository content, not a secret, and overwriting it from
/// attacker-committed ciphertext is the reveal-clobber channel.
///
/// The check is case-INSENSITIVE as a fallback (issue #21): on the macOS and
/// Windows default filesystems a case-variant spelling of a tracked path
/// resolves to the SAME file, so an exact-match miss must still refuse when
/// any case-variant of the path is in the index — a miss there would let a
/// committed payload ciphertext overwrite a tracked source file through
/// reveal. On case-sensitive filesystems the fallback can in principle
/// false-positive two genuinely distinct case-variant files; for a secrets
/// tool refusing beats overwriting, and the refusal names the path.
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
