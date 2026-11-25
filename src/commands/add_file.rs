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
/// docs/src/design.md.
pub fn cmd_add_file(
    repo_root: &Path,
    files: Vec<String>,
    remote_name: &str,
    key_store: &std::path::Path,
) -> Result<()> {
    let tracked_path = repo_root.join(".git-veil/tracked.json");
    let gitignore_path = repo_root.join(".gitignore");
    let gitignore_existed = gitignore_path.exists();
    let gitignore_original = if gitignore_existed {
        Some(
            std::fs::read_to_string(&gitignore_path)
                .with_context(|| "Failed to read .gitignore".to_string())?,
        )
    } else {
        None
    };

    let result = add_files(repo_root, files, remote_name, key_store, &tracked_path);
    if let Err(error) = result {
        restore_gitignore(&gitignore_path, gitignore_original, gitignore_existed)?;
        return Err(error);
    }

    Ok(())
}

/// Validates and applies add-file in dependency order.
///
/// Every path resolves and is safely ignored in two phases. The manifest
/// save happens before any allowance append. A later failure therefore
/// cannot leave standing first-encrypt consent that was not in the saved
/// manifest.
fn add_files(
    repo_root: &Path,
    files: Vec<String>,
    remote_name: &str,
    key_store: &std::path::Path,
    tracked_path: &Path,
) -> Result<()> {
    let mut tracked = TrackedFiles::load(tracked_path)?;

    let (repo_id, pin) = resolve_allowance_anchor(repo_root, remote_name, key_store)?;
    let principal = get_git_config_email(repo_root).context(
        "add-file records the allowance with the manifest nomination, which needs your git config user.email",
    )?;

    let mut resolved = Vec::with_capacity(files.len());
    for file in &files {
        let relative = resolve_repo_relative_input(
            repo_root,
            file,
            PathResolveMode::CanonicaliseRequireExists,
            "track",
        )?;
        if resolved.contains(&relative) {
            continue;
        }
        resolved.push(relative);
    }

    for value in &resolved {
        let relative_str = value.to_string_lossy().to_string();
        ensure_gitignored(repo_root, &relative_str)?;
        let secret_relative = format!("{}.secret", relative_str);
        if is_gitignored(repo_root, &secret_relative)? {
            println!(
                "warning: a ciphertext path is git-ignored with error code 40 so it will never reach the repository. Fix .gitignore before hiding"
            );
        }
        tracked.add(value.clone());
    }

    tracked.save(tracked_path)?;

    for value in &resolved {
        AllowanceStore::record(key_store, &repo_id, &pin, &principal, value)?;
    }

    println!("added {} files", resolved.len());
    Ok(())
}

fn restore_gitignore(path: &Path, original: Option<String>, existed: bool) -> Result<()> {
    match (existed, original) {
        (true, Some(content)) => std::fs::write(path, content)
            .with_context(|| "Failed to restore .gitignore".to_string()),
        (true, None) => {
            std::fs::write(path, "").with_context(|| "Failed to restore .gitignore".to_string())
        }
        _ => Ok(()),
    }
}

/// Runs `git check-ignore` for one repo-relative path: true when git
/// ignores it. Shared by the add-file warning and hide's fail-closed
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
/// or committed. Shared by reveal's tracked-plaintext
/// refusal (exit 43, docs/src/design.md "Ignore safety" gate 4). A
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

/// Encodes a repository-relative path as a literal Git ignore rule.
///
/// Git only special-cases a leading `#` or `!`, but escaping wildcard
/// characters, backslashes and spaces everywhere keeps the encoding
/// independent of later Git syntax changes and makes the line auditable
/// with `git check-ignore`.
fn literal_gitignore_rule(relative_path: &str) -> String {
    let mut pattern = String::with_capacity(relative_path.len());
    for (index, character) in relative_path.char_indices() {
        if index == 0 && (character == '#' || character == '!')
            || matches!(character, '\\' | '*' | '?' | '[' | ']' | ' ' | '#' | '!')
        {
            pattern.push('\\');
        }
        pattern.push(character);
    }
    pattern
}
/// Checks if a file is gitignored. If not, appends a literal Git rule
/// and verifies that Git ignored the path before reporting success.
fn ensure_gitignored(repo_root: &Path, relative_path: &str) -> Result<()> {
    if !is_gitignored(repo_root, relative_path)? {
        let gitignore_path = repo_root.join(".gitignore");
        let original = std::fs::read_to_string(&gitignore_path).unwrap_or_default();
        let mut content = original.clone();
        if !content.ends_with('\n') && !content.is_empty() {
            content.push('\n');
        }
        content.push_str(&literal_gitignore_rule(relative_path));
        content.push('\n');
        std::fs::write(&gitignore_path, content)
            .with_context(|| "Failed to write .gitignore".to_string())?;
        if !is_gitignored(repo_root, relative_path)? {
            std::fs::write(&gitignore_path, original).with_context(|| {
                "Failed to restore .gitignore after an invalid rule".to_string()
            })?;
            anyhow::bail!(
                "git check-ignore did not confirm the literal .gitignore rule for {}",
                relative_path
            );
        }
        println!("file not in .gitignore, adding: {}", relative_path);
    }

    Ok(())
}
