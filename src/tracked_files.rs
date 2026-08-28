use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use crate::fs_atomic::write_atomic;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TrackedFiles {
    pub files: Vec<PathBuf>,
}

/// Validates that a tracked path is a safe repo-relative path.
///
/// Tracked paths must be relative, must contain no `..` (or other
/// non-normal) components, and — as defence in depth — must stay inside
/// the repository root when joined under it (ciphertext lives beside the
/// plaintext as `<name>.secret`, so every tracked path is used both for
/// reads and for sibling writes). This is the shared boundary check used
/// when loading tracked.json and before any path use in hide/reveal, so a
/// malicious tracked.json (committed by any repo writer) cannot make git-veil
/// read or write outside the repository.
pub fn validate_tracked_path(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() {
        anyhow::bail!("Tracked path is empty");
    }
    if path.is_absolute() {
        anyhow::bail!(
            "Tracked path must be relative, got absolute path: {}",
            path.display()
        );
    }
    for component in path.components() {
        match component {
            Component::Normal(_) => {}
            other => anyhow::bail!(
                "Tracked path contains forbidden {:?} component: {}",
                other,
                path.display()
            ),
        }
    }
    if !stays_inside_repo_root(path) {
        anyhow::bail!(
            "Tracked path escapes the repository root: {}",
            path.display()
        );
    }
    Ok(())
}

/// Defence in depth: the tracked path, as it exists on disk under
/// `repo_root`, must not be a symlink and must be a regular file.
///
/// A committed tracked.json can name a path another repo writer has
/// committed as a SYMLINK pointing outside the repository (e.g.
/// `innocent.txt` -> `/home/victim/.ssh/id_rsa`). Opening such a path for
/// reading would leak the link target into ciphertext committed back to the
/// repo (hide), or print/diff it (cat/changes); writing through it would
/// corrupt the link target or silently replace the link. The lstat gate
/// (symlink_metadata, which does not follow the link) rejects this,
/// naming the path. A path that does not exist on disk is accepted: for
/// cat/changes/reveal/unhide the plaintext is normally ABSENT (the file is
/// hidden and only the `.secret` ciphertext remains).
pub fn ensure_regular_file(repo_root: &Path, file: &Path) -> Result<()> {
    let full_path = repo_root.join(file);
    let metadata = match fs::symlink_metadata(&full_path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(err)
                .with_context(|| format!("Failed to stat tracked path: {}", file.display()));
        }
    };
    if metadata.file_type().is_symlink() {
        anyhow::bail!(
            "tracked path is a symlink; refusing to read — remove the link and re-add the real file: {}",
            file.display()
        );
    }
    if !metadata.is_file() {
        anyhow::bail!("tracked path is not a regular file: {}", file.display());
    }
    Ok(())
}

/// Defence in depth: lexically joins `path` under a repository root and
/// resolves `.`/`..` components; the result must still be inside that root.
/// The component check in `validate_tracked_path` already rejects `..`, so
/// this names and enforces the repo-root containment guarantee on its own:
/// if the component rule is ever relaxed, this check still holds the line.
fn stays_inside_repo_root(path: &Path) -> bool {
    // A single representative root suffices: containment under an absolute
    // root is a lexical property independent of the root's exact name.
    let repo_root = PathBuf::from("/repo");
    let mut normalized = PathBuf::new();
    for component in repo_root.join(path).components() {
        match component {
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::Prefix(_) => return false,
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return false;
                }
            }
            Component::Normal(_) => normalized.push(component.as_os_str()),
        }
    }
    normalized.starts_with(&repo_root)
}

/// How a user-supplied path is resolved to its repo-relative tracked form.
///
/// The commands share one canonicalise-and-strip shape but deliberately
/// differ in two documented ways:
///
/// - whether the plaintext may be absent: `cmd_add`, `cmd_cat` and
///   `cmd_changes` require existence for the paths they canonicalise,
///   while `cmd_remove` and `cmd_unhide` must work while the file is
///   hidden (hide deleted the plaintext, only the `.secret` ciphertext
///   remains);
/// - which path `validate_tracked_path` guards: `cmd_add`/`cmd_remove`
///   validate the resolved result (it is about to be stored in
///   tracked.json), while `cmd_cat`/`cmd_changes`/`cmd_unhide` validate
///   only the literal relative input.
///
/// The variants pin down each caller's exact contract;
/// [`resolve_repo_relative_input`] enforces it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathResolveMode {
    /// `cmd_add`: the input must exist. Both absolute and relative inputs
    /// are canonicalised against the canonical repo root (symlinks
    /// resolved, `..` collapsed) before stripping, and the resolved path
    /// is validated.
    CanonicaliseRequireExists,
    /// `cmd_remove`: no existence requirement. Absolute inputs are
    /// stripped lexically against the canonical repo root, relative inputs
    /// are taken as-is, and the resolved path is validated.
    LexicalStripValidateResolved,
    /// `cmd_cat` / `cmd_changes`: absolute inputs must exist and are
    /// canonicalised before stripping; relative inputs are taken as-is
    /// after validation. The stripped absolute-derived path is NOT
    /// re-validated: the caller's tracked-file membership check guards it.
    CanonicaliseAbsoluteValidateRelative,
    /// `cmd_unhide`: no existence requirement. Absolute inputs are
    /// stripped lexically; relative inputs are taken as-is after
    /// validation; the stripped path is not re-validated.
    LexicalStripValidateRelative,
}

/// Resolves a user-supplied path to its repo-relative tracked form,
/// according to `mode`.
///
/// `root_verb` names the command's action for the "cannot operate on the
/// repository root itself" error (e.g. `"track"`, `"remove"`, `"cat"`,
/// `"unhide"`, `"check"`).
pub(crate) fn resolve_repo_relative_input(
    repo_root: &Path,
    user_path: &str,
    mode: PathResolveMode,
    root_verb: &str,
) -> Result<PathBuf> {
    let canonical_root =
        fs::canonicalize(repo_root).context("Failed to canonicalise repository root")?;
    let path = PathBuf::from(user_path);

    match mode {
        PathResolveMode::CanonicaliseRequireExists => {
            let canonical = fs::canonicalize(canonical_root.join(&path))
                .with_context(|| format!("File not found: {}", user_path))?;
            let relative = canonical
                .strip_prefix(&canonical_root)
                .with_context(|| {
                    format!(
                        "File is outside the repository: {} (resolves to {})",
                        user_path,
                        canonical.display()
                    )
                })?
                .to_path_buf();
            if relative.as_os_str().is_empty() {
                anyhow::bail!(
                    "Cannot {} the repository root itself: {}",
                    root_verb,
                    user_path
                );
            }
            validate_tracked_path(&relative)
                .with_context(|| format!("Invalid path for tracked file: {}", user_path))?;
            Ok(relative)
        }
        PathResolveMode::LexicalStripValidateResolved => {
            let relative: PathBuf = if path.is_absolute() {
                path.strip_prefix(&canonical_root)
                    .with_context(|| format!("File is outside the repository: {}", user_path))?
                    .to_path_buf()
            } else {
                path
            };
            if relative.as_os_str().is_empty() {
                anyhow::bail!(
                    "Cannot {} the repository root itself: {}",
                    root_verb,
                    user_path
                );
            }
            validate_tracked_path(&relative)
                .with_context(|| format!("Invalid path for tracked file: {}", user_path))?;
            Ok(relative)
        }
        PathResolveMode::CanonicaliseAbsoluteValidateRelative => {
            let relative: PathBuf = if path.is_absolute() {
                let canonical = fs::canonicalize(&path)
                    .with_context(|| format!("File not found: {}", user_path))?;
                canonical
                    .strip_prefix(&canonical_root)
                    .with_context(|| {
                        format!(
                            "File is outside the repository: {} (resolves to {})",
                            user_path,
                            canonical.display()
                        )
                    })?
                    .to_path_buf()
            } else {
                validate_tracked_path(&path)
                    .with_context(|| format!("Invalid path: {}", user_path))?;
                path
            };
            if relative.as_os_str().is_empty() {
                anyhow::bail!(
                    "Cannot {} the repository root itself: {}",
                    root_verb,
                    user_path
                );
            }
            Ok(relative)
        }
        PathResolveMode::LexicalStripValidateRelative => {
            let relative: PathBuf = if path.is_absolute() {
                path.strip_prefix(&canonical_root)
                    .with_context(|| format!("File is outside the repository: {}", user_path))?
                    .to_path_buf()
            } else {
                validate_tracked_path(&path)
                    .with_context(|| format!("Invalid path: {}", user_path))?;
                path
            };
            if relative.as_os_str().is_empty() {
                anyhow::bail!(
                    "Cannot {} the repository root itself: {}",
                    root_verb,
                    user_path
                );
            }
            Ok(relative)
        }
    }
}

impl TrackedFiles {
    pub fn load(path: &PathBuf) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = fs::read_to_string(path).context("Failed to read tracked files")?;
        let tracked: TrackedFiles =
            serde_json::from_str(&content).context("Failed to parse tracked files JSON")?;
        for file in &tracked.files {
            validate_tracked_path(file)
                .with_context(|| format!("Invalid tracked file entry: {}", file.display()))?;
        }
        Ok(tracked)
    }

    pub fn save(&self, path: &PathBuf) -> Result<()> {
        let content =
            serde_json::to_string_pretty(self).context("Failed to serialize tracked files")?;
        write_atomic(path, content.as_bytes()).context("Failed to write tracked files")?;
        Ok(())
    }

    pub fn add(&mut self, file: PathBuf) {
        if !self.files.contains(&file) {
            self.files.push(file);
        }
    }

    pub fn remove(&mut self, file: &PathBuf) {
        self.files.retain(|f| f != file);
    }
}

/// Gets the email configured in git config user.email.
pub fn get_git_config_email(repo_root: &Path) -> Result<String> {
    let output = Command::new("git")
        .args(["config", "user.email"])
        .current_dir(repo_root)
        .output()
        .context("Failed to execute git config user.email")?;

    if !output.status.success() {
        anyhow::bail!("git config user.email is not set");
    }

    let email = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if email.is_empty() {
        anyhow::bail!("git config user.email is empty");
    }

    Ok(email)
}
