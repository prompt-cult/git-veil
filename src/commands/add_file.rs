use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::process::Command;

use crate::allowance::AllowanceStore;
use crate::commands::allow::resolve_allowance_anchor;
use crate::fs_atomic::write_atomic;
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
        let normalized = normalize_separators(&relative_str);
        ensure_gitignored(repo_root, &normalized)?;
        let secret_relative = format!("{}.secret", normalized);
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
        (true, Some(content)) => write_gitignore(path, &content),
        (true, None) => write_gitignore(path, ""),
        (false, _) if path.exists() => std::fs::remove_file(path)
            .with_context(|| "Failed to remove a newly created .gitignore".to_string()),
        _ => Ok(()),
    }
}
/// Reads .gitignore, distinguishing an absent file from a read error.
/// A missing file is the only empty baseline. Any other read error is
/// reported unchanged, so a successful command cannot synthesize an
/// empty file after losing contact with the real rules.
fn read_gitignore(path: &Path) -> Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(content) => Ok(Some(content)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| "Failed to read .gitignore".to_string()),
    }
}
/// Writes .gitignore through the same crash-safe helper as every other
/// durable state file.
fn write_gitignore(path: &Path, content: &str) -> Result<()> {
    write_atomic(path, content.as_bytes()).with_context(|| "Failed to write .gitignore".to_string())
}

fn output_status_message(context: &str, output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stderr = stderr.trim();
    let code = output.status.code().unwrap_or(-1);
    if stderr.is_empty() {
        format!("{context}: unexpected git exit {code}")
    } else {
        format!("{context}: unexpected git exit {code}: {stderr}")
    }
}

/// Runs `git check-ignore` for one repo-relative path: true when git
/// ignores it. Git’s documented status 1 is a negative answer; every
/// other status is a hard error. The two-sided gate uses this shared
/// implementation so the answer cannot drift apart.
pub(crate) fn is_gitignored(repo_root: &Path, relative_path: &str) -> Result<bool> {
    let output = Command::new("git")
        .current_dir(repo_root)
        .args(["check-ignore", "--"])
        .arg(relative_path)
        .output()
        .context("Failed to run git check-ignore")?;

    match output.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => anyhow::bail!("{}", output_status_message("git check-ignore", &output)),
    }
}

/// True when the repo-relative path is tracked in the git index, staged
/// or committed. Shared by reveal’s tracked-plaintext
/// refusal (exit 43, docs/src/design.md "Ignore safety" gate 4). The
/// exact check uses literal pathspecs, so names containing `:` cannot
/// be reinterpreted as pathspec selectors.
///
/// A git-tracked plaintext is ordinary repository content, not a
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
pub(crate) fn is_tracked_in_git(repo_root: &Path, relative_path: &Path) -> Result<bool> {
    let exact = Command::new("git")
        .current_dir(repo_root)
        .args(["--literal-pathspecs", "ls-files", "--error-unmatch", "--"])
        .arg(relative_path)
        .output()
        .context("Failed to run git ls-files")?;
    match exact.status.code() {
        Some(0) => return Ok(true),
        Some(1) => {}
        _ => anyhow::bail!("{}", output_status_message("git ls-files", &exact)),
    }

    // Case-insensitive fallback over the full index listing.
    let fallback = Command::new("git")
        .current_dir(repo_root)
        .args(["--literal-pathspecs", "ls-files", "-z"])
        .output()
        .context("Failed to run git ls-files")?;
    match fallback.status.code() {
        Some(0) | Some(1) => {}
        _ => anyhow::bail!("{}", output_status_message("git ls-files", &fallback)),
    }

    let wanted = relative_path.to_string_lossy();
    Ok(fallback
        .stdout
        .split(|byte| *byte == 0)
        .any(|entry| entry.eq_ignore_ascii_case(wanted.as_bytes())))
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

/// Normalises a repo-relative path to the `/` separator git expects.
///
/// On Windows a `PathBuf` formats with `\` separators; git's ignore
/// engine and pathspecs only understand `/`. Everything git-veil hands
/// to git — the literal ignore rule, check-ignore verification, index
/// lookups — must use `/` so the written rule matches the path git sees.
pub(crate) fn normalize_separators(relative_path: &str) -> String {
    #[cfg(windows)]
    {
        relative_path.replace('\\', "/")
    }
    #[cfg(not(windows))]
    {
        relative_path.to_string()
    }
}
#[cfg(unix)]
fn gitignore_lock(repo_root: &Path) -> Result<std::fs::File> {
    use std::os::unix::io::AsRawFd as _;

    let canonical = repo_root.canonicalize().with_context(|| {
        "Failed to canonicalise the repository root for the .gitignore lock".to_string()
    })?;
    let digest = Sha256::digest(canonical.display().to_string().as_bytes());
    let lock_path = std::env::temp_dir().join(format!("git-veil-gitignore-{digest:x}.lock"));
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&lock_path)
        .with_context(|| "Failed to open the .gitignore lock".to_string())?;

    let locked = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if locked == -1 {
        anyhow::bail!("Failed to lock .gitignore");
    }

    Ok(file)
}

#[cfg(not(unix))]
#[allow(dead_code)]
fn gitignore_lock(_repo_root: &Path) -> Result<()> {
    Ok(())
}

fn with_gitignore_lock<T>(repo_root: &Path, action: impl FnOnce() -> Result<T>) -> Result<T> {
    let _guard = gitignore_lock(repo_root)?;
    action()
}

/// Checks if a file is gitignored. If not, appends a literal Git rule
/// and verifies that Git ignored the path before reporting success.
fn ensure_gitignored(repo_root: &Path, relative_path: &str) -> Result<()> {
    let normalized = normalize_separators(relative_path);
    with_gitignore_lock(repo_root, || {
        if !is_gitignored(repo_root, &normalized)? {
            let gitignore_path = repo_root.join(".gitignore");
            let original = read_gitignore(&gitignore_path)?;
            let mut content = original.clone().unwrap_or_default();
            if !content.ends_with("\n") && !content.is_empty() {
                content.push('\n');
            }
            content.push_str(&literal_gitignore_rule(&normalized));
            content.push('\n');
            write_gitignore(&gitignore_path, &content)?;
            if !is_gitignored(repo_root, &normalized)? {
                restore_gitignore(&gitignore_path, original.clone(), original.is_some())?;
                anyhow::bail!(
                    "git check-ignore did not confirm the literal .gitignore rule for {}",
                    relative_path
                );
            }
            println!("file not in .gitignore, adding: {}", relative_path);
        }
        Ok(())
    })
}
#[cfg(test)]
mod normalize_tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn normalize_separators_replaces_backslashes() {
        assert_eq!(
            normalize_separators(r"config\secrets.yml"),
            "config/secrets.yml"
        );
        assert_eq!(normalize_separators("a\\b\\c"), "a/b/c");
        assert_eq!(normalize_separators("no-slash"), "no-slash");
        assert_eq!(normalize_separators(""), "");
    }

    #[cfg(not(windows))]
    #[test]
    fn normalize_separators_is_identity_on_unix() {
        assert_eq!(
            normalize_separators("config/secrets.yml"),
            "config/secrets.yml"
        );
        assert_eq!(
            normalize_separators(r"config\secrets.yml"),
            r"config\secrets.yml"
        );
        assert_eq!(normalize_separators(""), "");
    }
}

#[cfg(unix)]
#[cfg(test)]
mod git_gate_tests {
    use super::*;
    use serial_test::serial;
    use std::os::unix::fs::PermissionsExt;

    /// Run a local copy of git in a temp repo with PATH overridden to a
    /// directory that contains a fake git with a selected exit code.
    /// This isolates the tests from the git binary on the host while
    /// exercising exactly the output status the gates care about.
    fn run_with_git(exit: i32) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("git");
        std::fs::write(&script, format!("#!/bin/sh\nexit {}\n", exit)).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::env::set_var("PATH", dir.path());
        dir
    }

    #[test]
    #[serial]
    fn gitignore_errors_are_not_negative_answers() {
        let dir = run_with_git(2);
        let result = is_gitignored(dir.path(), "not-ignored");
        assert!(result.is_err(), "unexpected git status must be an error");
    }

    #[test]
    #[serial]
    fn gitignore_status_one_is_a_negative_answer() {
        let dir = run_with_git(1);
        let result = is_gitignored(dir.path(), ":literal-name").unwrap();
        assert!(!result);
    }

    #[test]
    #[serial]
    fn index_errors_are_not_negative_answers() {
        let dir = run_with_git(2);
        let result = is_tracked_in_git(dir.path(), Path::new("not-tracked"));
        assert!(result.is_err(), "unexpected git status must be an error");
    }

    #[test]
    #[serial]
    fn index_status_one_is_a_negative_answer() {
        let dir = run_with_git(1);
        let result = is_tracked_in_git(dir.path(), Path::new(":literal-name")).unwrap();
        assert!(!result);
    }
}
