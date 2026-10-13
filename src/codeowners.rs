//! CODEOWNERS coverage for the trust-critical paths (issue #27).
//!
//! CODEOWNERS is a platform feature, not a git feature: plain git ignores
//! the file. Where the platform enforces it, a write-access attacker's
//! rekey of the trust anchor becomes a review-gated change instead of a
//! silent push. The tool suggests (init) and warns (trust); it never
//! requires, never creates the file, and never alters an exit code.
//!
//! Pattern matching reuses the gitignore matcher (gix-ignore): CODEOWNERS
//! patterns are a subset of gitignore, and the matcher answers exactly the
//! question asked here — does any pattern cover these paths, last match
//! wins. Owner strings are not validated; that is the platform's job.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

use crate::trust_store::TrustPinStore;

/// CODEOWNERS locations in platform precedence order: the repository root,
/// then the per-platform directories (GitHub, GitLab, Bitbucket, Gitea,
/// Forgejo). The first file found in this order is the one evaluated.
pub const CODEOWNERS_LOCATIONS: [&str; 7] = [
    "CODEOWNERS",
    ".github/CODEOWNERS",
    "docs/CODEOWNERS",
    ".gitlab/CODEOWNERS",
    ".gitea/CODEOWNERS",
    ".forgejo/CODEOWNERS",
    ".bitbucket/CODEOWNERS",
];

/// The key store file recording repositories whose CODEOWNERS warning is
/// suppressed (one sanitized repository id per line).
fn suppression_path(key_store: &Path) -> PathBuf {
    key_store.join("codeowners-suppression")
}

/// The first CODEOWNERS file that exists, in platform precedence order.
pub fn find(repo_root: &Path) -> Option<PathBuf> {
    for location in CODEOWNERS_LOCATIONS {
        let candidate = repo_root.join(location);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Whether any pattern in the CODEOWNERS content covers `path`, last match
/// wins. A final negated match counts as not covered (a file with
/// negation lines is not valid CODEOWNERS, but the matcher answers the
/// gitignore semantics honestly rather than guessing intent).
fn content_covers(content: &[u8], path: &str, is_dir: bool) -> bool {
    use bstr::ByteSlice;
    let rel_path = bstr::BString::from(path);
    let rel_path = rel_path.as_bstr();
    let basename_pos = rel_path.rfind(b"/").map(|p| p + 1);
    let patterns_only = pattern_tokens_only(content);
    let mut covered = false;
    for (pattern, _line_no, _kind) in gix_ignore::parse(patterns_only.as_slice(), false) {
        if pattern.matches_repo_relative_path(
            rel_path,
            basename_pos,
            Some(is_dir),
            gix_glob::pattern::Case::Sensitive,
            gix_glob::wildmatch::Mode::NO_MATCH_SLASH_LITERAL,
        ) {
            covered = !pattern.is_negative();
        }
    }
    covered
}

/// Whether a found CODEOWNERS file covers both trust-critical paths: the
/// committed owner verifying key and the `.git-veil/` directory (a pattern
/// matching a representative file inside the directory also counts —
/// gitignore patterns may name files rather than the directory itself).
pub fn covers_trust_critical_paths(repo_root: &Path) -> bool {
    let Some(codeowners) = find(repo_root) else {
        return false;
    };
    let Ok(content) = std::fs::read(&codeowners) else {
        return false;
    };
    let key_covered = content_covers(&content, "owner.verifying", false);
    let dir_covered = content_covers(&content, ".git-veil", true)
        || content_covers(&content, ".git-veil/tracked.json", false);
    key_covered && dir_covered
}

/// The init suggestion: which paths to protect and what to add. Printed
/// only by a non-quiet `init`; the tool never creates the file.
pub fn suggestion_text() -> String {
    "suggestion: protect the trust-critical paths with a CODEOWNERS file so changes to the trust anchor are review gated on the platform\n\
     add a CODEOWNERS file at the repository root, or under the platform directory, and give the trust-critical paths an owner, for example:\n\
     owner.verifying @the-repository-owner\n\
     .git-veil/ @the-repository-owner"
        .to_string()
}

/// The trust warning: the pin succeeded, but the platform will not
/// review-gate a trust-anchor change. Non-blocking: never an error, never
/// an exit code change.
pub fn warning_text() -> String {
    "warning: no CODEOWNERS file covers owner.verifying and the .git-veil directory. Trust anchor changes are not review gated on the platform."
        .to_string()
}

/// Whether the CODEOWNERS warning is suppressed for this repository: the
/// key store records suppressed repository ids per pinned repo.
pub fn is_suppressed(key_store: &Path, repo_id: &str) -> bool {
    let path = suppression_path(key_store);
    let sanitized = TrustPinStore::sanitize_repo_id(repo_id);
    std::fs::read_to_string(&path)
        .map(|content| content.lines().any(|line| line.trim() == sanitized))
        .unwrap_or(false)
}

/// Records the suppression for this repository, next to the pin in the key
/// store. Only the pin-creation command calls this: the suppression is
/// bound to the possession proof (or import) that created the pin.
pub fn record_suppression(key_store: &Path, repo_id: &str) -> Result<()> {
    let path = suppression_path(key_store);
    let sanitized = TrustPinStore::sanitize_repo_id(repo_id);
    std::fs::create_dir_all(key_store)?;
    let mut existing = if path.exists() {
        std::fs::read_to_string(&path)?
    } else {
        String::new()
    };
    if existing.lines().any(|line| line.trim() == sanitized) {
        return Ok(());
    }
    if !existing.is_empty() && !existing.ends_with('\n') {
        existing.push('\n');
    }
    existing.push_str(&sanitized);
    existing.push('\n');
    crate::fs_atomic::write_atomic(&path, existing.as_bytes())
        .context("Failed to record the CODEOWNERS suppression in the key store")
}

/// CODEOWNERS separates the pattern from its owner list with whitespace;
/// gitignore patterns cannot contain unescaped spaces, so the pattern is
/// the first whitespace-delimited token of each line. Comments and blanks
/// are dropped. The tokens are re-fed to the gitignore matcher one per
/// line.
fn pattern_tokens_only(content: &[u8]) -> Vec<u8> {
    use bstr::ByteSlice;
    let mut out: Vec<u8> = Vec::with_capacity(content.len());
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(b"#") {
            continue;
        }
        let token_end = line
            .find_byte(b' ')
            .unwrap_or(line.find_byte(b'\t').unwrap_or(line.len()))
            .min(line.find_byte(b'\t').unwrap_or(line.len()));
        if token_end == 0 {
            continue;
        }
        out.extend_from_slice(&line[..token_end]);
        out.push(b'\n');
    }
    out
}
