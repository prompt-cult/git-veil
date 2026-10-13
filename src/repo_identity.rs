use anyhow::{Context, Result};
use regex::Regex;
use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;
use std::sync::LazyLock;

/// SSH SCP-style: `user@host:owner/repo[.git][/][?]` - any SSH user (not just
/// `git`). The user part must not contain `/` so that scheme URLs like
/// `ssh://git@host:2222/...` are never mistaken for SCP-style URLs. The user,
/// host and owner/repo groups additionally exclude `@` and `:` (where shape
/// permits) so credential-shaped material can never land in the derived
/// repository id (fails closed instead).
static SSH_SCP_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[^@/]+@([^:/@]+):([^/@:]+)/([^/@:]+?)(?:\.git)?/?$")
        .expect("valid SCP-style SSH URL regex")
});

/// Scheme URL shared shape: `scheme://[user[:pass]@]host[:port]/owner/repo`.
/// The optional userinfo (`user[:pass]@`) is a login credential and is
/// stripped - it never becomes part of the repository id. The owner/repo
/// groups exclude `@` and `:` so credential-shaped material can never land
/// in the derived repository id (fails closed instead).
static SCHEME_USERINFO_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(ssh|git|https)://(?:[^/@]+@)?([^/:@]+)(?::\d+)?/([^/@:]+)/([^/@:]+?)(?:\.git)?/?$",
    )
    .expect("valid scheme URL regex")
});

/// Lowercases service, owner and repo so that `GitHub.com/Owner/Repo` and
/// `github.com/owner/repo` derive the same repository id.
fn normalize(repo: &str, owner: &str, service: &str) -> (String, String, String) {
    (
        repo.to_lowercase(),
        owner.to_lowercase(),
        service.to_lowercase(),
    )
}

/// Parses a git remote URL and extracts (repo_name, user_or_org, service).
///
/// All components are lowercased: one repository must yield one repo_id from
/// any supported URL shape.
///
/// Supports:
/// - GitHub SSH (SCP-style): `git@github.com:user/repo.git`
/// - Other SSH users (SCP-style): `deploy@host.tld:org/repo.git`,
///   `person@git.sr.ht:~person/repo.git`
/// - GitHub HTTPS: `https://github.com/user/repo.git`
/// - HTTPS with embedded credentials: `https://user@github.com/user/repo.git`,
///   `https://user:pass@github.com/user/repo.git` (credentials stripped,
///   never part of the repository id, never logged)
/// - GitLab SSH: `git@gitlab.com:org/project.git`
/// - GitLab HTTPS: `https://gitlab.com/org/project.git`
/// - Codeberg SSH: `ssh://git@codeberg.org/user/repo.git`
/// - git protocol: `git://github.com/owner/repo.git`
/// - Port forms (port discarded, service stays the bare host):
///   `ssh://git@codeberg.org:2222/user/repo.git`,
///   `https://host:8443/user/repo.git`, `git://host:9418/owner/repo.git`
/// - Trailing `.git` optional; trailing slashes tolerated
///
/// Returns error for invalid formats.
pub fn parse_git_remote_url(url: &str) -> Result<(String, String, String)> {
    if let Some(caps) = SSH_SCP_RE.captures(url) {
        let service = caps[1].to_string();
        let user = caps[2].to_string();
        let repo = caps[3].to_string();
        return Ok(normalize(&repo, &user, &service));
    }

    if let Some(caps) = SCHEME_USERINFO_RE.captures(url) {
        let service = caps[2].to_string();
        let user = caps[3].to_string();
        let repo = caps[4].to_string();
        return Ok(normalize(&repo, &user, &service));
    }

    // Never echo the failing URL: the user typed it, and echoing it risks
    // surfacing embedded credentials (redaction is shape-dependent and
    // cannot be made exhaustive). A fixed message carries no input material.
    anyhow::bail!("invalid git remote URL format. Expected a supported GitHub GitLab or Codeberg shape. See the trust documentation.")
}

/// Gets the push URL for a given remote from a git repository.
///
/// Runs `git -C <repo_path> remote get-url --push <remote_name>` and returns the URL.
pub fn get_remote_push_url(repo_path: &Path, remote_name: &str) -> Result<String> {
    let output = Command::new("git")
        .current_dir(repo_path)
        .args(["remote", "get-url", "--push", remote_name])
        .output()
        .context("Failed to execute git remote get-url")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("git remote get-url failed: {}", stderr.trim());
    }

    let url = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if url.is_empty() {
        anyhow::bail!("No push URL found for the requested remote");
    }

    Ok(url)
}

/// Derives a repository ID from a push URL in the format `{repo}+{user}@{service}`.
///
/// Example: `git@github.com:simbo1905/fara.git` → `fara+simbo1905@github.com`
pub fn derive_repo_id(push_url: &str) -> Result<String> {
    let (repo, user, service) = parse_git_remote_url(push_url)?;
    Ok(format!("{}+{}@{}", repo, user, service))
}

/// Derives the repository id of every configured remote's push URL
/// (`git remote --verbose`): the set of repository ids this checkout
/// currently points at - one id per remote, so a multi-remote repository
/// contributes one entry per remote.
///
/// The `(push)` lines carry the effective push URLs (the pushurl when
/// set, url rewriting applied). A remote with no fetch URL also prints a
/// bare `name` line with no URL; bare lines and push URLs with no
/// supported shape are skipped - trust records only ever hold ids derived
/// from supported shapes, so such a remote cannot correspond to any
/// recorded entry.
pub fn derive_configured_repo_ids(repo_path: &Path) -> Result<BTreeSet<String>> {
    let output = Command::new("git")
        .current_dir(repo_path)
        .args(["remote", "--verbose"])
        .output()
        .context("failed to enumerate the configured remotes")?;

    if !output.status.success() {
        anyhow::bail!("failed to enumerate the configured remotes");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut ids = BTreeSet::new();
    for line in stdout.lines() {
        // `name<TAB>url (push)`; multiple pushurls print one line each.
        let Some(head) = line.strip_suffix(" (push)") else {
            continue;
        };
        let mut fields = head.split_whitespace();
        let _name = fields.next();
        let Some(url) = fields.next() else {
            continue;
        };
        if let Ok(id) = derive_repo_id(url) {
            ids.insert(id);
        }
    }
    Ok(ids)
}
