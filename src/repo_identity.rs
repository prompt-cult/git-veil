use anyhow::{Context, Result};
use regex::Regex;
use std::path::Path;
use std::process::Command;
use std::sync::LazyLock;

/// SSH SCP-style: `user@host:owner/repo[.git]` — any SSH user (not just `git`).
/// The user part must not contain `/` so that scheme URLs like
/// `ssh://git@host:2222/...` are never mistaken for SCP-style URLs.
static SSH_SCP_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[^@/]+@([^:]+):([^/]+)/([^/]+?)(\.git)?$").expect("valid SCP-style SSH URL regex")
});

/// SSH URL: `ssh://[user@]host[:port]/owner/repo[.git]` — a `:port` suffix is
/// discarded so the service is always the bare host.
static SSH_URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^ssh://git@([^/:]+)(?::\d+)?/([^/]+)/([^/]+?)(\.git)?$").expect("valid ssh:// URL regex")
});

/// HTTPS URL: `https://host[:port]/owner/repo[.git]` — a `:port` suffix is
/// discarded so the service is always the bare host.
static HTTPS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^https://([^/:]+)(?::\d+)?/([^/]+)/([^/]+?)(\.git)?$").expect("valid https:// URL regex")
});

/// Parses a git remote URL and extracts (repo_name, user_or_org, service).
///
/// Supports:
/// - GitHub SSH (SCP-style): `git@github.com:user/repo.git`
/// - Other SSH users (SCP-style): `deploy@host.tld:org/repo.git`,
///   `person@git.sr.ht:~person/repo.git`
/// - GitHub HTTPS: `https://github.com/user/repo.git`
/// - GitLab SSH: `git@gitlab.com:org/project.git`
/// - GitLab HTTPS: `https://gitlab.com/org/project.git`
/// - Codeberg SSH: `ssh://git@codeberg.org/user/repo.git`
/// - Port forms (port discarded, service stays the bare host):
///   `ssh://git@codeberg.org:2222/user/repo.git`,
///   `https://host:8443/user/repo.git`
///
/// Returns error for invalid formats.
pub fn parse_git_remote_url(url: &str) -> Result<(String, String, String)> {
    if let Some(caps) = SSH_SCP_RE.captures(url) {
        let service = caps[1].to_string();
        let user = caps[2].to_string();
        let repo = caps[3].to_string();
        return Ok((repo, user, service));
    }

    if let Some(caps) = SSH_URL_RE.captures(url) {
        let service = caps[1].to_string();
        let user = caps[2].to_string();
        let repo = caps[3].to_string();
        return Ok((repo, user, service));
    }

    if let Some(caps) = HTTPS_RE.captures(url) {
        let service = caps[1].to_string();
        let user = caps[2].to_string();
        let repo = caps[3].to_string();
        return Ok((repo, user, service));
    }

    anyhow::bail!("Invalid git remote URL format: {}", url)
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
        anyhow::bail!("No push URL found for remote '{}'", remote_name);
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
