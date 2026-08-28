use anyhow::{Context, Result};
use regex::Regex;
use std::path::Path;
use std::process::Command;
use std::sync::LazyLock;

/// SSH SCP-style: `user@host:owner/repo[.git][/][?]` — any SSH user (not just
/// `git`). The user part must not contain `/` so that scheme URLs like
/// `ssh://git@host:2222/...` are never mistaken for SCP-style URLs. The user
/// and owner/repo groups additionally exclude `@` and `:` so credential-shaped
/// material can never land in the derived identity (fails closed instead).
static SSH_SCP_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[^@/]+@([^:/]+):([^/@:]+)/([^/@:]+?)(?:\.git)?/?$")
        .expect("valid SCP-style SSH URL regex")
});

/// Scheme URL shared shape: `scheme://[user[:pass]@]host[:port]/owner/repo`.
/// The optional userinfo (`user[:pass]@`) is a login credential and is
/// stripped — it never becomes part of the identity. The owner/repo groups
/// exclude `@` and `:` so credential-shaped material can never land in the
/// derived identity (fails closed instead).
static SCHEME_USERINFO_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(ssh|git|https)://(?:[^/@]+@)?([^/:@]+)(?::\d+)?/([^/@:]+)/([^/@:]+?)(?:\.git)?/?$")
        .expect("valid scheme URL regex")
});

/// Strips `user[:pass]@` credentials from a scheme URL so that failed parses
/// can be reported without ever logging credentials.
static REDACT_USERINFO_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^([a-zA-Z][a-zA-Z0-9+.-]*://)[^/@]+@").expect("valid userinfo redaction regex")
});

/// Redacts credentials from a URL for safe display in error messages.
fn redact_url(url: &str) -> String {
    REDACT_USERINFO_RE.replace(url, "${1}***@").into_owned()
}

/// Lowercases service, owner and repo so that `GitHub.com/Owner/Repo` and
/// `github.com/owner/repo` are the same repository identity.
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
///   never part of the identity, never logged)
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

    anyhow::bail!("Invalid git remote URL format: {}", redact_url(url))
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
