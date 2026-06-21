use anyhow::{Context, Result};
use regex::Regex;
use std::path::PathBuf;
use std::process::Command;

/// Parses a git remote URL and extracts (repo_name, user_or_org, service).
///
/// Supports:
/// - GitHub SSH: `git@github.com:user/repo.git`
/// - GitHub HTTPS: `https://github.com/user/repo.git`
/// - GitLab SSH: `git@gitlab.com:org/project.git`
/// - GitLab HTTPS: `https://gitlab.com/org/project.git`
/// - Codeberg SSH: `ssh://git@codeberg.org/user/repo.git`
///
/// Returns error for invalid formats.
pub fn parse_git_remote_url(url: &str) -> Result<(String, String, String)> {
    // SSH SCP-style: git@github.com:user/repo.git
    let ssh_scp_re = Regex::new(r"^git@([^:]+):([^/]+)/([^/]+?)(\.git)?$")?;
    if let Some(caps) = ssh_scp_re.captures(url) {
        let service = caps[1].to_string();
        let user = caps[2].to_string();
        let repo = caps[3].to_string();
        return Ok((repo, user, service));
    }

    // SSH URL: ssh://git@codeberg.org/user/repo.git
    let ssh_url_re = Regex::new(r"^ssh://git@([^/]+)/([^/]+)/([^/]+?)(\.git)?$")?;
    if let Some(caps) = ssh_url_re.captures(url) {
        let service = caps[1].to_string();
        let user = caps[2].to_string();
        let repo = caps[3].to_string();
        return Ok((repo, user, service));
    }

    // HTTPS URL: https://github.com/user/repo.git
    let https_re = Regex::new(r"^https://([^/]+)/([^/]+)/([^/]+?)(\.git)?$")?;
    if let Some(caps) = https_re.captures(url) {
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
pub fn get_remote_push_url(repo_path: &PathBuf, remote_name: &str) -> Result<String> {
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
