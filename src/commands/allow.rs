use anyhow::{Context, Result};
use std::path::Path;

use crate::allowance::AllowanceStore;
use crate::commands::add::is_gitignored;
use crate::exit_codes::{coded, ExitCode};
use crate::fingerprint::is_16_hex_pin_shape;
use crate::tracked_files::{get_git_config_email, resolve_repo_relative_input, PathResolveMode};
use crate::{derive_repo_id, get_remote_push_url, TrustPinStore};

/// Resolves the allowance context shared by allow and add-implies-allow:
/// the repository id derived from the remote and this machine's pin
/// fingerprint for it. The allowance record is anchored by the pin, so
/// both refuse until trust is established on this machine.
pub(crate) fn resolve_allowance_anchor(
    repo_root: &Path,
    remote_name: &str,
    key_store: &Path,
) -> Result<(String, String)> {
    let push_url = get_remote_push_url(repo_root, remote_name)?;
    let repo_id = derive_repo_id(&push_url)?;
    let pin = match TrustPinStore::read_pin(key_store, &repo_id)? {
        Some(pin) if !is_16_hex_pin_shape(&pin) => pin,
        Some(_) => {
            return Err(coded(
                ExitCode::Refused,
                "a trust pin in the 16 hex character fingerprint format was found. The fingerprint is SHA-256 over the label, a colon, and the public key encoding, printed as 64 lowercase hex characters. Re-establish the pin as described in the trust documentation.".to_string(),
            ))
        }
        None => {
            return Err(coded(
                ExitCode::NoTrustPin,
                format!(
                    "no trust pin exists on this machine for repository identity {repo_id} \
                     derived from remote {remote_name}. See the trust documentation."
                ),
            ))
        }
    };
    Ok((repo_id, pin))
}

/// Records files as allowed for encryption on this machine.
///
/// Paths are resolved exactly like add: the file must exist, canonicalise
/// inside the repository, and is stored repo-relative. The record lives in
/// the key store, keyed by the trust pin and the principal from git config
/// user.email. hide refuses to first-encrypt a tracked path that was never
/// allowed on this machine.
pub fn cmd_allow(
    repo_root: &Path,
    files: Vec<String>,
    remote_name: &str,
    key_store: &Path,
) -> Result<()> {
    let (repo_id, pin) = resolve_allowance_anchor(repo_root, remote_name, key_store)?;
    let principal = get_git_config_email(repo_root).context(
        "allow records the consent of a principal, which needs your git config user.email",
    )?;

    let mut count = 0;
    for file in &files {
        let relative = resolve_repo_relative_input(
            repo_root,
            file,
            PathResolveMode::CanonicaliseRequireExists,
            "allow",
        )?;

        // The same heads-up add gives: a ciphertext swallowed by a broad
        // ignore rule would never reach the repository. Hide refuses
        // outright before encrypting.
        let secret_relative = format!("{}.secret", relative.to_string_lossy());
        if is_gitignored(repo_root, &secret_relative)? {
            println!(
                "warning: a ciphertext path is git-ignored with error code 40 so it will never reach the repository. Fix .gitignore before hiding"
            );
        }

        AllowanceStore::record(key_store, &repo_id, &pin, &principal, &relative)?;
        count += 1;
    }

    println!("allowed {} files", count);
    Ok(())
}
