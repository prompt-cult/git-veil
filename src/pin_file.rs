//! The pin-file: the out-of-band artefact that carries a repository's trust
//! anchor from a machine that holds the owner's signing key to one that does
//! not.
//!
//! Pins originate only on machines holding the signing key: `export-pin`
//! (which itself requires a possession proof) writes this file, and the
//! receiving machine runs `trust --import`. Both commands refuse any path
//! inside the repository worktree — an attacker with repo write access
//! could otherwise commit a bogus pin-file and have the victim import it —
//! so the transfer is forced out of band (e.g. ssh), and pin-file integrity
//! rides the transport, the same model as `known_hosts` provisioning.
//!
//! File format (exactly two lines, order fixed, UTF-8, `\n` terminated):
//!
//! ```text
//! repo-id: <repo_id>
//! verifying-key: <64-hex Ed25519 verifying key>
//! ```
//!
//! The fingerprint is NOT stored: it is derived with the single documented
//! derivation (src/fingerprint.rs — the repository id as the label, the
//! verifying key hex as the public key encoding) by whoever needs it, so
//! the file cannot disagree with itself.

use anyhow::{Context, Result};
use std::path::Path;

use crate::exit_codes::{coded, ExitCode};
use crate::fingerprint::owner_key_fingerprint;
use crate::signing::parse_verifying_key;
use crate::{derive_repo_id, get_remote_push_url};
use ed25519_dalek::VerifyingKey;

/// A parsed pin-file: the repository id and the owner's Ed25519 verifying
/// key (public half only — a pin-file never carries a seed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinFile {
    pub repo_id: String,
    pub verifying_key: VerifyingKey,
}

impl PinFile {
    /// Serialises to the two-line file format.
    pub fn serialize(&self) -> String {
        format!(
            "repo-id: {}\nverifying-key: {}\n",
            self.repo_id,
            hex::encode(self.verifying_key.to_bytes())
        )
    }

    /// Parses the two-line file format. Anything else — missing lines,
    /// unknown keys, duplicate keys, extra content — is a hard refusal
    /// (exit code 62), never a best-effort guess: a pin-file is a trust
    /// anchor, and a malformed one must never be half-trusted.
    pub fn parse(content: &str) -> Result<Self> {
        let mut repo_id: Option<String> = None;
        let mut verifying_key: Option<VerifyingKey> = None;
        for (index, line) in content.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let (key, value) = line.split_once(':').ok_or_else(|| {
                coded(
                    ExitCode::KeyParseFailure,
                    format!("pin file line {} is not a key and value line", index + 1),
                )
            })?;
            let key = key.trim();
            let value = value.trim();
            match key {
                "repo-id" => {
                    if repo_id.is_some() {
                        return Err(coded(
                            ExitCode::KeyParseFailure,
                            "pin-file carries a duplicate repo-id line",
                        ));
                    }
                    if value.is_empty() {
                        return Err(coded(
                            ExitCode::KeyParseFailure,
                            "pin-file carries an empty repo-id",
                        ));
                    }
                    repo_id = Some(value.to_string());
                }
                "verifying-key" => {
                    if verifying_key.is_some() {
                        return Err(coded(
                            ExitCode::KeyParseFailure,
                            "pin-file carries a duplicate verifying-key line",
                        ));
                    }
                    verifying_key = Some(parse_verifying_key(value)?);
                }
                _ => {
                    return Err(coded(
                        ExitCode::KeyParseFailure,
                        format!("pin file carries an unknown field {}", key),
                    ));
                }
            }
        }
        let repo_id = repo_id
            .ok_or_else(|| coded(ExitCode::KeyParseFailure, "pin-file has no repo-id line"))?;
        let verifying_key = verifying_key.ok_or_else(|| {
            coded(
                ExitCode::KeyParseFailure,
                "pin-file has no verifying-key line",
            )
        })?;
        Ok(Self {
            repo_id,
            verifying_key,
        })
    }

    /// The owner key fingerprint of the carried verifying key under the
    /// single derivation, with the carried repository id as the label —
    /// the token for pin-file/metadata cross-checks and human out-of-band
    /// verification.
    pub fn owner_fingerprint(&self) -> String {
        owner_key_fingerprint(&self.repo_id, &self.verifying_key)
    }
}

/// Reads and parses the pin-file at `path`.
pub fn load_pin_file(path: &Path) -> Result<PinFile> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read pin-file {}", path.display()))?;
    PinFile::parse(&content)
}

/// Writes the pin-file atomically to `path`.
pub fn write_pin_file(path: &Path, pin_file: &PinFile) -> Result<()> {
    crate::fs_atomic::write_atomic(path, pin_file.serialize().as_bytes())
        .with_context(|| format!("failed to write pin-file {}", path.display()))
}

/// Derives the repository id from the live remote, refusing a `repo_id`
/// argument that does not match it (exit code 13) — the shared gate of
/// `trust` and `export-pin`.
pub fn derive_and_check_repo_id(repo_root: &Path, remote_name: &str, repo_id: &str) -> Result<()> {
    let push_url = get_remote_push_url(repo_root, remote_name)?;
    let computed = derive_repo_id(&push_url)?;
    if repo_id != computed {
        return Err(coded(
            ExitCode::TrustRepoIdMismatch,
            "the provided repository id does not match the one derived from the remote",
        ));
    }
    Ok(())
}
