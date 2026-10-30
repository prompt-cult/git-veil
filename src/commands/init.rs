use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

use super::trust::{
    codeowners_notice, ensure_path_outside_repo, prove_possession, read_verifying_key_file,
    write_pin_state,
};
use crate::codeowners::{covers_trust_critical_paths, suggestion_text};
use crate::exit_codes::{coded, ExitCode};
use crate::fs_atomic::write_atomic;
use crate::{derive_repo_id, get_remote_push_url, Keyring, TrackedFiles, TrustStore};

/// `git-veil init <VERIFYING_KEY>`: creates the `.git-veil/` state
/// directory, copies the repo owner's verifying key in, and runs the pin
/// ceremony.
///
/// The verifying key file is read from OUTSIDE the repository (the trust
/// anchor travels in from outside, never through the repository itself)
/// and the possession proof runs before any state is written, so only a
/// machine holding the matching Ed25519 signing seed can init: the repo
/// owner's.
///
/// Creates the internal state directory `.git-veil/` with keyring,
/// trust.json, tracked.json and owner.verifying. It never touches
/// `.gitignore`: ciphertext is stored in place beside the plaintext as
/// `<name>.secret`, and those files are meant to be committed, so
/// gitignoring them would defeat the fresh-clone decryptability contract.
pub fn cmd_init(
    repo_root: &Path,
    verifying_key_path: &Path,
    remote_name: &str,
    key_store: &Path,
    quiet: bool,
    suppress_codeowners: bool,
) -> Result<()> {
    // The trust anchor travels in from outside the repository only, and
    // the possession proof runs before anything is written. A refusal
    // here leaves the worktree untouched.
    ensure_path_outside_repo(repo_root, verifying_key_path)?;
    let (verifying_key, verifying_key_hex, public_key) =
        read_verifying_key_file(verifying_key_path)?;
    let push_url = get_remote_push_url(repo_root, remote_name)?;
    let repo_id = derive_repo_id(&push_url)?;
    prove_possession(key_store, &verifying_key)?;

    let git_veil_dir = repo_root.join(".git-veil");

    // Fresh init only. A re-init over an established trust anchor would
    // silently destroy the user's trust.json and tracked-file manifest, so
    // refuse while real trust state exists. A `.git-veil/` directory with
    // an absent or empty trust.json is a degenerate half-initialised
    // state. Init proceeds in that case.
    let trust_path = git_veil_dir.join("trust.json");
    if git_veil_dir.is_dir() && trust_path.exists() {
        let existing_trust = TrustStore::load_from_file(&trust_path)
            .context("Failed to read existing trust.json")?;
        if !existing_trust.owner_fingerprints.is_empty() {
            return Err(coded(
                ExitCode::Refused,
                "git-veil is already initialized here; refusing to reset existing trust state \
                 remove .git-veil/ explicitly if you really want a fresh start",
            ));
        }
    }

    // Create the internal state directory
    fs::create_dir_all(&git_veil_dir).context("Failed to create .git-veil directory")?;

    // Create empty keyring
    let keyring = Keyring::new();
    let keyring_content = keyring.serialize();
    write_atomic(&git_veil_dir.join("keyring"), keyring_content.as_bytes())
        .context("Failed to create keyring file")?;

    // Create empty trust.json via the type's own API (single source of
    // truth for the on-disk format)
    TrustStore::default()
        .save_to_file(&git_veil_dir.join("trust.json"))
        .context("Failed to create trust.json")?;

    // Create empty tracked.json via the type's own API (single source of
    // truth for the on-disk format)
    TrackedFiles::default()
        .save(&git_veil_dir.join("tracked.json"))
        .context("Failed to create tracked.json")?;

    // Commit the owner verifying key into the state directory: line 1 is
    // the 64-hex Ed25519 verifying key, line 2 when present the owner's
    // X25519 public key encoding, exactly the shape every gated command
    // reads back.
    let mut owner_verifying = verifying_key_hex.clone();
    owner_verifying.push('\n');
    if let Some(public_key_str) = &public_key {
        owner_verifying.push_str(public_key_str);
        owner_verifying.push('\n');
    }
    write_atomic(
        &git_veil_dir.join("owner.verifying"),
        owner_verifying.as_bytes(),
    )
    .context("Failed to write .git-veil/owner.verifying")?;

    println!("git-veil initialized");

    // The pin ceremony: the owner fingerprint into the committed
    // trust.json, the pin into the key store, the ring freshness baseline
    // reset. The exact writes the owner's possession proof always required.
    write_pin_state(
        repo_root,
        key_store,
        &repo_id,
        &verifying_key,
        &verifying_key_hex,
        public_key,
        true,
    )?;

    // Suggest CODEOWNERS coverage for the trust-critical paths. Once, in
    // plain text, with opt-out via -q. Never a prompt, never a block.
    if !quiet && !covers_trust_critical_paths(repo_root) {
        println!("{}", suggestion_text());
    }
    codeowners_notice(repo_root, key_store, &repo_id, suppress_codeowners)
}
