//! Pin creation (issue #28): possession proof is the ONLY way to create a
//! pin directly, and the keyfile argument is gone — a repository must never
//! be able to supply its own trust anchor.
//!
//! Two pin-creation paths exist, and nothing else:
//!
//! 1. `git-veil trust <repo_id>` — possession proof. The candidate is the
//!    repository's committed `owner.verifying`; the proof is an exact match
//!    between that candidate and the verifying key derived from a seed in
//!    the signing key store (`<key store>/signing-keys.txt`). A machine
//!    without the matching seed cannot pin.
//! 2. `git-veil trust --import <pin-file>` — a pin-file produced by
//!    `git-veil export-pin` on a machine that DID prove possession. Three
//!    mandatory consistency checks tie the pin-file to the repository's
//!    committed key and metadata; any mismatch is a refusal.
//!
//! Both commands refuse paths inside the repository worktree, so a bogus
//! pin-file cannot travel through the repository itself.

use anyhow::{Context, Result};
use ed25519_dalek::VerifyingKey;
use std::fs;
use std::path::Path;

use crate::exit_codes::{coded, ExitCode};
use crate::key_discovery::load_signing_keys;
use crate::pin_file::load_pin_file;
use crate::signing::{owner_fingerprint_for_verifying_key, parse_verifying_key};
use crate::{
    derive_repo_id, fingerprint_for_verifying_key, get_remote_push_url, import_recipient_to_store,
    TrustPinStore, TrustStore,
};

/// The repository's committed owner verifying key: line 1 is the 64-hex
/// Ed25519 verifying key; line 2, when present, is the owner's age
/// recipient string (imported into the key store as a convenience).
pub(crate) const OWNER_VERIFYING: &str = "owner.verifying";

/// Reads and parses the repository's committed `owner.verifying`.
///
/// Returns the verifying key, its hex form, and the optional age recipient
/// from the second line.
pub(crate) fn read_owner_verifying(
    repo_root: &Path,
) -> Result<(VerifyingKey, String, Option<String>)> {
    let path = repo_root.join(OWNER_VERIFYING);
    let content = fs::read_to_string(&path).map_err(|_| {
        coded(
            ExitCode::Refused,
            format!(
                "this repository has no {} file; the owner must create and commit it (see docs/solo.md)",
                OWNER_VERIFYING
            ),
        )
    })?;
    let mut lines = content.lines();
    let verifying_key_hex = lines
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            coded(
                ExitCode::KeyParseFailure,
                format!("{} is empty", OWNER_VERIFYING),
            )
        })?;
    let verifying_key = parse_verifying_key(verifying_key_hex)?;
    let recipient = lines
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty() && s.starts_with("age1"))
        .map(String::from);
    Ok((verifying_key, verifying_key_hex.to_string(), recipient))
}

/// The possession proof: the signing key store must hold a seed whose
/// derived verifying key exactly matches `candidate`.
///
/// All seeds are iterated; exactly one match pins, zero matches refuse
/// with the no-match error, and more than one (a degenerate duplicated
/// store) refuses on ambiguity rather than picking.
pub(crate) fn prove_possession(key_store: &Path, candidate: &VerifyingKey) -> Result<()> {
    let seeds = load_signing_keys(key_store)?;
    let matches: Vec<_> = seeds
        .iter()
        .filter(|seed| seed.verifying_key() == *candidate)
        .collect();
    match matches.len() {
        0 => Err(coded(
            ExitCode::NoSigningKey,
            "no local signing key matches this repository's owner key; pins are created only on machines holding the signing key — import a pin-file (git-veil trust --import) elsewhere",
        )),
        1 => Ok(()),
        _ => Err(coded(
            ExitCode::Refused,
            format!(
                "{} signing keys in {} match this repository's owner key; the match is ambiguous — remove the duplicate seeds",
                matches.len(),
                key_store.display()
            ),
        )),
    }
}

/// Appends the verifying key to `<key store>/verifying-keys.txt`, where
/// `verify-keyring` later loads the pinned key by fingerprint.
pub(crate) fn append_verifying_key_to_store(
    key_store: &Path,
    verifying_key_hex: &str,
) -> Result<()> {
    let verifying_keys_path = key_store.join("verifying-keys.txt");
    fs::create_dir_all(key_store).context("Failed to create key store directory")?;
    let mut existing = if verifying_keys_path.exists() {
        fs::read_to_string(&verifying_keys_path)?
    } else {
        String::new()
    };
    if !existing.is_empty() && !existing.ends_with('\n') {
        existing.push('\n');
    }
    existing.push_str(verifying_key_hex);
    existing.push('\n');
    crate::fs_atomic::write_atomic(&verifying_keys_path, existing.as_bytes())
        .context("Failed to write verifying-keys.txt")?;
    Ok(())
}

/// Refuses (exit code 71) when `path` resolves inside the repository
/// worktree. Pin-files must travel out of band: an attacker with repo write
/// access could otherwise commit a bogus pin-file (import) or sweep one
/// into a commit (export), and without a pin the tool refuses all other
/// operations, so the pin cannot travel through git-veil's own tracked-file
/// mechanism either.
///
/// The check resolves symlinks: a link pointing into the repo from outside
/// is still inside.
pub(crate) fn ensure_path_outside_repo(repo_root: &Path, path: &Path) -> Result<()> {
    let repo_canonical = repo_root
        .canonicalize()
        .context("Failed to resolve repository root")?;
    // The path may not exist yet (export writes it): canonicalise the
    // deepest existing ancestor, then re-attach the remaining components.
    let mut probe = path.to_path_buf();
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    while !probe.exists() {
        match probe.parent() {
            Some(parent) => {
                tail.push(probe.file_name().expect("non-root path").to_os_string());
                probe = parent.to_path_buf();
            }
            None => break,
        }
    }
    let mut resolved = probe.canonicalize().context("Failed to resolve path")?;
    for component in tail.iter().rev() {
        resolved.push(component);
    }
    if resolved.starts_with(&repo_canonical) {
        return Err(coded(
            ExitCode::UnsafePath,
            format!(
                "refusing a pin-file path inside the repository ({}); pin-files must travel out of band — e.g. ssh — never through the repository itself",
                resolved.display()
            ),
        ));
    }
    Ok(())
}

/// Writes the trust state shared by both pin-creation paths: the verifying
/// key into the key store, the committed trust record, the per-machine pin,
/// and a reset of the keyring freshness baseline (re-pinning is the
/// documented recovery for an intended keyring rollback, so the baseline
/// must not outlive the ceremony).
fn write_pin_state(
    repo_root: &Path,
    key_store: &Path,
    repo_id: &str,
    verifying_key: &VerifyingKey,
    verifying_key_hex: &str,
    recipient: Option<String>,
    record_owner_fingerprint: bool,
) -> Result<()> {
    if let Some(recipient_str) = recipient {
        import_recipient_to_store(key_store, &recipient_str)?;
    }

    append_verifying_key_to_store(key_store, verifying_key_hex)?;

    let fingerprint = fingerprint_for_verifying_key(verifying_key);

    // Re-trust visibility: if a pin already exists for this repo and names
    // a DIFFERENT fingerprint, this machine's record of the repository's
    // trust anchor is about to CHANGE — say so loudly before rewriting it.
    if let Some(previous) = TrustPinStore::read_pin(key_store, repo_id)? {
        if !previous.eq_ignore_ascii_case(&fingerprint) {
            println!(
                "replacing the previously pinned fingerprint {} for {} with {}",
                previous, repo_id, fingerprint
            );
        }
    }

    // Update the committed trust record. Ordering invariant: trust.json is
    // written BEFORE the pin. verify compares the committed trust.json
    // fingerprint against this pin and fails closed on a missing or
    // mismatched pin, so if the process dies between the two writes the
    // result is fail-closed (mismatch), never a state where a changed
    // anchor verifies without an explicit re-pin.
    let trust_path = repo_root.join(".git-veil/trust.json");
    let mut trust_store = TrustStore::load_from_file(&trust_path)?;
    trust_store.add_trust(repo_id.to_string(), fingerprint.clone());
    if record_owner_fingerprint {
        trust_store.set_owner_fingerprint(
            repo_id.to_string(),
            owner_fingerprint_for_verifying_key(verifying_key),
        );
    }
    trust_store.save_to_file(&trust_path)?;

    // Pin the fingerprint on this machine, outside the repo: trust.json is
    // committed (attacker-writable), so the local pin is the real anchor.
    TrustPinStore::write_pin(key_store, repo_id, &fingerprint)
        .context("Failed to write local trust pin")?;

    TrustPinStore::clear_ring_version(key_store, repo_id)
        .context("Failed to reset keyring freshness baseline")?;

    println!("Trusted key for {} (fingerprint: {})", repo_id, fingerprint);
    println!("Pinned {} for {} on this machine", fingerprint, repo_id);
    Ok(())
}

/// `git-veil trust <repo_id>`: pin the repository's owner key by proving
/// possession of the matching signing seed.
pub fn cmd_trust(
    repo_root: &Path,
    repo_id: &str,
    remote_name: &str,
    key_store: &Path,
) -> Result<()> {
    let push_url = get_remote_push_url(repo_root, remote_name)?;
    let computed_repo_id = derive_repo_id(&push_url)?;
    if repo_id != computed_repo_id {
        return Err(coded(
            ExitCode::TrustRepoIdMismatch,
            format!(
                "Repository ID mismatch: provided '{}' does not match computed '{}'",
                repo_id, computed_repo_id
            ),
        ));
    }

    // The candidate is the repository's committed owner.verifying — never
    // an argument. The proof: a seed in the signing key store derives to
    // exactly this key.
    let (verifying_key, verifying_key_hex, recipient) = read_owner_verifying(repo_root)?;
    prove_possession(key_store, &verifying_key)?;

    write_pin_state(
        repo_root,
        key_store,
        repo_id,
        &verifying_key,
        &verifying_key_hex,
        recipient,
        true,
    )
}

/// `git-veil trust --import <pin-file>`: pin from a pin-file exported by a
/// machine that proved possession. Three mandatory consistency checks tie
/// the pin-file to this repository; a mismatch on any of them means one of
/// the two channels is compromised.
pub fn cmd_trust_import(
    repo_root: &Path,
    pin_file_path: &Path,
    remote_name: &str,
    key_store: &Path,
) -> Result<()> {
    let push_url = get_remote_push_url(repo_root, remote_name)?;
    let repo_id = derive_repo_id(&push_url)?;

    // The pin-file is read from outside the repository only.
    ensure_path_outside_repo(repo_root, pin_file_path)?;
    let pin_file = load_pin_file(pin_file_path)?;

    // Check (a): the pin-file's repo-id matches the repository being pinned.
    if pin_file.repo_id != repo_id {
        return Err(coded(
            ExitCode::Refused,
            format!(
                "pin-file is for repository '{}' but this repository is '{}'; pin-file does not match this repository's committed owner key; one of the two channels is compromised",
                pin_file.repo_id, repo_id
            ),
        ));
    }

    // Check (b): the pin-file's verifying key exactly matches the
    // repository's committed owner.verifying.
    let (committed_key, verifying_key_hex, recipient) = read_owner_verifying(repo_root)?;
    if pin_file.verifying_key != committed_key {
        return Err(coded(
            ExitCode::Refused,
            "pin-file does not match this repository's committed owner key; one of the two channels is compromised",
        ));
    }

    // Check (c): the pin-file's verifying-key fingerprint (fixed, documented
    // derivation over the public half — never the seed) exactly matches the
    // owner fingerprint recorded in the committed .git-veil/ metadata. An
    // absent field is a refusal: the metadata predates this rule and must
    // be refreshed by the owner.
    let trust_path = repo_root.join(".git-veil/trust.json");
    let trust_store = TrustStore::load_from_file(&trust_path)?;
    let recorded = match trust_store.get_owner_fingerprint(&repo_id) {
        Some(fingerprint) => fingerprint,
        None => {
            if trust_store.owner_fingerprints.is_empty() {
                return Err(coded(
                    ExitCode::Refused,
                    format!(
                        ".git-veil/trust.json records no owner verifying-key fingerprint for {}; the owner must re-run git-veil trust {} on a machine holding the signing key and commit the updated metadata",
                        repo_id, repo_id
                    ),
                ));
            }
            let recorded_ids: Vec<&str> = trust_store
                .owner_fingerprints
                .keys()
                .map(String::as_str)
                .collect();
            return Err(coded(
                ExitCode::Refused,
                format!(
                    ".git-veil/trust.json records an owner fingerprint for {} but this repository derives {} (from remote '{}'); this looks like a rename or a remote change based on the repository's existing trust record",
                    recorded_ids.join(", "),
                    repo_id,
                    remote_name
                ),
            ));
        }
    };
    let pin_fingerprint = pin_file.owner_fingerprint();
    if !pin_fingerprint.eq_ignore_ascii_case(recorded) {
        return Err(coded(
            ExitCode::Refused,
            format!(
                "pin-file owner fingerprint {} does not match the fingerprint {} recorded in .git-veil/trust.json; pin-file does not match this repository's committed owner key; one of the two channels is compromised",
                pin_fingerprint, recorded
            ),
        ));
    }

    // All three channels agree: the pin-file is the anchor, the committed
    // key and the committed fingerprint are the witnesses. The metadata is
    // already committed and correct — import records the pin without
    // rewriting it.
    write_pin_state(
        repo_root,
        key_store,
        &repo_id,
        &pin_file.verifying_key,
        &verifying_key_hex,
        recipient,
        false,
    )
}
