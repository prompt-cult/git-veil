use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

use crate::age_crypto::for_each_store_line;
use crate::exit_codes::{coded, ExitCode};
use crate::fingerprint::{fingerprint_for_public_key, is_legacy_pin_shape};
use crate::{
    derive_repo_id, extract_content_to_verify_from_keyring, extract_signature_from_keyring,
    get_remote_push_url, keyring_content_digest, parse_verifying_key, verify_keyring_signature,
    Keyring, TrustPinStore, TrustStore,
};

/// The refusal for a retired 16 hex character fingerprint (the pre
/// issue-#41 derivation), wherever it is found. Plain ASCII, names the
/// derivation change, names no command: the remedy is the trust
/// documentation.
fn legacy_fingerprint_error() -> anyhow::Error {
    coded(
        ExitCode::Refused,
        "a trust pin or record in the retired 16 hex character fingerprint format was found. The fingerprint derivation changed to SHA-256 over the label, a colon, and the public key encoding, printed as 64 lowercase hex characters. Re-establish the pin as described in the trust documentation.".to_string(),
    )
}

/// Loads the Ed25519 verifying key whose owner key fingerprint - the
/// single derivation with the repository id as the label - equals
/// `fingerprint`, from the key store.
///
/// Like every key store read, a non-comment line that does not parse is a
/// hard refusal (code 62) naming the corrupt line - never a silent skip
/// that would misreport the pin as missing.
fn load_verifying_key_by_fingerprint(
    key_store: &Path,
    fingerprint: &str,
    repo_id: &str,
) -> Result<ed25519_dalek::VerifyingKey> {
    let verifying_keys_path = key_store.join("verifying-keys.txt");
    let content =
        fs::read_to_string(&verifying_keys_path).context("Failed to read verifying-keys.txt")?;

    let wanted = fingerprint.trim().to_lowercase();
    let mut found = None;
    for_each_store_line(&verifying_keys_path, &content, |_, line| {
        let key = parse_verifying_key(line)?;
        if fingerprint_for_public_key(repo_id, &hex::encode(key.to_bytes())) == wanted {
            found = Some(key);
        }
        Ok(())
    })?;

    found.ok_or_else(|| {
        coded(
            ExitCode::NoTrustPin,
            "the pinned trusted key is not present in this machine key store. See the trust documentation.".to_string(),
        )
    })
}

/// Verifies the keyring signature against the trusted signing key, without printing.
///
/// A keyring with no signature is only acceptable when it has zero entries
/// (the fresh-init state); a keyring containing entries must carry a valid
/// signature made by the trusted key.
///
/// Returns the repository ID, the trusted signer fingerprint, and the parsed keyring.
pub fn verify_keyring_against_trust(
    repo_root: &Path,
    remote_name: &str,
    key_store: &Path,
) -> Result<(String, String, Keyring)> {
    let push_url = get_remote_push_url(repo_root, remote_name)?;
    let repo_id = derive_repo_id(&push_url)?;

    // Load trust store
    let trust_path = repo_root.join(".git-veil/trust.json");
    let trust_store = TrustStore::load_from_file(&trust_path)?;
    // Covers both the no-trust.json case (empty store) and the
    // missing-repo_id case (store without this repo's entry): both name the
    // repo_id and the remote that produced it, plus the remedy.
    let trusted_fingerprint = match trust_store.get_trusted_fingerprint(&repo_id) {
        Some(fingerprint) => fingerprint,
        None => {
            if trust_store.trusted_keys.is_empty() {
                return Err(coded(
                    ExitCode::NoTrustRecord,
                    "no trust record for this repository. See the trust documentation.".to_string(),
                ));
            }
            let recorded_ids: Vec<&str> = trust_store
                .trusted_keys
                .keys()
                .map(String::as_str)
                .collect();
            return Err(coded(
                ExitCode::NoTrustRecord,
                format!(
                    "the committed trust record names {} but this repository derives {} from remote {}. This looks like a rename or a remote change based on the existing trust record.",
                    recorded_ids.join(", "),
                    repo_id,
                    remote_name
                ),
            ));
        }
    };

    // trust.json is committed to the repo and therefore attacker-writable;
    // it is never a sufficient anchor on its own. Require the per-machine
    // pin written by cmd_trust, and fail closed on any disagreement.
    //
    // A 16 hex character value is a retired fingerprint (issue #41):
    // hostile wherever it is found. The pin is checked before the
    // committed record so a missing pin stays a missing pin and a legacy
    // pin is never silently compared away; nothing is rewritten - the
    // recovery is re-establishing the pin.
    let pinned = match TrustPinStore::read_pin(key_store, &repo_id)? {
        Some(pinned) => {
            if is_legacy_pin_shape(&pinned) {
                return Err(legacy_fingerprint_error());
            }
            pinned
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
    if is_legacy_pin_shape(trusted_fingerprint) {
        return Err(legacy_fingerprint_error());
    }
    if !pinned.eq_ignore_ascii_case(trusted_fingerprint) {
        return Err(coded(
            ExitCode::TrustMismatch,
            "the pinned repository identity changed on this machine. The committed trust record and this machine pin disagree. See the trust documentation.".to_string(),
        ));
    }

    // Load signing (verifying) public key
    let verifying_key =
        load_verifying_key_by_fingerprint(key_store, trusted_fingerprint, &repo_id)?;

    // Load keyring
    let keyring_path = repo_root.join(".git-veil/keyring");
    let keyring_text = fs::read_to_string(&keyring_path).context("Failed to read keyring file")?;
    let keyring = Keyring::parse(&keyring_text)?;

    let sig_begin = "-----BEGIN GIT-VEIL SIGNATURE-----";
    let signed = keyring_text.contains(sig_begin);
    let mut content_to_verify = String::new();
    if signed {
        // Extract content and signature
        content_to_verify = extract_content_to_verify_from_keyring(&keyring_text)?;
        let signature_b64 = extract_signature_from_keyring(&keyring_text)?;

        // Verify signature
        verify_keyring_signature(&content_to_verify, &signature_b64, &verifying_key)
            .map_err(|_| {
                coded(
                    ExitCode::SignatureVerificationFailed,
                    "keyring signature verification failed. The keyring or its signature does not match the pinned trusted key.".to_string(),
                )
            })?;
    } else if !keyring.entries.is_empty() {
        return Err(coded(
            ExitCode::SignatureVerificationFailed,
            format!(
                "keyring contains {} entries but has no signature. Refusing to trust an unverified keyring.",
                keyring.entries.len()
            ),
        ));
    }

    // Freshness check (see "Keyring format and freshness" in docs/design.md):
    // a valid signature proves the owner signed this keyring at some point,
    // not that it is current. A `git revert` of a removeperson commit would
    // otherwise silently return a revoked collaborator to the keyring.
    // The per-machine baseline (highest version ever accepted here, stored
    // outside the repo beside the pin) turns any version regression  -
    // including a versionless pre-freshness keyring, which counts as 0  -
    // into a fail-closed refusal.
    //
    // An UNSIGNED zero-entry keyring (the fresh-init state) is unauthenticated
    // repo content: it is accepted as version 0 but must NEVER move the
    // baseline - otherwise an attacker's junk ring (e.g. version:u64::MAX,
    // issue #22) poisons the baseline and bricks every machine past a revert
    // of the attacker's commit.
    //
    // Fork detection (issue #20): the baseline also records the SHA-256
    // digest of the accepted signed content. An equal-version keyring with
    // DIFFERENT content (two machines curating without pulling, or an
    // attacker substituting a same-version ring) is refused as the same
    // trust violation class as a rollback - re-trust is the recovery.
    let unsigned_empty = keyring.entries.is_empty() && keyring.signature.is_none();
    let observed = if unsigned_empty {
        0
    } else {
        keyring.version.unwrap_or(0)
    };
    let current_digest = if signed {
        Some(keyring_content_digest(&content_to_verify))
    } else {
        None
    };
    let (baseline_version, baseline_digest) =
        TrustPinStore::read_ring_baseline(key_store, &repo_id)?;
    if let Some(bv) = baseline_version {
        if bv > observed {
            return Err(coded(
                ExitCode::KeyringRollback,
                "keyring rollback refused. The presented version is below this machine freshness baseline. See the keyring freshness documentation.".to_string(),
            ));
        }
        if bv == observed {
            if let (Some(bd), Some(cd)) = (&baseline_digest, &current_digest) {
                if bd != cd {
                    return Err(coded(
                        ExitCode::KeyringRollback,
                        "keyring fork refused. The keyring accepted on this machine at this version has different content than the one presented. This is an equal version substitution. See the keyring freshness documentation.".to_string(),
                    ));
                }
            }
        }
    }
    if let Some(cd) = current_digest {
        // Only an owner-signed ring may advance the baseline. A versionless
        // ring records 0 (the pre-freshness migration state).
        if baseline_version != Some(observed) || baseline_digest.as_deref() != Some(cd.as_str()) {
            TrustPinStore::write_ring_baseline(key_store, &repo_id, observed, &cd)?;
        }
    }

    Ok((repo_id, trusted_fingerprint.to_string(), keyring))
}

/// Verifies the keyring signature against the trusted signing key.
pub fn cmd_verify_keyring(repo_root: &Path, remote_name: &str, key_store: &Path) -> Result<()> {
    let (repo_id, fingerprint, keyring) =
        verify_keyring_against_trust(repo_root, remote_name, key_store)?;

    let _ = (&repo_id, &fingerprint);
    println!("keyring signature verified");
    println!("keys in keyring: {}", keyring.entries.len());
    Ok(())
}
