use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use pgp::composed::{SignedPublicKey, Deserializable};
use pgp::packet::{RevocationCode, Signature, SignatureType};
use pgp::types::KeyDetails;
use pgp::composed::ArmorOptions;

/// Parses an armored public key string into a SignedPublicKey.
pub fn parse_armored_public_key(armored: &str) -> Result<SignedPublicKey> {
    let (key, _headers) = SignedPublicKey::from_string(armored)
        .context("Failed to parse armored public key")?;
    Ok(key)
}

/// Extracts user identity strings from a public key.
pub fn extract_key_identities(key: &SignedPublicKey) -> Vec<String> {
    key.details
        .users
        .iter()
        .map(|user| String::from_utf8_lossy(user.id.id()).into_owned())
        .collect()
}

/// Extracts the fingerprint from a public key as an uppercase hex string.
pub fn extract_key_fingerprint(key: &SignedPublicKey) -> String {
    key.fingerprint().to_string()
}

/// Extracts the email address from a user-ID string.
///
/// If the ID contains an angle-bracket address (`Name <addr>`), the address
/// between the brackets is returned (trimmed, lowercased). Otherwise, if the
/// whole trimmed ID itself looks like a bare address (contains '@' and no
/// whitespace), it is returned lowercased. Otherwise there is no usable
/// address and `None` is returned.
pub fn extract_email_from_user_id(user_id: &str) -> Option<String> {
    let trimmed = user_id.trim();
    if let (Some(start), Some(end)) = (trimmed.find('<'), trimmed.find('>')) {
        if start < end {
            return Some(trimmed[start + 1..end].trim().to_lowercase());
        }
    }
    if trimmed.contains('@') && !trimmed.contains(char::is_whitespace) {
        return Some(trimmed.to_lowercase());
    }
    None
}

/// Checks if an email address is present in any of the key's user identities.
///
/// Matching is exact equality (case-insensitive) between the requested email
/// and the address extracted from each user-ID — never substring matching.
pub fn check_email_in_identities(key: &SignedPublicKey, email: &str) -> bool {
    let wanted = email.trim().to_lowercase();
    let identities = extract_key_identities(key);
    identities
        .iter()
        .filter_map(|id| extract_email_from_user_id(id))
        .any(|addr| addr == wanted)
}

/// Encodes a public key to base64 (after armoring it).
pub fn base64_encode_public_key(key: &SignedPublicKey) -> Result<String> {
    let armored = key
        .to_armored_string(ArmorOptions::default())
        .context("Failed to armor public key for keyring entry")?;
    Ok(STANDARD.encode(armored.as_bytes()))
}

/// Decodes a base64-encoded public key back to a SignedPublicKey.
pub fn base64_decode_public_key(encoded: &str) -> Result<SignedPublicKey> {
    let bytes = STANDARD.decode(encoded).context("Failed to decode base64")?;
    let armored = String::from_utf8(bytes).context("Invalid UTF-8 in decoded key")?;
    parse_armored_public_key(&armored)
}

/// The use a public key is being validated for.
///
/// A signing-only key (no encryption-capable subkey) is legitimate for
/// [`KeyUse::Certify`] (the repo trust anchor) but not for [`KeyUse::Encrypt`]
/// (a hide/tell recipient).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyUse {
    /// Trust-anchor / signing use (the `trust` gate).
    Certify,
    /// Recipient-encryption use (the `tell` and `hide` gates).
    Encrypt,
}

/// Unix seconds → "YYYY-MM-DD HH:MM:SS UTC" (Howard Hinnant's civil_from_days).
fn format_utc(secs: u64) -> String {
    fn civil_from_days(z: i64) -> (i64, u32, u32) {
        let z = z + 719_468;
        let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
        let doe = (z - era * 146_097) as u64;
        let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
        let y = yoe as i64 + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
        let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
        (if m <= 2 { y + 1 } else { y }, m, d)
    }
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        y,
        m,
        d,
        rem / 3_600,
        (rem % 3_600) / 60,
        rem % 60
    )
}

fn now_unix_secs() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before 1970")?
        .as_secs())
}

/// True for a HARD revocation: no reason subpacket, NoReason (unconditional),
/// KeyCompromised, or any unknown/private reason code. KeySuperseded and
/// KeyRetired are SOFT revocations (the key is deprecated, not invalid) and
/// are deliberately NOT treated as rejecting: the pgp 0.19 API
/// (`Signature::revocation_reason_code`, pgp-0.19.0
/// src/packet/signature/types.rs:895) exposes the reason code, so hard/soft IS
/// distinguishable. Note the crate does not expose a "revocation effective at
/// future date T" mechanism, so a soft revocation can never become a hard
/// rejection through time alone here — documented limitation.
fn is_hard_revocation(sig: &Signature) -> bool {
    !matches!(
        sig.revocation_reason_code(),
        Some(RevocationCode::KeySuperseded) | Some(RevocationCode::KeyRetired)
    )
}

/// Rejects `sig` if its declared expiry (creation time + duration) is not in
/// the future relative to `now`. `what` names the component in error messages.
fn check_expiry(
    fingerprint: &str,
    what: &str,
    sig: &Signature,
    now: u64,
) -> Result<()> {
    let Some(created) = sig.created() else {
        return Ok(());
    };
    // The signature itself may carry an expiration (SignatureExpirationTime):
    // an expired self-signature no longer establishes the key's validity.
    if let Some(d) = sig.signature_expiration_time() {
        let expires = u64::from(created.as_secs()) + u64::from(d.as_secs());
        if expires <= now {
            bail!(
                "{} of key {} expired at {} (signature expiration)",
                what,
                fingerprint,
                format_utc(expires)
            );
        }
    }
    // KeyExpirationTime: the expiry of the KEY component the signature covers.
    if let Some(d) = sig.key_expiration_time() {
        let expires = u64::from(created.as_secs()) + u64::from(d.as_secs());
        if expires <= now {
            bail!(
                "{} of key {} expired at {}",
                what,
                fingerprint,
                format_utc(expires)
            );
        }
    }
    Ok(())
}

/// Validates a parsed public key for a given use, fail-closed.
///
/// Checks (all reject, never warn-and-proceed):
/// a. Self-signature present: at least one direct self-signature or a
///    self-certification over a User ID (no unsigned key material).
/// b. Expiry: the newest self-signature must not itself be expired, and the
///    key expiration it declares (KeyExpirationTime, measured from that
///    signature's creation time) must be in the future. Legacy v3
///    `expiration days` on the primary key packet is honoured too. In
///    [`KeyUse::Encrypt`] mode the same checks apply to the encryption
///    subkey's newest binding signature.
/// c. Revocation: any HARD revocation (`KeyRevocation` on the primary, or
///    `SubkeyRevocation` on the selected encryption subkey) rejects. Soft
///    revocations (KeySuperseded / KeyRetired) are ignored — see
///    [`is_hard_revocation`].
/// d. In [`KeyUse::Encrypt`] mode: an encryption-capable subkey (or an
///    encryption-capable primary, e.g. RSA) with a valid binding signature
///    must exist.
///
/// pgp 0.19 API used (vendored source, pgp-0.19.0):
/// - `Signature::created()` / `key_expiration_time()` /
///   `signature_expiration_time()` (src/packet/signature/types.rs:788/797/806;
///   durations are measured from the signature creation time)
/// - `Signature::typ()` and `SignatureType::KeyRevocation`/`SubkeyRevocation`
///   (src/packet/signature/types.rs:1080-1145)
/// - `Signature::revocation_reason_code()` + `RevocationCode`
///   (src/packet/signature/types.rs:895/1569)
/// - `KeyDetails::legacy_v3_expiration_days()` / `created_at()`
///   (src/types/key_traits.rs)
/// - key material access: `SignedPublicKey.details.{direct_signatures,
///   revocation_signatures, users[].signatures}` and
///   `SignedPublicKey.public_subkeys[].signatures` (src/composed/signed_key/
///   public.rs, shared.rs)
///
/// NOTE: cryptographic verification of the self-signatures themselves is NOT
/// performed here (beyond structural presence); this is a validity-policy
/// gate, not a full certificate verifier.
pub fn validate_public_key_for_use(key: &SignedPublicKey, use_for: KeyUse) -> Result<()> {
    let fingerprint = extract_key_fingerprint(key);
    let now = now_unix_secs()?;

    // --- (a) self-signature present -----------------------------------
    let self_sigs: Vec<&Signature> = key
        .details
        .direct_signatures
        .iter()
        .chain(key.details.users.iter().flat_map(|u| u.signatures.iter()))
        .collect();
    if self_sigs.is_empty() {
        bail!(
            "key {} has no self-signature: unsigned key material is not trusted",
            fingerprint
        );
    }

    // --- (b) primary-key expiry ---------------------------------------
    // The newest self-signature decides; renewing a key produces a newer
    // self-signature, which may drop or extend the expiry.
    if let Some(newest) = self_sigs
        .iter()
        .filter_map(|s| s.created().map(|c| (*s, c)))
        .max_by_key(|(_, c)| c.as_secs())
    {
        check_expiry(&fingerprint, "primary key", newest.0, now)?;
    }
    // Legacy v3 keys carry expiry on the key packet itself.
    if let Some(days) = key.legacy_v3_expiration_days() {
        let expires = key.created_at().as_secs() as u64 + u64::from(days) * 86_400;
        if expires <= now {
            bail!(
                "primary key {} expired at {}",
                fingerprint,
                format_utc(expires)
            );
        }
    }

    // --- (c) primary-key revocation -----------------------------------
    for sig in &key.details.revocation_signatures {
        if sig.typ() == Some(SignatureType::KeyRevocation) && is_hard_revocation(sig) {
            bail!("key {} is revoked (hard revocation)", fingerprint);
        }
    }

    // --- (d) encryption-capable subkey (Encrypt mode) ------------------
    if use_for == KeyUse::Encrypt {
        let primary_encrypts = self_sigs
            .iter()
            .filter_map(|s| s.created().map(|c| (*s, c)))
            .max_by_key(|(_, c)| c.as_secs())
            .map(|(sig, _)| sig.key_flags().encrypt_comms() || sig.key_flags().encrypt_storage())
            .unwrap_or(false);

        let chosen = key.public_subkeys.iter().find(|sk| {
            newest_binding(sk).map_or(false, |sig| {
                sig.key_flags().encrypt_comms() || sig.key_flags().encrypt_storage()
            })
        });

        match chosen {
            Some(sub) => {
                // Expiry + revocation of the subkey that will actually be used.
                for sig in &sub.signatures {
                    if sig.typ() == Some(SignatureType::SubkeyRevocation)
                        && is_hard_revocation(sig)
                    {
                        bail!(
                            "encryption subkey {} of key {} is revoked (hard revocation)",
                            sub.fingerprint(),
                            fingerprint
                        );
                    }
                }
                if let Some(binding) = newest_binding(sub) {
                    check_expiry(
                        &fingerprint,
                        &format!("encryption subkey {}", sub.fingerprint()),
                        binding,
                        now,
                    )?;
                }
            }
            None if primary_encrypts => {
                // e.g. an RSA primary used directly for encryption: legitimate.
            }
            None => {
                bail!(
                    "key {} has no encryption-capable subkey with a valid binding signature",
                    fingerprint
                );
            }
        }
    }

    Ok(())
}

/// The newest SubkeyBinding signature of a subkey (by creation time).
fn newest_binding(subkey: &pgp::composed::SignedPublicSubKey) -> Option<&Signature> {
    subkey
        .signatures
        .iter()
        .filter(|s| s.typ() == Some(SignatureType::SubkeyBinding))
        .filter_map(|s| s.created().map(|c| (s, c)))
        .max_by_key(|(_, c)| c.as_secs())
        .map(|(s, _)| s)
}
