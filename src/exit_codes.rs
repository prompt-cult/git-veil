//! Documented exit codes.
//!
//! Every deliberate failure exits with a code from this enum; failures
//! without a more specific code exit 1, and clap usage errors exit 2. The
//! `error-codes` subcommand prints the table below, and the codes are
//! public API: they are never renumbered, only appended.
//!
//! Codes are carried inside `anyhow` errors as a [`CodedError`] payload so
//! command signatures stay `anyhow::Result` and `main` can still exit with
//! the right status — no error-type rewrite across every command.

use std::fmt;

/// A documented exit code. See the module docs for the contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExitCode {
    /// Failure without a more specific code.
    GeneralError = 1,
    /// Committed trust.json has no entry for this repository.
    NoTrustRecord = 10,
    /// No local trust pin on this machine.
    NoTrustPin = 11,
    /// Committed trust.json disagrees with this machine's pin.
    TrustMismatch = 12,
    /// repo_id argument does not match the one derived from the remote.
    TrustRepoIdMismatch = 13,
    /// No Ed25519 signing key in the key store.
    NoSigningKey = 20,
    /// No age identity in the key store matching your keyring entry.
    NoAgeIdentity = 21,
    /// Your email is not in the signed keyring.
    IdentityNotInKeyring = 22,
    /// Key store directory or private key file is group/world accessible.
    UnsafeKeyStorePermissions = 30,
    /// A `.secret` ciphertext path is git-ignored (fatal in `hide`).
    CiphertextIgnored = 40,
    /// Tracked plaintext on disk is not git-ignored (warning; exit stays 0).
    PlaintextNotIgnored = 41,
    /// Ciphertext could not be decrypted with the local identity.
    DecryptionFailed = 60,
    /// Encryption failed.
    EncryptionFailed = 61,
    /// A key, keyring or signature could not be parsed.
    KeyParseFailure = 62,
    /// Keyring signature missing or invalid.
    SignatureVerificationFailed = 63,
    /// Policy refusal (e.g. init over established trust, clean without --yes).
    Refused = 70,
    /// Path-safety refusal (symlink, outside repository, unsafe tracked path).
    UnsafePath = 71,
}

impl ExitCode {
    /// Every code, in numeric order — the source for `git-veil error-codes`.
    pub const ALL: &'static [ExitCode] = &[
        ExitCode::GeneralError,
        ExitCode::NoTrustRecord,
        ExitCode::NoTrustPin,
        ExitCode::TrustMismatch,
        ExitCode::TrustRepoIdMismatch,
        ExitCode::NoSigningKey,
        ExitCode::NoAgeIdentity,
        ExitCode::IdentityNotInKeyring,
        ExitCode::UnsafeKeyStorePermissions,
        ExitCode::CiphertextIgnored,
        ExitCode::PlaintextNotIgnored,
        ExitCode::DecryptionFailed,
        ExitCode::EncryptionFailed,
        ExitCode::KeyParseFailure,
        ExitCode::SignatureVerificationFailed,
        ExitCode::Refused,
        ExitCode::UnsafePath,
    ];

    /// The enum name, as printed by `git-veil error-codes`.
    pub fn name(self) -> &'static str {
        match self {
            ExitCode::GeneralError => "GeneralError",
            ExitCode::NoTrustRecord => "NoTrustRecord",
            ExitCode::NoTrustPin => "NoTrustPin",
            ExitCode::TrustMismatch => "TrustMismatch",
            ExitCode::TrustRepoIdMismatch => "TrustRepoIdMismatch",
            ExitCode::NoSigningKey => "NoSigningKey",
            ExitCode::NoAgeIdentity => "NoAgeIdentity",
            ExitCode::IdentityNotInKeyring => "IdentityNotInKeyring",
            ExitCode::UnsafeKeyStorePermissions => "UnsafeKeyStorePermissions",
            ExitCode::CiphertextIgnored => "CiphertextIgnored",
            ExitCode::PlaintextNotIgnored => "PlaintextNotIgnored",
            ExitCode::DecryptionFailed => "DecryptionFailed",
            ExitCode::EncryptionFailed => "EncryptionFailed",
            ExitCode::KeyParseFailure => "KeyParseFailure",
            ExitCode::SignatureVerificationFailed => "SignatureVerificationFailed",
            ExitCode::Refused => "Refused",
            ExitCode::UnsafePath => "UnsafePath",
        }
    }

    /// One-line meaning, as printed by `git-veil error-codes`.
    pub fn description(self) -> &'static str {
        match self {
            ExitCode::GeneralError => "Failure without a more specific code",
            ExitCode::NoTrustRecord => {
                "Committed trust.json has no entry for this repository; run git-veil trust"
            }
            ExitCode::NoTrustPin => {
                "No local trust pin on this machine; run git-veil trust"
            }
            ExitCode::TrustMismatch => {
                "Committed trust.json disagrees with this machine's pin; re-pin if intended"
            }
            ExitCode::TrustRepoIdMismatch => {
                "repo_id argument does not match the one derived from the remote"
            }
            ExitCode::NoSigningKey => {
                "No Ed25519 signing key in the key store; create one and back it up"
            }
            ExitCode::NoAgeIdentity => {
                "No age identity in the key store matching your keyring entry; create and import one"
            }
            ExitCode::IdentityNotInKeyring => {
                "Your email is not in the signed keyring; ask the owner to tell you"
            }
            ExitCode::UnsafeKeyStorePermissions => {
                "Key store directory or private key file is group/world accessible"
            }
            ExitCode::CiphertextIgnored => {
                "A .secret ciphertext path is git-ignored (fatal in hide; warning in add)"
            }
            ExitCode::PlaintextNotIgnored => {
                "Tracked plaintext on disk is not git-ignored (warning; exit stays 0)"
            }
            ExitCode::DecryptionFailed => {
                "Ciphertext could not be decrypted with the local identity"
            }
            ExitCode::EncryptionFailed => "Encryption failed",
            ExitCode::KeyParseFailure => "A key, keyring or signature could not be parsed",
            ExitCode::SignatureVerificationFailed => "Keyring signature missing or invalid",
            ExitCode::Refused => {
                "Policy refusal (e.g. init over established trust, clean without --yes)"
            }
            ExitCode::UnsafePath => {
                "Path-safety refusal (symlink, outside repository, unsafe tracked path)"
            }
        }
    }
}

/// An error carrying its documented exit code, embedded as the root cause
/// of an `anyhow::Error` so `main` can map it to `process::exit` without
/// changing every command's error type.
#[derive(Debug)]
pub struct CodedError {
    pub code: ExitCode,
    message: String,
}

impl fmt::Display for CodedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CodedError {}

/// Builds an `anyhow::Error` that exits with `code` and prints `message`.
pub fn coded(code: ExitCode, message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(CodedError {
        code,
        message: message.into(),
    })
}

/// The exit status for `err`: the code of the first `CodedError` in its
/// cause chain, or 1 for undecorated failures.
pub fn exit_code_of(err: &anyhow::Error) -> i32 {
    err.chain()
        .find_map(|cause| {
            cause
                .downcast_ref::<CodedError>()
                .map(|coded| coded.code as i32)
        })
        .unwrap_or(ExitCode::GeneralError as i32)
}
