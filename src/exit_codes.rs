//! Documented exit codes.
//!
//! Every deliberate failure exits with a code from this enum. Failures
//! without a more specific code exit 1, and clap usage errors exit 2.
//! The `error-codes` subcommand prints the table below. The codes are
//! public API: they are never renumbered, only appended.
//!
//! Codes are carried inside `anyhow` errors as a [`CodedError`] payload.
//! Command signatures stay `anyhow::Result`, and `main` still exits with
//! the right status, so no error-type rewrite is needed across every
//! command.

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
    /// Keyring version is below this machine's freshness baseline (rollback).
    KeyringRollback = 14,
    /// No Ed25519 signing key in the key store.
    NoSigningKey = 20,
    /// No X25519 private key in the key store matching your keyring entry.
    NoX25519PrivateKey = 21,
    /// Your principal is not in the signed keyring.
    PrincipalNotInKeyring = 22,
    /// Key store directory or private key file is group/world accessible.
    UnsafeKeyStorePermissions = 30,
    /// A `.secret` ciphertext path is git-ignored (fatal in `hide`).
    CiphertextIgnored = 40,
    /// Tracked plaintext on disk is not git-ignored (a warning, the exit code stays 0).
    PlaintextNotIgnored = 41,
    /// A committed `.secret` ciphertext path is not tracked (fatal in `hide`).
    OrphanedCiphertext = 42,
    /// The plaintext is tracked in git (fatal in `reveal`/`unhide`).
    PlaintextTracked = 43,
    /// Ciphertext could not be decrypted with the local private key.
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
    /// `hide` refuses to encrypt a path the user never added on this machine.
    UnintendedEncryption = 72,
}

impl ExitCode {
    /// Every code, in numeric order. The source for `git-veil error-codes`.
    pub const ALL: &'static [ExitCode] = &[
        ExitCode::GeneralError,
        ExitCode::NoTrustRecord,
        ExitCode::NoTrustPin,
        ExitCode::TrustMismatch,
        ExitCode::TrustRepoIdMismatch,
        ExitCode::KeyringRollback,
        ExitCode::NoSigningKey,
        ExitCode::NoX25519PrivateKey,
        ExitCode::PrincipalNotInKeyring,
        ExitCode::UnsafeKeyStorePermissions,
        ExitCode::CiphertextIgnored,
        ExitCode::PlaintextNotIgnored,
        ExitCode::OrphanedCiphertext,
        ExitCode::PlaintextTracked,
        ExitCode::DecryptionFailed,
        ExitCode::EncryptionFailed,
        ExitCode::KeyParseFailure,
        ExitCode::SignatureVerificationFailed,
        ExitCode::Refused,
        ExitCode::UnsafePath,
        ExitCode::UnintendedEncryption,
    ];

    /// The enum name, as printed by `git-veil error-codes`.
    pub fn name(self) -> &'static str {
        match self {
            ExitCode::GeneralError => "GeneralError",
            ExitCode::NoTrustRecord => "NoTrustRecord",
            ExitCode::NoTrustPin => "NoTrustPin",
            ExitCode::TrustMismatch => "TrustMismatch",
            ExitCode::TrustRepoIdMismatch => "TrustRepoIdMismatch",
            ExitCode::KeyringRollback => "KeyringRollback",
            ExitCode::NoSigningKey => "NoSigningKey",
            ExitCode::NoX25519PrivateKey => "NoX25519PrivateKey",
            ExitCode::PrincipalNotInKeyring => "PrincipalNotInKeyring",
            ExitCode::UnsafeKeyStorePermissions => "UnsafeKeyStorePermissions",
            ExitCode::CiphertextIgnored => "CiphertextIgnored",
            ExitCode::PlaintextNotIgnored => "PlaintextNotIgnored",
            ExitCode::OrphanedCiphertext => "OrphanedCiphertext",
            ExitCode::PlaintextTracked => "PlaintextTracked",
            ExitCode::DecryptionFailed => "DecryptionFailed",
            ExitCode::EncryptionFailed => "EncryptionFailed",
            ExitCode::KeyParseFailure => "KeyParseFailure",
            ExitCode::SignatureVerificationFailed => "SignatureVerificationFailed",
            ExitCode::Refused => "Refused",
            ExitCode::UnsafePath => "UnsafePath",
            ExitCode::UnintendedEncryption => "UnintendedEncryption",
        }
    }

    /// One-line meaning, as printed by `git-veil error-codes`.
    pub fn description(self) -> &'static str {
        match self {
            ExitCode::GeneralError => "Failure without a more specific code",
            ExitCode::NoTrustRecord => "No committed trust entry for this repository",
            ExitCode::NoTrustPin => "No local trust pin on this machine",
            ExitCode::TrustMismatch => "The committed trust record disagrees with this machine pin",
            ExitCode::TrustRepoIdMismatch => {
                "repo_id argument does not match the one derived from the remote"
            }
            ExitCode::KeyringRollback => "Keyring version is below this machine freshness baseline",
            ExitCode::NoSigningKey => "No Ed25519 signing key in the key store",
            ExitCode::NoX25519PrivateKey => {
                "No X25519 private key in the key store matching your keyring entry"
            }
            ExitCode::PrincipalNotInKeyring => "Your principal is not in the signed keyring",
            ExitCode::UnsafeKeyStorePermissions => {
                "Key store directory or private key file is group/world accessible"
            }
            ExitCode::CiphertextIgnored => {
                "A ciphertext path is git-ignored which is fatal in hide and a warning in add"
            }
            ExitCode::PlaintextNotIgnored => {
                "Tracked plaintext on disk is not git-ignored which is a warning only"
            }
            ExitCode::OrphanedCiphertext => {
                "A committed ciphertext path is not tracked which hide refuses"
            }
            ExitCode::PlaintextTracked => {
                "The plaintext is tracked in git which reveal and unhide refuse"
            }
            ExitCode::DecryptionFailed => {
                "Ciphertext could not be decrypted with the local private key"
            }
            ExitCode::EncryptionFailed => "Encryption failed",
            ExitCode::KeyParseFailure => "A key, keyring or signature could not be parsed",
            ExitCode::SignatureVerificationFailed => "Keyring signature missing or invalid",
            ExitCode::Refused => "Policy refusal such as init over established trust",
            ExitCode::UnsafePath => {
                "Path safety refusal such as a symlink or a path outside the repository"
            }
            ExitCode::UnintendedEncryption => {
                "hide refuses to encrypt a file the user never added on this machine"
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
