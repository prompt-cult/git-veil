//! git-gpg library - trust model implementation
//!
//! Pure Rust OpenPGP implementation using the `pgp` crate.

mod repo_identity;
mod keyring;
mod trust_store;
mod pubkey;
mod signature;
mod gpg_integration;
mod tracked_files;
mod commands;

pub use repo_identity::{parse_git_remote_url, get_remote_push_url, derive_repo_id};
pub use keyring::{Keyring, KeyringEntry, BEGIN_MARKER, END_MARKER, SIG_BEGIN, SIG_END};
pub use trust_store::TrustStore;
pub use pubkey::{parse_armored_public_key, extract_key_identities, extract_key_fingerprint, check_email_in_identities, base64_encode_public_key, base64_decode_public_key};
pub use signature::{sign_keyring_content, verify_keyring_signature, extract_signature_from_keyring, extract_content_to_verify_from_keyring};
pub use gpg_integration::{import_key_to_gpg_home, export_key_from_gpg_home, find_private_key_by_email, find_private_key_by_fingerprint, decrypt_with_gpg_key, encrypt_to_gpg_key, default_gpg_home};
pub use tracked_files::{TrackedFiles, get_git_config_email};
pub use commands::init::cmd_init;
pub use commands::trust::cmd_trust;
pub use commands::tell::cmd_tell;
pub use commands::show_repo_id::cmd_show_repo_id;
pub use commands::whoami::cmd_whoami;
pub use commands::verify_keyring::cmd_verify_keyring;
pub use commands::list_keys::cmd_list_keys;
pub use commands::add::cmd_add;
pub use commands::remove::cmd_remove;
pub use commands::list::cmd_list;
pub use commands::hide::cmd_hide;
pub use commands::reveal::cmd_reveal;
pub use commands::clean::cmd_clean;

use anyhow::Result;
use std::path::PathBuf;
