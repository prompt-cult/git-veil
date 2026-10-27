//! git-veil library - trust model implementation
//!
//! age encryption (age-encryption.org/v1) + Ed25519 signing (RFC 8032).

mod age_crypto;
mod allowance;
pub mod cli;
mod codeowners;
mod commands;
mod exit_codes;
mod fingerprint;
mod fs_atomic;
mod key_discovery;
mod keyring;
mod permissions;
mod pin_file;
mod repo_identity;
mod signing;
mod tracked_files;
mod trust_store;

pub use age_crypto::{
    decrypt_with_x25519_private_key, default_key_store, encrypt_to_x25519_public_key,
    encrypt_to_x25519_public_keys, find_x25519_private_key_by_public_key,
    generate_x25519_private_key, import_x25519_private_key_to_store,
    import_x25519_public_key_to_store, load_x25519_private_keys_from_store,
    load_x25519_public_keys_from_store, parse_x25519_private_key, parse_x25519_public_key,
    x25519_public_key_encoding,
};
pub use allowance::{allowance_record_key, AllowanceStore};
pub use codeowners::{
    covers_trust_critical_paths, find as find_codeowners, is_suppressed as codeowners_suppressed,
    record_suppression as record_codeowners_suppression, suggestion_text as codeowners_suggestion,
    warning_text as codeowners_warning,
};
pub use commands::add::cmd_add;
pub use commands::allow::cmd_allow;
pub use commands::cat::cmd_cat;
pub use commands::changes::cmd_changes;
pub use commands::clean::cmd_clean;
pub use commands::export::{cmd_export, export_public_key};
pub use commands::export_pin::cmd_export_pin;
pub use commands::fingerprint::cmd_fingerprint;
pub use commands::hide::{cmd_hide, cmd_hide_all};
pub use commands::import::cmd_import;
pub use commands::init::cmd_init;
pub use commands::list::cmd_list;
pub use commands::list_keys::cmd_list_keys;
pub use commands::remove::cmd_remove;
pub use commands::removekey::cmd_removekey;
pub use commands::removeperson::cmd_removeperson;
pub use commands::reveal::cmd_reveal;
pub use commands::show_repo_id::cmd_show_repo_id;
pub use commands::tell::cmd_tell;
pub use commands::trust::{cmd_trust, cmd_trust_import};
pub use commands::unhide::cmd_unhide;
pub use commands::verify_keyring::{cmd_verify_keyring, verify_keyring_against_trust};
pub use commands::whoami::cmd_whoami;
pub use exit_codes::{coded, exit_code_of, CodedError, ExitCode};
pub use fingerprint::{fingerprint_for_public_key, is_16_hex_pin_shape, owner_key_fingerprint};
pub use fs_atomic::{write_atomic, write_atomic_mode};
pub use key_discovery::{
    discover_signing_key, discover_signing_key_explicit, discover_x25519_private_key,
    load_signing_keys,
};
pub use keyring::{Keyring, KeyringEntry, BEGIN_MARKER, END_MARKER};
pub use permissions::{
    check_key_store_permissions, cmd_trust_permissions, find_unsafe_permissions,
    permissions_check_bypassed_from_env,
};
pub use pin_file::{load_pin_file, write_pin_file, PinFile};
pub use repo_identity::{
    derive_configured_repo_ids, derive_repo_id, get_remote_push_url, parse_git_remote_url,
};
pub use signing::{
    create_signature_block, extract_content_to_verify_from_keyring, extract_signature_from_keyring,
    generate_signing_keypair, keyring_content_digest, parse_signing_key, parse_verifying_key,
    sign_keyring_content, verify_keyring_signature,
};
pub use tracked_files::{get_git_config_email, validate_tracked_path, TrackedFiles};
pub use trust_store::{RingPassStore, TrustPinStore, TrustStore};
