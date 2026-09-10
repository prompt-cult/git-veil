//! git-veil library - trust model implementation
//!
//! age encryption (age-encryption.org/v1) + Ed25519 signing (RFC 8032).

mod age_crypto;
pub mod cli;
mod commands;
mod exit_codes;
mod fs_atomic;
mod key_discovery;
mod keyring;
mod permissions;
mod signing;
mod repo_identity;
mod tracked_files;
mod trust_store;

pub use commands::add::cmd_add;
pub use commands::cat::cmd_cat;
pub use commands::changes::cmd_changes;
pub use commands::clean::cmd_clean;
pub use commands::export::{cmd_export, export_public_key};
pub use commands::hide::cmd_hide;
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
pub use commands::trust::cmd_trust;
pub use commands::unhide::cmd_unhide;
pub use commands::verify_keyring::{cmd_verify_keyring, verify_keyring_against_trust};
pub use commands::whoami::cmd_whoami;
pub use exit_codes::{exit_code_of, coded, CodedError, ExitCode};
pub use fs_atomic::{write_atomic, write_atomic_mode};
pub use key_discovery::{discover_identity, discover_signing_key, load_signing_keys};
pub use keyring::{Keyring, KeyringEntry, BEGIN_MARKER, END_MARKER};
pub use permissions::{
    check_key_store_permissions, cmd_trust_permissions, find_unsafe_permissions,
    permissions_check_bypassed_from_env,
};
pub use age_crypto::{
    decrypt_with_identity, default_key_store, encrypt_to_recipient, encrypt_to_recipients,
    find_identity_by_fingerprint, find_identity_by_recipient,
    import_identity_to_store, import_recipient_to_store,
    load_identities_from_store, load_recipients_from_store,
    parse_recipient, parse_identity, recipient_from_identity,
    generate_identity, fingerprint_for_recipient,
    find_recipient_by_fingerprint,
};
pub use signing::{
    create_signature_block, extract_content_to_verify_from_keyring,
    extract_signature_from_keyring, sign_keyring_content, verify_keyring_signature,
    parse_verifying_key, parse_signing_key,
    fingerprint_for_verifying_key, generate_signing_keypair,
};
pub use repo_identity::{derive_repo_id, get_remote_push_url, parse_git_remote_url};
pub use tracked_files::{get_git_config_email, validate_tracked_path, TrackedFiles};
pub use trust_store::{TrustPinStore, TrustStore};
