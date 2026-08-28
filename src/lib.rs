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

pub use commands::add::cmd_add;
pub use commands::cat::cmd_cat;
pub use commands::changes::cmd_changes;
pub use commands::clean::cmd_clean;
pub use commands::hide::cmd_hide;
pub use commands::init::cmd_init;
pub use commands::import::cmd_import;
pub use commands::list::cmd_list;
pub use commands::list_keys::cmd_list_keys;
pub use commands::remove::cmd_remove;
pub use commands::removeperson::cmd_removeperson;
pub use commands::reveal::cmd_reveal;
pub use commands::show_repo_id::cmd_show_repo_id;
pub use commands::tell::cmd_tell;
pub use commands::trust::cmd_trust;
pub use commands::verify_keyring::{cmd_verify_keyring, verify_keyring_against_trust};
pub use commands::whoami::cmd_whoami;
pub use gpg_integration::{decrypt_with_gpg_key, default_gpg_home, encrypt_to_gpg_key, encrypt_to_gpg_keys, find_private_key_by_email, find_private_key_by_fingerprint, import_key_to_gpg_home};
pub use keyring::{Keyring, KeyringEntry, BEGIN_MARKER, END_MARKER, SIG_BEGIN, SIG_END};
pub use pubkey::{base64_decode_public_key, base64_encode_public_key, check_email_in_identities, extract_email_from_user_id, extract_key_fingerprint, extract_key_identities, parse_armored_public_key};
pub use repo_identity::{derive_repo_id, get_remote_push_url, parse_git_remote_url};
pub use signature::{extract_content_to_verify_from_keyring, extract_signature_from_keyring, sign_keyring_content, verify_keyring_signature};
pub use tracked_files::{get_git_config_email, TrackedFiles};
pub use trust_store::{TrustPinStore, TrustStore};

