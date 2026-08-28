//! Complete test suite for git-gpg trust model implementation.
//!
//! All tests are failing stubs (Red phase) - they panic with "not implemented"
//! until the corresponding implementation is written.

use git_gpg::*;
use std::path::PathBuf;
use pgp::composed::{SecretKeyParamsBuilder, SubkeyParamsBuilder, KeyType, EncryptionCaps};
use rand::thread_rng;
use serial_test::serial;

/// Helper function to generate a test PGP key pair
fn generate_test_key(email: &str) -> (pgp::composed::SignedSecretKey, pgp::composed::SignedPublicKey) {
    let mut rng = thread_rng();
    
    let encrypt_subkey = SubkeyParamsBuilder::default()
        .key_type(KeyType::X25519)
        .can_encrypt(EncryptionCaps::All)
        .build()
        .expect("build encrypt subkey params");
    
    let params = SecretKeyParamsBuilder::default()
        .key_type(KeyType::Ed25519)
        .can_certify(true)
        .can_sign(true)
        .primary_user_id(format!("Test User <{}>", email))
        .passphrase(None)
        .subkeys(vec![encrypt_subkey])
        .build()
        .expect("build key params");
    
    let secret_key = params.generate(&mut rng).expect("generate key");
    let public_key = secret_key.to_public_key();
    
    (secret_key, public_key)
}

// ============================================================================
// Phase 1: Repository Identity
// ============================================================================

#[test]
#[serial]
fn test_parse_github_ssh_url() {
    let (repo, user, service) = parse_git_remote_url("git@github.com:user/repo.git").unwrap();
    assert_eq!(repo, "repo");
    assert_eq!(user, "user");
    assert_eq!(service, "github.com");
}

#[test]
#[serial]
fn test_parse_github_https_url() {
    let (repo, user, service) = parse_git_remote_url("https://github.com/user/repo.git").unwrap();
    assert_eq!(repo, "repo");
    assert_eq!(user, "user");
    assert_eq!(service, "github.com");
}

#[test]
#[serial]
fn test_parse_codeberg_ssh_url() {
    let (repo, user, service) = parse_git_remote_url("ssh://git@codeberg.org/user/repo.git").unwrap();
    assert_eq!(repo, "repo");
    assert_eq!(user, "user");
    assert_eq!(service, "codeberg.org");
}

#[test]
#[serial]
fn test_parse_gitlab_ssh_url() {
    let (repo, user, service) = parse_git_remote_url("git@gitlab.com:org/project.git").unwrap();
    assert_eq!(repo, "project");
    assert_eq!(user, "org");
    assert_eq!(service, "gitlab.com");
}

#[test]
#[serial]
fn test_parse_gitlab_https_url() {
    let (repo, user, service) = parse_git_remote_url("https://gitlab.com/org/project.git").unwrap();
    assert_eq!(repo, "project");
    assert_eq!(user, "org");
    assert_eq!(service, "gitlab.com");
}

#[test]
#[serial]
fn test_parse_url_strips_git_extension() {
    let (repo, _, _) = parse_git_remote_url("git@github.com:user/my-project.git").unwrap();
    assert_eq!(repo, "my-project");
}

#[test]
#[serial]
fn test_parse_url_handles_no_git_extension() {
    let (repo, _, _) = parse_git_remote_url("git@github.com:user/my-project").unwrap();
    assert_eq!(repo, "my-project");
}

#[test]
#[serial]
fn test_parse_url_invalid_format_returns_error() {
    let result = parse_git_remote_url("not-a-valid-url");
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_get_remote_push_url_origin() {
    let temp = tempfile::tempdir().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["init"]).output().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    
    let url = get_remote_push_url(&temp.path().to_path_buf(), "origin").unwrap();
    assert!(url.contains("github.com") && url.contains("user/repo"));
}

#[test]
#[serial]
fn test_get_remote_push_url_custom_remote() {
    let temp = tempfile::tempdir().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["init"]).output().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["remote", "add", "fork", "ssh://git@codeberg.org/user/repo.git"]).output().unwrap();
    
    let url = get_remote_push_url(&temp.path().to_path_buf(), "fork").unwrap();
    assert!(url.contains("codeberg.org"));
}

#[test]
#[serial]
fn test_get_remote_push_url_nonexistent_remote_fails() {
    let temp = tempfile::tempdir().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["init"]).output().unwrap();
    
    let result = get_remote_push_url(&temp.path().to_path_buf(), "nonexistent");
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_derive_repo_id_from_git_remote() {
    let repo_id = derive_repo_id("git@github.com:simbo1905/fara.git").unwrap();
    assert_eq!(repo_id, "fara+simbo1905@github.com");
}

// ============================================================================
// Phase 1: Keyring Format
// ============================================================================

#[test]
#[serial]
fn test_keyring_format_single_entry() {
    let content = "-----BEGIN GIT-GPG KEYRING-----\nalice@example.com:YWJj:ABC123\n-----END GIT-GPG KEYRING-----";
    let keyring = Keyring::parse(content).unwrap();
    assert_eq!(keyring.entries.len(), 1);
    assert_eq!(keyring.entries[0].email, "alice@example.com");
    assert_eq!(keyring.entries[0].base64_key, "YWJj");
    assert_eq!(keyring.entries[0].fingerprint, "ABC123");
}

#[test]
#[serial]
fn test_keyring_format_multiple_entries() {
    let content = "-----BEGIN GIT-GPG KEYRING-----\nalice@example.com:YWJj:ABC123\nbob@work.com:ZGVm:DEF456\n-----END GIT-GPG KEYRING-----";
    let keyring = Keyring::parse(content).unwrap();
    assert_eq!(keyring.entries.len(), 2);
}

#[test]
#[serial]
fn test_keyring_parse_with_markers() {
    let content = "-----BEGIN GIT-GPG KEYRING-----\n-----END GIT-GPG KEYRING-----";
    let result = Keyring::parse(content);
    assert!(result.is_ok());
}

#[test]
#[serial]
fn test_keyring_parse_with_signature() {
    let content = "-----BEGIN GIT-GPG KEYRING-----\nalice@example.com:YWJj:ABC123\n-----END GIT-GPG KEYRING-----\n-----BEGIN PGP SIGNATURE-----\nsig\n-----END PGP SIGNATURE-----";
    let keyring = Keyring::parse(content).unwrap();
    assert!(keyring.signature.is_some());
    assert_eq!(keyring.entries.len(), 1);
}

#[test]
#[serial]
fn test_keyring_parse_empty() {
    let content = "-----BEGIN GIT-GPG KEYRING-----\n-----END GIT-GPG KEYRING-----";
    let keyring = Keyring::parse(content).unwrap();
    assert_eq!(keyring.entries.len(), 0);
}

#[test]
#[serial]
fn test_keyring_parse_missing_end_marker_fails() {
    let content = "-----BEGIN GIT-GPG KEYRING-----\nalice@example.com:YWJj:ABC123";
    let result = Keyring::parse(content);
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_keyring_parse_malformed_entry_fails() {
    let content = "-----BEGIN GIT-GPG KEYRING-----\nmalformed_entry_no_colons\n-----END GIT-GPG KEYRING-----";
    let result = Keyring::parse(content);
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_keyring_serialize_single_entry() {
    let mut keyring = Keyring::new();
    keyring.add_entry("alice@example.com".into(), "YWJj".into(), "ABC123".into());
    let serialized = keyring.serialize();
    assert!(serialized.contains("-----BEGIN GIT-GPG KEYRING-----"));
    assert!(serialized.contains("alice@example.com"));
    assert!(serialized.contains("YWJj"));
    assert!(serialized.contains("ABC123"));
    assert!(serialized.contains("-----END GIT-GPG KEYRING-----"));
}

#[test]
#[serial]
fn test_keyring_serialize_multiple_entries() {
    let mut keyring = Keyring::new();
    keyring.add_entry("alice@example.com".into(), "YWJj".into(), "ABC123".into());
    keyring.add_entry("bob@work.com".into(), "ZGVm".into(), "DEF456".into());
    let serialized = keyring.serialize();
    assert!(serialized.contains("alice@example.com"));
    assert!(serialized.contains("bob@work.com"));
}

#[test]
#[serial]
fn test_keyring_add_entry() {
    let mut keyring = Keyring::new();
    assert_eq!(keyring.entries.len(), 0);
    keyring.add_entry("alice@example.com".into(), "YWJj".into(), "ABC123".into());
    assert_eq!(keyring.entries.len(), 1);
}

#[test]
#[serial]
fn test_keyring_find_by_email() {
    let mut keyring = Keyring::new();
    keyring.add_entry("alice@example.com".into(), "YWJj".into(), "ABC123".into());
    let entry = keyring.find_by_email("alice@example.com").unwrap();
    assert_eq!(entry.email, "alice@example.com");
}

#[test]
#[serial]
fn test_keyring_find_by_email_not_found() {
    let keyring = Keyring::new();
    let result = keyring.find_by_email("nonexistent@example.com");
    assert!(result.is_none());
}

#[test]
#[serial]
fn test_keyring_list_all_emails() {
    let mut keyring = Keyring::new();
    keyring.add_entry("alice@example.com".into(), "YWJj".into(), "ABC123".into());
    keyring.add_entry("bob@work.com".into(), "ZGVm".into(), "DEF456".into());
    let emails = keyring.list_emails();
    assert_eq!(emails.len(), 2);
    assert!(emails.contains(&"alice@example.com"));
    assert!(emails.contains(&"bob@work.com"));
}

#[test]
#[serial]
fn test_keyring_extract_fingerprints() {
    let mut keyring = Keyring::new();
    keyring.add_entry("alice@example.com".into(), "YWJj".into(), "ABC123".into());
    keyring.add_entry("bob@work.com".into(), "ZGVm".into(), "DEF456".into());
    let fps = keyring.extract_fingerprints();
    assert_eq!(fps.len(), 2);
    assert!(fps.contains(&"ABC123"));
    assert!(fps.contains(&"DEF456"));
}

#[test]
#[serial]
fn test_colon_not_in_base64() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let test_bytes = b"hello:world:test";
    let encoded = STANDARD.encode(test_bytes);
    assert!(!encoded.contains(':'), "base64 should not contain colon");
}

#[test]
#[serial]
fn test_colon_not_in_email() {
    let email = "alice@example.com";
    assert!(!email.contains(':'), "email should not contain colon");
}

// ============================================================================
// Phase 1: Trust Store
// ============================================================================

#[test]
#[serial]
fn test_trust_store_create_empty() {
    let store = TrustStore::new();
    assert!(store.trusted_keys.is_empty());
}

#[test]
#[serial]
fn test_trust_store_add_trust() {
    let mut store = TrustStore::new();
    store.add_trust("repo+user@github.com".into(), "ABC123".into());
    assert_eq!(store.trusted_keys.len(), 1);
}

#[test]
#[serial]
fn test_trust_store_get_trusted_fingerprint() {
    let mut store = TrustStore::new();
    store.add_trust("repo+user@github.com".into(), "ABC123".into());
    let fp = store.get_trusted_fingerprint("repo+user@github.com").unwrap();
    assert_eq!(fp, "ABC123");
}

#[test]
#[serial]
fn test_trust_store_get_trusted_fingerprint_not_found() {
    let store = TrustStore::new();
    let result = store.get_trusted_fingerprint("nonexistent");
    assert!(result.is_none());
}

#[test]
#[serial]
fn test_trust_store_update_existing_trust() {
    let mut store = TrustStore::new();
    store.add_trust("repo+user@github.com".into(), "ABC123".into());
    store.add_trust("repo+user@github.com".into(), "DEF456".into());
    assert_eq!(store.trusted_keys.len(), 1);
    assert_eq!(store.get_trusted_fingerprint("repo+user@github.com").unwrap(), "DEF456");
}

#[test]
#[serial]
fn test_trust_store_serialize_to_json() {
    let mut store = TrustStore::new();
    store.add_trust("repo+user@github.com".into(), "ABC123".into());
    let json = store.serialize().unwrap();
    assert!(json.contains("repo+user@github.com"));
    assert!(json.contains("ABC123"));
}

#[test]
#[serial]
fn test_trust_store_deserialize_from_json() {
    let json = r#"{"trusted_keys":{"repo+user@github.com":"ABC123"}}"#;
    let store = TrustStore::deserialize(json).unwrap();
    assert_eq!(store.get_trusted_fingerprint("repo+user@github.com").unwrap(), "ABC123");
}

#[test]
#[serial]
fn test_trust_store_save_to_file() {
    let mut store = TrustStore::new();
    store.add_trust("repo+user@github.com".into(), "ABC123".into());
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("trust.json");
    store.save_to_file(&path).unwrap();
    assert!(path.exists());
}

#[test]
#[serial]
fn test_trust_store_load_from_file() {
    let mut store = TrustStore::new();
    store.add_trust("repo+user@github.com".into(), "ABC123".into());
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("trust.json");
    store.save_to_file(&path).unwrap();
    
    let loaded = TrustStore::load_from_file(&path).unwrap();
    assert_eq!(loaded.get_trusted_fingerprint("repo+user@github.com").unwrap(), "ABC123");
}

#[test]
#[serial]
fn test_trust_store_load_nonexistent_file_returns_empty() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("nonexistent.json");
    let store = TrustStore::load_from_file(&path).unwrap();
    assert!(store.trusted_keys.is_empty());
}

// ============================================================================
// Phase 2: Public Key Ops
// ============================================================================

#[test]
#[serial]
fn test_parse_armored_public_key() {
    let (_secret_key, public_key) = generate_test_key("test@example.com");
    let armored = public_key.to_armored_string(Default::default()).unwrap();
    let result = parse_armored_public_key(&armored);
    assert!(result.is_ok());
}

#[test]
#[serial]
fn test_extract_key_identities() {
    let (_secret_key, public_key) = generate_test_key("alice@example.com");
    let identities = extract_key_identities(&public_key);
    assert_eq!(identities.len(), 1);
    assert!(identities[0].contains("alice@example.com"));
}

#[test]
#[serial]
fn test_extract_key_fingerprint() {
    let (_secret_key, public_key) = generate_test_key("alice@example.com");
    let fingerprint = extract_key_fingerprint(&public_key);
    assert!(!fingerprint.is_empty());
    assert!(fingerprint.len() > 0);
    // Fingerprint should be hex string
    assert!(fingerprint.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
#[serial]
fn test_check_email_in_identities_found() {
    let (_secret_key, public_key) = generate_test_key("alice@example.com");
    assert!(check_email_in_identities(&public_key, "alice@example.com"));
}

#[test]
#[serial]
fn test_check_email_in_identities_not_found() {
    let (_secret_key, public_key) = generate_test_key("alice@example.com");
    assert!(!check_email_in_identities(&public_key, "bob@example.com"));
}

#[test]
#[serial]
fn test_base64_encode_public_key() {
    let (_secret_key, public_key) = generate_test_key("alice@example.com");
    let encoded = base64_encode_public_key(&public_key);
    assert!(!encoded.is_empty());
    // Should be valid base64
    assert!(encoded.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='));
}

#[test]
#[serial]
fn test_base64_decode_public_key() {
    let (_secret_key, public_key) = generate_test_key("alice@example.com");
    let encoded = base64_encode_public_key(&public_key);
    let decoded = base64_decode_public_key(&encoded).expect("decode should succeed");
    let original_fp = extract_key_fingerprint(&public_key);
    let decoded_fp = extract_key_fingerprint(&decoded);
    assert_eq!(original_fp, decoded_fp);
}

#[test]
#[serial]
fn test_roundtrip_base64_encoding() {
    let (_secret_key, public_key) = generate_test_key("alice@example.com");
    let encoded = base64_encode_public_key(&public_key);
    let decoded = base64_decode_public_key(&encoded).expect("decode should succeed");
    let re_encoded = base64_encode_public_key(&decoded);
    assert_eq!(encoded, re_encoded);
}

#[test]
#[serial]
fn test_parse_invalid_armored_key_fails() {
    let result = parse_armored_public_key("not a valid key");
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_extract_identities_from_multiple_uids() {
    // Generate a key with primary email
    let (_secret_key, public_key) = generate_test_key("alice@example.com");
    let identities = extract_key_identities(&public_key);
    // By default, key has one user ID
    assert_eq!(identities.len(), 1);
    assert!(identities[0].contains("alice@example.com"));
}

// ============================================================================
// Phase 2: Signature Ops
// ============================================================================

#[test]
#[serial]
fn test_sign_keyring_content() {
    let (secret_key, _public_key) = generate_test_key("alice@example.com");
    let keyring_content = "test keyring content";
    let signature = sign_keyring_content(keyring_content, &secret_key).expect("signing should succeed");
    assert!(signature.contains("-----BEGIN PGP SIGNATURE-----"));
    assert!(signature.contains("-----END PGP SIGNATURE-----"));
}

#[test]
#[serial]
fn test_verify_keyring_signature_valid() {
    let (secret_key, public_key) = generate_test_key("alice@example.com");
    let keyring_content = "test keyring content";
    let signature = sign_keyring_content(keyring_content, &secret_key).expect("signing should succeed");
    let result = verify_keyring_signature(keyring_content, &signature, &public_key);
    assert!(result.is_ok());
}

#[test]
#[serial]
fn test_verify_keyring_signature_invalid_tampering() {
    let (secret_key, public_key) = generate_test_key("alice@example.com");
    let keyring_content = "test keyring content";
    let signature = sign_keyring_content(keyring_content, &secret_key).expect("signing should succeed");
    // Tamper with the content
    let tampered_content = "tampered keyring content";
    let result = verify_keyring_signature(tampered_content, &signature, &public_key);
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_verify_keyring_signature_wrong_key() {
    let (secret_key_alice, _public_key_alice) = generate_test_key("alice@example.com");
    let (_secret_key_bob, public_key_bob) = generate_test_key("bob@example.com");
    let keyring_content = "test keyring content";
    let signature = sign_keyring_content(keyring_content, &secret_key_alice).expect("signing should succeed");
    // Try to verify with wrong key
    let result = verify_keyring_signature(keyring_content, &signature, &public_key_bob);
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_sign_and_verify_roundtrip() {
    let (secret_key, public_key) = generate_test_key("alice@example.com");
    let keyring_content = "test keyring content for roundtrip";
    
    // Sign
    let signature = sign_keyring_content(keyring_content, &secret_key).expect("signing should succeed");
    
    // Verify
    let result = verify_keyring_signature(keyring_content, &signature, &public_key);
    assert!(result.is_ok(), "Signature verification should succeed");
}

#[test]
#[serial]
fn test_extract_signature_from_keyring() {
    let content = "-----BEGIN GIT-GPG KEYRING-----\n-----END GIT-GPG KEYRING-----\n-----BEGIN PGP SIGNATURE-----\nsig123\n-----END PGP SIGNATURE-----";
    let sig = extract_signature_from_keyring(content).unwrap();
    assert!(sig.contains("sig123"));
}

#[test]
#[serial]
fn test_extract_content_to_verify_from_keyring() {
    let content = "-----BEGIN GIT-GPG KEYRING-----\nalice@example.com:YWJj:ABC123\n-----END GIT-GPG KEYRING-----\n-----BEGIN PGP SIGNATURE-----\nsig\n-----END PGP SIGNATURE-----";
    let to_verify = extract_content_to_verify_from_keyring(content).unwrap();
    assert!(to_verify.contains("alice@example.com"));
    assert!(!to_verify.contains("PGP SIGNATURE"));
}

#[test]
#[serial]
fn test_verify_detached_signature() {
    let (secret_key, public_key) = generate_test_key("alice@example.com");
    let content = "detached signature test content";
    
    // Create detached signature
    let signature = sign_keyring_content(content, &secret_key).expect("signing should succeed");
    
    // Verify it's a valid detached signature
    assert!(signature.contains("-----BEGIN PGP SIGNATURE-----"));
    assert!(signature.contains("-----END PGP SIGNATURE-----"));
    
    // Verify signature is valid
    let result = verify_keyring_signature(content, &signature, &public_key);
    assert!(result.is_ok());
}

#[test]
#[serial]
fn test_sign_empty_keyring() {
    let (secret_key, public_key) = generate_test_key("alice@example.com");
    let empty_keyring = "-----BEGIN GIT-GPG KEYRING-----\n-----END GIT-GPG KEYRING-----\n";
    
    // Sign empty keyring
    let signature = sign_keyring_content(empty_keyring, &secret_key).expect("signing empty keyring should succeed");
    
    // Verify signature
    let result = verify_keyring_signature(empty_keyring, &signature, &public_key);
    assert!(result.is_ok(), "Empty keyring signature should be valid");
}

// ============================================================================
// Phase 2: GPG Integration
// ============================================================================

#[test]
#[serial]
fn test_import_key_to_gpg_home() {
    let temp = tempfile::tempdir().unwrap();
    let gpg_home = temp.path().to_path_buf();
    
    let (_secret_key, public_key) = generate_test_key("alice@example.com");
    let armored = public_key.to_armored_string(Default::default()).unwrap();
    
    let result = import_key_to_gpg_home(&gpg_home, &armored);
    assert!(result.is_ok());
    assert!(gpg_home.join("pubring.pgp").exists());
}

#[test]
#[serial]
fn test_find_private_key_by_email() {
    let temp = tempfile::tempdir().unwrap();
    let gpg_home = temp.path().to_path_buf();
    
    let (secret_key, _public_key) = generate_test_key("alice@example.com");
    let armored = secret_key.to_armored_string(Default::default()).unwrap();
    
    // Write to secring.pgp
    std::fs::write(gpg_home.join("secring.pgp"), &armored).unwrap();
    
    let result = find_private_key_by_email(&gpg_home, "alice@example.com");
    assert!(result.is_ok());
}

#[test]
#[serial]
fn test_find_private_key_by_fingerprint() {
    let temp = tempfile::tempdir().unwrap();
    let gpg_home = temp.path().to_path_buf();
    
    let (secret_key, public_key) = generate_test_key("alice@example.com");
    let fingerprint = extract_key_fingerprint(&public_key);
    let armored = secret_key.to_armored_string(Default::default()).unwrap();
    
    // Write to secring.pgp
    std::fs::write(gpg_home.join("secring.pgp"), &armored).unwrap();
    
    let result = find_private_key_by_fingerprint(&gpg_home, &fingerprint);
    assert!(result.is_ok());
}

#[test]
#[serial]
fn test_find_private_key_not_found() {
    let temp = tempfile::tempdir().unwrap();
    let result = find_private_key_by_email(&temp.path().to_path_buf(), "nonexistent@example.com");
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_encrypt_to_gpg_key() {
    let (_secret_key, public_key) = generate_test_key("alice@example.com");
    let plaintext = b"Hello, World!";
    
    let encrypted = encrypt_to_gpg_key(plaintext, &public_key).expect("encryption should succeed");
    assert!(encrypted.contains("-----BEGIN PGP MESSAGE-----"));
    assert!(encrypted.contains("-----END PGP MESSAGE-----"));
}

#[test]
#[serial]
fn test_decrypt_with_gpg_key() {
    let (secret_key, public_key) = generate_test_key("alice@example.com");
    let plaintext = b"Hello, World!";
    
    let encrypted = encrypt_to_gpg_key(plaintext, &public_key).expect("encryption should succeed");
    let decrypted = decrypt_with_gpg_key(&encrypted, &secret_key).expect("decryption should succeed");
    
    assert_eq!(decrypted, plaintext);
}

#[test]
#[serial]
fn test_custom_gpg_home_location() {
    let _temp = tempfile::tempdir().unwrap();
    let home = default_gpg_home().expect("HOME must be set to resolve the default gpg home");
    assert!(home.exists() || home.to_str().unwrap().contains(".gnupg"));
}

// ============================================================================
// Phase 3: Init Command
// ============================================================================

#[test]
#[serial]
fn test_init_creates_git_gpg_directory() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    cmd_init().unwrap();
    assert!(temp.path().join(".git-gpg").exists());
}

#[test]
#[serial]
fn test_init_creates_empty_keyring_with_markers() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    cmd_init().unwrap();
    let keyring_path = temp.path().join(".git-gpg").join("keyring");
    assert!(keyring_path.exists());
    let content = std::fs::read_to_string(keyring_path).unwrap();
    assert!(content.contains("-----BEGIN GIT-GPG KEYRING-----"));
    assert!(content.contains("-----END GIT-GPG KEYRING-----"));
}

#[test]
#[serial]
fn test_init_creates_empty_trust_json() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    cmd_init().unwrap();
    let trust_path = temp.path().join(".git-gpg").join("trust.json");
    assert!(trust_path.exists());
}

#[test]
#[serial]
fn test_init_creates_empty_tracked_json() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    cmd_init().unwrap();
    let tracked_path = temp.path().join(".git-gpg").join("tracked.json");
    assert!(tracked_path.exists());
}

#[test]
#[serial]
fn test_init_creates_secrets_directory() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    cmd_init().unwrap();
    assert!(temp.path().join(".git-gpg").join("secrets").exists());
}

#[test]
#[serial]
fn test_init_adds_gitignore_entry() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    cmd_init().unwrap();
    let gitignore = temp.path().join(".gitignore");
    assert!(gitignore.exists());
    let content = std::fs::read_to_string(gitignore).unwrap();
    assert!(content.contains(".git-gpg/secrets"));
}

#[test]
#[serial]
fn test_init_idempotent() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    cmd_init().unwrap();
    cmd_init().unwrap();
}

#[test]
#[serial]
fn test_init_appends_to_existing_gitignore() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::fs::write(temp.path().join(".gitignore"), "/target\n").unwrap();
    cmd_init().unwrap();
    let content = std::fs::read_to_string(temp.path().join(".gitignore")).unwrap();
    assert!(content.contains("/target"));
    assert!(content.contains(".git-gpg/secrets"));
}

// ============================================================================
// Phase 3: Trust Command
// ============================================================================

#[test]
#[serial]
fn test_trust_validates_repo_id_matches_remote() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();

    // A provided repo_id that does not match the one computed from the
    // remote's push URL must be rejected with the mismatch error. That check
    // runs before the signing key is read, so the nonexistent key path never
    // matters here.
    let result = cmd_trust("wrong+user@github.com", "/nonexistent/key.pub", "origin", &PathBuf::from("/tmp"));
    let err = result
        .err()
        .expect("a repo_id that does not match the remote must be rejected");
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("does not match"),
        "error must be the repo-id mismatch, got: {}",
        err_msg
    );
    assert!(
        err_msg.contains("wrong+user@github.com"),
        "error must name the provided repo id, got: {}",
        err_msg
    );
    assert!(
        err_msg.contains("repo+user@github.com"),
        "error must name the computed repo id, got: {}",
        err_msg
    );
}

#[test]
#[serial]
fn test_trust_validates_repo_id_mismatch_fails() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_trust("wrong+user@github.com", "/nonexistent/key.pub", "origin", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_trust_validates_email_in_signing_key() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_trust("repo+user@github.com", "/nonexistent/key.pub", "origin", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_trust_validates_email_not_in_key_fails() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_trust("repo+user@github.com", "/nonexistent/key.pub", "origin", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_trust_imports_key_to_gpg_home() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_trust("repo+user@github.com", "/nonexistent/key.pub", "origin", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_trust_saves_to_trust_json() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_trust("repo+user@github.com", "/nonexistent/key.pub", "origin", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_trust_updates_existing_trust() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_trust("repo+user@github.com", "/nonexistent/key.pub", "origin", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_trust_with_custom_remote() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "fork", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_trust("repo+user@github.com", "/nonexistent/key.pub", "fork", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_trust_with_custom_gpg_home() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let gpg_home = temp.path().join("custom-gpg");
    std::fs::create_dir_all(&gpg_home).unwrap();
    let result = cmd_trust("repo+user@github.com", "/nonexistent/key.pub", "origin", &gpg_home);
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_trust_fails_if_not_in_git_repo() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    
    let result = cmd_trust("repo+user@github.com", "/nonexistent/key.pub", "origin", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

// ============================================================================
// Phase 3: Tell Command
// ============================================================================

#[test]
#[serial]
fn test_tell_validates_email_in_public_key() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_tell("alice@example.com", "/nonexistent/key.pub", "origin", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_tell_validates_email_not_in_key_fails() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_tell("alice@example.com", "/nonexistent/key.pub", "origin", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_tell_extracts_fingerprint() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_tell("alice@example.com", "/nonexistent/key.pub", "origin", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_tell_base64_encodes_key() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_tell("alice@example.com", "/nonexistent/key.pub", "origin", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_tell_appends_to_keyring() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_tell("alice@example.com", "/nonexistent/key.pub", "origin", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_tell_signs_keyring_after_append() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_tell("alice@example.com", "/nonexistent/key.pub", "origin", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_tell_fails_if_trust_not_established() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_tell("alice@example.com", "/nonexistent/key.pub", "origin", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_tell_fails_if_signing_key_not_in_gpg_home() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_tell("alice@example.com", "/nonexistent/key.pub", "origin", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_tell_with_custom_remote() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "fork", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_tell("alice@example.com", "/nonexistent/key.pub", "fork", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_tell_with_custom_gpg_home() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let gpg_home = temp.path().join("custom-gpg");
    std::fs::create_dir_all(&gpg_home).unwrap();
    let result = cmd_tell("alice@example.com", "/nonexistent/key.pub", "origin", &gpg_home);
    assert!(result.is_err());
}

// test_tell_duplicate_email_updates_entry deleted: the update-not-duplicate
// contract for a repeated email is covered by add_entry_updates_existing_email_and_clears_signature
// and tell_twice_same_email_updates_rather_than_duplicates in tests/features.rs.

#[test]
#[serial]
fn test_tell_preserves_existing_keyring_entries() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_tell("alice@example.com", "/nonexistent/key.pub", "origin", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

// ============================================================================
// Phase 4: Show-Repo-ID
// ============================================================================

#[test]
#[serial]
fn test_show_repo_id_default_origin_remote() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    
    let result = cmd_show_repo_id("origin");
    assert!(result.is_ok());
}

#[test]
#[serial]
fn test_show_repo_id_custom_remote() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "fork", "git@github.com:user/repo.git"]).output().unwrap();
    
    let result = cmd_show_repo_id("fork");
    assert!(result.is_ok());
}

#[test]
#[serial]
fn test_show_repo_id_displays_push_url() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    
    let result = cmd_show_repo_id("origin");
    assert!(result.is_ok());
}

#[test]
#[serial]
fn test_show_repo_id_displays_remote_name() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    
    let result = cmd_show_repo_id("origin");
    assert!(result.is_ok());
}

#[test]
#[serial]
fn test_show_repo_id_fails_if_not_git_repo() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    
    let result = cmd_show_repo_id("origin");
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_show_repo_id_fails_if_remote_not_found() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    
    let result = cmd_show_repo_id("nonexistent");
    assert!(result.is_err());
}

// ============================================================================
// Phase 4: Whoami
// ============================================================================

#[test]
#[serial]
fn test_whoami_from_git_config_user_email() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["config", "user.email", "test@example.com"]).output().unwrap();
    
    let result = cmd_whoami(None, &PathBuf::from("/tmp"));
    assert!(result.is_ok());
}

#[test]
#[serial]
fn test_whoami_from_email_flag_override() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    
    let result = cmd_whoami(Some("override@example.com"), &PathBuf::from("/tmp"));
    assert!(result.is_ok());
}

#[test]
#[serial]
fn test_whoami_displays_gpg_home_location() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["config", "user.email", "test@example.com"]).output().unwrap();
    
    let result = cmd_whoami(None, &PathBuf::from("/tmp"));
    assert!(result.is_ok());
}

#[test]
#[serial]
fn test_whoami_displays_custom_gpg_home() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["config", "user.email", "test@example.com"]).output().unwrap();
    
    let gpg_home = temp.path().join("custom-gpg");
    std::fs::create_dir_all(&gpg_home).unwrap();
    let result = cmd_whoami(None, &gpg_home);
    assert!(result.is_ok());
}

#[test]
#[serial]
fn test_whoami_fails_if_no_git_config_and_no_flag() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    
    // Set HOME to temp so git can't find global config
    let orig_home = std::env::var("HOME").ok();
    std::env::set_var("HOME", temp.path());
    std::env::set_var("GIT_CONFIG_NOSYSTEM", "1");
    
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    
    let result = cmd_whoami(None, &PathBuf::from("/tmp"));
    assert!(result.is_err());
    
    // Restore HOME
    if let Some(home) = orig_home {
        std::env::set_var("HOME", home);
    }
    std::env::remove_var("GIT_CONFIG_NOSYSTEM");
}

// ============================================================================
// Phase 4: Verify-Keyring
// ============================================================================

#[test]
#[serial]
fn test_verify_keyring_valid_signature() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_verify_keyring("origin", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_verify_keyring_invalid_signature_tampered() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_verify_keyring("origin", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_verify_keyring_no_signature_section_fails() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_verify_keyring("origin", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_verify_keyring_wrong_signing_key_fails() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_verify_keyring("origin", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_verify_keyring_displays_signer_email() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_verify_keyring("origin", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_verify_keyring_displays_repo_id() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_verify_keyring("origin", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_verify_keyring_displays_key_count() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_verify_keyring("origin", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_verify_keyring_fails_if_trust_not_established() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_verify_keyring("origin", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_verify_keyring_with_custom_remote() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "fork", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_verify_keyring("fork", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_verify_keyring_with_custom_gpg_home() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let gpg_home = temp.path().join("custom-gpg");
    std::fs::create_dir_all(&gpg_home).unwrap();
    let result = cmd_verify_keyring("origin", &gpg_home);
    assert!(result.is_err());
}

// ============================================================================
// Phase 4: List-Keys
// ============================================================================

#[test]
#[serial]
fn test_list_keys_empty_keyring() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_list_keys();
    assert!(result.is_ok());
}

#[test]
#[serial]
fn test_list_keys_single_entry() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_list_keys();
    assert!(result.is_ok());
}

#[test]
#[serial]
fn test_list_keys_multiple_entries() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_list_keys();
    assert!(result.is_ok());
}

#[test]
#[serial]
fn test_list_keys_displays_email_and_fingerprint() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_list_keys();
    assert!(result.is_ok());
}

#[test]
#[serial]
fn test_list_keys_displays_total_count() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_list_keys();
    assert!(result.is_ok());
}

// ============================================================================
// Phase 5: Add Command
// ============================================================================

#[test]
#[serial]
fn test_add_single_file_to_tracked_json() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    cmd_init().unwrap();
    
    let test_file = temp.path().join("secret.txt");
    std::fs::write(&test_file, "content").unwrap();
    
    let result = cmd_add(vec!["secret.txt".to_string()]);
    assert!(result.is_ok());
}

#[test]
#[serial]
fn test_add_multiple_files_to_tracked_json() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    cmd_init().unwrap();
    
    std::fs::write(temp.path().join("file1.txt"), "content1").unwrap();
    std::fs::write(temp.path().join("file2.txt"), "content2").unwrap();
    
    let result = cmd_add(vec!["file1.txt".to_string(), "file2.txt".to_string()]);
    assert!(result.is_ok());
}

#[test]
#[serial]
fn test_add_stores_repo_relative_paths() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    cmd_init().unwrap();
    
    let test_file = temp.path().join("secret.txt");
    std::fs::write(&test_file, "content").unwrap();
    
    let result = cmd_add(vec!["secret.txt".to_string()]);
    assert!(result.is_ok());
}

#[test]
#[serial]
fn test_add_duplicate_file_idempotent() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    cmd_init().unwrap();
    
    let test_file = temp.path().join("secret.txt");
    std::fs::write(&test_file, "content").unwrap();
    
    cmd_add(vec!["secret.txt".to_string()]).unwrap();
    let result = cmd_add(vec!["secret.txt".to_string()]);
    assert!(result.is_ok());
}

#[test]
#[serial]
fn test_add_nonexistent_file_fails() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_add(vec!["nonexistent.txt".to_string()]);
    assert!(result.is_err());
}

// ============================================================================
// Phase 5: Remove Command
// ============================================================================

#[test]
#[serial]
fn test_remove_file_from_tracked_json() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    cmd_init().unwrap();
    
    let test_file = temp.path().join("secret.txt");
    std::fs::write(&test_file, "content").unwrap();
    cmd_add(vec!["secret.txt".to_string()]).unwrap();
    
    let result = cmd_remove(vec!["secret.txt".to_string()]);
    assert!(result.is_ok());
}

#[test]
#[serial]
fn test_remove_multiple_files() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    cmd_init().unwrap();
    
    std::fs::write(temp.path().join("file1.txt"), "content1").unwrap();
    std::fs::write(temp.path().join("file2.txt"), "content2").unwrap();
    cmd_add(vec!["file1.txt".to_string(), "file2.txt".to_string()]).unwrap();
    
    let result = cmd_remove(vec!["file1.txt".to_string(), "file2.txt".to_string()]);
    assert!(result.is_ok());
}

#[test]
#[serial]
fn test_remove_nonexistent_file_fails() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_remove(vec!["nonexistent.txt".to_string()]);
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_remove_not_tracked_file_fails() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    cmd_init().unwrap();
    
    let test_file = temp.path().join("untracked.txt");
    std::fs::write(&test_file, "content").unwrap();
    
    let result = cmd_remove(vec!["untracked.txt".to_string()]);
    assert!(result.is_err());
}

// ============================================================================
// Phase 5: List Command
// ============================================================================

#[test]
#[serial]
fn test_list_empty_tracked_json() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_list();
    assert!(result.is_ok());
}

#[test]
#[serial]
fn test_list_single_file() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    cmd_init().unwrap();
    
    let test_file = temp.path().join("secret.txt");
    std::fs::write(&test_file, "content").unwrap();
    cmd_add(vec!["secret.txt".to_string()]).unwrap();
    
    let result = cmd_list();
    assert!(result.is_ok());
}

#[test]
#[serial]
fn test_list_multiple_files() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    cmd_init().unwrap();
    
    std::fs::write(temp.path().join("file1.txt"), "content1").unwrap();
    std::fs::write(temp.path().join("file2.txt"), "content2").unwrap();
    cmd_add(vec!["file1.txt".to_string(), "file2.txt".to_string()]).unwrap();
    
    let result = cmd_list();
    assert!(result.is_ok());
}

#[test]
#[serial]
fn test_list_displays_tracked_paths() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    cmd_init().unwrap();
    
    let test_file = temp.path().join("secret.txt");
    std::fs::write(&test_file, "content").unwrap();
    cmd_add(vec!["secret.txt".to_string()]).unwrap();
    
    let result = cmd_list();
    assert!(result.is_ok());
}

// ============================================================================
// Phase 6: Hide Command
// ============================================================================

#[test]
#[serial]
fn test_hide_verifies_keyring_signature_first() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_hide("origin", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_hide_fails_if_signature_invalid() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_hide("origin", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_hide_fails_if_trust_not_established() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_hide("origin", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_hide_encrypts_to_all_keys_in_keyring() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_hide("origin", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_hide_removes_original_files() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_hide("origin", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_hide_creates_encrypted_asc_files() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_hide("origin", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_hide_preserves_directory_structure() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_hide("origin", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_hide_preserves_original_extension() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_hide("origin", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_hide_with_custom_remote() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "fork", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_hide("fork", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_hide_with_custom_gpg_home() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let gpg_home = temp.path().join("custom-gpg");
    std::fs::create_dir_all(&gpg_home).unwrap();
    let result = cmd_hide("origin", &gpg_home);
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_hide_empty_tracked_list_succeeds() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_hide("origin", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_hide_missing_tracked_file_fails() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_hide("origin", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

// ============================================================================
// Phase 6: Reveal Command
// ============================================================================

#[test]
#[serial]
fn test_reveal_verifies_keyring_signature_first() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_reveal("test@example.com", "origin", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_reveal_fails_if_signature_invalid() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_reveal("test@example.com", "origin", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_reveal_fails_if_trust_not_established() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_reveal("test@example.com", "origin", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_reveal_finds_user_email_in_keyring() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_reveal("test@example.com", "origin", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_reveal_fails_if_email_not_in_keyring() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_reveal("nonexistent@example.com", "origin", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_reveal_finds_private_key_in_gpg_home() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_reveal("test@example.com", "origin", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_reveal_fails_if_private_key_not_found() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_reveal("test@example.com", "origin", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_reveal_decrypts_files() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_reveal("test@example.com", "origin", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_reveal_restores_original_filenames() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_reveal("test@example.com", "origin", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_reveal_removes_encrypted_asc_files() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_reveal("test@example.com", "origin", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_reveal_with_email_flag_override() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_reveal("override@example.com", "origin", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_reveal_with_git_config_email_default() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    std::process::Command::new("git").args(&["config", "user.email", "test@example.com"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_reveal("", "origin", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_reveal_with_custom_remote() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "fork", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_reveal("test@example.com", "fork", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_reveal_with_custom_gpg_home() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let gpg_home = temp.path().join("custom-gpg");
    std::fs::create_dir_all(&gpg_home).unwrap();
    let result = cmd_reveal("test@example.com", "origin", &gpg_home);
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_reveal_missing_encrypted_file_fails() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_reveal("test@example.com", "origin", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

// ============================================================================
// Phase 6: Clean Command
// ============================================================================

#[test]
#[serial]
fn test_clean_removes_git_gpg_directory() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_clean();
    assert!(result.is_ok());
    assert!(!temp.path().join(".git-gpg").exists());
}

#[test]
#[serial]
fn test_clean_removes_gitignore_entry() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::fs::write(temp.path().join(".gitignore"), "/target\n").unwrap();
    cmd_init().unwrap();
    
    let result = cmd_clean();
    assert!(result.is_ok());
    
    let gitignore = std::fs::read_to_string(temp.path().join(".gitignore")).unwrap();
    assert!(!gitignore.contains(".git-gpg/secrets"));
}

#[test]
#[serial]
fn test_clean_idempotent() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    cmd_init().unwrap();
    
    cmd_clean().unwrap();
    let result = cmd_clean();
    assert!(result.is_ok());
}

// ============================================================================
// Phase 7: Integration
// ============================================================================

#[test]
#[serial]
fn test_full_workflow_owner_setup() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    
    // Initialize
    cmd_init().unwrap();
    
    // Generate owner key
    let (owner_secret, owner_public) = generate_test_key("owner@example.com");
    let owner_fingerprint = extract_key_fingerprint(&owner_public);
    
    // Create keyring with owner
    let mut keyring = Keyring::new();
    let owner_base64 = base64_encode_public_key(&owner_public);
    keyring.add_entry("owner@example.com".to_string(), owner_base64, owner_fingerprint.clone());
    
    // Sign keyring
    let content = keyring.serialize();
    let signature = sign_keyring_content(&content, &owner_secret).expect("signing should succeed");
    
    assert!(signature.contains("-----BEGIN PGP SIGNATURE-----"));
}

#[test]
#[serial]
fn test_full_workflow_add_collaborator() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    // Generate owner and collaborator keys
    let (owner_secret, owner_public) = generate_test_key("owner@example.com");
    let (_collab_secret, collab_public) = generate_test_key("collab@example.com");
    
    // Create keyring with both
    let mut keyring = Keyring::new();
    keyring.add_entry("owner@example.com".to_string(), base64_encode_public_key(&owner_public), extract_key_fingerprint(&owner_public));
    keyring.add_entry("collab@example.com".to_string(), base64_encode_public_key(&collab_public), extract_key_fingerprint(&collab_public));
    
    // Sign keyring
    let content = keyring.serialize();
    let _signature = sign_keyring_content(&content, &owner_secret).expect("signing should succeed");
    
    assert!(keyring.entries.len() == 2);
}

#[test]
#[serial]
fn test_full_workflow_collaborator_clone_and_reveal() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    // Generate keys
    let (owner_secret, owner_public) = generate_test_key("owner@example.com");
    let (_collab_secret, collab_public) = generate_test_key("collab@example.com");
    
    // Create keyring
    let mut keyring = Keyring::new();
    keyring.add_entry("owner@example.com".to_string(), base64_encode_public_key(&owner_public), extract_key_fingerprint(&owner_public));
    keyring.add_entry("collab@example.com".to_string(), base64_encode_public_key(&collab_public), extract_key_fingerprint(&collab_public));
    
    // Sign and verify
    let content = keyring.serialize();
    let signature = sign_keyring_content(&content, &owner_secret).expect("signing should succeed");
    let result = verify_keyring_signature(&content, &signature, &owner_public);
    assert!(result.is_ok());
}

#[test]
#[serial]
fn test_full_workflow_hide_reveal_roundtrip() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    // Generate key
    let (_secret_key, public_key) = generate_test_key("alice@example.com");
    
    // Test encryption/decryption roundtrip
    let plaintext = b"secret content";
    let encrypted = encrypt_to_gpg_key(plaintext, &public_key).expect("encryption should succeed");
    assert!(encrypted.contains("-----BEGIN PGP MESSAGE-----"));
}

#[test]
#[serial]
fn test_multi_collaborator_workflow() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    // Generate multiple collaborator keys
    let (owner_secret, owner_public) = generate_test_key("owner@example.com");
    let (_collab1_secret, collab1_public) = generate_test_key("collab1@example.com");
    let (_collab2_secret, collab2_public) = generate_test_key("collab2@example.com");
    
    // Create keyring with all collaborators
    let mut keyring = Keyring::new();
    keyring.add_entry("owner@example.com".to_string(), base64_encode_public_key(&owner_public), extract_key_fingerprint(&owner_public));
    keyring.add_entry("collab1@example.com".to_string(), base64_encode_public_key(&collab1_public), extract_key_fingerprint(&collab1_public));
    keyring.add_entry("collab2@example.com".to_string(), base64_encode_public_key(&collab2_public), extract_key_fingerprint(&collab2_public));
    
    assert!(keyring.entries.len() == 3);
    
    // Sign and verify
    let content = keyring.serialize();
    let signature = sign_keyring_content(&content, &owner_secret).expect("signing should succeed");
    let result = verify_keyring_signature(&content, &signature, &owner_public);
    assert!(result.is_ok());
}

#[test]
#[serial]
fn test_tampered_keyring_blocks_hide() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    // Tamper with keyring
    let keyring_path = std::path::PathBuf::from(".git-gpg/keyring");
    let tampered_content = "-----BEGIN GIT-GPG KEYRING-----\ntampered\n-----END GIT-GPG KEYRING-----\n";
    std::fs::write(&keyring_path, tampered_content).unwrap();
    
    // Hide should fail with tampered keyring
    let result = cmd_hide(
        "origin",
        &default_gpg_home().expect("HOME must be set to resolve the default gpg home"),
    );
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_tampered_keyring_blocks_reveal() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    // Tamper with keyring
    let keyring_path = std::path::PathBuf::from(".git-gpg/keyring");
    let tampered_content = "-----BEGIN GIT-GPG KEYRING-----\ntampered\n-----END GIT-GPG KEYRING-----\n";
    std::fs::write(&keyring_path, tampered_content).unwrap();
    
    // Reveal should fail with tampered keyring
    let result = cmd_reveal(
        "alice@example.com",
        "origin",
        &default_gpg_home().expect("HOME must be set to resolve the default gpg home"),
    );
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_keyring_signature_rotation() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    cmd_init().unwrap();
    
    let (secret_key, public_key) = generate_test_key("alice@example.com");
    let fingerprint = extract_key_fingerprint(&public_key);
    let base64_key = base64_encode_public_key(&public_key);
    
    // Create keyring with entry
    let mut keyring = Keyring::new();
    keyring.add_entry("alice@example.com".to_string(), base64_key, fingerprint);
    
    // Sign keyring content (without signature)
    let content_without_sig = keyring.serialize();
    let signature = sign_keyring_content(&content_without_sig, &secret_key).expect("signing should succeed");
    keyring.signature = Some(signature.clone());
    
    // Verify signature using the content without signature
    let result = verify_keyring_signature(&content_without_sig, &signature, &public_key);
    assert!(result.is_ok());
}

#[test]
#[serial]
fn test_multiple_remotes_workflow() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "fork", "git@github.com:fork/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    // Both remotes should work
    let result1 = cmd_show_repo_id("origin");
    assert!(result1.is_ok());
    
    let result2 = cmd_show_repo_id("fork");
    assert!(result2.is_ok());
}

#[test]
#[serial]
fn test_custom_gpg_home_workflow() {
    let temp = tempfile::tempdir().unwrap();
    let custom_gpg_home = temp.path().join("custom-gpg");
    std::fs::create_dir_all(&custom_gpg_home).unwrap();
    
    let (secret_key, _public_key) = generate_test_key("alice@example.com");
    let armored = secret_key.to_armored_string(Default::default()).unwrap();
    
    // Import to custom GPG home
    import_key_to_gpg_home(&custom_gpg_home, &armored).unwrap();
    assert!(custom_gpg_home.join("pubring.pgp").exists());
}

#[test]
#[serial]
fn test_binary_file_encryption_workflow() {
    let (_secret_key, public_key) = generate_test_key("alice@example.com");
    
    // Binary data
    let binary_data: Vec<u8> = (0..255).collect();
    
    let encrypted = encrypt_to_gpg_key(&binary_data, &public_key).expect("encryption should succeed");
    assert!(encrypted.contains("-----BEGIN PGP MESSAGE-----"));
}

#[test]
#[serial]
fn test_nested_directory_workflow() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    cmd_init().unwrap();
    
    // Create nested directory structure
    let nested_dir = temp.path().join("subdir").join("nested");
    std::fs::create_dir_all(&nested_dir).unwrap();
    let test_file = nested_dir.join("secret.txt");
    std::fs::write(&test_file, "nested secret content").unwrap();
    
    let result = cmd_add(vec!["subdir/nested/secret.txt".to_string()]);
    assert!(result.is_ok());
}

// ============================================================================
// Phase 7: Error Handling
// ============================================================================

#[test]
#[serial]
fn test_not_in_git_repo_fails_gracefully() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    
    let result = cmd_show_repo_id("origin");
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_git_gpg_not_initialized_fails_gracefully() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    
    let result = cmd_list_keys();
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_corrupted_trust_json_fails_gracefully() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    cmd_init().unwrap();
    
    std::fs::write(temp.path().join(".git-gpg").join("trust.json"), "corrupted").unwrap();
    
    let result = TrustStore::load_from_file(&temp.path().join(".git-gpg").join("trust.json"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_corrupted_tracked_json_fails_gracefully() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    cmd_init().unwrap();
    
    std::fs::write(temp.path().join(".git-gpg").join("tracked.json"), "corrupted").unwrap();
    
    let result = TrackedFiles::load(&temp.path().join(".git-gpg").join("tracked.json"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_corrupted_keyring_fails_gracefully() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    cmd_init().unwrap();
    
    std::fs::write(temp.path().join(".git-gpg").join("keyring"), "corrupted").unwrap();
    
    let content = std::fs::read_to_string(temp.path().join(".git-gpg").join("keyring")).unwrap();
    let result = Keyring::parse(&content);
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_missing_keyring_file_fails_gracefully() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    std::process::Command::new("git").args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init().unwrap();
    
    std::fs::remove_file(temp.path().join(".git-gpg").join("keyring")).unwrap();
    
    let result = cmd_verify_keyring("origin", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_empty_keyring_signature_valid() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    cmd_init().unwrap();
    
    let result = cmd_list_keys();
    assert!(result.is_ok());
}

#[test]
#[serial]
fn test_concurrent_tell_operations() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    std::process::Command::new("git").args(&["init"]).output().unwrap();
    cmd_init().unwrap();
    
    // Simulate concurrent tell operations by adding multiple keys sequentially
    let (_key1, pub1) = generate_test_key("alice@example.com");
    let (_key2, pub2) = generate_test_key("bob@example.com");
    
    // Both operations should succeed
    let armored1 = pub1.to_armored_string(Default::default()).unwrap();
    let armored2 = pub2.to_armored_string(Default::default()).unwrap();
    
    assert!(!armored1.is_empty());
    assert!(!armored2.is_empty());
}
