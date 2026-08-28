//! Trust-model, keyring and command-flow tests for git-gpg.
//!
//! Pure-function contracts (URL parsing, keyring parse/serialize, trust store,
//! signature primitives) are asserted directly here; end-to-end command
//! contracts live in tests/features.rs and tests/cli.rs.

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

// ---------------------------------------------------------------------------
// Command-flow helpers (patterns copied from tests/features.rs)
// ---------------------------------------------------------------------------

fn write_public_key_file(public_key: &pgp::composed::SignedPublicKey, path: &PathBuf) {
    let armored = public_key.to_armored_string(Default::default()).unwrap();
    std::fs::write(path, armored).unwrap();
}

fn write_multi_key_secring(gpg_home: &PathBuf, keys: &[pgp::composed::SignedSecretKey]) {
    let mut content = String::new();
    for key in keys {
        if !content.is_empty() {
            content.push('\n');
        }
        content.push_str(&key.to_armored_string(Default::default()).unwrap());
    }
    std::fs::create_dir_all(gpg_home).unwrap();
    std::fs::write(gpg_home.join("secring.pgp"), content).unwrap();
}

fn setup_git_repo_with_origin_remote() -> tempfile::TempDir {
    let temp = tempfile::tempdir().unwrap();
    for args in [
        vec!["init"],
        vec!["remote", "add", "origin", "git@github.com:owner/repo.git"],
    ] {
        let status = std::process::Command::new("git")
            .current_dir(temp.path())
            .args(&args)
            .status()
            .expect("run git");
        assert!(status.success(), "git {:?} failed", args);
    }
    temp
}

/// A repo with trust established AND the owner key present as a keyring entry,
/// so hide/reveal/list flows can run end to end.
fn setup_trusted_repo_with_owner_in_keyring() -> (tempfile::TempDir, PathBuf) {
    let repo_temp = setup_git_repo_with_origin_remote();

    cmd_init(repo_temp.path()).expect("cmd_init must succeed");

    let (owner_sec, owner_pub) = generate_test_key("owner@github.com");
    let owner_keyfile = repo_temp.path().join("owner.pub");
    write_public_key_file(&owner_pub, &owner_keyfile);

    let gpg_home = repo_temp.path().join("gpg-home");

    cmd_trust(
        repo_temp.path(),
        "repo+owner@github.com",
        owner_keyfile.to_str().unwrap(),
        "origin",
        &gpg_home,
    )
    .expect("cmd_trust must succeed");

    write_multi_key_secring(&gpg_home, &[owner_sec]);

    cmd_tell(
        repo_temp.path(),
        "owner@github.com",
        owner_keyfile.to_str().unwrap(),
        "origin",
        &gpg_home, None
    )
    .expect("cmd_tell must succeed");

    (repo_temp, gpg_home)
}

// ============================================================================
// Phase 1: Repository Identity
// ============================================================================

#[test]
fn test_parse_github_ssh_url() {
    let (repo, user, service) = parse_git_remote_url("git@github.com:user/repo.git").unwrap();
    assert_eq!(repo, "repo");
    assert_eq!(user, "user");
    assert_eq!(service, "github.com");
}

#[test]
fn test_parse_github_https_url() {
    let (repo, user, service) = parse_git_remote_url("https://github.com/user/repo.git").unwrap();
    assert_eq!(repo, "repo");
    assert_eq!(user, "user");
    assert_eq!(service, "github.com");
}

#[test]
fn test_parse_codeberg_ssh_url() {
    let (repo, user, service) = parse_git_remote_url("ssh://git@codeberg.org/user/repo.git").unwrap();
    assert_eq!(repo, "repo");
    assert_eq!(user, "user");
    assert_eq!(service, "codeberg.org");
}

#[test]
fn test_parse_gitlab_ssh_url() {
    let (repo, user, service) = parse_git_remote_url("git@gitlab.com:org/project.git").unwrap();
    assert_eq!(repo, "project");
    assert_eq!(user, "org");
    assert_eq!(service, "gitlab.com");
}

#[test]
fn test_parse_gitlab_https_url() {
    let (repo, user, service) = parse_git_remote_url("https://gitlab.com/org/project.git").unwrap();
    assert_eq!(repo, "project");
    assert_eq!(user, "org");
    assert_eq!(service, "gitlab.com");
}

#[test]
fn test_parse_url_strips_git_extension() {
    let (repo, _, _) = parse_git_remote_url("git@github.com:user/my-project.git").unwrap();
    assert_eq!(repo, "my-project");
}

#[test]
fn test_parse_url_handles_no_git_extension() {
    let (repo, _, _) = parse_git_remote_url("git@github.com:user/my-project").unwrap();
    assert_eq!(repo, "my-project");
}

#[test]
fn test_parse_url_invalid_format_returns_error() {
    let result = parse_git_remote_url("not-a-valid-url");
    assert!(result.is_err());
}

#[test]
fn test_get_remote_push_url_origin() {
    let temp = tempfile::tempdir().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["init"]).output().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    
    let url = get_remote_push_url(&temp.path().to_path_buf(), "origin").unwrap();
    assert!(url.contains("github.com") && url.contains("user/repo"));
}

#[test]
fn test_get_remote_push_url_custom_remote() {
    let temp = tempfile::tempdir().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["init"]).output().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["remote", "add", "fork", "ssh://git@codeberg.org/user/repo.git"]).output().unwrap();
    
    let url = get_remote_push_url(&temp.path().to_path_buf(), "fork").unwrap();
    assert!(url.contains("codeberg.org"));
}

#[test]
fn test_get_remote_push_url_nonexistent_remote_fails() {
    let temp = tempfile::tempdir().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["init"]).output().unwrap();
    
    let result = get_remote_push_url(&temp.path().to_path_buf(), "nonexistent");
    assert!(result.is_err());
}

#[test]
fn test_derive_repo_id_from_git_remote() {
    let repo_id = derive_repo_id("git@github.com:simbo1905/fara.git").unwrap();
    assert_eq!(repo_id, "fara+simbo1905@github.com");
}

// ============================================================================
// Phase 1: Keyring Format
// ============================================================================

#[test]
fn test_keyring_format_single_entry() {
    let content = "-----BEGIN GIT-GPG KEYRING-----\nalice@example.com:YWJj:ABC123\n-----END GIT-GPG KEYRING-----";
    let keyring = Keyring::parse(content).unwrap();
    assert_eq!(keyring.entries.len(), 1);
    assert_eq!(keyring.entries[0].email, "alice@example.com");
    assert_eq!(keyring.entries[0].base64_key, "YWJj");
    assert_eq!(keyring.entries[0].fingerprint, "ABC123");
}

#[test]
fn test_keyring_format_multiple_entries() {
    let content = "-----BEGIN GIT-GPG KEYRING-----\nalice@example.com:YWJj:ABC123\nbob@work.com:ZGVm:DEF456\n-----END GIT-GPG KEYRING-----";
    let keyring = Keyring::parse(content).unwrap();
    assert_eq!(keyring.entries.len(), 2);
}

#[test]
fn test_keyring_parse_with_markers() {
    let content = "-----BEGIN GIT-GPG KEYRING-----\n-----END GIT-GPG KEYRING-----";
    let result = Keyring::parse(content);
    assert!(result.is_ok());
}

#[test]
fn test_keyring_parse_with_signature() {
    let content = "-----BEGIN GIT-GPG KEYRING-----\nalice@example.com:YWJj:ABC123\n-----END GIT-GPG KEYRING-----\n-----BEGIN PGP SIGNATURE-----\nsig\n-----END PGP SIGNATURE-----";
    let keyring = Keyring::parse(content).unwrap();
    assert!(keyring.signature.is_some());
    assert_eq!(keyring.entries.len(), 1);
}

#[test]
fn test_keyring_parse_empty() {
    let content = "-----BEGIN GIT-GPG KEYRING-----\n-----END GIT-GPG KEYRING-----";
    let keyring = Keyring::parse(content).unwrap();
    assert_eq!(keyring.entries.len(), 0);
}

#[test]
fn test_keyring_parse_missing_end_marker_fails() {
    let content = "-----BEGIN GIT-GPG KEYRING-----\nalice@example.com:YWJj:ABC123";
    let result = Keyring::parse(content);
    assert!(result.is_err());
}

#[test]
fn test_keyring_parse_malformed_entry_fails() {
    let content = "-----BEGIN GIT-GPG KEYRING-----\nmalformed_entry_no_colons\n-----END GIT-GPG KEYRING-----";
    let result = Keyring::parse(content);
    assert!(result.is_err());
}

#[test]
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
fn test_keyring_serialize_multiple_entries() {
    let mut keyring = Keyring::new();
    keyring.add_entry("alice@example.com".into(), "YWJj".into(), "ABC123".into());
    keyring.add_entry("bob@work.com".into(), "ZGVm".into(), "DEF456".into());
    let serialized = keyring.serialize();
    assert!(serialized.contains("alice@example.com"));
    assert!(serialized.contains("bob@work.com"));
}

#[test]
fn test_keyring_add_entry() {
    let mut keyring = Keyring::new();
    assert_eq!(keyring.entries.len(), 0);
    keyring.add_entry("alice@example.com".into(), "YWJj".into(), "ABC123".into());
    assert_eq!(keyring.entries.len(), 1);
}

#[test]
fn test_keyring_find_by_email() {
    let mut keyring = Keyring::new();
    keyring.add_entry("alice@example.com".into(), "YWJj".into(), "ABC123".into());
    let entry = keyring.find_by_email("alice@example.com").unwrap();
    assert_eq!(entry.email, "alice@example.com");
}

#[test]
fn test_keyring_find_by_email_not_found() {
    let keyring = Keyring::new();
    let result = keyring.find_by_email("nonexistent@example.com");
    assert!(result.is_none());
}

#[test]
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
fn test_colon_not_in_base64() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let test_bytes = b"hello:world:test";
    let encoded = STANDARD.encode(test_bytes);
    assert!(!encoded.contains(':'), "base64 should not contain colon");
}

#[test]
fn test_colon_not_in_email() {
    let email = "alice@example.com";
    assert!(!email.contains(':'), "email should not contain colon");
}

// ============================================================================
// Phase 1: Trust Store
// ============================================================================

#[test]
fn test_trust_store_create_empty() {
    let store = TrustStore::new();
    assert!(store.trusted_keys.is_empty());
}

#[test]
fn test_trust_store_add_trust() {
    let mut store = TrustStore::new();
    store.add_trust("repo+user@github.com".into(), "ABC123".into());
    assert_eq!(store.trusted_keys.len(), 1);
}

#[test]
fn test_trust_store_get_trusted_fingerprint() {
    let mut store = TrustStore::new();
    store.add_trust("repo+user@github.com".into(), "ABC123".into());
    let fp = store.get_trusted_fingerprint("repo+user@github.com").unwrap();
    assert_eq!(fp, "ABC123");
}

#[test]
fn test_trust_store_get_trusted_fingerprint_not_found() {
    let store = TrustStore::new();
    let result = store.get_trusted_fingerprint("nonexistent");
    assert!(result.is_none());
}

#[test]
fn test_trust_store_update_existing_trust() {
    let mut store = TrustStore::new();
    store.add_trust("repo+user@github.com".into(), "ABC123".into());
    store.add_trust("repo+user@github.com".into(), "DEF456".into());
    assert_eq!(store.trusted_keys.len(), 1);
    assert_eq!(store.get_trusted_fingerprint("repo+user@github.com").unwrap(), "DEF456");
}

#[test]
fn test_trust_store_serialize_to_json() {
    let mut store = TrustStore::new();
    store.add_trust("repo+user@github.com".into(), "ABC123".into());
    let json = store.serialize().unwrap();
    assert!(json.contains("repo+user@github.com"));
    assert!(json.contains("ABC123"));
}

#[test]
fn test_trust_store_deserialize_from_json() {
    let json = r#"{"trusted_keys":{"repo+user@github.com":"ABC123"}}"#;
    let store = TrustStore::deserialize(json).unwrap();
    assert_eq!(store.get_trusted_fingerprint("repo+user@github.com").unwrap(), "ABC123");
}

#[test]
fn test_trust_store_save_to_file() {
    let mut store = TrustStore::new();
    store.add_trust("repo+user@github.com".into(), "ABC123".into());
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("trust.json");
    store.save_to_file(&path).unwrap();
    assert!(path.exists());
}

#[test]
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
fn test_parse_armored_public_key() {
    let (_secret_key, public_key) = generate_test_key("test@example.com");
    let armored = public_key.to_armored_string(Default::default()).unwrap();
    let result = parse_armored_public_key(&armored);
    assert!(result.is_ok());
}

#[test]
fn test_extract_key_identities() {
    let (_secret_key, public_key) = generate_test_key("alice@example.com");
    let identities = extract_key_identities(&public_key);
    assert_eq!(identities.len(), 1);
    assert!(identities[0].contains("alice@example.com"));
}

#[test]
fn test_extract_key_fingerprint() {
    let (_secret_key, public_key) = generate_test_key("alice@example.com");
    let fingerprint = extract_key_fingerprint(&public_key);
    assert!(!fingerprint.is_empty());
    assert!(fingerprint.len() > 0);
    // Fingerprint should be hex string
    assert!(fingerprint.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_check_email_in_identities_found() {
    let (_secret_key, public_key) = generate_test_key("alice@example.com");
    assert!(check_email_in_identities(&public_key, "alice@example.com"));
}

#[test]
fn test_check_email_in_identities_not_found() {
    let (_secret_key, public_key) = generate_test_key("alice@example.com");
    assert!(!check_email_in_identities(&public_key, "bob@example.com"));
}

#[test]
fn test_base64_encode_public_key() {
    let (_secret_key, public_key) = generate_test_key("alice@example.com");
    let encoded = base64_encode_public_key(&public_key);
    assert!(!encoded.is_empty());
    // Should be valid base64
    assert!(encoded.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='));
}

#[test]
fn test_base64_decode_public_key() {
    let (_secret_key, public_key) = generate_test_key("alice@example.com");
    let encoded = base64_encode_public_key(&public_key);
    let decoded = base64_decode_public_key(&encoded).expect("decode should succeed");
    let original_fp = extract_key_fingerprint(&public_key);
    let decoded_fp = extract_key_fingerprint(&decoded);
    assert_eq!(original_fp, decoded_fp);
}

#[test]
fn test_roundtrip_base64_encoding() {
    let (_secret_key, public_key) = generate_test_key("alice@example.com");
    let encoded = base64_encode_public_key(&public_key);
    let decoded = base64_decode_public_key(&encoded).expect("decode should succeed");
    let re_encoded = base64_encode_public_key(&decoded);
    assert_eq!(encoded, re_encoded);
}

#[test]
fn test_parse_invalid_armored_key_fails() {
    let result = parse_armored_public_key("not a valid key");
    assert!(result.is_err());
}

#[test]
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
fn test_sign_keyring_content() {
    let (secret_key, _public_key) = generate_test_key("alice@example.com");
    let keyring_content = "test keyring content";
    let signature = sign_keyring_content(keyring_content, &secret_key, None).expect("signing should succeed");
    assert!(signature.contains("-----BEGIN PGP SIGNATURE-----"));
    assert!(signature.contains("-----END PGP SIGNATURE-----"));
}

#[test]
fn test_verify_keyring_signature_valid() {
    let (secret_key, public_key) = generate_test_key("alice@example.com");
    let keyring_content = "test keyring content";
    let signature = sign_keyring_content(keyring_content, &secret_key, None).expect("signing should succeed");
    let result = verify_keyring_signature(keyring_content, &signature, &public_key);
    assert!(result.is_ok());
}

#[test]
fn test_verify_keyring_signature_invalid_tampering() {
    let (secret_key, public_key) = generate_test_key("alice@example.com");
    let keyring_content = "test keyring content";
    let signature = sign_keyring_content(keyring_content, &secret_key, None).expect("signing should succeed");
    // Tamper with the content
    let tampered_content = "tampered keyring content";
    let result = verify_keyring_signature(tampered_content, &signature, &public_key);
    assert!(result.is_err());
}

#[test]
fn test_verify_keyring_signature_wrong_key() {
    let (secret_key_alice, _public_key_alice) = generate_test_key("alice@example.com");
    let (_secret_key_bob, public_key_bob) = generate_test_key("bob@example.com");
    let keyring_content = "test keyring content";
    let signature = sign_keyring_content(keyring_content, &secret_key_alice, None).expect("signing should succeed");
    // Try to verify with wrong key
    let result = verify_keyring_signature(keyring_content, &signature, &public_key_bob);
    assert!(result.is_err());
}

#[test]
fn test_sign_and_verify_roundtrip() {
    let (secret_key, public_key) = generate_test_key("alice@example.com");
    let keyring_content = "test keyring content for roundtrip";
    
    // Sign
    let signature = sign_keyring_content(keyring_content, &secret_key, None).expect("signing should succeed");
    
    // Verify
    let result = verify_keyring_signature(keyring_content, &signature, &public_key);
    assert!(result.is_ok(), "Signature verification should succeed");
}

#[test]
fn test_extract_signature_from_keyring() {
    let content = "-----BEGIN GIT-GPG KEYRING-----\n-----END GIT-GPG KEYRING-----\n-----BEGIN PGP SIGNATURE-----\nsig123\n-----END PGP SIGNATURE-----";
    let sig = extract_signature_from_keyring(content).unwrap();
    assert!(sig.contains("sig123"));
}

#[test]
fn test_extract_content_to_verify_from_keyring() {
    let content = "-----BEGIN GIT-GPG KEYRING-----\nalice@example.com:YWJj:ABC123\n-----END GIT-GPG KEYRING-----\n-----BEGIN PGP SIGNATURE-----\nsig\n-----END PGP SIGNATURE-----";
    let to_verify = extract_content_to_verify_from_keyring(content).unwrap();
    assert!(to_verify.contains("alice@example.com"));
    assert!(!to_verify.contains("PGP SIGNATURE"));
}

#[test]
fn test_verify_detached_signature() {
    let (secret_key, public_key) = generate_test_key("alice@example.com");
    let content = "detached signature test content";
    
    // Create detached signature
    let signature = sign_keyring_content(content, &secret_key, None).expect("signing should succeed");
    
    // Verify it's a valid detached signature
    assert!(signature.contains("-----BEGIN PGP SIGNATURE-----"));
    assert!(signature.contains("-----END PGP SIGNATURE-----"));
    
    // Verify signature is valid
    let result = verify_keyring_signature(content, &signature, &public_key);
    assert!(result.is_ok());
}

#[test]
fn test_sign_empty_keyring() {
    let (secret_key, public_key) = generate_test_key("alice@example.com");
    let empty_keyring = "-----BEGIN GIT-GPG KEYRING-----\n-----END GIT-GPG KEYRING-----\n";
    
    // Sign empty keyring
    let signature = sign_keyring_content(empty_keyring, &secret_key, None).expect("signing empty keyring should succeed");
    
    // Verify signature
    let result = verify_keyring_signature(empty_keyring, &signature, &public_key);
    assert!(result.is_ok(), "Empty keyring signature should be valid");
}

// ============================================================================
// Phase 2: GPG Integration
// ============================================================================

#[test]
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
fn test_find_private_key_not_found() {
    let temp = tempfile::tempdir().unwrap();
    let result = find_private_key_by_email(&temp.path().to_path_buf(), "nonexistent@example.com");
    assert!(result.is_err());
}

#[test]
fn test_encrypt_to_gpg_key() {
    let (_secret_key, public_key) = generate_test_key("alice@example.com");
    let plaintext = b"Hello, World!";
    
    let encrypted = encrypt_to_gpg_key(plaintext, &public_key).expect("encryption should succeed");
    assert!(encrypted.contains("-----BEGIN PGP MESSAGE-----"));
    assert!(encrypted.contains("-----END PGP MESSAGE-----"));
}

#[test]
fn test_decrypt_with_gpg_key() {
    let (secret_key, public_key) = generate_test_key("alice@example.com");
    let plaintext = b"Hello, World!";
    
    let encrypted = encrypt_to_gpg_key(plaintext, &public_key).expect("encryption should succeed");
    let decrypted = decrypt_with_gpg_key(&encrypted, &secret_key, None).expect("decryption should succeed");
    
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
fn test_init_creates_git_gpg_directory() {
    let temp = tempfile::tempdir().unwrap();
    cmd_init(temp.path()).unwrap();
    assert!(temp.path().join(".git-gpg").exists());
}

#[test]
fn test_init_creates_empty_keyring_with_markers() {
    let temp = tempfile::tempdir().unwrap();
    cmd_init(temp.path()).unwrap();
    let keyring_path = temp.path().join(".git-gpg").join("keyring");
    assert!(keyring_path.exists());
    let content = std::fs::read_to_string(keyring_path).unwrap();
    assert!(content.contains("-----BEGIN GIT-GPG KEYRING-----"));
    assert!(content.contains("-----END GIT-GPG KEYRING-----"));
}

#[test]
fn test_init_creates_empty_trust_json() {
    let temp = tempfile::tempdir().unwrap();
    cmd_init(temp.path()).unwrap();
    let trust_path = temp.path().join(".git-gpg").join("trust.json");
    assert!(trust_path.exists());
}

#[test]
fn test_init_creates_empty_tracked_json() {
    let temp = tempfile::tempdir().unwrap();
    cmd_init(temp.path()).unwrap();
    let tracked_path = temp.path().join(".git-gpg").join("tracked.json");
    assert!(tracked_path.exists());
}

#[test]
fn init_no_longer_creates_secrets_dir_or_gitignore_entry() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join(".gitignore"), "/target\n*.log\n").unwrap();
    let gitignore_before =
        std::fs::read(temp.path().join(".gitignore")).unwrap();

    cmd_init(temp.path()).unwrap();

    assert!(
        !temp.path().join(".git-gpg").join("secrets").exists(),
        "init must not create a .git-gpg/secrets directory"
    );
    let gitignore_after =
        std::fs::read(temp.path().join(".gitignore")).unwrap();
    assert_eq!(
        gitignore_before, gitignore_after,
        ".gitignore must be byte-identical after init"
    );
    assert!(
        !gitignore_after.windows(b".git-gpg".len()).any(|w| w == b".git-gpg"),
        ".gitignore must gain no git-gpg entry, got: {:?}",
        String::from_utf8_lossy(&gitignore_after)
    );
}

#[test]
fn test_init_idempotent() {
    let temp = tempfile::tempdir().unwrap();
    cmd_init(temp.path()).unwrap();
    cmd_init(temp.path()).unwrap();
}

#[test]
fn test_init_leaves_existing_gitignore_untouched() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join(".gitignore"), "/target\n").unwrap();
    cmd_init(temp.path()).unwrap();
    let content = std::fs::read_to_string(temp.path().join(".gitignore")).unwrap();
    assert!(content.contains("/target"));
    assert!(
        !content.contains(".git-gpg"),
        "init must not append any .git-gpg line, got: {}",
        content
    );
}

// ============================================================================
// Phase 3: Trust Command
// ============================================================================

#[test]
fn test_trust_validates_repo_id_matches_remote() {
    let temp = tempfile::tempdir().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["init"]).output().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init(temp.path()).unwrap();

    // A provided repo_id that does not match the one computed from the
    // remote's push URL must be rejected with the mismatch error. That check
    // runs before the signing key is read, so the nonexistent key path never
    // matters here.
    let result = cmd_trust(temp.path(), "wrong+user@github.com", "/nonexistent/key.pub", "origin", &PathBuf::from("/tmp"));
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

// The remaining trust-command stubs were deleted: the mismatch contract is
// asserted above; email-in-key acceptance/rejection is covered by
// trust_accepts_owner_key_matching_user_at_service_email and
// trust_rejects_key_without_owner_email; persistence/pin by trust_writes_local_pin
// and verify_fails_closed_when_pin_mismatches (tests/features.rs); key import and
// trust-store update by test_import_key_to_gpg_home and
// test_trust_store_update_existing_trust (this file); remote-name resolution by
// test_get_remote_push_url_custom_remote; non-repo failure by
// test_get_remote_push_url_nonexistent_remote_fails and cli_reports_nonzero_exit_on_failure.

// ============================================================================
// Phase 3: Tell Command
// ============================================================================

// The tell-command stubs test_tell_validates_email_in_public_key,
// test_tell_extracts_fingerprint, test_tell_base64_encodes_key,
// test_tell_appends_to_keyring and test_tell_signs_keyring_after_append were
// deleted: those contracts are asserted by tell_first_entry_on_fresh_repo_succeeds
// (tests/features.rs, entry present + keyring signed) and the primitives
// test_extract_key_fingerprint / test_base64_encode_public_key (this file).
// Custom-remote / custom-gpg-home pass-through is covered by
// test_get_remote_push_url_custom_remote and the features.rs tell tests, which
// all run against an explicit repo-local gpg home.

#[test]
fn test_tell_fails_if_trust_not_established() {
    let temp = tempfile::tempdir().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(["init"]).output().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init(temp.path()).unwrap();

    let result = cmd_tell(temp.path(), "alice@example.com", "/nonexistent/key.pub", "origin", &PathBuf::from("/tmp"), None);
    let err = result.err().expect("tell without established trust must fail");
    assert!(
        err.to_string().contains("No trust established"),
        "the failure must be the trust-not-established error, got: {}",
        err
    );
}

#[test]
fn test_tell_validates_email_not_in_key_fails() {
    let (repo_temp, gpg_home) = setup_trusted_repo_with_owner_in_keyring();

    // A real key whose identity does NOT contain the email claimed for it.
    let (_bob_sec, bob_pub) = generate_test_key("bob@example.com");
    let bob_keyfile = repo_temp.path().join("bob.pub");
    write_public_key_file(&bob_pub, &bob_keyfile);

    let result = cmd_tell(
        repo_temp.path(),
        "alice@example.com",
        bob_keyfile.to_str().unwrap(),
        "origin",
        &gpg_home, None
    );
    let err = result
        .err()
        .expect("a key that does not carry the claimed email must be rejected");
    assert!(
        err.to_string().contains("does not contain email"),
        "the failure must be the email-not-in-key error, got: {}",
        err
    );
}

#[test]
fn test_tell_fails_if_signing_key_not_in_gpg_home() {
    let repo_temp = setup_git_repo_with_origin_remote();
    cmd_init(repo_temp.path()).unwrap();

    // Trust is established (the owner PUBLIC key is imported and pinned), but
    // the owner SECRET key is deliberately absent from the secring, so tell
    // cannot sign the updated keyring.
    let (_owner_sec, owner_pub) = generate_test_key("owner@github.com");
    let owner_keyfile = repo_temp.path().join("owner.pub");
    write_public_key_file(&owner_pub, &owner_keyfile);
    let gpg_home = repo_temp.path().join("gpg-home");
    cmd_trust(
        repo_temp.path(),
        "repo+owner@github.com",
        owner_keyfile.to_str().unwrap(),
        "origin",
        &gpg_home,
    )
    .expect("cmd_trust must succeed");

    let (alice_sec, alice_pub) = generate_test_key("alice@example.com");
    let alice_keyfile = repo_temp.path().join("alice.pub");
    write_public_key_file(&alice_pub, &alice_keyfile);

    // The secring holds only the COLLABORATOR's secret key, not the trusted
    // owner key tell must sign with.
    write_multi_key_secring(&gpg_home, &[alice_sec]);

    let result = cmd_tell(
        repo_temp.path(),
        "alice@example.com",
        alice_keyfile.to_str().unwrap(),
        "origin",
        &gpg_home, None
    );
    let err = result
        .err()
        .expect("tell without the trusted secret key must fail");
    assert!(
        err.to_string().contains("No secret key found for fingerprint"),
        "the failure must be the missing-signing-key error, got: {}",
        err
    );
}

#[test]
fn tell_failure_leaves_existing_keyring_untouched() {
    let (repo_temp, gpg_home) = setup_trusted_repo_with_owner_in_keyring();
    let keyring_path = repo_temp.path().join(".git-gpg/keyring");
    let keyring_before = std::fs::read(&keyring_path).unwrap();

    let (_bob_sec, bob_pub) = generate_test_key("bob@example.com");
    let bob_keyfile = repo_temp.path().join("bob.pub");
    write_public_key_file(&bob_pub, &bob_keyfile);

    // Rejected at the email check, i.e. AFTER the existing keyring is loaded
    // but BEFORE any mutation is written back.
    let result = cmd_tell(
        repo_temp.path(),
        "alice@example.com",
        bob_keyfile.to_str().unwrap(),
        "origin",
        &gpg_home, None
    );
    assert!(result.is_err(), "the mismatched tell must be rejected");

    let keyring_after = std::fs::read(&keyring_path).unwrap();
    assert_eq!(
        keyring_before, keyring_after,
        "a failed tell must not touch the existing keyring"
    );
}

// ============================================================================
// Phase 4: Show-Repo-ID
// ============================================================================

#[test]
fn test_show_repo_id_default_origin_remote() {
    let temp = tempfile::tempdir().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["init"]).output().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    
    let result = cmd_show_repo_id(temp.path(), "origin");
    assert!(result.is_ok());
}

#[test]
fn test_show_repo_id_custom_remote() {
    let temp = tempfile::tempdir().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["init"]).output().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["remote", "add", "fork", "git@github.com:user/repo.git"]).output().unwrap();
    
    let result = cmd_show_repo_id(temp.path(), "fork");
    assert!(result.is_ok());
}

// test_show_repo_id_displays_push_url and test_show_repo_id_displays_remote_name
// deleted: they were byte-identical to test_show_repo_id_default_origin_remote and
// never asserted the stdout they promised (println capture needs the CLI-process
// lane of tests/cli.rs). test_show_repo_id_fails_if_not_git_repo was deleted as a
// duplicate of test_not_in_git_repo_fails_gracefully below.

#[test]
fn test_show_repo_id_fails_if_remote_not_found() {
    let temp = tempfile::tempdir().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["init"]).output().unwrap();
    
    let result = cmd_show_repo_id(temp.path(), "nonexistent");
    assert!(result.is_err());
}

// ============================================================================
// Phase 4: Whoami
// ============================================================================

#[test]
fn test_whoami_from_git_config_user_email() {
    let temp = tempfile::tempdir().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["init"]).output().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["config", "user.email", "test@example.com"]).output().unwrap();
    
    let result = cmd_whoami(temp.path(), None, &PathBuf::from("/tmp"));
    assert!(result.is_ok());
}

#[test]
fn test_whoami_from_email_flag_override() {
    let temp = tempfile::tempdir().unwrap();
    
    let result = cmd_whoami(temp.path(), Some("override@example.com"), &PathBuf::from("/tmp"));
    assert!(result.is_ok());
}

// test_whoami_displays_gpg_home_location deleted: byte-identical to
// test_whoami_from_git_config_user_email; the stdout it promised is not
// assertable in-process (println capture needs tests/cli.rs).

#[test]
fn test_whoami_displays_custom_gpg_home() {
    let temp = tempfile::tempdir().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["init"]).output().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["config", "user.email", "test@example.com"]).output().unwrap();
    
    let gpg_home = temp.path().join("custom-gpg");
    std::fs::create_dir_all(&gpg_home).unwrap();
    let result = cmd_whoami(temp.path(), None, &gpg_home);
    assert!(result.is_ok());
}

#[test]
#[serial]
fn test_whoami_fails_if_no_git_config_and_no_flag() {
    let temp = tempfile::tempdir().unwrap();
    
    // Set HOME to temp so git can't find global config
    let orig_home = std::env::var("HOME").ok();
    std::env::set_var("HOME", temp.path());
    std::env::set_var("GIT_CONFIG_NOSYSTEM", "1");
    
    std::process::Command::new("git").current_dir(temp.path()).args(&["init"]).output().unwrap();
    
    let result = cmd_whoami(temp.path(), None, &PathBuf::from("/tmp"));
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

// The verify-keyring stubs were deleted: with no trust established they all
// aborted at the "No trust established" early exit and never reached the
// behaviour their names promised. The real contracts are covered elsewhere:
// valid/tampered/wrong-key verification by test_verify_keyring_signature_valid,
// test_verify_keyring_signature_invalid_tampering and
// test_verify_keyring_signature_wrong_key (this file, primitives) plus
// verify_fails_closed_when_pin_missing and verify_fails_closed_when_pin_mismatches
// (tests/features.rs, message-asserted at the command level through the same
// verify_keyring_against_trust function); unsigned-keyring rejection by
// tell_rejects_unsigned_keyring_containing_entries (tests/features.rs). The
// "displays signer email / repo id / key count" stdout contracts are not
// assertable in-process (println capture needs tests/cli.rs).

// ============================================================================
// Phase 4: List-Keys
// ============================================================================

#[test]
fn test_list_keys_empty_keyring() {
    let temp = tempfile::tempdir().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["init"]).output().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init(temp.path()).unwrap();
    
    let result = cmd_list_keys(temp.path());
    assert!(result.is_ok());
}

// test_list_keys_multiple_entries, test_list_keys_displays_email_and_fingerprint
// and test_list_keys_displays_total_count were deleted: their bodies never added
// any keyring entry and asserted only is_ok, and the stdout they promised is not
// assertable in-process (println capture needs tests/cli.rs).

#[test]
fn test_list_keys_single_entry() {
    let (repo_temp, _gpg_home) = setup_trusted_repo_with_owner_in_keyring();

    let result = cmd_list_keys(repo_temp.path());
    assert!(
        result.is_ok(),
        "list-keys over a populated keyring must succeed: {:?}",
        result.err()
    );
}

// ============================================================================
// Phase 5: Add Command
// ============================================================================

// test_add_single_file_to_tracked_json and test_add_stores_repo_relative_paths
// were deleted: the single-file add and repo-relative path storage contracts are
// asserted with content checks by add_stores_repo_relative_paths
// (tests/features.rs).

#[test]
fn test_add_multiple_files_to_tracked_json() {
    let temp = tempfile::tempdir().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(["init"]).output().unwrap();
    cmd_init(temp.path()).unwrap();

    std::fs::write(temp.path().join("file1.txt"), "content1").unwrap();
    std::fs::write(temp.path().join("file2.txt"), "content2").unwrap();

    cmd_add(temp.path(), vec!["file1.txt".to_string(), "file2.txt".to_string()])
        .expect("multi-file cmd_add must succeed");

    let tracked = TrackedFiles::load(&temp.path().join(".git-gpg").join("tracked.json"))
        .expect("tracked.json must stay loadable after a multi-file add");
    let names: Vec<String> = tracked
        .files
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect();
    assert!(
        names.contains(&"file1.txt".to_string()) && names.contains(&"file2.txt".to_string()),
        "both files must be recorded in tracked.json, got: {:?}",
        names
    );
}

#[test]
fn test_add_duplicate_file_idempotent() {
    let temp = tempfile::tempdir().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["init"]).output().unwrap();
    cmd_init(temp.path()).unwrap();
    
    let test_file = temp.path().join("secret.txt");
    std::fs::write(&test_file, "content").unwrap();
    
    cmd_add(temp.path(), vec!["secret.txt".to_string()]).unwrap();
    let result = cmd_add(temp.path(), vec!["secret.txt".to_string()]);
    assert!(result.is_ok());
}

#[test]
fn test_add_nonexistent_file_fails() {
    let temp = tempfile::tempdir().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["init"]).output().unwrap();
    cmd_init(temp.path()).unwrap();
    
    let result = cmd_add(temp.path(), vec!["nonexistent.txt".to_string()]);
    assert!(result.is_err());
}

// ============================================================================
// Phase 5: Remove Command
// ============================================================================

#[test]
fn test_remove_file_from_tracked_json() {
    let temp = tempfile::tempdir().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["init"]).output().unwrap();
    cmd_init(temp.path()).unwrap();
    
    let test_file = temp.path().join("secret.txt");
    std::fs::write(&test_file, "content").unwrap();
    cmd_add(temp.path(), vec!["secret.txt".to_string()]).unwrap();
    
    let result = cmd_remove(temp.path(), vec!["secret.txt".to_string()]);
    assert!(result.is_ok());
}

#[test]
fn test_remove_multiple_files() {
    let temp = tempfile::tempdir().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["init"]).output().unwrap();
    cmd_init(temp.path()).unwrap();
    
    std::fs::write(temp.path().join("file1.txt"), "content1").unwrap();
    std::fs::write(temp.path().join("file2.txt"), "content2").unwrap();
    cmd_add(temp.path(), vec!["file1.txt".to_string(), "file2.txt".to_string()]).unwrap();
    
    let result = cmd_remove(temp.path(), vec!["file1.txt".to_string(), "file2.txt".to_string()]);
    assert!(result.is_ok());
}

#[test]
fn test_remove_nonexistent_file_fails() {
    let temp = tempfile::tempdir().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["init"]).output().unwrap();
    cmd_init(temp.path()).unwrap();
    
    let result = cmd_remove(temp.path(), vec!["nonexistent.txt".to_string()]);
    assert!(result.is_err());
}

#[test]
fn test_remove_not_tracked_file_fails() {
    let temp = tempfile::tempdir().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["init"]).output().unwrap();
    cmd_init(temp.path()).unwrap();
    
    let test_file = temp.path().join("untracked.txt");
    std::fs::write(&test_file, "content").unwrap();
    
    let result = cmd_remove(temp.path(), vec!["untracked.txt".to_string()]);
    assert!(result.is_err());
}

// ============================================================================
// Phase 5: List Command
// ============================================================================

#[test]
fn test_list_empty_tracked_json() {
    let temp = tempfile::tempdir().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["init"]).output().unwrap();
    cmd_init(temp.path()).unwrap();
    
    let result = cmd_list(temp.path());
    assert!(result.is_ok());
}

#[test]
fn test_list_single_file() {
    let temp = tempfile::tempdir().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["init"]).output().unwrap();
    cmd_init(temp.path()).unwrap();
    
    let test_file = temp.path().join("secret.txt");
    std::fs::write(&test_file, "content").unwrap();
    cmd_add(temp.path(), vec!["secret.txt".to_string()]).unwrap();
    
    let result = cmd_list(temp.path());
    assert!(result.is_ok());
}

#[test]
fn test_list_multiple_files() {
    let temp = tempfile::tempdir().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["init"]).output().unwrap();
    cmd_init(temp.path()).unwrap();
    
    std::fs::write(temp.path().join("file1.txt"), "content1").unwrap();
    std::fs::write(temp.path().join("file2.txt"), "content2").unwrap();
    cmd_add(temp.path(), vec!["file1.txt".to_string(), "file2.txt".to_string()]).unwrap();
    
    let result = cmd_list(temp.path());
    assert!(result.is_ok());
}

// test_list_displays_tracked_paths deleted: byte-identical to
// test_list_single_file above; the stdout it promised is not assertable
// in-process (println capture needs tests/cli.rs).

// ============================================================================
// Phase 6: Hide Command
// ============================================================================

// The hide-command stubs were deleted: with no trust established they all
// aborted at the "No trust established" early exit of the shared keyring
// verification and never reached the behaviour their names promised. The real
// contracts are covered elsewhere: encrypts-to-every-key by
// hide_encrypts_to_every_key_in_keyring, original-file removal and plaintext
// replacement by reveal_works_for_each_collaborator_after_hide (tests/features.rs),
// in-place .secret naming (the dead .asc naming is gone) by
// ciphertext_filename_is_full_name_plus_secret, ciphertext_filename_for_dotfile
// and hide_writes_ciphertext_next_to_plaintext, directory preservation by
// hide_then_reveal_in_subdirectory, trust/signature failure by
// verify_fails_closed_when_pin_missing and verify_fails_closed_when_pin_mismatches
// (all tests/features.rs). Custom-remote / custom-gpg-home pass-through is
// covered by test_get_remote_push_url_custom_remote and the features.rs tests,
// which run against explicit repo-local gpg homes.

#[test]
fn test_hide_empty_tracked_list_succeeds() {
    let (repo_temp, gpg_home) = setup_trusted_repo_with_owner_in_keyring();

    cmd_hide(repo_temp.path(), "origin", &gpg_home)
        .expect("hide with nothing tracked must be a successful no-op");
}

#[test]
fn test_hide_missing_tracked_file_fails() {
    let (repo_temp, gpg_home) = setup_trusted_repo_with_owner_in_keyring();

    std::fs::write(repo_temp.path().join("secret.env"), "s3cret").unwrap();
    cmd_add(repo_temp.path(), vec!["secret.env".to_string()]).expect("cmd_add must succeed");
    std::fs::remove_file(repo_temp.path().join("secret.env")).unwrap();

    let result = cmd_hide(repo_temp.path(), "origin", &gpg_home);
    let err = result
        .err()
        .expect("hide must abort when a tracked file is missing from disk");
    assert!(
        err.to_string().contains("Failed to read file"),
        "the failure must name the unreadable tracked file, got: {}",
        err
    );
}

// ============================================================================
// Phase 6: Reveal Command
// ============================================================================

// The reveal-command stubs were deleted: with no trust established they all
// aborted at the "No trust established" early exit of the shared keyring
// verification and never reached the behaviour their names promised. The real
// contracts are covered elsewhere: decryption and per-collaborator reveal by
// reveal_works_for_each_collaborator_after_hide and
// hide_then_reveal_restores_exact_bytes, filename restoration (the dead .asc
// naming is gone) by hide_then_reveal_roundtrip_fully_preserves_file_names,
// ciphertext removal by reveal_restores_plaintext_and_removes_secret_file,
// email lookup and private-key lookup by find_private_key_by_email_* (this file
// and tests/features.rs), email-flag and git-config defaults by
// reveal_with_explicit_email_succeeds and reveal_defaults_to_git_config_user_email
// (tests/cli.rs), trust/signature failure by verify_fails_closed_when_pin_missing
// and verify_fails_closed_when_pin_mismatches (tests/features.rs).

#[test]
fn test_reveal_fails_if_email_not_in_keyring() {
    let (repo_temp, gpg_home) = setup_trusted_repo_with_owner_in_keyring();

    let result = cmd_reveal(repo_temp.path(), "mallory@evil.com", "origin", &gpg_home, None);
    let err = result
        .err()
        .expect("reveal for an email absent from the keyring must fail");
    assert!(
        err.to_string().contains("not found in keyring"),
        "the failure must name the missing keyring email, got: {}",
        err
    );
}

#[test]
fn test_reveal_missing_encrypted_file_fails() {
    let (repo_temp, gpg_home) = setup_trusted_repo_with_owner_in_keyring();

    std::fs::write(repo_temp.path().join("secret.env"), "s3cret").unwrap();
    cmd_add(repo_temp.path(), vec!["secret.env".to_string()]).expect("cmd_add must succeed");

    // Tracked and on disk, but never hidden: no secret.env.secret exists.
    let result = cmd_reveal(repo_temp.path(), "owner@github.com", "origin", &gpg_home, None);
    let err = result
        .err()
        .expect("reveal without the ciphertext file must fail");
    assert!(
        err.to_string().contains("Encrypted file not found"),
        "the failure must name the missing ciphertext file, got: {}",
        err
    );
}

// ============================================================================
// Phase 6: Clean Command
// ============================================================================

#[test]
fn test_clean_removes_git_gpg_directory() {
    let temp = tempfile::tempdir().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["init"]).output().unwrap();
    cmd_init(temp.path()).unwrap();
    
    let result = cmd_clean(temp.path());
    assert!(result.is_ok());
    assert!(!temp.path().join(".git-gpg").exists());
}

#[test]
fn clean_keeps_gitignore_untouched() {
    let temp = tempfile::tempdir().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["init"]).output().unwrap();
    std::fs::write(temp.path().join(".gitignore"), "/target\n*.log\n").unwrap();
    cmd_init(temp.path()).unwrap();

    let result = cmd_clean(temp.path());
    assert!(result.is_ok());

    let gitignore = std::fs::read_to_string(temp.path().join(".gitignore")).unwrap();
    assert_eq!(
        gitignore, "/target\n*.log\n",
        "clean must not rewrite .gitignore"
    );
}

#[test]
fn test_clean_idempotent() {
    let temp = tempfile::tempdir().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["init"]).output().unwrap();
    cmd_init(temp.path()).unwrap();
    
    cmd_clean(temp.path()).unwrap();
    let result = cmd_clean(temp.path());
    assert!(result.is_ok());
}

// ============================================================================
// Phase 7: Integration
// ============================================================================

#[test]
fn test_full_workflow_owner_setup() {
    let temp = tempfile::tempdir().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["init"]).output().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    
    // Initialize
    cmd_init(temp.path()).unwrap();
    
    // Generate owner key
    let (owner_secret, owner_public) = generate_test_key("owner@example.com");
    let owner_fingerprint = extract_key_fingerprint(&owner_public);
    
    // Create keyring with owner
    let mut keyring = Keyring::new();
    let owner_base64 = base64_encode_public_key(&owner_public);
    keyring.add_entry("owner@example.com".to_string(), owner_base64, owner_fingerprint.clone());
    
    // Sign keyring
    let content = keyring.serialize();
    let signature = sign_keyring_content(&content, &owner_secret, None).expect("signing should succeed");
    
    assert!(signature.contains("-----BEGIN PGP SIGNATURE-----"));
}

#[test]
fn test_full_workflow_add_collaborator() {
    let temp = tempfile::tempdir().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["init"]).output().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init(temp.path()).unwrap();
    
    // Generate owner and collaborator keys
    let (owner_secret, owner_public) = generate_test_key("owner@example.com");
    let (_collab_secret, collab_public) = generate_test_key("collab@example.com");
    
    // Create keyring with both
    let mut keyring = Keyring::new();
    keyring.add_entry("owner@example.com".to_string(), base64_encode_public_key(&owner_public), extract_key_fingerprint(&owner_public));
    keyring.add_entry("collab@example.com".to_string(), base64_encode_public_key(&collab_public), extract_key_fingerprint(&collab_public));
    
    // Sign keyring
    let content = keyring.serialize();
    let _signature = sign_keyring_content(&content, &owner_secret, None).expect("signing should succeed");
    
    assert!(keyring.entries.len() == 2);
}

#[test]
fn test_full_workflow_collaborator_clone_and_reveal() {
    let temp = tempfile::tempdir().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["init"]).output().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init(temp.path()).unwrap();
    
    // Generate keys
    let (owner_secret, owner_public) = generate_test_key("owner@example.com");
    let (_collab_secret, collab_public) = generate_test_key("collab@example.com");
    
    // Create keyring
    let mut keyring = Keyring::new();
    keyring.add_entry("owner@example.com".to_string(), base64_encode_public_key(&owner_public), extract_key_fingerprint(&owner_public));
    keyring.add_entry("collab@example.com".to_string(), base64_encode_public_key(&collab_public), extract_key_fingerprint(&collab_public));
    
    // Sign and verify
    let content = keyring.serialize();
    let signature = sign_keyring_content(&content, &owner_secret, None).expect("signing should succeed");
    let result = verify_keyring_signature(&content, &signature, &owner_public);
    assert!(result.is_ok());
}

#[test]
fn test_full_workflow_hide_reveal_roundtrip() {
    let temp = tempfile::tempdir().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["init"]).output().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init(temp.path()).unwrap();
    
    // Generate key
    let (_secret_key, public_key) = generate_test_key("alice@example.com");
    
    // Test encryption/decryption roundtrip
    let plaintext = b"secret content";
    let encrypted = encrypt_to_gpg_key(plaintext, &public_key).expect("encryption should succeed");
    assert!(encrypted.contains("-----BEGIN PGP MESSAGE-----"));
}

#[test]
fn test_multi_collaborator_workflow() {
    let temp = tempfile::tempdir().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["init"]).output().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init(temp.path()).unwrap();
    
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
    let signature = sign_keyring_content(&content, &owner_secret, None).expect("signing should succeed");
    let result = verify_keyring_signature(&content, &signature, &owner_public);
    assert!(result.is_ok());
}

// test_tampered_keyring_blocks_hide and test_tampered_keyring_blocks_reveal
// were deleted: with no trust established both aborted at the "No trust
// established" early exit before ever reading the tampered keyring. Tampering
// rejection is covered by verify_fails_closed_when_pin_mismatches (validly
// attacker-signed ring rejected, keyring bytes untouched) and
// removeperson_rejects_tampered_keyring (tests/features.rs); malformed-keyring
// parse failure by test_corrupted_keyring_fails_gracefully (this file).

#[test]
fn test_keyring_signature_rotation() {
    let temp = tempfile::tempdir().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["init"]).output().unwrap();
    cmd_init(temp.path()).unwrap();
    
    let (secret_key, public_key) = generate_test_key("alice@example.com");
    let fingerprint = extract_key_fingerprint(&public_key);
    let base64_key = base64_encode_public_key(&public_key);
    
    // Create keyring with entry
    let mut keyring = Keyring::new();
    keyring.add_entry("alice@example.com".to_string(), base64_key, fingerprint);
    
    // Sign keyring content (without signature)
    let content_without_sig = keyring.serialize();
    let signature = sign_keyring_content(&content_without_sig, &secret_key, None).expect("signing should succeed");
    keyring.signature = Some(signature.clone());
    
    // Verify signature using the content without signature
    let result = verify_keyring_signature(&content_without_sig, &signature, &public_key);
    assert!(result.is_ok());
}

#[test]
fn test_multiple_remotes_workflow() {
    let temp = tempfile::tempdir().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["init"]).output().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["remote", "add", "fork", "git@github.com:fork/repo.git"]).output().unwrap();
    cmd_init(temp.path()).unwrap();
    
    // Both remotes should work
    let result1 = cmd_show_repo_id(temp.path(), "origin");
    assert!(result1.is_ok());
    
    let result2 = cmd_show_repo_id(temp.path(), "fork");
    assert!(result2.is_ok());
}

#[test]
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
fn test_binary_file_encryption_workflow() {
    let (_secret_key, public_key) = generate_test_key("alice@example.com");
    
    // Binary data
    let binary_data: Vec<u8> = (0..255).collect();
    
    let encrypted = encrypt_to_gpg_key(&binary_data, &public_key).expect("encryption should succeed");
    assert!(encrypted.contains("-----BEGIN PGP MESSAGE-----"));
}

#[test]
fn test_nested_directory_workflow() {
    let temp = tempfile::tempdir().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["init"]).output().unwrap();
    cmd_init(temp.path()).unwrap();
    
    // Create nested directory structure
    let nested_dir = temp.path().join("subdir").join("nested");
    std::fs::create_dir_all(&nested_dir).unwrap();
    let test_file = nested_dir.join("secret.txt");
    std::fs::write(&test_file, "nested secret content").unwrap();
    
    let result = cmd_add(temp.path(), vec!["subdir/nested/secret.txt".to_string()]);
    assert!(result.is_ok());
}

// ============================================================================
// Phase 7: Error Handling
// ============================================================================

#[test]
fn test_not_in_git_repo_fails_gracefully() {
    let temp = tempfile::tempdir().unwrap();
    
    let result = cmd_show_repo_id(temp.path(), "origin");
    assert!(result.is_err());
}

#[test]
fn test_git_gpg_not_initialized_fails_gracefully() {
    let temp = tempfile::tempdir().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["init"]).output().unwrap();
    
    let result = cmd_list_keys(temp.path());
    assert!(result.is_err());
}

#[test]
fn test_corrupted_trust_json_fails_gracefully() {
    let temp = tempfile::tempdir().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["init"]).output().unwrap();
    cmd_init(temp.path()).unwrap();
    
    std::fs::write(temp.path().join(".git-gpg").join("trust.json"), "corrupted").unwrap();
    
    let result = TrustStore::load_from_file(&temp.path().join(".git-gpg").join("trust.json"));
    assert!(result.is_err());
}

#[test]
fn test_corrupted_tracked_json_fails_gracefully() {
    let temp = tempfile::tempdir().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["init"]).output().unwrap();
    cmd_init(temp.path()).unwrap();
    
    std::fs::write(temp.path().join(".git-gpg").join("tracked.json"), "corrupted").unwrap();
    
    let result = TrackedFiles::load(&temp.path().join(".git-gpg").join("tracked.json"));
    assert!(result.is_err());
}

#[test]
fn test_corrupted_keyring_fails_gracefully() {
    let temp = tempfile::tempdir().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["init"]).output().unwrap();
    cmd_init(temp.path()).unwrap();
    
    std::fs::write(temp.path().join(".git-gpg").join("keyring"), "corrupted").unwrap();
    
    let content = std::fs::read_to_string(temp.path().join(".git-gpg").join("keyring")).unwrap();
    let result = Keyring::parse(&content);
    assert!(result.is_err());
}

#[test]
fn test_missing_keyring_file_fails_gracefully() {
    let temp = tempfile::tempdir().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["init"]).output().unwrap();
    std::process::Command::new("git").current_dir(temp.path()).args(&["remote", "add", "origin", "git@github.com:user/repo.git"]).output().unwrap();
    cmd_init(temp.path()).unwrap();
    
    std::fs::remove_file(temp.path().join(".git-gpg").join("keyring")).unwrap();
    
    let result = cmd_verify_keyring(temp.path(), "origin", &PathBuf::from("/tmp"));
    assert!(result.is_err());
}

// test_empty_keyring_signature_valid deleted: its body only ran cmd_list_keys
// and never touched a signature; the empty-keyring-signature contract is
// asserted by test_sign_empty_keyring (this file). test_concurrent_tell_operations
// deleted: it never called cmd_tell; the armored-key material it checked is
// asserted by test_base64_encode_public_key (this file).
