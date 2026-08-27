//! Contract tests for git-gpg features and regression fixes.
//!
//! Each test targets one named contract. Tests here are written Red/Green:
//! they must fail against the code they were written to fix, and pass after.

use git_gpg::{cmd_init, cmd_trust, extract_key_fingerprint, find_private_key_by_email, find_private_key_by_fingerprint};
use pgp::composed::{EncryptionCaps, KeyType, SecretKeyParamsBuilder, SubkeyParamsBuilder};
use rand::thread_rng;
use serial_test::serial;
use std::path::PathBuf;

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

fn write_public_key_file(public_key: &pgp::composed::SignedPublicKey, path: &PathBuf) {
    let armored = public_key.to_armored_string(Default::default()).unwrap();
    std::fs::write(path, armored).unwrap();
}

// ============================================================================
// Secret key selection from a multi-key secring
// ============================================================================

#[test]
#[serial]
fn find_private_key_by_email_selects_matching_key_when_not_first_in_secring() {
    let temp = tempfile::tempdir().unwrap();
    let gpg_home = temp.path().to_path_buf();
    let (alice, _) = generate_test_key("alice@example.com");
    let (bob, _) = generate_test_key("bob@example.com");
    write_multi_key_secring(&gpg_home, &[alice, bob]);

    let result = find_private_key_by_email(&gpg_home, "bob@example.com");
    assert!(
        result.is_ok(),
        "bob's key should be found even though alice's key comes first: {:?}",
        result.err()
    );
}

#[test]
#[serial]
fn find_private_key_by_fingerprint_selects_matching_key_when_not_first_in_secring() {
    let temp = tempfile::tempdir().unwrap();
    let gpg_home = temp.path().to_path_buf();
    let (alice, _) = generate_test_key("alice@example.com");
    let (bob, bob_pub) = generate_test_key("bob@example.com");
    let bob_fingerprint = extract_key_fingerprint(&bob_pub);
    write_multi_key_secring(&gpg_home, &[alice, bob]);

    let result = find_private_key_by_fingerprint(&gpg_home, &bob_fingerprint);
    assert!(
        result.is_ok(),
        "bob's key should be found even though alice's key comes first: {:?}",
        result.err()
    );
}

#[test]
#[serial]
fn find_private_key_by_email_fails_when_no_key_matches() {
    let temp = tempfile::tempdir().unwrap();
    let gpg_home = temp.path().to_path_buf();
    let (alice, _) = generate_test_key("alice@example.com");
    write_multi_key_secring(&gpg_home, &[alice]);

    let result = find_private_key_by_email(&gpg_home, "carol@example.com");
    assert!(result.is_err(), "unknown email must not match any key");
}

// ============================================================================
// Trust establishment validates the owner email from the repo ID
// ============================================================================

#[test]
#[serial]
fn trust_accepts_owner_key_matching_user_at_service_email() {
    let original_dir = std::env::current_dir().unwrap();
    let repo_temp = setup_git_repo_with_origin_remote();
    std::env::set_current_dir(repo_temp.path()).unwrap();

    cmd_init().expect("cmd_init must succeed");

    let (_, owner_pub) = generate_test_key("owner@github.com");
    let keyfile = repo_temp.path().join("owner.pub");
    write_public_key_file(&owner_pub, &keyfile);

    let gpg_temp = tempfile::tempdir().unwrap();

    let result = cmd_trust(
        "repo+owner@github.com",
        keyfile.to_str().unwrap(),
        "origin",
        &gpg_temp.path().to_path_buf(),
    );

    std::env::set_current_dir(original_dir).unwrap();

    assert!(
        result.is_ok(),
        "owner key for owner@github.com must be trusted: {:?}",
        result.err()
    );
}

#[test]
#[serial]
fn trust_rejects_key_without_owner_email() {
    let original_dir = std::env::current_dir().unwrap();
    let repo_temp = setup_git_repo_with_origin_remote();
    std::env::set_current_dir(repo_temp.path()).unwrap();

    cmd_init().expect("cmd_init must succeed");

    let (_, evil_pub) = generate_test_key("evil@attacker.com");
    let keyfile = repo_temp.path().join("evil.pub");
    write_public_key_file(&evil_pub, &keyfile);

    let gpg_temp = tempfile::tempdir().unwrap();

    let result = cmd_trust(
        "repo+owner@github.com",
        keyfile.to_str().unwrap(),
        "origin",
        &gpg_temp.path().to_path_buf(),
    );

    std::env::set_current_dir(original_dir).unwrap();

    let err = result.err().expect("evil key must not be trusted");
    assert!(
        err.to_string().contains("owner@github.com"),
        "error must come from the owner-email check, got: {}",
        err
    );
}
