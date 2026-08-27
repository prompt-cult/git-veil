//! Contract tests for git-gpg features and regression fixes.
//!
//! Each test targets one named contract. Tests here are written Red/Green:
//! they must fail against the code they were written to fix, and pass after.

use git_gpg::{
    cmd_add, cmd_hide, cmd_init, cmd_remove, cmd_reveal, cmd_tell, cmd_trust, cmd_verify_keyring,
    encrypt_to_gpg_key, extract_content_to_verify_from_keyring, extract_key_fingerprint,
    find_private_key_by_email, find_private_key_by_fingerprint, sign_keyring_content, Keyring,
    KeyringEntry, TrustStore, TrackedFiles,
};
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

// ============================================================================
// Tell must not launder trust (C1): verify incoming keyring signature first
// ============================================================================

/// Sets up a repo with trust established for owner@github.com and a gpg home
/// containing the owner key (pubring, via cmd_trust) plus the given secret keys
/// in the secring. Returns (repo_temp, gpg_home).
fn setup_trusted_repo_with_secring(
    secret_keys: &[pgp::composed::SignedSecretKey],
) -> (tempfile::TempDir, PathBuf) {
    let repo_temp = setup_git_repo_with_origin_remote();
    std::env::set_current_dir(repo_temp.path()).unwrap();

    cmd_init().expect("cmd_init must succeed");

    let (owner_sec, owner_pub) = generate_test_key("owner@github.com");
    let owner_keyfile = repo_temp.path().join("owner.pub");
    write_public_key_file(&owner_pub, &owner_keyfile);

    let gpg_home = repo_temp.path().join("gpg-home");

    cmd_trust(
        "repo+owner@github.com",
        owner_keyfile.to_str().unwrap(),
        "origin",
        &gpg_home,
    )
    .expect("cmd_trust must succeed");

    let mut secring_keys: Vec<pgp::composed::SignedSecretKey> = vec![owner_sec];
    secring_keys.extend_from_slice(secret_keys);
    write_multi_key_secring(&gpg_home, &secring_keys);

    (repo_temp, gpg_home)
}

#[test]
#[serial]
fn tell_rejects_unsigned_keyring_containing_entries() {
    let original_dir = std::env::current_dir().unwrap();
    let (alice_sec, alice_pub) = generate_test_key("alice@example.com");
    let (repo_temp, gpg_home) = setup_trusted_repo_with_secring(&[alice_sec]);

    // Overwrite the keyring with a well-formed but UNSIGNED keyring that
    // already contains an attacker entry.
    let unsigned_keyring = Keyring {
        entries: vec![KeyringEntry {
            email: "attacker@evil.com".to_string(),
            base64_key: "QUJDREVGR0hJSktMTU5PUA==".to_string(),
            fingerprint: "ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234".to_string(),
        }],
        signature: None,
    };
    std::fs::write(".git-gpg/keyring", unsigned_keyring.serialize()).unwrap();

    let alice_keyfile = repo_temp.path().join("alice.pub");
    write_public_key_file(&alice_pub, &alice_keyfile);

    let result = cmd_tell(
        "alice@example.com",
        alice_keyfile.to_str().unwrap(),
        "origin",
        &gpg_home,
    );

    std::env::set_current_dir(original_dir).unwrap();

    assert!(
        result.is_err(),
        "tell must reject an unsigned keyring that already contains entries"
    );
}

#[test]
#[serial]
fn tell_rejects_keyring_signed_by_wrong_key() {
    let original_dir = std::env::current_dir().unwrap();
    let (alice_sec, alice_pub) = generate_test_key("alice@example.com");
    let (repo_temp, gpg_home) = setup_trusted_repo_with_secring(&[alice_sec]);

    // Forge a keyring containing a third-party entry, signed by a key that is
    // NOT the trusted owner key. Sign the canonical content verify_keyring
    // extracts, so rejection is attributable to the signer's identity alone.
    let (mallory_sec, mallory_pub) = generate_test_key("mallory@evil.com");
    let mut forged = Keyring {
        entries: vec![KeyringEntry {
            email: "mallory@evil.com".to_string(),
            base64_key: "QUJDREVGR0hJSktMTU5PUA==".to_string(),
            fingerprint: extract_key_fingerprint(&mallory_pub),
        }],
        signature: None,
    };
    let serialized = forged.serialize();
    let content_to_sign = extract_content_to_verify_from_keyring(&serialized)
        .expect("freshly serialized keyring must contain the END marker");
    let signature = sign_keyring_content(&content_to_sign, &mallory_sec)
        .expect("mallory must be able to sign her own keyring");
    forged.signature = Some(signature);
    std::fs::write(".git-gpg/keyring", forged.serialize()).unwrap();

    let alice_keyfile = repo_temp.path().join("alice.pub");
    write_public_key_file(&alice_pub, &alice_keyfile);

    let result = cmd_tell(
        "alice@example.com",
        alice_keyfile.to_str().unwrap(),
        "origin",
        &gpg_home,
    );

    std::env::set_current_dir(original_dir).unwrap();

    assert!(
        result.is_err(),
        "tell must reject a keyring signed by a non-trusted key"
    );
}

#[test]
#[serial]
fn tell_first_entry_on_fresh_repo_succeeds() {
    let original_dir = std::env::current_dir().unwrap();
    let (alice_sec, alice_pub) = generate_test_key("alice@example.com");
    let (repo_temp, gpg_home) = setup_trusted_repo_with_secring(&[alice_sec]);

    let alice_keyfile = repo_temp.path().join("alice.pub");
    write_public_key_file(&alice_pub, &alice_keyfile);

    let result = cmd_tell(
        "alice@example.com",
        alice_keyfile.to_str().unwrap(),
        "origin",
        &gpg_home,
    );

    let keyring_text =
        std::fs::read_to_string(".git-gpg/keyring").expect("keyring must exist after tell");

    std::env::set_current_dir(original_dir).unwrap();

    assert!(
        result.is_ok(),
        "first tell on a fresh repo (zero-entry unsigned keyring) must succeed: {:?}",
        result.err()
    );
    assert!(
        keyring_text.contains("alice@example.com"),
        "keyring must contain alice's entry after tell"
    );
    assert!(
        keyring_text.contains("-----BEGIN PGP SIGNATURE-----"),
        "keyring must be signed after tell"
    );
}

// ============================================================================
// Init produces loadable, canonical store files
// ============================================================================

#[test]
#[serial]
fn init_creates_loadable_trust_store() {
    let original_dir = std::env::current_dir().unwrap();
    let repo_temp = setup_git_repo_with_origin_remote();
    std::env::set_current_dir(repo_temp.path()).unwrap();

    cmd_init().expect("cmd_init must succeed");

    let loaded = TrustStore::load_from_file(&PathBuf::from(".git-gpg/trust.json"));

    std::env::set_current_dir(original_dir).unwrap();

    let store = loaded.expect("trust.json written by init must load via TrustStore");
    assert!(
        store.trusted_keys.is_empty(),
        "a freshly initialised trust store must be empty"
    );
}

// ============================================================================
// Fresh repo multi-command happy path: init -> trust -> tell -> verify
// ============================================================================

#[test]
#[serial]
fn fresh_repo_init_trust_tell_verify_happy_path() {
    let original_dir = std::env::current_dir().unwrap();
    let repo_temp = setup_git_repo_with_origin_remote();
    std::env::set_current_dir(repo_temp.path()).unwrap();

    cmd_init().expect("cmd_init must succeed");

    let (owner_sec, owner_pub) = generate_test_key("owner@github.com");
    let owner_keyfile = repo_temp.path().join("owner.pub");
    write_public_key_file(&owner_pub, &owner_keyfile);

    let gpg_home = repo_temp.path().join("gpg-home");

    let trust_result = cmd_trust(
        "repo+owner@github.com",
        owner_keyfile.to_str().unwrap(),
        "origin",
        &gpg_home,
    );

    let (alice_sec, alice_pub) = generate_test_key("alice@example.com");
    write_multi_key_secring(&gpg_home, &[owner_sec, alice_sec]);

    let alice_keyfile = repo_temp.path().join("alice.pub");
    write_public_key_file(&alice_pub, &alice_keyfile);

    let tell_result = cmd_tell(
        "alice@example.com",
        alice_keyfile.to_str().unwrap(),
        "origin",
        &gpg_home,
    );

    let verify_result = cmd_verify_keyring("origin", &gpg_home);

    std::env::set_current_dir(original_dir).unwrap();

    trust_result.expect("cmd_trust must succeed on a fresh repo");
    tell_result.expect("cmd_tell must succeed on a fresh repo");
    verify_result.expect("cmd_verify_keyring must succeed after trust and tell");
}

// ============================================================================
// C2/M4: tracked paths are repo-relative and validated at every boundary
// ============================================================================

fn init_git_repo_in_cwd() {
    let status = std::process::Command::new("git")
        .args(["init"])
        .status()
        .expect("run git init");
    assert!(status.success(), "git init failed");
    cmd_init().expect("cmd_init must succeed");
}

fn write_tracked_json(files: &[&str]) {
    let entries: Vec<String> = files.iter().map(|f| format!("\"{}\"", f)).collect();
    let content = format!("{{\n  \"files\": [{}]\n}}", entries.join(", "));
    std::fs::create_dir_all(".git-gpg").unwrap();
    std::fs::write(".git-gpg/tracked.json", content).unwrap();
}

/// Sets up a repo where the trusted owner key is also a keyring entry, so a
/// full add -> hide -> reveal flow can run with the owner's own keypair.
fn setup_repo_with_owner_in_keyring()
-> (tempfile::TempDir, PathBuf, pgp::composed::SignedPublicKey) {
    let repo_temp = setup_git_repo_with_origin_remote();
    std::env::set_current_dir(repo_temp.path()).unwrap();

    cmd_init().expect("cmd_init must succeed");

    let (owner_sec, owner_pub) = generate_test_key("owner@github.com");
    let owner_keyfile = repo_temp.path().join("owner.pub");
    write_public_key_file(&owner_pub, &owner_keyfile);

    let gpg_home = repo_temp.path().join("gpg-home");

    cmd_trust(
        "repo+owner@github.com",
        owner_keyfile.to_str().unwrap(),
        "origin",
        &gpg_home,
    )
    .expect("cmd_trust must succeed");

    write_multi_key_secring(&gpg_home, &[owner_sec]);

    cmd_tell(
        "owner@github.com",
        owner_keyfile.to_str().unwrap(),
        "origin",
        &gpg_home,
    )
    .expect("cmd_tell must succeed");

    (repo_temp, gpg_home, owner_pub)
}

#[test]
#[serial]
fn tracked_files_load_rejects_absolute_paths() {
    let temp = tempfile::tempdir().unwrap();
    let tracked_path = temp.path().join(".git-gpg").join("tracked.json");
    std::fs::create_dir_all(tracked_path.parent().unwrap()).unwrap();
    std::fs::write(&tracked_path, r#"{"files":["/etc/passwd"]}"#).unwrap();

    let result = TrackedFiles::load(&tracked_path);

    let err = result.err().expect("absolute tracked path must be rejected");
    assert!(
        err.to_string().contains("/etc/passwd"),
        "error must name the offending path, got: {}",
        err
    );
}

#[test]
#[serial]
fn tracked_files_load_rejects_dotdot_components() {
    let temp = tempfile::tempdir().unwrap();
    let tracked_path = temp.path().join(".git-gpg").join("tracked.json");
    std::fs::create_dir_all(tracked_path.parent().unwrap()).unwrap();
    std::fs::write(&tracked_path, r#"{"files":["../escape.txt"]}"#).unwrap();

    let result = TrackedFiles::load(&tracked_path);

    let err = result
        .err()
        .expect("tracked path with a .. component must be rejected");
    assert!(
        err.to_string().contains("../escape.txt"),
        "error must name the offending path, got: {}",
        err
    );
}

#[test]
#[serial]
fn add_stores_repo_relative_paths() {
    let original_dir = std::env::current_dir().unwrap();
    let temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp.path()).unwrap();
    init_git_repo_in_cwd();

    std::fs::write("secret.env", "s3cret").unwrap();
    let result = cmd_add(vec!["secret.env".to_string()]);

    let tracked_content = std::fs::read_to_string(temp.path().join(".git-gpg/tracked.json"))
        .expect("tracked.json must exist after add");

    std::env::set_current_dir(original_dir).unwrap();

    result.expect("cmd_add must succeed for a file inside the repo");
    assert!(
        tracked_content.contains("\"secret.env\""),
        "tracked.json must store the repo-relative path, got: {}",
        tracked_content
    );
    assert!(
        !tracked_content.contains(temp.path().to_str().unwrap()),
        "tracked.json must not contain absolute paths, got: {}",
        tracked_content
    );
}

#[test]
#[serial]
fn add_rejects_file_outside_repo() {
    let original_dir = std::env::current_dir().unwrap();
    let repo_temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(repo_temp.path()).unwrap();
    init_git_repo_in_cwd();

    let outside = tempfile::tempdir().unwrap();
    let outside_file = outside.path().join("outside.env");
    std::fs::write(&outside_file, "nope").unwrap();

    let result = cmd_add(vec![outside_file.to_str().unwrap().to_string()]);

    std::env::set_current_dir(original_dir).unwrap();

    assert!(
        result.is_err(),
        "cmd_add must reject a file outside the repository: {:?}",
        result.err()
    );
}

#[test]
#[serial]
fn remove_rejects_file_outside_repo() {
    let original_dir = std::env::current_dir().unwrap();
    let repo_temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(repo_temp.path()).unwrap();
    init_git_repo_in_cwd();

    let outside = tempfile::tempdir().unwrap();
    let outside_file = outside.path().join("outside.env");
    std::fs::write(&outside_file, "nope").unwrap();

    let result = cmd_remove(vec![outside_file.to_str().unwrap().to_string()]);

    std::env::set_current_dir(original_dir).unwrap();

    assert!(
        result.is_err(),
        "cmd_remove must reject a file outside the repository: {:?}",
        result.err()
    );
}

#[test]
#[serial]
fn reveal_refuses_escaping_tracked_path() {
    let original_dir = std::env::current_dir().unwrap();
    let (repo_temp, gpg_home, owner_pub) = setup_repo_with_owner_in_keyring();

    std::fs::write("secret.env", "topsecret").unwrap();
    cmd_add(vec!["secret.env".to_string()]).expect("cmd_add must succeed");
    cmd_hide("origin", &gpg_home).expect("cmd_hide must succeed");
    assert!(
        repo_temp.path().join(".git-gpg/secrets/secret.env.asc").exists(),
        "hide must write the ciphertext into .git-gpg/secrets"
    );

    // Attacker (any repo writer) tampers with the committed tracked.json to
    // point one level above the repo root, and commits a ciphertext that
    // decrypts with the victim's key. join("../outside.txt") under
    // .git-gpg/secrets lands at .git-gpg/outside.txt.asc.
    write_tracked_json(&["../outside.txt"]);
    let ciphertext = encrypt_to_gpg_key(b"pwned", &owner_pub).unwrap();
    std::fs::write(".git-gpg/outside.txt.asc", ciphertext).unwrap();

    let target = repo_temp
        .path()
        .parent()
        .unwrap()
        .join("outside.txt");
    let _ = std::fs::remove_file(&target);

    let result = cmd_reveal("owner@github.com", "origin", &gpg_home);

    std::env::set_current_dir(original_dir).unwrap();

    let target_exists = target.exists();
    let _ = std::fs::remove_file(&target);

    assert!(
        result.is_err(),
        "reveal must refuse an escaping tracked path: {:?}",
        result.err()
    );
    assert!(
        !target_exists,
        "reveal must not write outside the repository, but {} was created",
        target.display()
    );
}

// ============================================================================
// Full hide -> reveal roundtrip restores exact bytes
//
// These are protective (Green-only) tests: they pin the successful
// decrypt-and-restore path that no earlier test exercised. They were written
// to pass against the current implementation, not to fix a regression.
// ============================================================================

#[test]
#[serial]
fn hide_then_reveal_restores_exact_bytes() {
    let original_dir = std::env::current_dir().unwrap();
    let (alice_sec, alice_pub) = generate_test_key("alice@example.com");
    let (repo_temp, gpg_home) = setup_trusted_repo_with_secring(&[alice_sec]);

    let alice_keyfile = repo_temp.path().join("alice.pub");
    write_public_key_file(&alice_pub, &alice_keyfile);

    cmd_tell(
        "alice@example.com",
        alice_keyfile.to_str().unwrap(),
        "origin",
        &gpg_home,
    )
    .expect("cmd_tell must succeed");

    let plaintext: &str = "API_KEY=s3cr3t-value\nDB_PASSWORD=hunter2\n# unicode: héllo wörld — 日本語 🌍\nline with trailing spaces   \n";
    std::fs::write("secret.env", plaintext).unwrap();

    cmd_add(vec!["secret.env".to_string()]).expect("cmd_add must succeed");

    let hide_result = cmd_hide("origin", &gpg_home);
    let plaintext_gone_after_hide = !std::path::Path::new("secret.env").exists();
    let ciphertext_after_hide =
        std::path::Path::new(".git-gpg/secrets/secret.env.asc").exists();

    let reveal_result = cmd_reveal("alice@example.com", "origin", &gpg_home);
    let restored = std::fs::read("secret.env");
    let ciphertext_gone_after_reveal =
        !std::path::Path::new(".git-gpg/secrets/secret.env.asc").exists();

    std::env::set_current_dir(original_dir).unwrap();

    hide_result.expect("cmd_hide must succeed");
    assert!(
        plaintext_gone_after_hide,
        "hide must delete the plaintext file"
    );
    assert!(
        ciphertext_after_hide,
        "hide must write the ciphertext into .git-gpg/secrets/secret.env.asc"
    );
    reveal_result.expect("cmd_reveal must succeed");
    assert_eq!(
        restored.expect("revealed file must exist"),
        plaintext.as_bytes(),
        "reveal must restore the exact original bytes"
    );
    assert!(
        ciphertext_gone_after_reveal,
        "reveal must delete the ciphertext"
    );
    assert!(
        repo_temp.path().join("secret.env").is_file(),
        "the revealed file must be a regular file at the original path"
    );
}

#[test]
#[serial]
fn hide_then_reveal_in_subdirectory() {
    let original_dir = std::env::current_dir().unwrap();
    let (alice_sec, alice_pub) = generate_test_key("alice@example.com");
    let (repo_temp, gpg_home) = setup_trusted_repo_with_secring(&[alice_sec]);

    let alice_keyfile = repo_temp.path().join("alice.pub");
    write_public_key_file(&alice_pub, &alice_keyfile);

    cmd_tell(
        "alice@example.com",
        alice_keyfile.to_str().unwrap(),
        "origin",
        &gpg_home,
    )
    .expect("cmd_tell must succeed");

    let tracked_rel = "a/b/c/secret.env";
    let plaintext: &str = "NESTED_SECRET=prüne\ntrailing newline follows\n";
    std::fs::create_dir_all("a/b/c").unwrap();
    std::fs::write(tracked_rel, plaintext).unwrap();

    cmd_add(vec![tracked_rel.to_string()]).expect("cmd_add must succeed");

    let hide_result = cmd_hide("origin", &gpg_home);
    let plaintext_gone_after_hide = !std::path::Path::new(tracked_rel).exists();
    let ciphertext_after_hide = std::path::Path::new(
        ".git-gpg/secrets/a/b/c/secret.env.asc",
    )
    .exists();

    let reveal_result = cmd_reveal("alice@example.com", "origin", &gpg_home);
    let restored = std::fs::read(tracked_rel);
    let ciphertext_gone_after_reveal = !std::path::Path::new(
        ".git-gpg/secrets/a/b/c/secret.env.asc",
    )
    .exists();

    std::env::set_current_dir(original_dir).unwrap();

    hide_result.expect("cmd_hide must succeed");
    assert!(
        plaintext_gone_after_hide,
        "hide must delete the plaintext file"
    );
    assert!(
        ciphertext_after_hide,
        "hide must preserve the directory structure under .git-gpg/secrets"
    );
    reveal_result.expect("cmd_reveal must succeed");
    assert_eq!(
        restored.expect("revealed file must exist"),
        plaintext.as_bytes(),
        "reveal must restore the exact original bytes at the nested path"
    );
    assert!(
        ciphertext_gone_after_reveal,
        "reveal must delete the ciphertext"
    );
    assert!(
        repo_temp.path().join(tracked_rel).is_file(),
        "the revealed file must be recreated at the nested path"
    );
}

#[test]
#[serial]
fn hide_reveal_roundtrip_binary_file() {
    let original_dir = std::env::current_dir().unwrap();
    let (alice_sec, alice_pub) = generate_test_key("alice@example.com");
    let (repo_temp, gpg_home) = setup_trusted_repo_with_secring(&[alice_sec]);

    let alice_keyfile = repo_temp.path().join("alice.pub");
    write_public_key_file(&alice_pub, &alice_keyfile);

    cmd_tell(
        "alice@example.com",
        alice_keyfile.to_str().unwrap(),
        "origin",
        &gpg_home,
    )
    .expect("cmd_tell must succeed");

    let plaintext: Vec<u8> = (0..=255u8).collect();
    std::fs::write("blob.bin", &plaintext).unwrap();

    cmd_add(vec!["blob.bin".to_string()]).expect("cmd_add must succeed");

    let hide_result = cmd_hide("origin", &gpg_home);
    let plaintext_gone_after_hide = !std::path::Path::new("blob.bin").exists();

    let reveal_result = cmd_reveal("alice@example.com", "origin", &gpg_home);
    let restored = std::fs::read("blob.bin");

    std::env::set_current_dir(original_dir).unwrap();

    hide_result.expect("cmd_hide must succeed");
    assert!(
        plaintext_gone_after_hide,
        "hide must delete the plaintext file"
    );
    reveal_result.expect("cmd_reveal must succeed");
    assert_eq!(
        restored.expect("revealed file must exist"),
        plaintext,
        "reveal must restore every byte value 0x00..=0xFF unchanged"
    );
    assert!(
        repo_temp.path().join("blob.bin").is_file(),
        "the revealed file must be a regular file at the original path"
    );
}

#[test]
#[serial]
fn symlink_outside_repo_is_rejected() {
    let original_dir = std::env::current_dir().unwrap();
    let repo_temp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(repo_temp.path()).unwrap();
    init_git_repo_in_cwd();

    let outside = tempfile::tempdir().unwrap();
    let outside_file = outside.path().join("target.env");
    std::fs::write(&outside_file, "outside").unwrap();
    std::os::unix::fs::symlink(&outside_file, repo_temp.path().join("link.env")).unwrap();

    let result = cmd_add(vec!["link.env".to_string()]);

    let tracked_content = std::fs::read_to_string(repo_temp.path().join(".git-gpg/tracked.json"))
        .expect("tracked.json must exist");

    std::env::set_current_dir(original_dir).unwrap();

    assert!(
        result.is_err(),
        "cmd_add must reject a symlink whose target is outside the repo: {:?}",
        result.err()
    );
    assert!(
        outside_file.exists(),
        "the symlink target outside the repo must be untouched"
    );
    assert!(
        !tracked_content.contains("link.env"),
        "escaping symlink must not be tracked, got: {}",
        tracked_content
    );
}
