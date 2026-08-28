//! Contract tests for git-gpg features and regression fixes.
//!
//! Each test targets one named contract. Tests here are written Red/Green:
//! they must fail against the code they were written to fix, and pass after.

use git_gpg::{
    base64_encode_public_key, check_email_in_identities, cmd_add, cmd_cat, cmd_changes, cmd_hide,
    cmd_init, cmd_remove, cmd_removeperson, cmd_reveal, cmd_tell, cmd_trust, cmd_verify_keyring,
    decrypt_with_gpg_key, default_gpg_home, encrypt_to_gpg_key,
    extract_content_to_verify_from_keyring,
    extract_key_fingerprint, find_private_key_by_email, find_private_key_by_fingerprint,
    import_key_to_gpg_home, sign_keyring_content, Keyring, KeyringEntry, TrustPinStore, TrustStore,
    TrackedFiles,
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
    write_secring_content(gpg_home, &content);
}

fn write_secring_content(gpg_home: &PathBuf, content: &str) {
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
// default_gpg_home refuses to fall back to /tmp when HOME is unset (M6)
// ============================================================================

#[test]
#[serial]
fn default_gpg_home_errors_when_home_unset() {
    let saved = std::env::var("HOME").ok();
    std::env::remove_var("HOME");

    let result = default_gpg_home();

    match saved {
        Some(v) => std::env::set_var("HOME", v),
        None => std::env::remove_var("HOME"),
    }

    let err = result
        .err()
        .expect("unset HOME must be an error, not a silent /tmp fallback");
    assert!(
        err.to_string().contains("HOME"),
        "the error must mention HOME, got: {}",
        err
    );
}

#[test]
#[serial]
fn default_gpg_home_uses_home_when_set() {
    let saved = std::env::var("HOME").ok();
    let temp = tempfile::tempdir().unwrap();
    std::env::set_var("HOME", temp.path());

    let result = default_gpg_home();

    match saved {
        Some(v) => std::env::set_var("HOME", v),
        None => std::env::remove_var("HOME"),
    }

    assert_eq!(
        result.expect("a set HOME must resolve to $HOME/.gnupg"),
        temp.path().join(".gnupg"),
        "default_gpg_home must be $HOME/.gnupg"
    );
}

// ============================================================================
// Secret key selection from a multi-key secring
// ============================================================================

#[test]
fn find_private_key_by_email_selects_matching_key_when_not_first_in_secring() {
    let temp = tempfile::tempdir().unwrap();
    let gpg_home = temp.path().to_path_buf();
    let (alice, _) = generate_test_key("alice@example.com");
    let (bob, bob_pub) = generate_test_key("bob@example.com");
    let bob_fingerprint = extract_key_fingerprint(&bob_pub);
    write_multi_key_secring(&gpg_home, &[alice, bob]);

    let key = find_private_key_by_email(&gpg_home, "bob@example.com").expect(
        "bob's key should be found even though alice's key comes first",
    );
    assert_eq!(
        extract_key_fingerprint(&key.to_public_key()),
        bob_fingerprint,
        "the key returned for bob@example.com must be bob's key, not another key from the secring"
    );
}

#[test]
fn find_private_key_by_fingerprint_selects_matching_key_when_not_first_in_secring() {
    let temp = tempfile::tempdir().unwrap();
    let gpg_home = temp.path().to_path_buf();
    let (alice, _) = generate_test_key("alice@example.com");
    let (bob, bob_pub) = generate_test_key("bob@example.com");
    let bob_fingerprint = extract_key_fingerprint(&bob_pub);
    write_multi_key_secring(&gpg_home, &[alice, bob]);

    let key = find_private_key_by_fingerprint(&gpg_home, &bob_fingerprint).expect(
        "bob's key should be found even though alice's key comes first",
    );
    assert_eq!(
        extract_key_fingerprint(&key.to_public_key()),
        bob_fingerprint,
        "the key returned for bob's fingerprint must be bob's key, not another key from the secring"
    );
}

#[test]
fn find_private_key_by_email_fails_when_no_key_matches() {
    let temp = tempfile::tempdir().unwrap();
    let gpg_home = temp.path().to_path_buf();
    let (alice, _) = generate_test_key("alice@example.com");
    write_multi_key_secring(&gpg_home, &[alice]);

    let result = find_private_key_by_email(&gpg_home, "carol@example.com");
    assert!(result.is_err(), "unknown email must not match any key");
}

#[test]
fn find_private_key_by_email_errors_on_empty_secring() {
    let temp = tempfile::tempdir().unwrap();
    let gpg_home = temp.path().to_path_buf();
    write_secring_content(&gpg_home, "");

    let result = find_private_key_by_email(&gpg_home, "alice@example.com");

    let err = result.err().expect("an empty secring must not yield any key");
    assert!(
        err.to_string().contains("No private key blocks found"),
        "the error must state that no private key blocks were found, got: {}",
        err
    );
    assert!(
        err.to_string().contains("secring.pgp"),
        "the error must mention the secring file, got: {}",
        err
    );
}

#[test]
fn find_private_key_by_email_ignores_garbage_between_blocks() {
    let temp = tempfile::tempdir().unwrap();
    let gpg_home = temp.path().to_path_buf();
    let (alice, _) = generate_test_key("alice@example.com");
    let (bob, bob_pub) = generate_test_key("bob@example.com");
    let bob_fingerprint = extract_key_fingerprint(&bob_pub);
    let alice_armored = alice.to_armored_string(Default::default()).unwrap();
    let bob_armored = bob.to_armored_string(Default::default()).unwrap();
    let content = format!(
        "this leading text is not a key at all\n{}\n>>> random junk between blocks <<<\n{}\ntrailing junk",
        alice_armored, bob_armored
    );
    write_secring_content(&gpg_home, &content);

    let key = find_private_key_by_email(&gpg_home, "bob@example.com")
        .expect("bob's key must be found despite junk text around the blocks");
    assert_eq!(
        extract_key_fingerprint(&key.to_public_key()),
        bob_fingerprint,
        "the key returned for bob@example.com must be bob's key"
    );
}

#[test]
fn find_private_key_by_email_errors_on_truncated_final_block() {
    let temp = tempfile::tempdir().unwrap();
    let gpg_home = temp.path().to_path_buf();
    let (alice, _) = generate_test_key("alice@example.com");
    let (bob, _) = generate_test_key("bob@example.com");
    let alice_armored = alice.to_armored_string(Default::default()).unwrap();
    let bob_armored = bob.to_armored_string(Default::default()).unwrap();
    let end_marker = "-----END PGP PRIVATE KEY BLOCK-----";
    let truncated_bob = bob_armored[..bob_armored.find(end_marker).unwrap()].to_string();
    let content = format!("{}\n{}", alice_armored, truncated_bob);
    write_secring_content(&gpg_home, &content);

    let bob_result = find_private_key_by_email(&gpg_home, "bob@example.com");

    let bob_err = bob_result.err().expect(
        "a secring whose final block is truncated must not yield any key",
    );
    assert!(
        bob_err.to_string().contains("Unterminated private key block"),
        "the error must name the unterminated block, not the misleading 'No secret key found for email', got: {}",
        bob_err
    );
    assert!(
        bob_err.to_string().contains("corrupt secring"),
        "the error must state the secring is corrupt, got: {}",
        bob_err
    );
    assert!(
        bob_err.to_string().contains("secring.pgp"),
        "the error must mention the secring file, got: {}",
        bob_err
    );
    assert!(
        !bob_err.to_string().contains("No secret key found for email"),
        "the error must not be indistinguishable from 'email never existed', got: {}",
        bob_err
    );

    // A corrupt tail invalidates the whole secring: for a secrets tool the
    // safe choice is to reject every key rather than silently serve the
    // healthy-looking prefix, because truncation may itself be an attack
    // (an attacker who can truncate the secring must not be able to quietly
    // remove keys from use).
    let alice_result = find_private_key_by_email(&gpg_home, "alice@example.com");

    let alice_err = alice_result.err().expect(
        "a corrupt secring must be rejected in full: even keys before the truncated tail must not be served",
    );
    assert!(
        alice_err.to_string().contains("Unterminated private key block"),
        "alice's lookup must fail with the corrupt-secring error too, got: {}",
        alice_err
    );
}

#[test]
fn find_private_key_by_email_errors_on_truncated_only_secring() {
    let temp = tempfile::tempdir().unwrap();
    let gpg_home = temp.path().to_path_buf();
    let (alice, _) = generate_test_key("alice@example.com");
    let alice_armored = alice.to_armored_string(Default::default()).unwrap();
    let end_marker = "-----END PGP PRIVATE KEY BLOCK-----";
    let truncated = alice_armored[..alice_armored.find(end_marker).unwrap()].to_string();
    write_secring_content(&gpg_home, &truncated);

    let result = find_private_key_by_email(&gpg_home, "alice@example.com");

    let err = result
        .err()
        .expect("a secring holding only a truncated block must not yield any key");
    assert!(
        err.to_string().contains("Unterminated private key block"),
        "the error must name the unterminated block, got: {}",
        err
    );
    assert!(
        !err.to_string().contains("No private key blocks found"),
        "the error must not misleadingly claim no blocks were found, got: {}",
        err
    );
}

#[test]
fn find_private_key_by_email_returns_first_matching_key_when_email_is_duplicated() {
    let temp = tempfile::tempdir().unwrap();
    let gpg_home = temp.path().to_path_buf();
    let (carol_first, carol_first_pub) = generate_test_key("carol@example.com");
    let (carol_second, _) = generate_test_key("carol@example.com");
    let first_fingerprint = extract_key_fingerprint(&carol_first_pub);
    write_multi_key_secring(&gpg_home, &[carol_first, carol_second]);

    // Documented current behaviour: when two keys in the secring claim the
    // same email, the first matching key in file order wins. Treating
    // duplicated emails as an ambiguity error is out of scope here and is
    // reviewed under a separate task.
    let key = find_private_key_by_email(&gpg_home, "carol@example.com")
        .expect("a key matching the duplicated email must be found");
    assert_eq!(
        extract_key_fingerprint(&key.to_public_key()),
        first_fingerprint,
        "the first key in secring order must win when the email is duplicated"
    );
}

// ============================================================================
// Email matching requires exact address equality (M1)
// ============================================================================

fn generate_test_key_with_uid(uid: &str) -> (pgp::composed::SignedSecretKey, pgp::composed::SignedPublicKey) {
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
        .primary_user_id(uid.to_string())
        .passphrase(None)
        .subkeys(vec![encrypt_subkey])
        .build()
        .expect("build key params");

    let secret_key = params.generate(&mut rng).expect("generate key");
    let public_key = secret_key.to_public_key();

    (secret_key, public_key)
}

#[test]
fn email_matching_requires_exact_address() {
    let (_, evil_pub) =
        generate_test_key_with_uid("Evil <evil-bob@x.com.attacker.net>");

    // A UID whose address merely *contains* the requested email as a
    // substring must NOT match: trusting/adding for bob@x.com must not
    // bless a key held by evil-bob@x.com.attacker.net.
    assert!(
        !check_email_in_identities(&evil_pub, "bob@x.com"),
        "substring user-ID match must not count as owning bob@x.com"
    );

    // Exact address still matches.
    assert!(
        check_email_in_identities(&evil_pub, "evil-bob@x.com.attacker.net"),
        "the key's exact address must match"
    );

    // Matching is case-insensitive.
    let (_, bob_pub) = generate_test_key("bob@x.com");
    assert!(
        check_email_in_identities(&bob_pub, "BOB@X.COM"),
        "email matching must be case-insensitive"
    );
}

#[test]
fn find_private_key_by_email_requires_exact_address() {
    let temp = tempfile::tempdir().unwrap();
    let gpg_home = temp.path().to_path_buf();
    let (evil, _) = generate_test_key("xalice@example.com.evil.net");
    let (alice, alice_pub) = generate_test_key("alice@example.com");
    let alice_fingerprint = extract_key_fingerprint(&alice_pub);
    write_multi_key_secring(&gpg_home, &[evil, alice]);

    let result = find_private_key_by_email(&gpg_home, "alice@example.com");
    let key = result.expect(
        "alice's exact key must be found even though another key's address contains the query as a substring",
    );
    assert_eq!(
        extract_key_fingerprint(&key.to_public_key()),
        alice_fingerprint,
        "the key returned for alice@example.com must be alice's key, not the substring impostor"
    );
}

#[test]
fn find_private_key_by_email_rejects_substring_only_match() {
    let temp = tempfile::tempdir().unwrap();
    let gpg_home = temp.path().to_path_buf();
    let (evil, _) = generate_test_key("xalice@example.com.evil.net");
    write_multi_key_secring(&gpg_home, &[evil]);

    let result = find_private_key_by_email(&gpg_home, "alice@example.com");
    assert!(
        result.is_err(),
        "a key whose address merely contains the query as a substring must not be returned"
    );
}

#[test]
fn bare_user_id_without_angle_brackets_still_matches() {
    let (_, plain_pub) = generate_test_key_with_uid("plain@example.com");

    assert!(
        check_email_in_identities(&plain_pub, "plain@example.com"),
        "a bare user-ID that is itself an address must match exactly"
    );
    assert!(
        !check_email_in_identities(&plain_pub, "other@example.com"),
        "a bare user-ID must not match a different address"
    );

    let temp = tempfile::tempdir().unwrap();
    let gpg_home = temp.path().to_path_buf();
    let (plain_sec, plain_sec_pub) = generate_test_key_with_uid("plain@example.com");
    let stored_fingerprint = extract_key_fingerprint(&plain_sec_pub);
    write_multi_key_secring(&gpg_home, &[plain_sec]);

    let found = find_private_key_by_email(&gpg_home, "plain@example.com")
        .expect("a bare user-ID secring key must be findable by exact email");
    assert_eq!(
        extract_key_fingerprint(&found.to_public_key()),
        stored_fingerprint,
        "the bare-UID key found must be the one stored"
    );
}

// ============================================================================
// Keyring add_entry: update-not-duplicate for a repeated email (M3)
// ============================================================================

#[test]
fn add_entry_updates_existing_email_and_clears_signature() {
    let mut keyring = Keyring::new();
    keyring.add_entry(
        "alice@example.com".to_string(),
        "QUJDREVGR0hJSktMTU5PUA==".to_string(),
        "AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111".to_string(),
    );
    keyring.add_entry(
        "bob@example.com".to_string(),
        "QkNERUVGR0hJSktMTU5PUFI=".to_string(),
        "BBBB2222BBBB2222BBBB2222BBBB2222BBBB2222".to_string(),
    );
    keyring.signature = Some("-----BEGIN PGP SIGNATURE-----\nstale\n-----END PGP SIGNATURE-----".to_string());

    keyring.add_entry(
        "alice@example.com".to_string(),
        "REVGREdISklLTE1OT1BSU1Q=".to_string(),
        "CCCC3333CCCC3333CCCC3333CCCC3333CCCC3333".to_string(),
    );

    assert_eq!(
        keyring.entries.len(),
        2,
        "re-adding an existing email must not append a duplicate entry, got: {:?}",
        keyring.entries
    );
    assert_eq!(keyring.entries[0].email, "alice@example.com", "order must be preserved: alice first");
    assert_eq!(keyring.entries[1].email, "bob@example.com", "order must be preserved: bob second");
    assert_eq!(
        keyring.entries[0].fingerprint, "CCCC3333CCCC3333CCCC3333CCCC3333CCCC3333",
        "alice's fingerprint must be updated in place, got: {:?}",
        keyring.entries[0]
    );
    assert_eq!(
        keyring.entries[0].base64_key, "REVGREdISklLTE1OT1BSU1Q=",
        "alice's key material must be replaced, got: {:?}",
        keyring.entries[0]
    );
    assert!(
        keyring.signature.is_none(),
        "add_entry must clear the signature so the keyring gets re-signed"
    );
}

#[test]
fn tell_twice_same_email_updates_rather_than_duplicates() {
    let (alice_sec, alice_pub) = generate_test_key("alice@example.com");
    let (repo_temp, gpg_home) = setup_trusted_repo_with_secring(&[alice_sec]);

    let alice_keyfile = repo_temp.path().join("alice.pub");
    write_public_key_file(&alice_pub, &alice_keyfile);

    cmd_tell(
        repo_temp.path(),
        "alice@example.com",
        alice_keyfile.to_str().unwrap(),
        "origin",
        &gpg_home,
    )
    .expect("first tell must succeed");

    let keyring_after_first =
        Keyring::parse(&std::fs::read_to_string(repo_temp.path().join(".git-gpg/keyring")).unwrap()).unwrap();

    let second_tell = cmd_tell(
        repo_temp.path(),
        "alice@example.com",
        alice_keyfile.to_str().unwrap(),
        "origin",
        &gpg_home,
    );

    let keyring_text = std::fs::read_to_string(repo_temp.path().join(".git-gpg/keyring")).unwrap();
    let keyring_after_second = Keyring::parse(&keyring_text).unwrap();
    let alice_count = keyring_after_second
        .entries
        .iter()
        .filter(|e| e.email == "alice@example.com")
        .count();
    let verify_result = cmd_verify_keyring(repo_temp.path(), "origin", &gpg_home);

    second_tell.expect("second tell for the same email must succeed");
    assert_eq!(
        keyring_after_first.entries.len(),
        1,
        "sanity: first tell must yield one entry, got: {:?}",
        keyring_after_first.entries
    );
    assert_eq!(
        alice_count, 1,
        "telling the same email twice must update, not duplicate: got {} alice entries in {}",
        alice_count, keyring_text
    );
    assert_eq!(
        keyring_after_second.entries.len(), 1,
        "keyring must hold exactly one entry total after duplicate tell, got: {:?}",
        keyring_after_second.entries
    );
    verify_result.expect("keyring must still verify after duplicate tell");
}

// ============================================================================
// Trust establishment validates the owner email from the repo ID
// ============================================================================

#[test]
fn trust_accepts_owner_key_matching_user_at_service_email() {
    let repo_temp = setup_git_repo_with_origin_remote();

    cmd_init(repo_temp.path()).expect("cmd_init must succeed");

    let (_, owner_pub) = generate_test_key("owner@github.com");
    let keyfile = repo_temp.path().join("owner.pub");
    write_public_key_file(&owner_pub, &keyfile);

    let gpg_temp = tempfile::tempdir().unwrap();

    let result = cmd_trust(
        repo_temp.path(),
        "repo+owner@github.com",
        keyfile.to_str().unwrap(),
        "origin",
        &gpg_temp.path().to_path_buf(),
    );

    assert!(
        result.is_ok(),
        "owner key for owner@github.com must be trusted: {:?}",
        result.err()
    );
}

#[test]
fn trust_rejects_key_without_owner_email() {
    let repo_temp = setup_git_repo_with_origin_remote();

    cmd_init(repo_temp.path()).expect("cmd_init must succeed");

    let (_, evil_pub) = generate_test_key("evil@attacker.com");
    let keyfile = repo_temp.path().join("evil.pub");
    write_public_key_file(&evil_pub, &keyfile);

    let gpg_temp = tempfile::tempdir().unwrap();

    let result = cmd_trust(
        repo_temp.path(),
        "repo+owner@github.com",
        keyfile.to_str().unwrap(),
        "origin",
        &gpg_temp.path().to_path_buf(),
    );

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

    let mut secring_keys: Vec<pgp::composed::SignedSecretKey> = vec![owner_sec];
    secring_keys.extend_from_slice(secret_keys);
    write_multi_key_secring(&gpg_home, &secring_keys);

    (repo_temp, gpg_home)
}

#[test]
fn tell_rejects_unsigned_keyring_containing_entries() {
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
    std::fs::write(repo_temp.path().join(".git-gpg/keyring"), unsigned_keyring.serialize()).unwrap();

    let alice_keyfile = repo_temp.path().join("alice.pub");
    write_public_key_file(&alice_pub, &alice_keyfile);

    let result = cmd_tell(
        repo_temp.path(),
        "alice@example.com",
        alice_keyfile.to_str().unwrap(),
        "origin",
        &gpg_home,
    );

    assert!(
        result.is_err(),
        "tell must reject an unsigned keyring that already contains entries"
    );
}

#[test]
fn tell_rejects_keyring_signed_by_wrong_key() {
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
    std::fs::write(repo_temp.path().join(".git-gpg/keyring"), forged.serialize()).unwrap();

    let alice_keyfile = repo_temp.path().join("alice.pub");
    write_public_key_file(&alice_pub, &alice_keyfile);

    let result = cmd_tell(
        repo_temp.path(),
        "alice@example.com",
        alice_keyfile.to_str().unwrap(),
        "origin",
        &gpg_home,
    );

    assert!(
        result.is_err(),
        "tell must reject a keyring signed by a non-trusted key"
    );
}

#[test]
fn tell_first_entry_on_fresh_repo_succeeds() {
    let (alice_sec, alice_pub) = generate_test_key("alice@example.com");
    let (repo_temp, gpg_home) = setup_trusted_repo_with_secring(&[alice_sec]);

    let alice_keyfile = repo_temp.path().join("alice.pub");
    write_public_key_file(&alice_pub, &alice_keyfile);

    let result = cmd_tell(
        repo_temp.path(),
        "alice@example.com",
        alice_keyfile.to_str().unwrap(),
        "origin",
        &gpg_home,
    );

    let keyring_text =
        std::fs::read_to_string(repo_temp.path().join(".git-gpg/keyring")).expect("keyring must exist after tell");

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
// removeperson: revoking a collaborator from the keyring
// ============================================================================

#[test]
fn removeperson_removes_entry_and_resigns() {
    let (_, alice_pub) = generate_test_key("alice@example.com");
    let (_, bob_pub) = generate_test_key("bob@example.com");
    let (repo_temp, gpg_home) = setup_trusted_repo_with_secring(&[]);

    let alice_keyfile = repo_temp.path().join("alice.pub");
    write_public_key_file(&alice_pub, &alice_keyfile);
    let bob_keyfile = repo_temp.path().join("bob.pub");
    write_public_key_file(&bob_pub, &bob_keyfile);

    cmd_tell(
        repo_temp.path(),
        "alice@example.com",
        alice_keyfile.to_str().unwrap(),
        "origin",
        &gpg_home,
    )
    .expect("tell alice must succeed");
    cmd_tell(        repo_temp.path(),
        "bob@example.com",
        bob_keyfile.to_str().unwrap(),
        "origin",
        &gpg_home,
    )
    .expect("tell bob must succeed");

    let remove_result = cmd_removeperson(repo_temp.path(), "bob@example.com", "origin", &gpg_home);

    let keyring_text = std::fs::read_to_string(repo_temp.path().join(".git-gpg/keyring")).unwrap();
    let keyring = Keyring::parse(&keyring_text).unwrap();
    let verify_result = cmd_verify_keyring(repo_temp.path(), "origin", &gpg_home);

    remove_result.expect("removeperson must succeed for an existing collaborator");
    assert_eq!(
        keyring.list_emails(),
        vec!["alice@example.com"],
        "keyring must contain exactly alice after removing bob, got: {:?}",
        keyring.entries
    );
    assert!(
        keyring_text.contains("-----BEGIN PGP SIGNATURE-----"),
        "keyring must be re-signed after removeperson, got: {}",
        keyring_text
    );
    verify_result.expect("keyring signature must still verify after removeperson");
}

#[test]
fn removeperson_unknown_email_fails() {
    let (_, alice_pub) = generate_test_key("alice@example.com");
    let (repo_temp, gpg_home) = setup_trusted_repo_with_secring(&[]);

    let alice_keyfile = repo_temp.path().join("alice.pub");
    write_public_key_file(&alice_pub, &alice_keyfile);

    cmd_tell(
        repo_temp.path(),
        "alice@example.com",
        alice_keyfile.to_str().unwrap(),
        "origin",
        &gpg_home,
    )
    .expect("tell alice must succeed");

    let remove_result = cmd_removeperson(repo_temp.path(), "carol@example.com", "origin", &gpg_home);

    let err = remove_result.err().expect("removing an unknown email must fail");
    assert!(
        err.to_string().contains("carol@example.com"),
        "the error must name the missing email, got: {}",
        err
    );
}

#[test]
fn removeperson_requires_trust() {
    let repo_temp = setup_git_repo_with_origin_remote();

    cmd_init(repo_temp.path()).expect("cmd_init must succeed");

    let remove_result = cmd_removeperson(
        repo_temp.path(),
        "alice@example.com",
        "origin",
        &repo_temp.path().join("gpg-home"),
    );

    assert!(
        remove_result.is_err(),
        "removeperson without established trust must fail: {:?}",
        remove_result.err()
    );
}

#[test]
fn removeperson_rejects_tampered_keyring() {
    let (_, alice_pub) = generate_test_key("alice@example.com");
    let (repo_temp, gpg_home) = setup_trusted_repo_with_secring(&[]);

    let alice_keyfile = repo_temp.path().join("alice.pub");
    write_public_key_file(&alice_pub, &alice_keyfile);

    cmd_tell(
        repo_temp.path(),
        "alice@example.com",
        alice_keyfile.to_str().unwrap(),
        "origin",
        &gpg_home,
    )
    .expect("tell alice must succeed");

    // Tamper: forge a keyring containing an attacker entry, signed by a key
    // that is NOT the trusted owner key. removeperson must refuse to touch
    // (and never re-sign) this content.
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
    std::fs::write(repo_temp.path().join(".git-gpg/keyring"), forged.serialize()).unwrap();

    let remove_result = cmd_removeperson(repo_temp.path(), "mallory@evil.com", "origin", &gpg_home);

    let keyring_text_after = std::fs::read_to_string(repo_temp.path().join(".git-gpg/keyring")).unwrap();

    assert!(
        remove_result.is_err(),
        "removeperson must reject a tampered keyring: {:?}",
        remove_result.err()
    );
    assert!(
        keyring_text_after.contains("mallory@evil.com"),
        "the tampered keyring must be left untouched, got: {}",
        keyring_text_after
    );
}

// ============================================================================
// Init produces loadable, canonical store files
// ============================================================================

#[test]
fn init_creates_loadable_trust_store() {
    let repo_temp = setup_git_repo_with_origin_remote();

    cmd_init(repo_temp.path()).expect("cmd_init must succeed");

    let loaded = TrustStore::load_from_file(&repo_temp.path().join(".git-gpg/trust.json"));

    let store = loaded.expect("trust.json written by init must load via TrustStore");
    assert!(
        store.trusted_keys.is_empty(),
        "a freshly initialised trust store must be empty"
    );
}

#[test]
fn trust_store_load_from_file_accepts_empty_object() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("trust.json");
    std::fs::write(&path, "{}").unwrap();

    let loaded = TrustStore::load_from_file(&path);

    let store = loaded.expect("an empty JSON object must load as an empty trust store");
    assert!(
        store.trusted_keys.is_empty(),
        "loading '{{}}' must yield an empty trust store, got: {:?}",
        store.trusted_keys
    );
}

// ============================================================================
// Fresh repo multi-command happy path: init -> trust -> tell -> verify
// ============================================================================

#[test]
fn fresh_repo_init_trust_tell_verify_happy_path() {
    let repo_temp = setup_git_repo_with_origin_remote();

    cmd_init(repo_temp.path()).expect("cmd_init must succeed");

    let (owner_sec, owner_pub) = generate_test_key("owner@github.com");
    let owner_keyfile = repo_temp.path().join("owner.pub");
    write_public_key_file(&owner_pub, &owner_keyfile);

    let gpg_home = repo_temp.path().join("gpg-home");

    let trust_result = cmd_trust(
        repo_temp.path(),
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
        repo_temp.path(),
        "alice@example.com",
        alice_keyfile.to_str().unwrap(),
        "origin",
        &gpg_home,
    );

    let verify_result = cmd_verify_keyring(repo_temp.path(), "origin", &gpg_home);

    trust_result.expect("cmd_trust must succeed on a fresh repo");
    tell_result.expect("cmd_tell must succeed on a fresh repo");
    verify_result.expect("cmd_verify_keyring must succeed after trust and tell");
}

// ============================================================================
// C2/M4: tracked paths are repo-relative and validated at every boundary
// ============================================================================

fn init_git_repo(repo_root: &std::path::Path) {
    let status = std::process::Command::new("git")
        .current_dir(repo_root)
        .args(["init"])
        .status()
        .expect("run git init");
    assert!(status.success(), "git init failed");
    cmd_init(repo_root).expect("cmd_init must succeed");
}

fn write_tracked_json(repo_root: &std::path::Path, files: &[&str]) {
    let entries: Vec<String> = files.iter().map(|f| format!("\"{}\"", f)).collect();
    let content = format!("{{\n  \"files\": [{}]\n}}", entries.join(", "));
    std::fs::create_dir_all(repo_root.join(".git-gpg")).unwrap();
    std::fs::write(repo_root.join(".git-gpg/tracked.json"), content).unwrap();
}

/// Sets up a repo where the trusted owner key is also a keyring entry, so a
/// full add -> hide -> reveal flow can run with the owner's own keypair.
fn setup_repo_with_owner_in_keyring()
-> (tempfile::TempDir, PathBuf, pgp::composed::SignedPublicKey) {
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
        &gpg_home,
    )
    .expect("cmd_tell must succeed");

    (repo_temp, gpg_home, owner_pub)
}

#[test]
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
fn add_stores_repo_relative_paths() {
    let temp = tempfile::tempdir().unwrap();
    init_git_repo(temp.path());

    std::fs::write(temp.path().join("secret.env"), "s3cret").unwrap();
    let result = cmd_add(temp.path(), vec!["secret.env".to_string()]);

    let tracked_content = std::fs::read_to_string(temp.path().join(".git-gpg/tracked.json"))
        .expect("tracked.json must exist after add");

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
fn add_rejects_file_outside_repo() {
    let repo_temp = tempfile::tempdir().unwrap();
    init_git_repo(repo_temp.path());

    let outside = tempfile::tempdir().unwrap();
    let outside_file = outside.path().join("outside.env");
    std::fs::write(&outside_file, "nope").unwrap();

    let result = cmd_add(repo_temp.path(), vec![outside_file.to_str().unwrap().to_string()]);

    assert!(
        result.is_err(),
        "cmd_add must reject a file outside the repository: {:?}",
        result.err()
    );
}

#[test]
fn remove_rejects_file_outside_repo() {
    let repo_temp = tempfile::tempdir().unwrap();
    init_git_repo(repo_temp.path());

    let outside = tempfile::tempdir().unwrap();
    let outside_file = outside.path().join("outside.env");
    std::fs::write(&outside_file, "nope").unwrap();

    let result = cmd_remove(repo_temp.path(), vec![outside_file.to_str().unwrap().to_string()]);

    assert!(
        result.is_err(),
        "cmd_remove must reject a file outside the repository: {:?}",
        result.err()
    );
}

#[test]
fn reveal_refuses_escaping_tracked_path() {
    let (repo_temp, gpg_home, owner_pub) = setup_repo_with_owner_in_keyring();

    std::fs::write(repo_temp.path().join("secret.env"), "topsecret").unwrap();
    cmd_add(repo_temp.path(), vec!["secret.env".to_string()]).expect("cmd_add must succeed");
    cmd_hide(repo_temp.path(), "origin", &gpg_home).expect("cmd_hide must succeed");
    assert!(
        repo_temp.path().join(".git-gpg/secrets/secret.env.asc").exists(),
        "hide must write the ciphertext into .git-gpg/secrets"
    );

    // Attacker (any repo writer) tampers with the committed tracked.json to
    // point one level above the repo root, and commits a ciphertext that
    // decrypts with the victim's key. join("../outside.txt") under
    // .git-gpg/secrets lands at .git-gpg/outside.txt.asc.
    write_tracked_json(repo_temp.path(), &["../outside.txt"]);
    let ciphertext = encrypt_to_gpg_key(b"pwned", &owner_pub).unwrap();
    std::fs::write(repo_temp.path().join(".git-gpg/outside.txt.asc"), ciphertext).unwrap();

    let target = repo_temp
        .path()
        .parent()
        .unwrap()
        .join("outside.txt");
    let _ = std::fs::remove_file(&target);

    let result = cmd_reveal(repo_temp.path(), "owner@github.com", "origin", &gpg_home);

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
fn hide_then_reveal_restores_exact_bytes() {
    let (alice_sec, alice_pub) = generate_test_key("alice@example.com");
    let (repo_temp, gpg_home) = setup_trusted_repo_with_secring(&[alice_sec]);

    let alice_keyfile = repo_temp.path().join("alice.pub");
    write_public_key_file(&alice_pub, &alice_keyfile);

    cmd_tell(
        repo_temp.path(),
        "alice@example.com",
        alice_keyfile.to_str().unwrap(),
        "origin",
        &gpg_home,
    )
    .expect("cmd_tell must succeed");

    let plaintext: &str = "API_KEY=s3cr3t-value\nDB_PASSWORD=hunter2\n# unicode: héllo wörld — 日本語 🌍\nline with trailing spaces   \n";
    std::fs::write(repo_temp.path().join("secret.env"), plaintext).unwrap();

    cmd_add(repo_temp.path(), vec!["secret.env".to_string()]).expect("cmd_add must succeed");

    let hide_result = cmd_hide(repo_temp.path(), "origin", &gpg_home);
    let plaintext_gone_after_hide = !repo_temp.path().join("secret.env").exists();
    let ciphertext_after_hide =
        repo_temp.path().join(".git-gpg/secrets/secret.env.asc").exists();

    let reveal_result = cmd_reveal(repo_temp.path(), "alice@example.com", "origin", &gpg_home);
    let restored = std::fs::read(repo_temp.path().join("secret.env"));
    let ciphertext_gone_after_reveal =
        !repo_temp.path().join(".git-gpg/secrets/secret.env.asc").exists();

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
fn hide_then_reveal_in_subdirectory() {
    let (alice_sec, alice_pub) = generate_test_key("alice@example.com");
    let (repo_temp, gpg_home) = setup_trusted_repo_with_secring(&[alice_sec]);

    let alice_keyfile = repo_temp.path().join("alice.pub");
    write_public_key_file(&alice_pub, &alice_keyfile);

    cmd_tell(
        repo_temp.path(),
        "alice@example.com",
        alice_keyfile.to_str().unwrap(),
        "origin",
        &gpg_home,
    )
    .expect("cmd_tell must succeed");

    let tracked_rel = "a/b/c/secret.env";
    let plaintext: &str = "NESTED_SECRET=prüne\ntrailing newline follows\n";
    std::fs::create_dir_all(repo_temp.path().join("a/b/c")).unwrap();
    std::fs::write(repo_temp.path().join(tracked_rel), plaintext).unwrap();

    cmd_add(repo_temp.path(), vec![tracked_rel.to_string()]).expect("cmd_add must succeed");

    let hide_result = cmd_hide(repo_temp.path(), "origin", &gpg_home);
    let plaintext_gone_after_hide = !repo_temp.path().join(tracked_rel).exists();
    let ciphertext_after_hide = repo_temp.path().join(".git-gpg/secrets/a/b/c/secret.env.asc")
    .exists();

    let reveal_result = cmd_reveal(repo_temp.path(), "alice@example.com", "origin", &gpg_home);
    let restored = std::fs::read(repo_temp.path().join(tracked_rel));
    let ciphertext_gone_after_reveal = !repo_temp.path().join(".git-gpg/secrets/a/b/c/secret.env.asc")
    .exists();

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
fn hide_reveal_roundtrip_binary_file() {
    let (alice_sec, alice_pub) = generate_test_key("alice@example.com");
    let (repo_temp, gpg_home) = setup_trusted_repo_with_secring(&[alice_sec]);

    let alice_keyfile = repo_temp.path().join("alice.pub");
    write_public_key_file(&alice_pub, &alice_keyfile);

    cmd_tell(
        repo_temp.path(),
        "alice@example.com",
        alice_keyfile.to_str().unwrap(),
        "origin",
        &gpg_home,
    )
    .expect("cmd_tell must succeed");

    let plaintext: Vec<u8> = (0..=255u8).collect();
    std::fs::write(repo_temp.path().join("blob.bin"), &plaintext).unwrap();

    cmd_add(repo_temp.path(), vec!["blob.bin".to_string()]).expect("cmd_add must succeed");

    let hide_result = cmd_hide(repo_temp.path(), "origin", &gpg_home);
    let plaintext_gone_after_hide = !repo_temp.path().join("blob.bin").exists();

    let reveal_result = cmd_reveal(repo_temp.path(), "alice@example.com", "origin", &gpg_home);
    let restored = std::fs::read(repo_temp.path().join("blob.bin"));

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

// ============================================================================
// L4: ciphertext filename is the FULL original file name plus ".asc"
//
// Regression tests written Red/Green: previously the ciphertext path was
// computed with with_extension(), which for an extensionless file appended
// a bare second dot (notes -> notes..asc, .env -> .env..asc).
// ============================================================================

#[test]
fn ciphertext_filename_is_full_name_plus_asc() {
    let (repo_temp, gpg_home, _) = setup_repo_with_owner_in_keyring();

    std::fs::write(repo_temp.path().join("notes"), "no extension here\n").unwrap();
    cmd_add(repo_temp.path(), vec!["notes".to_string()]).expect("cmd_add must succeed");

    let hide_result = cmd_hide(repo_temp.path(), "origin", &gpg_home);
    let ciphertext_exists =
        repo_temp.path().join(".git-gpg/secrets/notes.asc").exists();
    let mangled_exists =
        repo_temp.path().join(".git-gpg/secrets/notes..asc").exists();

    hide_result.expect("cmd_hide must succeed");
    assert!(
        ciphertext_exists,
        "hide must write the ciphertext to .git-gpg/secrets/notes.asc"
    );
    assert!(
        !mangled_exists,
        "hide must not mangle the ciphertext name to notes..asc"
    );
}

#[test]
fn ciphertext_filename_for_dotfile() {
    let (repo_temp, gpg_home, _) = setup_repo_with_owner_in_keyring();

    std::fs::write(repo_temp.path().join(".env"), "DOTENV=1\n").unwrap();
    cmd_add(repo_temp.path(), vec![".env".to_string()]).expect("cmd_add must succeed");

    let hide_result = cmd_hide(repo_temp.path(), "origin", &gpg_home);
    let ciphertext_exists =
        repo_temp.path().join(".git-gpg/secrets/.env.asc").exists();
    let mangled_exists =
        repo_temp.path().join(".git-gpg/secrets/.env..asc").exists();

    hide_result.expect("cmd_hide must succeed");
    assert!(
        ciphertext_exists,
        "hide must write the ciphertext to .git-gpg/secrets/.env.asc"
    );
    assert!(
        !mangled_exists,
        "hide must not mangle the ciphertext name to .env..asc"
    );
}

#[test]
fn hide_then_reveal_roundtrip_fully_preserves_file_names() {
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("notes", b"extensionless notes\n".to_vec()),
        (".env", b"DOTENV_SECRET=topsecret\n".to_vec()),
        ("a.tar.gz", b"double-extension archive bytes".to_vec()),
    ];
    let (alice_sec, alice_pub) = generate_test_key("alice@example.com");
    let (repo_temp, gpg_home) = setup_trusted_repo_with_secring(&[alice_sec]);

    let alice_keyfile = repo_temp.path().join("alice.pub");
    write_public_key_file(&alice_pub, &alice_keyfile);

    cmd_tell(
        repo_temp.path(),
        "alice@example.com",
        alice_keyfile.to_str().unwrap(),
        "origin",
        &gpg_home,
    )
    .expect("cmd_tell must succeed");

    for (name, bytes) in &cases {
        std::fs::write(repo_temp.path().join(name), bytes).unwrap();
        cmd_add(repo_temp.path(), vec![name.to_string()])
            .unwrap_or_else(|e| panic!("cmd_add must succeed for {}: {:?}", name, e));
    }

    let hide_result = cmd_hide(repo_temp.path(), "origin", &gpg_home);
    let ciphertexts_exist: Vec<(String, bool)> = cases
        .iter()
        .map(|(name, _)| {
            (
                name.to_string(),
                repo_temp
                    .path()
                    .join(".git-gpg/secrets")
                    .join(format!("{}.asc", name))
                    .exists(),
            )
        })
        .collect();

    let reveal_result = cmd_reveal(repo_temp.path(), "alice@example.com", "origin", &gpg_home);
    let restored: Vec<(String, Option<Vec<u8>>)> = cases
        .iter()
        .map(|(name, _)| (name.to_string(), std::fs::read(repo_temp.path().join(name)).ok()))
        .collect();

    hide_result.expect("cmd_hide must succeed");
    for (name, exists) in ciphertexts_exist {
        assert!(
            exists,
            "hide must write the ciphertext to .git-gpg/secrets/{}.asc",
            name
        );
    }
    reveal_result.expect("cmd_reveal must succeed");
    for ((name, original), (restored_name, restored_bytes)) in
        cases.iter().zip(restored.iter())
    {
        assert_eq!(name, restored_name, "test bookkeeping must stay in sync");
        let restored_bytes = restored_bytes.as_ref().unwrap_or_else(|| {
            panic!("reveal must recreate {}", name)
        });
        assert_eq!(
            restored_bytes, original,
            "reveal must restore {} byte-exactly under its full original name",
            name
        );
    }
    assert!(
        repo_temp.path().join("a.tar.gz").is_file(),
        "the revealed multi-extension file must keep its full original name"
    );
}

#[test]
fn symlink_outside_repo_is_rejected() {
    let repo_temp = tempfile::tempdir().unwrap();
    init_git_repo(repo_temp.path());

    let outside = tempfile::tempdir().unwrap();
    let outside_file = outside.path().join("target.env");
    std::fs::write(&outside_file, "outside").unwrap();
    std::os::unix::fs::symlink(&outside_file, repo_temp.path().join("link.env")).unwrap();

    let result = cmd_add(repo_temp.path(), vec!["link.env".to_string()]);

    let tracked_content = std::fs::read_to_string(repo_temp.path().join(".git-gpg/tracked.json"))
        .expect("tracked.json must exist");

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

// ============================================================================
// cat: decrypt a single tracked file to stdout without touching disk state
// ============================================================================

/// Full flow: init -> trust -> tell(alice) -> add -> hide, with alice's key
/// in the secring. Returns (repo_temp, gpg_home).
fn setup_hidden_repo_with_alice_key() -> (tempfile::TempDir, PathBuf) {
    let (alice_sec, alice_pub) = generate_test_key("alice@example.com");
    let (repo_temp, gpg_home) = setup_trusted_repo_with_secring(&[alice_sec]);

    let alice_keyfile = repo_temp.path().join("alice.pub");
    write_public_key_file(&alice_pub, &alice_keyfile);

    cmd_tell(
        repo_temp.path(),
        "alice@example.com",
        alice_keyfile.to_str().unwrap(),
        "origin",
        &gpg_home,
    )
    .expect("cmd_tell must succeed");

    (repo_temp, gpg_home)
}

#[test]
fn cat_returns_exact_bytes_without_touching_disk() {
    let (repo_temp, gpg_home) = setup_hidden_repo_with_alice_key();

    let plaintext: &str = "API_KEY=cat-s3cr3t\nDB_PASSWORD=hunter2\n# unicode: héllo — 日本語\n";
    std::fs::write(repo_temp.path().join("secret.env"), plaintext).unwrap();
    cmd_add(repo_temp.path(), vec!["secret.env".to_string()]).expect("cmd_add must succeed");
    cmd_hide(repo_temp.path(), "origin", &gpg_home).expect("cmd_hide must succeed");

    let cat_result = cmd_cat(repo_temp.path(), "secret.env", "alice@example.com", "origin", &gpg_home);
    let ciphertext_still_exists =
        repo_temp.path().join(".git-gpg/secrets/secret.env.asc").exists();
    let no_plaintext_on_disk = !repo_temp.path().join("secret.env").exists();

    let bytes = cat_result.expect("cmd_cat must decrypt the tracked file");
    assert_eq!(
        bytes, plaintext.as_bytes(),
        "cat must return the exact original plaintext bytes"
    );
    assert!(
        ciphertext_still_exists,
        "cat must not delete the ciphertext"
    );
    assert!(
        no_plaintext_on_disk,
        "cat must not write a plaintext file to disk"
    );
    assert!(
        !repo_temp.path().join("secret.env").exists(),
        "cat must leave no plaintext at the tracked path"
    );
}

#[test]
fn cat_fails_for_untracked_file() {
    let (repo_temp, gpg_home) = setup_hidden_repo_with_alice_key();

    let result = cmd_cat(repo_temp.path(), "not-tracked.env", "alice@example.com", "origin", &gpg_home);

    let err = result.err().expect("cat of an untracked file must fail");
    assert!(
        err.to_string().contains("not tracked"),
        "the error must say the file is not tracked, got: {}",
        err
    );
}

#[test]
fn cat_rejects_path_escaping_the_repo() {
    let (repo_temp, gpg_home) = setup_hidden_repo_with_alice_key();

    std::fs::write(repo_temp.path().join("secret.env"), "s3cret").unwrap();
    cmd_add(repo_temp.path(), vec!["secret.env".to_string()]).expect("cmd_add must succeed");
    cmd_hide(repo_temp.path(), "origin", &gpg_home).expect("cmd_hide must succeed");

    let dotdot_result = cmd_cat(repo_temp.path(), "../outside.txt", "alice@example.com", "origin", &gpg_home);
    let outside = repo_temp.path().parent().unwrap().join("outside.txt");
    std::fs::write(&outside, "nope").unwrap();
    let absolute_result = cmd_cat(
        repo_temp.path(),
        outside.to_str().unwrap(),
        "alice@example.com",
        "origin",
        &gpg_home,
    );
    let absolute_exists = outside.exists();
    let _ = std::fs::remove_file(&outside);

    let dotdot_err = dotdot_result
        .err()
        .expect("cat of a ../ path must be rejected");
    assert!(
        dotdot_err.to_string().contains("../outside.txt"),
        "the error must name the escaping path, got: {}",
        dotdot_err
    );
    let absolute_err = absolute_result
        .err()
        .expect("cat of an absolute path outside the repo must be rejected");
    assert!(
        absolute_err.to_string().contains("outside the repository")
            || absolute_err.to_string().contains("not tracked")
            || absolute_err.to_string().contains("outside.txt"),
        "the error must explain the rejection, got: {}",
        absolute_err
    );
    assert!(
        absolute_exists,
        "the outside file must be untouched by the rejected cat"
    );
}

// ============================================================================
// changes: report where on-disk plaintext differs from the last hidden version
// ============================================================================

#[test]
fn changes_reports_no_changes_when_plaintext_matches() {
    let (repo_temp, gpg_home, _) = setup_repo_with_owner_in_keyring();

    let plaintext = "API_KEY=s3cr3t-value\nDB_PASSWORD=hunter2\n";
    std::fs::write(repo_temp.path().join("secret.env"), plaintext).unwrap();
    cmd_add(repo_temp.path(), vec!["secret.env".to_string()]).expect("cmd_add must succeed");
    cmd_hide(repo_temp.path(), "origin", &gpg_home).expect("cmd_hide must succeed");

    // Re-create the plaintext with IDENTICAL bytes, as if revealed and untouched.
    std::fs::write(repo_temp.path().join("secret.env"), plaintext).unwrap();

    let result = cmd_changes(repo_temp.path(), vec![], "owner@github.com", "origin", &gpg_home);
    let ciphertext_still_exists =
        repo_temp.path().join(".git-gpg/secrets/secret.env.asc").exists();

    let changed = result.expect("cmd_changes must succeed when plaintext matches");
    assert!(
        changed.is_empty(),
        "identical plaintext must not be reported as changed, got: {:?}",
        changed
    );
    assert!(
        ciphertext_still_exists,
        "changes must not delete the ciphertext"
    );
    assert!(
        repo_temp.path().join("secret.env").is_file(),
        "changes must not touch the plaintext on disk"
    );
}

#[test]
fn changes_reports_modified_file() {
    let (repo_temp, gpg_home, _) = setup_repo_with_owner_in_keyring();

    std::fs::write(repo_temp.path().join("secret.env"), "API_KEY=old-value\n").unwrap();
    cmd_add(repo_temp.path(), vec!["secret.env".to_string()]).expect("cmd_add must succeed");
    cmd_hide(repo_temp.path(), "origin", &gpg_home).expect("cmd_hide must succeed");

    std::fs::write(repo_temp.path().join("secret.env"), "API_KEY=NEW-value\nDB=hunter2\n").unwrap();

    let result = cmd_changes(repo_temp.path(), vec![], "owner@github.com", "origin", &gpg_home);

    let changed = result.expect("cmd_changes must succeed for a modified file");
    assert_eq!(
        changed,
        vec![PathBuf::from("secret.env")],
        "the modified file must be the only reported change, got: {:?}",
        changed
    );
}

#[test]
fn changes_ignores_missing_plaintext() {
    let (repo_temp, gpg_home, _) = setup_repo_with_owner_in_keyring();

    std::fs::write(repo_temp.path().join("secret.env"), "API_KEY=s3cr3t\n").unwrap();
    cmd_add(repo_temp.path(), vec!["secret.env".to_string()]).expect("cmd_add must succeed");
    cmd_hide(repo_temp.path(), "origin", &gpg_home).expect("cmd_hide must succeed");
    // hide deleted the plaintext; it is still hidden but absent on disk.

    let result = cmd_changes(repo_temp.path(), vec![], "owner@github.com", "origin", &gpg_home);

    let changed = result.expect("missing plaintext must be skipped, not an error");
    assert!(
        changed.is_empty(),
        "a file hidden with no plaintext on disk must not be reported as changed, got: {:?}",
        changed
    );
    assert!(
        repo_temp.path().join(".git-gpg/secrets/secret.env.asc").exists(),
        "the ciphertext must remain in place after the skipped file"
    );
}

#[test]
fn changes_fails_for_untracked_file() {
    let (repo_temp, gpg_home, _) = setup_repo_with_owner_in_keyring();

    let result = cmd_changes(
        repo_temp.path(),
        vec!["not-tracked.env".to_string()],
        "owner@github.com",
        "origin",
        &gpg_home,
    );

    let err = result.err().expect("changes for an untracked file must fail");
    assert!(
        err.to_string().contains("not tracked"),
        "the error must say the file is not tracked, got: {}",
        err
    );
}

#[test]
fn changes_detects_binary_difference() {
    let (repo_temp, gpg_home, _) = setup_repo_with_owner_in_keyring();

    let original: Vec<u8> = vec![0u8, 1, 2, 3, 255];
    std::fs::write(repo_temp.path().join("blob.bin"), &original).unwrap();
    cmd_add(repo_temp.path(), vec!["blob.bin".to_string()]).expect("cmd_add must succeed");
    cmd_hide(repo_temp.path(), "origin", &gpg_home).expect("cmd_hide must succeed");

    let modified: Vec<u8> = vec![0u8, 1, 2, 3, 254, 9];
    std::fs::write(repo_temp.path().join("blob.bin"), &modified).unwrap();

    let result = cmd_changes(repo_temp.path(), vec![], "owner@github.com", "origin", &gpg_home);

    let changed = result.expect("cmd_changes must succeed for a binary file");
    assert_eq!(
        changed,
        vec![PathBuf::from("blob.bin")],
        "the binary difference must be detected in the changed list, got: {:?}",
        changed
    );
}

// ============================================================================
// Local key pinning (H4): trust.json is committed and attacker-writable, so
// it must never be the sole trust anchor. cmd_trust pins the fingerprint in
// the tool-owned key store OUTSIDE the repo; verify fails closed unless the
// pin exists and matches.
// ============================================================================

#[test]
fn trust_writes_local_pin() {
    let repo_temp = setup_git_repo_with_origin_remote();

    cmd_init(repo_temp.path()).expect("cmd_init must succeed");

    let (_, owner_pub) = generate_test_key("owner@github.com");
    let keyfile = repo_temp.path().join("owner.pub");
    write_public_key_file(&owner_pub, &keyfile);

    let gpg_home = tempfile::tempdir().unwrap().path().to_path_buf();

    cmd_trust(
        repo_temp.path(),
        "repo+owner@github.com",
        keyfile.to_str().unwrap(),
        "origin",
        &gpg_home,
    )
    .expect("cmd_trust must succeed");

    assert!(
        gpg_home.join("trust-pins").is_dir(),
        "the pin must live in the tool-owned key store, not inside the repo"
    );
    let pin = TrustPinStore::read_pin(&gpg_home, "repo+owner@github.com")
        .expect("reading the pin must not error");
    assert_eq!(
        pin.as_deref(),
        Some(extract_key_fingerprint(&owner_pub).as_str()),
        "cmd_trust must pin the trusted fingerprint for this repo on this machine"
    );
}

#[test]
fn verify_fails_closed_when_pin_missing() {
    let (repo_temp, gpg_home, owner_pub) = setup_repo_with_owner_in_keyring();

    // A fresh clone arrives with trust.json + signed keyring committed but
    // NO per-machine pin: simulate that by deleting the pin this machine
    // wrote during cmd_trust.
    std::fs::remove_dir_all(gpg_home.join("trust-pins")).unwrap();

    std::fs::write(repo_temp.path().join("secret.env"), "s3cret").unwrap();
    cmd_add(repo_temp.path(), vec!["secret.env".to_string()]).expect("cmd_add must succeed");

    let hide_result = cmd_hide(repo_temp.path(), "origin", &gpg_home);
    let hide_err = hide_result
        .err()
        .expect("hide without a local pin must fail closed");
    assert!(
        hide_err.to_string().contains("no local pin"),
        "hide must fail with the pin-missing message, got: {}",
        hide_err
    );

    let reveal_result = cmd_reveal(repo_temp.path(), "owner@github.com", "origin", &gpg_home);
    let reveal_err = reveal_result
        .err()
        .expect("reveal without a local pin must fail closed");
    assert!(
        reveal_err.to_string().contains("no local pin"),
        "reveal must fail with the pin-missing message, got: {}",
        reveal_err
    );

    // Protective completion: re-establishing trust (which re-pins) must make
    // the normal flow work again.
    let owner_keyfile = repo_temp.path().join("owner.pub");
    write_public_key_file(&owner_pub, &owner_keyfile);
    cmd_trust(
        repo_temp.path(),
        "repo+owner@github.com",
        owner_keyfile.to_str().unwrap(),
        "origin",
        &gpg_home,
    )
    .expect("re-running cmd_trust must succeed");

    cmd_hide(repo_temp.path(), "origin", &gpg_home)
        .expect("hide must succeed once the pin is re-established");
    cmd_reveal(repo_temp.path(), "owner@github.com", "origin", &gpg_home)
        .expect("reveal must succeed once the pin is re-established");
}

#[test]
fn verify_fails_closed_when_pin_mismatches() {
    let (repo_temp, gpg_home, owner_pub) = setup_repo_with_owner_in_keyring();
    let owner_fingerprint = extract_key_fingerprint(&owner_pub);

    // FULL ATTACK SIMULATION: the attacker's key already exists in the
    // victim's local key store (imported for an unrelated repo).
    let (attacker_sec, attacker_pub) = generate_test_key("attacker@evil.com");
    import_key_to_gpg_home(
        &gpg_home,
        &attacker_pub.to_armored_string(Default::default()).unwrap(),
    )
    .unwrap();
    let attacker_fingerprint = extract_key_fingerprint(&attacker_pub);

    // (a) rewrite the committed trust.json to map the repo's repo_id to the
    // attacker's fingerprint...
    let trust_path = repo_temp.path().join(".git-gpg/trust.json");
    let mut tampered_trust = TrustStore::load_from_file(&trust_path).unwrap();
    tampered_trust.add_trust("repo+owner@github.com".to_string(), attacker_fingerprint.clone());
    tampered_trust.save_to_file(&trust_path).unwrap();

    // ...and (b) ship a keyring validly signed by that key.
    let mut attacker_ring = Keyring {
        entries: vec![KeyringEntry {
            email: "attacker@evil.com".to_string(),
            base64_key: base64_encode_public_key(&attacker_pub),
            fingerprint: attacker_fingerprint.clone(),
        }],
        signature: None,
    };
    let serialized = attacker_ring.serialize();
    let content_to_sign = extract_content_to_verify_from_keyring(&serialized)
        .expect("freshly serialized keyring must contain the END marker");
    let signature = sign_keyring_content(&content_to_sign, &attacker_sec)
        .expect("the attacker must be able to sign their own keyring");
    attacker_ring.signature = Some(signature);
    let keyring_path = repo_temp.path().join(".git-gpg/keyring");
    std::fs::write(&keyring_path, attacker_ring.serialize()).unwrap();
    let keyring_before = std::fs::read(&keyring_path).unwrap();

    let hide_result = cmd_hide(repo_temp.path(), "origin", &gpg_home);
    let keyring_after = std::fs::read(&keyring_path).unwrap();

    let err = hide_result.err().expect(
        "the trust.json-rewrite attack must be blocked: the signature verifies but the pin does not match",
    );
    let msg = err.to_string();
    assert!(
        msg.contains("changed on this machine's record"),
        "hide must fail with the pin-mismatch message, got: {}",
        msg
    );
    assert!(
        msg.contains(&owner_fingerprint) && msg.contains(&attacker_fingerprint),
        "the mismatch message must name both the pinned ({}) and the new ({}) fingerprint, got: {}",
        owner_fingerprint,
        attacker_fingerprint,
        msg
    );
    assert_eq!(
        keyring_before, keyring_after,
        "the keyring file must be untouched by the failed verify"
    );
}

// ============================================================================
// Multi-recipient hide: encrypt to ALL keyring keys, revocation end-to-end
//
// The collaboration promise is "any collaborator can reveal". These tests
// were written Red: pre-fix, cmd_hide encrypts only to the first keyring
// entry, so collaborators 2..n cannot decrypt.
// ============================================================================

/// Sets up a trusted repo whose keyring contains the owner plus the given
/// collaborators (each added via cmd_tell, the keyring signed by the trusted
/// owner key), and whose secring holds every secret key (owner + all
/// collaborators). Returns (repo_temp, gpg_home).
fn setup_repo_with_owner_and_collaborators(
    collaborator_emails: &[&str],
) -> (tempfile::TempDir, PathBuf) {
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

    // tell signs with the trusted owner key, so the owner's secret must be
    // in the secring before any tell runs.
    write_multi_key_secring(&gpg_home, std::slice::from_ref(&owner_sec));

    cmd_tell(
        repo_temp.path(),
        "owner@github.com",
        owner_keyfile.to_str().unwrap(),
        "origin",
        &gpg_home,
    )
    .expect("cmd_tell must succeed for the owner");

    let mut collaborator_secrets = Vec::new();
    for (i, email) in collaborator_emails.iter().enumerate() {
        let (sec, pub_key) = generate_test_key(email);
        let keyfile = repo_temp.path().join(format!("collaborator-{}.pub", i));
        write_public_key_file(&pub_key, &keyfile);

        cmd_tell(
            repo_temp.path(),
            email,
            keyfile.to_str().unwrap(),
            "origin",
            &gpg_home,
        )
        .unwrap_or_else(|e| panic!("cmd_tell must succeed for {}: {:?}", email, e));

        collaborator_secrets.push(sec);
    }

    // Replace the secring with one holding every secret key (owner + all
    // collaborators) so each participant can decrypt/verify locally.
    let mut secring_keys = vec![owner_sec];
    secring_keys.extend(collaborator_secrets);
    write_multi_key_secring(&gpg_home, &secring_keys);

    (repo_temp, gpg_home)
}

#[test]
fn hide_encrypts_to_every_key_in_keyring() {
    let emails = ["alice@example.com", "bob@example.com", "carol@example.com"];
    let (repo_temp, gpg_home) = setup_repo_with_owner_and_collaborators(&emails);

    let plaintext: &str = "SHARED_SECRET=every-collaborator-can-reveal\n";
    std::fs::write(repo_temp.path().join("secret.env"), plaintext).unwrap();
    cmd_add(repo_temp.path(), vec!["secret.env".to_string()]).expect("cmd_add must succeed");

    cmd_hide(repo_temp.path(), "origin", &gpg_home).expect("cmd_hide must succeed");

    let ciphertext = std::fs::read_to_string(repo_temp.path().join(".git-gpg/secrets/secret.env.asc"))
        .expect("hide must write the ciphertext into .git-gpg/secrets");

    for email in emails {
        let secret_key = find_private_key_by_email(&gpg_home, email)
            .unwrap_or_else(|e| panic!("secring must hold {}'s secret key: {}", email, e));
        let decrypted = decrypt_with_gpg_key(&ciphertext, &secret_key)
            .unwrap_or_else(|e| panic!("{} must be able to decrypt the shared ciphertext: {}", email, e));
        assert_eq!(
            decrypted,
            plaintext.as_bytes(),
            "{} must recover the exact original plaintext from the ONE shared ciphertext",
            email
        );
    }
}

#[test]
fn reveal_works_for_each_collaborator_after_hide() {
    let emails = ["alice@example.com", "bob@example.com", "carol@example.com"];
    let (repo_temp, gpg_home) = setup_repo_with_owner_and_collaborators(&emails);

    let plaintext: &str = "ROUND_TRIP=per-collaborator-reveal\n";
    std::fs::write(repo_temp.path().join("secret.env"), plaintext).unwrap();
    cmd_add(repo_temp.path(), vec!["secret.env".to_string()]).expect("cmd_add must succeed");

    for email in emails {
        cmd_hide(repo_temp.path(), "origin", &gpg_home)
            .unwrap_or_else(|e| panic!("cmd_hide must succeed before {}'s reveal: {:?}", email, e));
        assert!(
            !repo_temp.path().join("secret.env").exists()
                && repo_temp.path().join(".git-gpg/secrets/secret.env.asc").exists(),
            "hide must have replaced the plaintext with ciphertext before {}'s reveal",
            email
        );

        cmd_reveal(repo_temp.path(), email, "origin", &gpg_home)
            .unwrap_or_else(|e| panic!("{} must be able to cmd_reveal the hidden file: {:?}", email, e));

        let restored = std::fs::read(repo_temp.path().join("secret.env"))
            .unwrap_or_else(|e| panic!("reveal must restore the plaintext for {}: {}", email, e));
        assert_eq!(
            restored,
            plaintext.as_bytes(),
            "{}'s reveal must restore the exact original bytes",
            email
        );
    }
}

#[test]
fn removed_collaborator_cannot_decrypt_after_removeperson_and_rehide() {
    let emails = ["alice@example.com", "bob@example.com", "carol@example.com"];
    let (repo_temp, gpg_home) = setup_repo_with_owner_and_collaborators(&emails);

    let plaintext: &str = "REVOCATION=boot-the-removed-collaborator\n";
    std::fs::write(repo_temp.path().join("secret.env"), plaintext).unwrap();
    cmd_add(repo_temp.path(), vec!["secret.env".to_string()]).expect("cmd_add must succeed");

    // Before removal: ALL three collaborators decrypt the SAME ciphertext.
    cmd_hide(repo_temp.path(), "origin", &gpg_home).expect("first hide must succeed");
    let ciphertext_before = std::fs::read_to_string(repo_temp.path().join(".git-gpg/secrets/secret.env.asc"))
        .expect("ciphertext must exist after the first hide");
    for email in emails {
        let secret_key = find_private_key_by_email(&gpg_home, email).unwrap();
        let decrypted = decrypt_with_gpg_key(&ciphertext_before, &secret_key)
            .unwrap_or_else(|e| panic!("before removal, {} must be able to decrypt: {}", email, e));
        assert_eq!(decrypted, plaintext.as_bytes());
    }

    // Revoke Bob, then re-hide (reveal as Alice restores the plaintext first).
    cmd_removeperson(repo_temp.path(), "bob@example.com", "origin", &gpg_home)
        .expect("cmd_removeperson must succeed");
    cmd_reveal(repo_temp.path(), "alice@example.com", "origin", &gpg_home)
        .expect("reveal as alice must restore the plaintext for the re-hide");
    cmd_hide(repo_temp.path(), "origin", &gpg_home)
        .expect("re-hide after removal must succeed");
    let ciphertext_after = std::fs::read_to_string(repo_temp.path().join(".git-gpg/secrets/secret.env.asc"))
        .expect("ciphertext must exist after the re-hide");

    // Bob's key must now FAIL against the new ciphertext.
    let bob_key = find_private_key_by_email(&gpg_home, "bob@example.com").unwrap();
    assert!(
        decrypt_with_gpg_key(&ciphertext_after, &bob_key).is_err(),
        "the removed collaborator must NOT be able to decrypt ciphertext written after their removal"
    );

    // Alice and Carol must still decrypt the new ciphertext.
    for email in ["alice@example.com", "carol@example.com"] {
        let secret_key = find_private_key_by_email(&gpg_home, email).unwrap();
        let decrypted = decrypt_with_gpg_key(&ciphertext_after, &secret_key)
            .unwrap_or_else(|e| panic!("after removal, {} must still be able to decrypt: {}", email, e));
        assert_eq!(decrypted, plaintext.as_bytes());
    }
}

#[test]
fn sanitized_pin_filename_is_stable() {
    assert_eq!(
        TrustPinStore::sanitize_repo_id("repo+owner@github.com"),
        "repo%2Bowner%40github.com",
        "'+' and '@' must be percent-encoded"
    );
    assert_eq!(
        TrustPinStore::sanitize_repo_id("répo+owner@x.com"),
        "r%C3%A9po%2Bowner%40x.com",
        "non-ASCII characters must be percent-encoded as UTF-8 bytes"
    );
    assert_eq!(
        TrustPinStore::sanitize_repo_id("a+b@c"),
        TrustPinStore::sanitize_repo_id("a+b@c"),
        "sanitization must be deterministic"
    );
    for repo_id in ["../../etc/passwd", "a/b", "a\\b", "a b", "a\nb", ".", ".."] {
        let name = TrustPinStore::sanitize_repo_id(repo_id);
        assert!(
            !name.contains('/') && !name.contains('\\'),
            "sanitized name for {:?} must contain no path separators, got: {:?}",
            repo_id,
            name
        );
        assert!(
            name != "." && name != "..",
            "sanitized name for {:?} must never be a directory alias, got: {:?}",
            repo_id,
            name
        );
        assert!(
            name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '%')),
            "sanitized name for {:?} must only use safe characters, got: {:?}",
            repo_id,
            name
        );
    }
}
