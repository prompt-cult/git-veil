//! Contract tests for git-veil features and regression fixes.
//!
//! Each test targets one named contract. Tests here are written Red/Green:
//! they must fail against the code they were written to fix, and pass after.

use git_veil::{
    base64_decode_public_key, base64_encode_public_key, check_email_in_identities, cmd_add,
    cmd_cat, cmd_changes, cmd_export, cmd_hide, cmd_import, cmd_init, cmd_list_keys, cmd_remove,
    cmd_removekey, cmd_removeperson, cmd_reveal, cmd_tell, cmd_trust, cmd_unhide,
    cmd_verify_keyring, decrypt_with_private_key, default_key_store, encrypt_to_public_key,
    export_public_key, extract_content_to_verify_from_keyring, extract_key_fingerprint,
    find_private_key_by_email, find_private_key_by_fingerprint, import_key_to_store,
    parse_armored_public_key, parse_git_remote_url, sign_keyring_content,
    verify_keyring_against_trust, write_atomic, Keyring, KeyringEntry, TrackedFiles, TrustPinStore,
    TrustStore,
};
use pgp::composed::{EncryptionCaps, KeyType, SecretKeyParamsBuilder, SubkeyParamsBuilder};
use rand::thread_rng;
use serial_test::serial;
use std::path::PathBuf;

fn generate_test_key(
    email: &str,
) -> (
    pgp::composed::SignedSecretKey,
    pgp::composed::SignedPublicKey,
) {
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

/// Like generate_test_key, but the secret material is protected by the given
/// passphrase (mirroring what a real user's key looks like on disk). BOTH the
/// primary key and the encryption subkey are protected: reveal/c decrypt via
/// the subkey, tell signs via the primary key.
fn generate_protected_test_key(
    email: &str,
    passphrase: &str,
) -> (
    pgp::composed::SignedSecretKey,
    pgp::composed::SignedPublicKey,
) {
    let mut rng = thread_rng();

    let encrypt_subkey = SubkeyParamsBuilder::default()
        .key_type(KeyType::X25519)
        .can_encrypt(EncryptionCaps::All)
        .passphrase(Some(passphrase.to_string()))
        .build()
        .expect("build encrypt subkey params");

    let params = SecretKeyParamsBuilder::default()
        .key_type(KeyType::Ed25519)
        .can_certify(true)
        .can_sign(true)
        .primary_user_id(format!("Test User <{}>", email))
        .passphrase(Some(passphrase.to_string()))
        .subkeys(vec![encrypt_subkey])
        .build()
        .expect("build key params");

    let secret_key = params.generate(&mut rng).expect("generate key");
    let public_key = secret_key.to_public_key();

    (secret_key, public_key)
}

fn write_multi_key_secret_keys(key_store: &PathBuf, keys: &[pgp::composed::SignedSecretKey]) {
    let mut content = String::new();
    for key in keys {
        if !content.is_empty() {
            content.push('\n');
        }
        content.push_str(&key.to_armored_string(Default::default()).unwrap());
    }
    write_secret_keys_content(key_store, &content);
}

fn write_secret_keys_content(key_store: &PathBuf, content: &str) {
    std::fs::create_dir_all(key_store).unwrap();
    std::fs::write(key_store.join("secret-keys.pgp"), content).unwrap();
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
// default_key_store refuses to fall back to /tmp when HOME is unset (M6)
// ============================================================================

#[test]
#[serial]
fn default_key_store_errors_when_home_unset() {
    let saved = std::env::var("HOME").ok();
    std::env::remove_var("HOME");

    let result = default_key_store();

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
fn default_key_store_is_home_git_veil() {
    let saved = std::env::var("HOME").ok();
    let temp = tempfile::tempdir().unwrap();
    std::env::set_var("HOME", temp.path());

    let result = default_key_store();

    match saved {
        Some(v) => std::env::set_var("HOME", v),
        None => std::env::remove_var("HOME"),
    }

    assert_eq!(
        result.expect("a set HOME must resolve to $HOME/.git-veil"),
        temp.path().join(".git-veil"),
        "default key store must be $HOME/.git-veil"
    );
}

// ============================================================================
// Secret key selection from a multi-key secret key store
// ============================================================================

#[test]
fn find_private_key_by_email_selects_matching_key_when_not_first_in_secret_key_store() {
    let temp = tempfile::tempdir().unwrap();
    let key_store = temp.path().to_path_buf();
    let (alice, _) = generate_test_key("alice@example.com");
    let (bob, bob_pub) = generate_test_key("bob@example.com");
    let bob_fingerprint = extract_key_fingerprint(&bob_pub);
    write_multi_key_secret_keys(&key_store, &[alice, bob]);

    let key = find_private_key_by_email(&key_store, "bob@example.com")
        .expect("bob's key should be found even though alice's key comes first");
    assert_eq!(
        extract_key_fingerprint(&key.to_public_key()),
        bob_fingerprint,
        "the key returned for bob@example.com must be bob's key, not another key from the secret key store"
    );
}

#[test]
fn find_private_key_by_fingerprint_selects_matching_key_when_not_first_in_secret_key_store() {
    let temp = tempfile::tempdir().unwrap();
    let key_store = temp.path().to_path_buf();
    let (alice, _) = generate_test_key("alice@example.com");
    let (bob, bob_pub) = generate_test_key("bob@example.com");
    let bob_fingerprint = extract_key_fingerprint(&bob_pub);
    write_multi_key_secret_keys(&key_store, &[alice, bob]);

    let key = find_private_key_by_fingerprint(&key_store, &bob_fingerprint)
        .expect("bob's key should be found even though alice's key comes first");
    assert_eq!(
        extract_key_fingerprint(&key.to_public_key()),
        bob_fingerprint,
        "the key returned for bob's fingerprint must be bob's key, not another key from the secret key store"
    );
}

#[test]
fn find_private_key_by_email_fails_when_no_key_matches() {
    let temp = tempfile::tempdir().unwrap();
    let key_store = temp.path().to_path_buf();
    let (alice, _) = generate_test_key("alice@example.com");
    write_multi_key_secret_keys(&key_store, &[alice]);

    let result = find_private_key_by_email(&key_store, "carol@example.com");
    assert!(result.is_err(), "unknown email must not match any key");
}

#[test]
fn find_private_key_by_email_errors_on_empty_secret_key_store() {
    let temp = tempfile::tempdir().unwrap();
    let key_store = temp.path().to_path_buf();
    write_secret_keys_content(&key_store, "");

    let result = find_private_key_by_email(&key_store, "alice@example.com");

    let err = result
        .err()
        .expect("an empty secret key store must not yield any key");
    assert!(
        err.to_string().contains("No private key blocks found"),
        "the error must state that no private key blocks were found, got: {}",
        err
    );
    assert!(
        err.to_string().contains("secret-keys.pgp"),
        "the error must mention the secret key store file, got: {}",
        err
    );
}

#[test]
fn find_private_key_by_email_ignores_garbage_between_blocks() {
    let temp = tempfile::tempdir().unwrap();
    let key_store = temp.path().to_path_buf();
    let (alice, _) = generate_test_key("alice@example.com");
    let (bob, bob_pub) = generate_test_key("bob@example.com");
    let bob_fingerprint = extract_key_fingerprint(&bob_pub);
    let alice_armored = alice.to_armored_string(Default::default()).unwrap();
    let bob_armored = bob.to_armored_string(Default::default()).unwrap();
    let content = format!(
        "this leading text is not a key at all\n{}\n>>> random junk between blocks <<<\n{}\ntrailing junk",
        alice_armored, bob_armored
    );
    write_secret_keys_content(&key_store, &content);

    let key = find_private_key_by_email(&key_store, "bob@example.com")
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
    let key_store = temp.path().to_path_buf();
    let (alice, _) = generate_test_key("alice@example.com");
    let (bob, _) = generate_test_key("bob@example.com");
    let alice_armored = alice.to_armored_string(Default::default()).unwrap();
    let bob_armored = bob.to_armored_string(Default::default()).unwrap();
    let end_marker = "-----END PGP PRIVATE KEY BLOCK-----";
    let truncated_bob = bob_armored[..bob_armored.find(end_marker).unwrap()].to_string();
    let content = format!("{}\n{}", alice_armored, truncated_bob);
    write_secret_keys_content(&key_store, &content);

    let bob_result = find_private_key_by_email(&key_store, "bob@example.com");

    let bob_err = bob_result
        .err()
        .expect("a secret key store whose final block is truncated must not yield any key");
    assert!(
        bob_err.to_string().contains("Unterminated private key block"),
        "the error must name the unterminated block, not the misleading 'No secret key found for email', got: {}",
        bob_err
    );
    assert!(
        bob_err.to_string().contains("corrupt secret key store"),
        "the error must state the secret key store is corrupt, got: {}",
        bob_err
    );
    assert!(
        bob_err.to_string().contains("secret-keys.pgp"),
        "the error must mention the secret key store file, got: {}",
        bob_err
    );
    assert!(
        !bob_err
            .to_string()
            .contains("No secret key found for email"),
        "the error must not be indistinguishable from 'email never existed', got: {}",
        bob_err
    );

    // A corrupt tail invalidates the whole secret key store: for a secrets tool the
    // safe choice is to reject every key rather than silently serve the
    // healthy-looking prefix, because truncation may itself be an attack
    // (an attacker who can truncate the secret key store must not be able to quietly
    // remove keys from use).
    let alice_result = find_private_key_by_email(&key_store, "alice@example.com");

    let alice_err = alice_result.err().expect(
        "a corrupt secret key store must be rejected in full: even keys before the truncated tail must not be served",
    );
    assert!(
        alice_err
            .to_string()
            .contains("Unterminated private key block"),
        "alice's lookup must fail with the corrupt secret key store error too, got: {}",
        alice_err
    );
}

#[test]
fn find_private_key_by_email_errors_on_truncated_only_secret_key_store() {
    let temp = tempfile::tempdir().unwrap();
    let key_store = temp.path().to_path_buf();
    let (alice, _) = generate_test_key("alice@example.com");
    let alice_armored = alice.to_armored_string(Default::default()).unwrap();
    let end_marker = "-----END PGP PRIVATE KEY BLOCK-----";
    let truncated = alice_armored[..alice_armored.find(end_marker).unwrap()].to_string();
    write_secret_keys_content(&key_store, &truncated);

    let result = find_private_key_by_email(&key_store, "alice@example.com");

    let err = result
        .err()
        .expect("a secret key store holding only a truncated block must not yield any key");
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
    let key_store = temp.path().to_path_buf();
    let (carol_first, carol_first_pub) = generate_test_key("carol@example.com");
    let (carol_second, _) = generate_test_key("carol@example.com");
    let first_fingerprint = extract_key_fingerprint(&carol_first_pub);
    write_multi_key_secret_keys(&key_store, &[carol_first, carol_second]);

    // Documented current behaviour: when two keys in the secret key store claim the
    // same email, the first matching key in file order wins. Treating
    // duplicated emails as an ambiguity error is out of scope here and is
    // reviewed under a separate task.
    let key = find_private_key_by_email(&key_store, "carol@example.com")
        .expect("a key matching the duplicated email must be found");
    assert_eq!(
        extract_key_fingerprint(&key.to_public_key()),
        first_fingerprint,
        "the first key in the secret key store's order must win when the email is duplicated"
    );
}

// ============================================================================
// Email matching requires exact address equality (M1)
// ============================================================================

fn generate_test_key_with_uid(
    uid: &str,
) -> (
    pgp::composed::SignedSecretKey,
    pgp::composed::SignedPublicKey,
) {
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
    let (_, evil_pub) = generate_test_key_with_uid("Evil <evil-bob@x.com.attacker.net>");

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
    let key_store = temp.path().to_path_buf();
    let (evil, _) = generate_test_key("xalice@example.com.evil.net");
    let (alice, alice_pub) = generate_test_key("alice@example.com");
    let alice_fingerprint = extract_key_fingerprint(&alice_pub);
    write_multi_key_secret_keys(&key_store, &[evil, alice]);

    let result = find_private_key_by_email(&key_store, "alice@example.com");
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
    let key_store = temp.path().to_path_buf();
    let (evil, _) = generate_test_key("xalice@example.com.evil.net");
    write_multi_key_secret_keys(&key_store, &[evil]);

    let result = find_private_key_by_email(&key_store, "alice@example.com");
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
    let key_store = temp.path().to_path_buf();
    let (plain_sec, plain_sec_pub) = generate_test_key_with_uid("plain@example.com");
    let stored_fingerprint = extract_key_fingerprint(&plain_sec_pub);
    write_multi_key_secret_keys(&key_store, &[plain_sec]);

    let found = find_private_key_by_email(&key_store, "plain@example.com")
        .expect("a bare user-ID key in the secret key store must be findable by exact email");
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
    keyring
        .add_entry(
            "alice@example.com".to_string(),
            "QUJDREVGR0hJSktMTU5PUA==".to_string(),
            "AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111".to_string(),
        )
        .unwrap();
    keyring
        .add_entry(
            "bob@example.com".to_string(),
            "QkNERUVGR0hJSktMTU5PUFI=".to_string(),
            "BBBB2222BBBB2222BBBB2222BBBB2222BBBB2222".to_string(),
        )
        .unwrap();
    keyring.signature =
        Some("-----BEGIN PGP SIGNATURE-----\nstale\n-----END PGP SIGNATURE-----".to_string());

    keyring
        .add_entry(
            "alice@example.com".to_string(),
            "REVGREdISklLTE1OT1BSU1Q=".to_string(),
            "CCCC3333CCCC3333CCCC3333CCCC3333CCCC3333".to_string(),
        )
        .unwrap();

    assert_eq!(
        keyring.entries.len(),
        2,
        "re-adding an existing email must not append a duplicate entry, got: {:?}",
        keyring.entries
    );
    assert_eq!(
        keyring.entries[0].email, "alice@example.com",
        "order must be preserved: alice first"
    );
    assert_eq!(
        keyring.entries[1].email, "bob@example.com",
        "order must be preserved: bob second"
    );
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
fn keyring_parse_rejects_end_marker_before_begin() {
    // A committed keyring is attacker-writable content: an END marker that
    // precedes (or overlaps) the BEGIN marker must yield a proper parse
    // error, never a panic (this input used to panic with
    // "byte range starts at .. but ends at 0" in the marker slicing).
    let inverted = format!("{}\n{}\n", git_veil::END_MARKER, git_veil::BEGIN_MARKER);
    let err = Keyring::parse(&inverted)
        .err()
        .expect("END-before-BEGIN keyring must be rejected, not panic");
    let message = format!("{err:#}");
    assert!(
        message.to_lowercase().contains("marker"),
        "the error must name the marker misordering, got: {message}"
    );

    // BEGIN followed by END with nothing (or junk) between still parses as
    // an empty keyring; a second BEGIN inside the body is malformed.
    let nested = format!(
        "{}\n{}\n{}\n",
        git_veil::BEGIN_MARKER,
        git_veil::BEGIN_MARKER,
        git_veil::END_MARKER
    );
    assert!(
        Keyring::parse(&nested).is_err(),
        "a nested BEGIN marker must be rejected as a malformed entry"
    );
}

// Andon (fuzz finding, 2026-08-28): fuzz_parse_git_remote_url showed the
// remote-URL parser accepted '@' and ':' inside the user/repo components, so
// credential-shaped material landed IN the derived repo_id — e.g.
// `https://github.com/user:pass@evil/repo` yielded user = "user:pass@evil",
// and `git@github.com:git@github.com:simbo1905/fara.srg:2g2` yielded
// user = "git@github.com:simbo1905". Fixed in src/repo_identity.rs by
// excluding '@' and ':' from the user and repo capture groups in SSH_SCP_RE
// and SCHEME_USERINFO_RE, so credential-shaped URLs fail closed. This test is
// the Green half of the Red/Green pair and guards the fix.
#[test]
fn repo_id_components_never_contain_credential_shaped_material() {
    let urls = [
        "https://github.com/user:pass@evil/repo",
        "git@github.com:git@github.com:simbo1905/fara.srg:2g2",
    ];
    for url in urls {
        if let Ok((repo, user, service)) = parse_git_remote_url(url) {
            assert!(
                !repo.contains(['@', ':'])
                    && !user.contains(['@', ':'])
                    && !service.contains(['@', ':']),
                "credential-shaped material leaked into repo_id components for {url}: \
                 repo={repo:?} user={user:?} service={service:?}"
            );
        }
    }
}

#[test]
fn keyring_find_by_email_is_case_insensitive() {
    let mut keyring = Keyring::new();
    keyring
        .add_entry(
            "alice@example.com".to_string(),
            "QUJDREVGR0hJSktMTU5PUA==".to_string(),
            "AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111".to_string(),
        )
        .unwrap();

    let found = keyring
        .find_by_email("ALICE@EXAMPLE.COM")
        .expect("find_by_email must match emails case-insensitively, like every other email comparison in the codebase");
    assert_eq!(
        found.email, "alice@example.com",
        "the stored email must not be rewritten, got: {:?}",
        found
    );
}

#[test]
fn tell_twice_same_email_updates_rather_than_duplicates() {
    let (alice_sec, alice_pub) = generate_test_key("alice@example.com");
    let (repo_temp, key_store) = setup_trusted_repo_with_secret_keys(&[alice_sec]);

    let alice_keyfile = repo_temp.path().join("alice.pub");
    write_public_key_file(&alice_pub, &alice_keyfile);

    cmd_tell(
        repo_temp.path(),
        "alice@example.com",
        alice_keyfile.to_str().unwrap(),
        "origin",
        &key_store,
        None,
    )
    .expect("first tell must succeed");

    let keyring_after_first = Keyring::parse(
        &std::fs::read_to_string(repo_temp.path().join(".git-veil/keyring")).unwrap(),
    )
    .unwrap();

    let second_tell = cmd_tell(
        repo_temp.path(),
        "alice@example.com",
        alice_keyfile.to_str().unwrap(),
        "origin",
        &key_store,
        None,
    );

    let keyring_text = std::fs::read_to_string(repo_temp.path().join(".git-veil/keyring")).unwrap();
    let keyring_after_second = Keyring::parse(&keyring_text).unwrap();
    let alice_count = keyring_after_second
        .entries
        .iter()
        .filter(|e| e.email == "alice@example.com")
        .count();
    let verify_result = cmd_verify_keyring(repo_temp.path(), "origin", &key_store);

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
        keyring_after_second.entries.len(),
        1,
        "keyring must hold exactly one entry total after duplicate tell, got: {:?}",
        keyring_after_second.entries
    );
    verify_result.expect("keyring must still verify after duplicate tell");
}

#[test]
fn tell_twice_with_different_email_case_updates_rather_than_duplicates() {
    let (alice_sec, alice_pub) = generate_test_key("alice@x.com");
    let (repo_temp, key_store) = setup_trusted_repo_with_secret_keys(&[alice_sec]);

    let alice_keyfile = repo_temp.path().join("alice.pub");
    write_public_key_file(&alice_pub, &alice_keyfile);

    cmd_tell(
        repo_temp.path(),
        "alice@x.com",
        alice_keyfile.to_str().unwrap(),
        "origin",
        &key_store,
        None,
    )
    .expect("first tell must succeed");

    cmd_tell(
        repo_temp.path(),
        "ALICE@X.COM",
        alice_keyfile.to_str().unwrap(),
        "origin",
        &key_store,
        None,
    )
    .expect("second tell with different email case must succeed");

    let keyring_text = std::fs::read_to_string(repo_temp.path().join(".git-veil/keyring")).unwrap();
    let keyring = Keyring::parse(&keyring_text).unwrap();

    assert_eq!(
        keyring.entries.len(),
        1,
        "telling with a different email case must update, not duplicate: got {:?} in {}",
        keyring.entries,
        keyring_text
    );
    assert_eq!(
        keyring.entries[0].email, "alice@x.com",
        "the first-seen stored email casing must be preserved, got: {:?}",
        keyring.entries[0]
    );
    cmd_verify_keyring(repo_temp.path(), "origin", &key_store)
        .expect("keyring must still verify after case-variant tell");
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

    let store_temp = tempfile::tempdir().unwrap();

    let result = cmd_trust(
        repo_temp.path(),
        "repo+owner@github.com",
        keyfile.to_str().unwrap(),
        "origin",
        &store_temp.path().to_path_buf(),
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

    let store_temp = tempfile::tempdir().unwrap();

    let result = cmd_trust(
        repo_temp.path(),
        "repo+owner@github.com",
        keyfile.to_str().unwrap(),
        "origin",
        &store_temp.path().to_path_buf(),
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

/// Sets up a repo with trust established for owner@github.com and a key store
/// containing the owner key (public-keys.pgp, via cmd_trust) plus the given secret keys
/// in the secret key store. Returns (repo_temp, key_store).
fn setup_trusted_repo_with_secret_keys(
    secret_keys: &[pgp::composed::SignedSecretKey],
) -> (tempfile::TempDir, PathBuf) {
    let repo_temp = setup_git_repo_with_origin_remote();

    cmd_init(repo_temp.path()).expect("cmd_init must succeed");

    let (owner_sec, owner_pub) = generate_test_key("owner@github.com");
    let owner_keyfile = repo_temp.path().join("owner.pub");
    write_public_key_file(&owner_pub, &owner_keyfile);

    let key_store = repo_temp.path().join("key-store");

    cmd_trust(
        repo_temp.path(),
        "repo+owner@github.com",
        owner_keyfile.to_str().unwrap(),
        "origin",
        &key_store,
    )
    .expect("cmd_trust must succeed");

    let mut store_keys: Vec<pgp::composed::SignedSecretKey> = vec![owner_sec];
    store_keys.extend_from_slice(secret_keys);
    write_multi_key_secret_keys(&key_store, &store_keys);

    (repo_temp, key_store)
}

#[test]
fn tell_rejects_unsigned_keyring_containing_entries() {
    let (alice_sec, alice_pub) = generate_test_key("alice@example.com");
    let (repo_temp, key_store) = setup_trusted_repo_with_secret_keys(&[alice_sec]);

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
    std::fs::write(
        repo_temp.path().join(".git-veil/keyring"),
        unsigned_keyring.serialize(),
    )
    .unwrap();

    let alice_keyfile = repo_temp.path().join("alice.pub");
    write_public_key_file(&alice_pub, &alice_keyfile);

    let result = cmd_tell(
        repo_temp.path(),
        "alice@example.com",
        alice_keyfile.to_str().unwrap(),
        "origin",
        &key_store,
        None,
    );

    assert!(
        result.is_err(),
        "tell must reject an unsigned keyring that already contains entries"
    );
}

// ============================================================================
// list-keys is gated on keyring signature verification (docs-vs-code #15)
// ============================================================================

/// Sets up a trusted repo whose signed keyring contains only alice, and
/// tampers the keyring file by appending an attacker entry plus a bogus
/// signature. Returns (repo_temp, key_store, keyring_path).
fn setup_tampered_keyring_repo() -> (tempfile::TempDir, PathBuf, std::path::PathBuf) {
    let (alice_sec, alice_pub) = generate_test_key("alice@example.com");
    let (repo_temp, key_store) = setup_trusted_repo_with_secret_keys(&[alice_sec]);

    let alice_keyfile = repo_temp.path().join("alice.pub");
    write_public_key_file(&alice_pub, &alice_keyfile);
    cmd_tell(
        repo_temp.path(),
        "alice@example.com",
        alice_keyfile.to_str().unwrap(),
        "origin",
        &key_store,
        None,
    )
    .expect("cmd_tell must succeed");

    let keyring_path = repo_temp.path().join(".git-veil/keyring");
    let mut tampered = Keyring::parse(&std::fs::read_to_string(&keyring_path).unwrap()).unwrap();
    tampered
        .add_entry(
            "attacker@evil.com".to_string(),
            "QUJDREVGR0hJSktMTU5PUA==".to_string(),
            "ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234".to_string(),
        )
        .unwrap();
    tampered.signature =
        Some("-----BEGIN PGP SIGNATURE-----\nbogus\n-----END PGP SIGNATURE-----".to_string());
    std::fs::write(&keyring_path, tampered.serialize()).unwrap();

    (repo_temp, key_store, keyring_path)
}

#[test]
fn list_keys_on_tampered_keyring_fails_closed() {
    let (repo_temp, key_store, keyring_path) = setup_tampered_keyring_repo();
    let keyring_before = std::fs::read(&keyring_path).unwrap();

    let result = cmd_list_keys(repo_temp.path(), "origin", &key_store);
    let keyring_after = std::fs::read(&keyring_path).unwrap();

    let err = result
        .err()
        .expect("list-keys over a tampered keyring must fail closed");
    assert!(
        err.to_string().to_lowercase().contains("signature"),
        "the error must be the underlying signature verification failure, got: {}",
        err
    );
    assert_eq!(
        keyring_before, keyring_after,
        "a failed list-keys must leave the keyring file untouched"
    );
}

#[test]
fn list_keys_on_valid_keyring_succeeds_and_reports_verification() {
    let (alice_sec, alice_pub) = generate_test_key("alice@example.com");
    let (repo_temp, key_store) = setup_trusted_repo_with_secret_keys(&[alice_sec]);

    let alice_keyfile = repo_temp.path().join("alice.pub");
    write_public_key_file(&alice_pub, &alice_keyfile);
    cmd_tell(
        repo_temp.path(),
        "alice@example.com",
        alice_keyfile.to_str().unwrap(),
        "origin",
        &key_store,
        None,
    )
    .expect("cmd_tell must succeed");

    cmd_list_keys(repo_temp.path(), "origin", &key_store)
        .expect("list-keys over a validly signed keyring must succeed");
}

// ============================================================================
// verify-keyring reports the signer identity (docs-vs-code #7)
// ============================================================================

#[test]
fn verify_keyring_reports_trusted_fingerprint() {
    let (repo_temp, key_store, owner_pub) = setup_repo_with_owner_in_keyring();
    let owner_fingerprint = extract_key_fingerprint(&owner_pub);

    let (repo_id, fingerprint, _keyring) =
        verify_keyring_against_trust(repo_temp.path(), "origin", &key_store)
            .expect("verification must succeed on a trusted repo");

    assert_eq!(
        repo_id, "repo+owner@github.com",
        "the returned repo id must match the trusted repo"
    );
    assert_eq!(
        fingerprint, owner_fingerprint,
        "the returned fingerprint must be the trusted owner key's fingerprint"
    );
    let pin = TrustPinStore::read_pin(&key_store, &repo_id)
        .expect("reading the pin must not error")
        .expect("cmd_trust must have pinned this repo on this machine");
    assert_eq!(
        fingerprint, pin,
        "the returned fingerprint must match the pin cmd_trust wrote"
    );
}

#[test]
fn tell_rejects_keyring_signed_by_wrong_key() {
    let (alice_sec, alice_pub) = generate_test_key("alice@example.com");
    let (repo_temp, key_store) = setup_trusted_repo_with_secret_keys(&[alice_sec]);

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
    let signature = sign_keyring_content(&content_to_sign, &mallory_sec, None)
        .expect("mallory must be able to sign her own keyring");
    forged.signature = Some(signature);
    std::fs::write(
        repo_temp.path().join(".git-veil/keyring"),
        forged.serialize(),
    )
    .unwrap();

    let alice_keyfile = repo_temp.path().join("alice.pub");
    write_public_key_file(&alice_pub, &alice_keyfile);

    let result = cmd_tell(
        repo_temp.path(),
        "alice@example.com",
        alice_keyfile.to_str().unwrap(),
        "origin",
        &key_store,
        None,
    );

    assert!(
        result.is_err(),
        "tell must reject a keyring signed by a non-trusted key"
    );
}

#[test]
fn tell_first_entry_on_fresh_repo_succeeds() {
    let (alice_sec, alice_pub) = generate_test_key("alice@example.com");
    let (repo_temp, key_store) = setup_trusted_repo_with_secret_keys(&[alice_sec]);

    let alice_keyfile = repo_temp.path().join("alice.pub");
    write_public_key_file(&alice_pub, &alice_keyfile);

    let result = cmd_tell(
        repo_temp.path(),
        "alice@example.com",
        alice_keyfile.to_str().unwrap(),
        "origin",
        &key_store,
        None,
    );

    let keyring_text = std::fs::read_to_string(repo_temp.path().join(".git-veil/keyring"))
        .expect("keyring must exist after tell");

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

fn generate_subkeyless_test_key(email: &str) -> pgp::composed::SignedPublicKey {
    let mut rng = thread_rng();

    let params = SecretKeyParamsBuilder::default()
        .key_type(KeyType::Ed25519)
        .can_certify(true)
        .can_sign(true)
        .primary_user_id(format!("Test User <{}>", email))
        .passphrase(None)
        .build()
        .expect("build subkeyless key params");

    params
        .generate(&mut rng)
        .expect("generate subkeyless key")
        .to_public_key()
}

// ============================================================================
// tell test-encrypts a canary to the collaborator key before signing it in
// ============================================================================

/// The canary bytes cmd_tell test-encrypts with. Must match
/// TELL_CANARY in src/commands/tell.rs; the contract under test is that
/// these bytes never reach disk.
const TELL_CANARY: &[u8] = b"git-veil tell canary";

#[test]
#[serial]
fn tell_fails_when_collaborator_key_cannot_encrypt() {
    // A malformed-but-parseable key: only the primary certification/signing
    // key, no encryption subkey at all.
    let alice_pub = generate_subkeyless_test_key("alice@example.com");
    let (alice_sec, _) = generate_test_key("alice@example.com");
    let (repo_temp, key_store) = setup_trusted_repo_with_secret_keys(&[alice_sec]);

    let alice_keyfile = repo_temp.path().join("alice.pub");
    write_public_key_file(&alice_pub, &alice_keyfile);

    let keyring_path = repo_temp.path().join(".git-veil/keyring");
    let keyring_before = std::fs::read(&keyring_path).unwrap();

    let result = cmd_tell(
        repo_temp.path(),
        "alice@example.com",
        alice_keyfile.to_str().unwrap(),
        "origin",
        &key_store,
        None,
    );

    let keyring_after = std::fs::read(&keyring_path).unwrap();

    let err = result.expect_err("tell must refuse a collaborator key that cannot encrypt");
    let msg = format!("{}", err);
    assert!(
        msg.contains("collaborator key cannot encrypt for alice@example.com"),
        "failure must name the collaborator email, got: {}",
        msg
    );
    assert!(
        msg.contains("No encryption subkey found in public key"),
        "failure must include the underlying cause, got: {}",
        msg
    );
    assert_eq!(
        keyring_before, keyring_after,
        "keyring must remain byte-identical after a failed tell"
    );
}

#[test]
#[serial]
fn tell_canary_does_not_appear_anywhere() {
    fn contains_canary(dir: &std::path::Path) -> Vec<PathBuf> {
        let mut hits = Vec::new();
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_dir() {
                hits.extend(contains_canary(&path));
            } else if std::fs::read(&path)
                .map(|b| b.windows(TELL_CANARY.len()).any(|w| w == TELL_CANARY))
                .unwrap_or(false)
            {
                hits.push(path);
            }
        }
        hits
    }

    let (alice_sec, alice_pub) = generate_test_key("alice@example.com");
    let (repo_temp, key_store) = setup_trusted_repo_with_secret_keys(&[alice_sec]);

    let alice_keyfile = repo_temp.path().join("alice.pub");
    write_public_key_file(&alice_pub, &alice_keyfile);

    cmd_tell(
        repo_temp.path(),
        "alice@example.com",
        alice_keyfile.to_str().unwrap(),
        "origin",
        &key_store,
        None,
    )
    .expect("tell with an encryptable key must succeed");

    let hits = contains_canary(repo_temp.path());
    assert!(
        hits.is_empty(),
        "tell canary bytes must never be written anywhere under the repo, found in: {:?}",
        hits
    );
}

// ============================================================================
// removeperson: revoking a collaborator from the keyring
// ============================================================================

#[test]
fn removeperson_removes_entry_and_resigns() {
    let (_, alice_pub) = generate_test_key("alice@example.com");
    let (_, bob_pub) = generate_test_key("bob@example.com");
    let (repo_temp, key_store) = setup_trusted_repo_with_secret_keys(&[]);

    let alice_keyfile = repo_temp.path().join("alice.pub");
    write_public_key_file(&alice_pub, &alice_keyfile);
    let bob_keyfile = repo_temp.path().join("bob.pub");
    write_public_key_file(&bob_pub, &bob_keyfile);

    cmd_tell(
        repo_temp.path(),
        "alice@example.com",
        alice_keyfile.to_str().unwrap(),
        "origin",
        &key_store,
        None,
    )
    .expect("tell alice must succeed");
    cmd_tell(
        repo_temp.path(),
        "bob@example.com",
        bob_keyfile.to_str().unwrap(),
        "origin",
        &key_store,
        None,
    )
    .expect("tell bob must succeed");

    let remove_result = cmd_removeperson(
        repo_temp.path(),
        "bob@example.com",
        "origin",
        &key_store,
        None,
    );

    let keyring_text = std::fs::read_to_string(repo_temp.path().join(".git-veil/keyring")).unwrap();
    let keyring = Keyring::parse(&keyring_text).unwrap();
    let verify_result = cmd_verify_keyring(repo_temp.path(), "origin", &key_store);

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
fn removeperson_removes_entry_regardless_of_email_case() {
    let (_, alice_pub) = generate_test_key("alice@example.com");
    let (repo_temp, key_store) = setup_trusted_repo_with_secret_keys(&[]);

    let alice_keyfile = repo_temp.path().join("alice.pub");
    write_public_key_file(&alice_pub, &alice_keyfile);

    cmd_tell(
        repo_temp.path(),
        "alice@example.com",
        alice_keyfile.to_str().unwrap(),
        "origin",
        &key_store,
        None,
    )
    .expect("tell alice must succeed");

    let remove_result = cmd_removeperson(
        repo_temp.path(),
        "ALICE@EXAMPLE.COM",
        "origin",
        &key_store,
        None,
    );

    let keyring_text = std::fs::read_to_string(repo_temp.path().join(".git-veil/keyring")).unwrap();
    let keyring = Keyring::parse(&keyring_text).unwrap();
    let verify_result = cmd_verify_keyring(repo_temp.path(), "origin", &key_store);

    remove_result.expect(
        "removeperson must remove the entry regardless of email case, matching the case-insensitive reveal lookup",
    );
    assert!(
        keyring.entries.is_empty(),
        "keyring must contain no entries after removing alice case-insensitively, got: {:?}",
        keyring.entries
    );
    verify_result.expect("keyring signature must still verify after removeperson");
}

#[test]
fn removeperson_unknown_email_fails() {
    let (_, alice_pub) = generate_test_key("alice@example.com");
    let (repo_temp, key_store) = setup_trusted_repo_with_secret_keys(&[]);

    let alice_keyfile = repo_temp.path().join("alice.pub");
    write_public_key_file(&alice_pub, &alice_keyfile);

    cmd_tell(
        repo_temp.path(),
        "alice@example.com",
        alice_keyfile.to_str().unwrap(),
        "origin",
        &key_store,
        None,
    )
    .expect("tell alice must succeed");

    let remove_result = cmd_removeperson(
        repo_temp.path(),
        "carol@example.com",
        "origin",
        &key_store,
        None,
    );

    let err = remove_result
        .err()
        .expect("removing an unknown email must fail");
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
        &repo_temp.path().join("key-store"),
        None,
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
    let (repo_temp, key_store) = setup_trusted_repo_with_secret_keys(&[]);

    let alice_keyfile = repo_temp.path().join("alice.pub");
    write_public_key_file(&alice_pub, &alice_keyfile);

    cmd_tell(
        repo_temp.path(),
        "alice@example.com",
        alice_keyfile.to_str().unwrap(),
        "origin",
        &key_store,
        None,
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
    let signature = sign_keyring_content(&content_to_sign, &mallory_sec, None)
        .expect("mallory must be able to sign her own keyring");
    forged.signature = Some(signature);
    std::fs::write(
        repo_temp.path().join(".git-veil/keyring"),
        forged.serialize(),
    )
    .unwrap();

    let remove_result = cmd_removeperson(
        repo_temp.path(),
        "mallory@evil.com",
        "origin",
        &key_store,
        None,
    );

    let keyring_text_after =
        std::fs::read_to_string(repo_temp.path().join(".git-veil/keyring")).unwrap();

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

    let loaded = TrustStore::load_from_file(&repo_temp.path().join(".git-veil/trust.json"));

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

    let key_store = repo_temp.path().join("key-store");

    let trust_result = cmd_trust(
        repo_temp.path(),
        "repo+owner@github.com",
        owner_keyfile.to_str().unwrap(),
        "origin",
        &key_store,
    );

    let (alice_sec, alice_pub) = generate_test_key("alice@example.com");
    write_multi_key_secret_keys(&key_store, &[owner_sec, alice_sec]);

    let alice_keyfile = repo_temp.path().join("alice.pub");
    write_public_key_file(&alice_pub, &alice_keyfile);

    let tell_result = cmd_tell(
        repo_temp.path(),
        "alice@example.com",
        alice_keyfile.to_str().unwrap(),
        "origin",
        &key_store,
        None,
    );

    let verify_result = cmd_verify_keyring(repo_temp.path(), "origin", &key_store);

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
    std::fs::create_dir_all(repo_root.join(".git-veil")).unwrap();
    std::fs::write(repo_root.join(".git-veil/tracked.json"), content).unwrap();
}

/// Sets up a repo where the trusted owner key is also a keyring entry, so a
/// full add -> hide -> reveal flow can run with the owner's own keypair.
fn setup_repo_with_owner_in_keyring() -> (tempfile::TempDir, PathBuf, pgp::composed::SignedPublicKey)
{
    let repo_temp = setup_git_repo_with_origin_remote();

    cmd_init(repo_temp.path()).expect("cmd_init must succeed");

    let (owner_sec, owner_pub) = generate_test_key("owner@github.com");
    let owner_keyfile = repo_temp.path().join("owner.pub");
    write_public_key_file(&owner_pub, &owner_keyfile);

    let key_store = repo_temp.path().join("key-store");

    cmd_trust(
        repo_temp.path(),
        "repo+owner@github.com",
        owner_keyfile.to_str().unwrap(),
        "origin",
        &key_store,
    )
    .expect("cmd_trust must succeed");

    write_multi_key_secret_keys(&key_store, &[owner_sec]);

    cmd_tell(
        repo_temp.path(),
        "owner@github.com",
        owner_keyfile.to_str().unwrap(),
        "origin",
        &key_store,
        None,
    )
    .expect("cmd_tell must succeed");

    (repo_temp, key_store, owner_pub)
}

#[test]
fn tracked_files_load_rejects_absolute_paths() {
    let temp = tempfile::tempdir().unwrap();
    let tracked_path = temp.path().join(".git-veil").join("tracked.json");
    std::fs::create_dir_all(tracked_path.parent().unwrap()).unwrap();
    std::fs::write(&tracked_path, r#"{"files":["/etc/passwd"]}"#).unwrap();

    let result = TrackedFiles::load(&tracked_path);

    let err = result
        .err()
        .expect("absolute tracked path must be rejected");
    assert!(
        err.to_string().contains("/etc/passwd"),
        "error must name the offending path, got: {}",
        err
    );
}

#[test]
fn tracked_files_load_rejects_dotdot_components() {
    let temp = tempfile::tempdir().unwrap();
    let tracked_path = temp.path().join(".git-veil").join("tracked.json");
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

    let tracked_content = std::fs::read_to_string(temp.path().join(".git-veil/tracked.json"))
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

    let result = cmd_add(
        repo_temp.path(),
        vec![outside_file.to_str().unwrap().to_string()],
    );

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

    let result = cmd_remove(
        repo_temp.path(),
        vec![outside_file.to_str().unwrap().to_string()],
    );

    assert!(
        result.is_err(),
        "cmd_remove must reject a file outside the repository: {:?}",
        result.err()
    );
}

#[test]
fn remove_works_on_currently_hidden_file() {
    let (repo_temp, key_store, _owner_pub) = setup_repo_with_owner_in_keyring();

    std::fs::write(repo_temp.path().join("a.env"), "alpha").unwrap();
    std::fs::write(repo_temp.path().join("b.env"), "beta").unwrap();
    cmd_add(
        repo_temp.path(),
        vec!["a.env".to_string(), "b.env".to_string()],
    )
    .expect("cmd_add must succeed");
    cmd_hide(repo_temp.path(), "origin", &key_store).expect("cmd_hide must succeed");

    // hide deleted the plaintexts and left ciphertexts beside them
    assert!(
        !repo_temp.path().join("a.env").exists(),
        "hide must have deleted the plaintext a.env"
    );
    assert!(
        !repo_temp.path().join("b.env").exists(),
        "hide must have deleted the plaintext b.env"
    );
    let a_secret = repo_temp.path().join("a.env.secret");
    let b_secret = repo_temp.path().join("b.env.secret");
    assert!(a_secret.exists(), "hide must have written a.env.secret");
    assert!(b_secret.exists(), "hide must have written b.env.secret");
    let a_secret_before = std::fs::read(&a_secret).unwrap();

    // The plaintext does not exist, yet the user must be able to untrack it
    // WITHOUT revealing it first (reveal would write plaintext back to disk).
    let result = cmd_remove(repo_temp.path(), vec!["a.env".to_string()]);

    result.expect(
        "cmd_remove must untrack a currently hidden file; revealing the secret \
         just to untrack it defeats the purpose",
    );

    let tracked_content = std::fs::read_to_string(repo_temp.path().join(".git-veil/tracked.json"))
        .expect("tracked.json must exist after remove");
    assert!(
        !tracked_content.contains("\"a.env\""),
        "tracked.json must no longer list a.env, got: {}",
        tracked_content
    );
    assert!(
        tracked_content.contains("\"b.env\""),
        "tracked.json must still list b.env, got: {}",
        tracked_content
    );

    // Untracking is not decrypting: the ciphertext must be untouched.
    assert!(
        a_secret.exists(),
        "remove must not delete the a.env.secret ciphertext"
    );
    assert_eq!(
        std::fs::read(&a_secret).unwrap(),
        a_secret_before,
        "remove must not modify the a.env.secret ciphertext"
    );
    assert!(
        b_secret.exists(),
        "remove must not delete the b.env.secret ciphertext"
    );
}

#[test]
fn remove_still_rejects_paths_outside_the_repo() {
    let repo_temp = tempfile::tempdir().unwrap();
    init_git_repo(repo_temp.path());

    // A sibling directory outside the repository, holding an existing file:
    // even though the path exists, it must be rejected.
    let outside = tempfile::tempdir_in(repo_temp.path().parent().unwrap()).unwrap();
    let outside_file = outside.path().join("outside.env");
    std::fs::write(&outside_file, "nope").unwrap();

    let result = cmd_remove(
        repo_temp.path(),
        vec![outside_file.to_str().unwrap().to_string()],
    );

    assert!(
        result.is_err(),
        "cmd_remove must reject a path outside the repository: {:?}",
        result.err()
    );
}

#[test]
fn reveal_refuses_escaping_tracked_path() {
    let (repo_temp, key_store, owner_pub) = setup_repo_with_owner_in_keyring();

    std::fs::write(repo_temp.path().join("secret.env"), "topsecret").unwrap();
    cmd_add(repo_temp.path(), vec!["secret.env".to_string()]).expect("cmd_add must succeed");
    cmd_hide(repo_temp.path(), "origin", &key_store).expect("cmd_hide must succeed");
    assert!(
        repo_temp.path().join("secret.env.secret").exists(),
        "hide must write the ciphertext beside the plaintext"
    );

    // Attacker (any repo writer) tampers with the committed tracked.json to
    // point one level above the repo root, and commits a ciphertext that
    // decrypts with the victim's key. Under the in-place naming the
    // ciphertext for ../outside.txt would land beside the repo as
    // outside.txt.secret.
    write_tracked_json(repo_temp.path(), &["../outside.txt"]);
    let ciphertext = encrypt_to_public_key(b"pwned", &owner_pub).unwrap();
    let planted = repo_temp
        .path()
        .parent()
        .unwrap()
        .join("outside.txt.secret");
    std::fs::write(&planted, ciphertext).unwrap();

    let target = repo_temp.path().parent().unwrap().join("outside.txt");
    let _ = std::fs::remove_file(&target);

    let result = cmd_reveal(
        repo_temp.path(),
        "owner@github.com",
        "origin",
        &key_store,
        None,
    );

    let target_exists = target.exists();
    let _ = std::fs::remove_file(&target);
    let _ = std::fs::remove_file(&planted);

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
    let (repo_temp, key_store) = setup_trusted_repo_with_secret_keys(&[alice_sec]);

    let alice_keyfile = repo_temp.path().join("alice.pub");
    write_public_key_file(&alice_pub, &alice_keyfile);

    cmd_tell(
        repo_temp.path(),
        "alice@example.com",
        alice_keyfile.to_str().unwrap(),
        "origin",
        &key_store,
        None,
    )
    .expect("cmd_tell must succeed");

    let plaintext: &str = "API_KEY=s3cr3t-value\nDB_PASSWORD=hunter2\n# unicode: héllo wörld — 日本語 🌍\nline with trailing spaces   \n";
    std::fs::write(repo_temp.path().join("secret.env"), plaintext).unwrap();

    cmd_add(repo_temp.path(), vec!["secret.env".to_string()]).expect("cmd_add must succeed");

    let hide_result = cmd_hide(repo_temp.path(), "origin", &key_store);
    let plaintext_gone_after_hide = !repo_temp.path().join("secret.env").exists();
    let ciphertext_after_hide = repo_temp.path().join("secret.env.secret").exists();

    let reveal_result = cmd_reveal(
        repo_temp.path(),
        "alice@example.com",
        "origin",
        &key_store,
        None,
    );
    let restored = std::fs::read(repo_temp.path().join("secret.env"));
    let ciphertext_gone_after_reveal = !repo_temp.path().join("secret.env.secret").exists();

    hide_result.expect("cmd_hide must succeed");
    assert!(
        plaintext_gone_after_hide,
        "hide must delete the plaintext file"
    );
    assert!(
        ciphertext_after_hide,
        "hide must write the ciphertext beside the plaintext as secret.env.secret"
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
    let (repo_temp, key_store) = setup_trusted_repo_with_secret_keys(&[alice_sec]);

    let alice_keyfile = repo_temp.path().join("alice.pub");
    write_public_key_file(&alice_pub, &alice_keyfile);

    cmd_tell(
        repo_temp.path(),
        "alice@example.com",
        alice_keyfile.to_str().unwrap(),
        "origin",
        &key_store,
        None,
    )
    .expect("cmd_tell must succeed");

    let tracked_rel = "a/b/c/secret.env";
    let plaintext: &str = "NESTED_SECRET=prüne\ntrailing newline follows\n";
    std::fs::create_dir_all(repo_temp.path().join("a/b/c")).unwrap();
    std::fs::write(repo_temp.path().join(tracked_rel), plaintext).unwrap();

    cmd_add(repo_temp.path(), vec![tracked_rel.to_string()]).expect("cmd_add must succeed");

    let hide_result = cmd_hide(repo_temp.path(), "origin", &key_store);
    let plaintext_gone_after_hide = !repo_temp.path().join(tracked_rel).exists();
    let ciphertext_after_hide = repo_temp.path().join("a/b/c/secret.env.secret").exists();

    let reveal_result = cmd_reveal(
        repo_temp.path(),
        "alice@example.com",
        "origin",
        &key_store,
        None,
    );
    let restored = std::fs::read(repo_temp.path().join(tracked_rel));
    let ciphertext_gone_after_reveal = !repo_temp.path().join("a/b/c/secret.env.secret").exists();

    hide_result.expect("cmd_hide must succeed");
    assert!(
        plaintext_gone_after_hide,
        "hide must delete the plaintext file"
    );
    assert!(
        ciphertext_after_hide,
        "hide must write the ciphertext beside the plaintext in its subdirectory"
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
    let (repo_temp, key_store) = setup_trusted_repo_with_secret_keys(&[alice_sec]);

    let alice_keyfile = repo_temp.path().join("alice.pub");
    write_public_key_file(&alice_pub, &alice_keyfile);

    cmd_tell(
        repo_temp.path(),
        "alice@example.com",
        alice_keyfile.to_str().unwrap(),
        "origin",
        &key_store,
        None,
    )
    .expect("cmd_tell must succeed");

    let plaintext: Vec<u8> = (0..=255u8).collect();
    std::fs::write(repo_temp.path().join("blob.bin"), &plaintext).unwrap();

    cmd_add(repo_temp.path(), vec!["blob.bin".to_string()]).expect("cmd_add must succeed");

    let hide_result = cmd_hide(repo_temp.path(), "origin", &key_store);
    let plaintext_gone_after_hide = !repo_temp.path().join("blob.bin").exists();

    let reveal_result = cmd_reveal(
        repo_temp.path(),
        "alice@example.com",
        "origin",
        &key_store,
        None,
    );
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
// L4: ciphertext filename is the FULL original file name plus ".secret"
//
// Regression tests: the ciphertext name must never be derived by replacing
// the extension (notes -> notes..secret, .env -> .env..secret) — it is the
// full original name plus the .secret suffix, written beside the plaintext.
// ============================================================================

#[test]
fn ciphertext_filename_is_full_name_plus_secret() {
    let (repo_temp, key_store, _) = setup_repo_with_owner_in_keyring();

    std::fs::write(repo_temp.path().join("notes"), "no extension here\n").unwrap();
    cmd_add(repo_temp.path(), vec!["notes".to_string()]).expect("cmd_add must succeed");

    let hide_result = cmd_hide(repo_temp.path(), "origin", &key_store);
    let ciphertext_exists = repo_temp.path().join("notes.secret").exists();
    let mangled_exists = repo_temp.path().join("notes..secret").exists();

    hide_result.expect("cmd_hide must succeed");
    assert!(
        ciphertext_exists,
        "hide must write the ciphertext beside the plaintext as notes.secret"
    );
    assert!(
        !mangled_exists,
        "hide must not mangle the ciphertext name to notes..secret"
    );
}

#[test]
fn ciphertext_filename_for_dotfile() {
    let (repo_temp, key_store, _) = setup_repo_with_owner_in_keyring();

    std::fs::write(repo_temp.path().join(".env"), "DOTENV=1\n").unwrap();
    cmd_add(repo_temp.path(), vec![".env".to_string()]).expect("cmd_add must succeed");

    let hide_result = cmd_hide(repo_temp.path(), "origin", &key_store);
    let ciphertext_exists = repo_temp.path().join(".env.secret").exists();
    let mangled_exists = repo_temp.path().join(".env..secret").exists();

    hide_result.expect("cmd_hide must succeed");
    assert!(
        ciphertext_exists,
        "hide must write the ciphertext beside the plaintext as .env.secret"
    );
    assert!(
        !mangled_exists,
        "hide must not mangle the ciphertext name to .env..secret"
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
    let (repo_temp, key_store) = setup_trusted_repo_with_secret_keys(&[alice_sec]);

    let alice_keyfile = repo_temp.path().join("alice.pub");
    write_public_key_file(&alice_pub, &alice_keyfile);

    cmd_tell(
        repo_temp.path(),
        "alice@example.com",
        alice_keyfile.to_str().unwrap(),
        "origin",
        &key_store,
        None,
    )
    .expect("cmd_tell must succeed");

    for (name, bytes) in &cases {
        std::fs::write(repo_temp.path().join(name), bytes).unwrap();
        cmd_add(repo_temp.path(), vec![name.to_string()])
            .unwrap_or_else(|e| panic!("cmd_add must succeed for {}: {:?}", name, e));
    }

    let hide_result = cmd_hide(repo_temp.path(), "origin", &key_store);
    let ciphertexts_exist: Vec<(String, bool)> = cases
        .iter()
        .map(|(name, _)| {
            (
                name.to_string(),
                repo_temp.path().join(format!("{}.secret", name)).exists(),
            )
        })
        .collect();

    let reveal_result = cmd_reveal(
        repo_temp.path(),
        "alice@example.com",
        "origin",
        &key_store,
        None,
    );
    let restored: Vec<(String, Option<Vec<u8>>)> = cases
        .iter()
        .map(|(name, _)| {
            (
                name.to_string(),
                std::fs::read(repo_temp.path().join(name)).ok(),
            )
        })
        .collect();

    hide_result.expect("cmd_hide must succeed");
    for (name, exists) in ciphertexts_exist {
        assert!(
            exists,
            "hide must write the ciphertext beside the plaintext as {}.secret",
            name
        );
    }
    reveal_result.expect("cmd_reveal must succeed");
    for ((name, original), (restored_name, restored_bytes)) in cases.iter().zip(restored.iter()) {
        assert_eq!(name, restored_name, "test bookkeeping must stay in sync");
        let restored_bytes = restored_bytes
            .as_ref()
            .unwrap_or_else(|| panic!("reveal must recreate {}", name));
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

    let tracked_content = std::fs::read_to_string(repo_temp.path().join(".git-veil/tracked.json"))
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
/// in the secret key store. Returns (repo_temp, key_store).
fn setup_hidden_repo_with_alice_key() -> (tempfile::TempDir, PathBuf) {
    let (alice_sec, alice_pub) = generate_test_key("alice@example.com");
    let (repo_temp, key_store) = setup_trusted_repo_with_secret_keys(&[alice_sec]);

    let alice_keyfile = repo_temp.path().join("alice.pub");
    write_public_key_file(&alice_pub, &alice_keyfile);

    cmd_tell(
        repo_temp.path(),
        "alice@example.com",
        alice_keyfile.to_str().unwrap(),
        "origin",
        &key_store,
        None,
    )
    .expect("cmd_tell must succeed");

    (repo_temp, key_store)
}

#[test]
fn cat_returns_exact_bytes_without_touching_disk() {
    let (repo_temp, key_store) = setup_hidden_repo_with_alice_key();

    let plaintext: &str = "API_KEY=cat-s3cr3t\nDB_PASSWORD=hunter2\n# unicode: héllo — 日本語\n";
    std::fs::write(repo_temp.path().join("secret.env"), plaintext).unwrap();
    cmd_add(repo_temp.path(), vec!["secret.env".to_string()]).expect("cmd_add must succeed");
    cmd_hide(repo_temp.path(), "origin", &key_store).expect("cmd_hide must succeed");

    let cat_result = cmd_cat(
        repo_temp.path(),
        "secret.env",
        "alice@example.com",
        "origin",
        &key_store,
        None,
    );
    let ciphertext_still_exists = repo_temp.path().join("secret.env.secret").exists();
    let no_plaintext_on_disk = !repo_temp.path().join("secret.env").exists();

    let bytes = cat_result.expect("cmd_cat must decrypt the tracked file");
    assert_eq!(
        bytes,
        plaintext.as_bytes(),
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
    let (repo_temp, key_store) = setup_hidden_repo_with_alice_key();

    let result = cmd_cat(
        repo_temp.path(),
        "not-tracked.env",
        "alice@example.com",
        "origin",
        &key_store,
        None,
    );

    let err = result.err().expect("cat of an untracked file must fail");
    assert!(
        err.to_string().contains("not tracked"),
        "the error must say the file is not tracked, got: {}",
        err
    );
}

#[test]
fn cat_rejects_path_escaping_the_repo() {
    let (repo_temp, key_store) = setup_hidden_repo_with_alice_key();

    std::fs::write(repo_temp.path().join("secret.env"), "s3cret").unwrap();
    cmd_add(repo_temp.path(), vec!["secret.env".to_string()]).expect("cmd_add must succeed");
    cmd_hide(repo_temp.path(), "origin", &key_store).expect("cmd_hide must succeed");

    let dotdot_result = cmd_cat(
        repo_temp.path(),
        "../outside.txt",
        "alice@example.com",
        "origin",
        &key_store,
        None,
    );
    let outside = repo_temp.path().parent().unwrap().join("outside.txt");
    std::fs::write(&outside, "nope").unwrap();
    let absolute_result = cmd_cat(
        repo_temp.path(),
        outside.to_str().unwrap(),
        "alice@example.com",
        "origin",
        &key_store,
        None,
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
// committed tracked.json + committed symlink: read gates refuse symlinks
//
// tracked.json is attacker-writable repo content. A committed symlink at a
// tracked path must never be followed: hide/cat/changes would read outside
// the repo and exfiltrate via ciphertext, and reveal/unhide would write
// through the link (or silently replace it).
// ============================================================================

/// Scans `dir` recursively; true if any `*.secret` file contains `needle`.
fn any_secret_file_contains(dir: &std::path::Path, needle: &str) -> bool {
    let mut found = false;
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                found = found || any_secret_file_contains(&path, needle);
            } else if path.to_string_lossy().ends_with(".secret") {
                if let Ok(content) = std::fs::read(&path) {
                    found = found || String::from_utf8_lossy(&content).contains(needle);
                }
            }
        }
    }
    found
}

/// Attack setup: a trusted repo whose committed tracked.json names
/// `link.txt` — a symlink inside the repo targeting `../<outside_name>`,
/// a file OUTSIDE the repository. Returns
/// (repo_temp, key_store, owner_pub, outside_file, link_path).
fn setup_tracked_symlink_repo(
    outside_name: &str,
) -> (
    tempfile::TempDir,
    PathBuf,
    pgp::composed::SignedPublicKey,
    std::path::PathBuf,
    std::path::PathBuf,
) {
    let (repo_temp, key_store, owner_pub) = setup_repo_with_owner_in_keyring();

    let outside_file = repo_temp.path().parent().unwrap().join(outside_name);
    std::fs::write(&outside_file, "VICTIM-SSH-PRIVATE-KEY").unwrap();
    std::os::unix::fs::symlink(
        format!("../{}", outside_name),
        repo_temp.path().join("link.txt"),
    )
    .unwrap();

    // Attacker-committed tracked.json naming the symlink: the entry itself
    // is relative and passes C2 validation — only the lstat gate can see
    // that it is a symlink.
    write_tracked_json(repo_temp.path(), &["link.txt"]);

    let link_path = repo_temp.path().join("link.txt");
    (repo_temp, key_store, owner_pub, outside_file, link_path)
}

#[test]
fn hide_refuses_tracked_symlink() {
    let (repo_temp, key_store, _owner_pub, outside_file, link_path) =
        setup_tracked_symlink_repo("outside-hide.txt");

    let result = cmd_hide(repo_temp.path(), "origin", &key_store);

    let err = result
        .err()
        .expect("hide must refuse to read a tracked symlink");
    assert!(
        err.to_string().contains("symlink"),
        "the error must say the tracked path is a symlink, got: {}",
        err
    );
    assert!(
        err.to_string().contains("link.txt"),
        "the error must name the offending path, got: {}",
        err
    );
    assert!(
        link_path
            .symlink_metadata()
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false),
        "hide must not delete or replace the committed symlink"
    );
    assert_eq!(
        std::fs::read(&outside_file).unwrap(),
        b"VICTIM-SSH-PRIVATE-KEY".as_slice(),
        "the file outside the repo must be untouched"
    );
    assert!(
        !repo_temp.path().join("link.txt.secret").exists(),
        "hide must not write a ciphertext for a tracked symlink"
    );
    assert!(
        !any_secret_file_contains(repo_temp.path(), "VICTIM-SSH-PRIVATE-KEY"),
        "the outside file's content must never appear in any .secret in the repo"
    );

    let _ = std::fs::remove_file(&outside_file);
}

#[test]
fn cat_refuses_tracked_symlink() {
    let (repo_temp, key_store, owner_pub, outside_file, link_path) =
        setup_tracked_symlink_repo("outside-cat.txt");

    // A planted ciphertext beside the symlink: in the vulnerable state cat
    // happily decrypts it, so the red failure is a success, not a parse error.
    let planted = repo_temp.path().join("link.txt.secret");
    std::fs::write(
        &planted,
        encrypt_to_public_key(b"ATTACKER-PLANTED", &owner_pub).unwrap(),
    )
    .unwrap();

    let result = cmd_cat(
        repo_temp.path(),
        "link.txt",
        "owner@github.com",
        "origin",
        &key_store,
        None,
    );

    let err = result
        .err()
        .expect("cat must refuse to operate on a tracked symlink");
    assert!(
        err.to_string().contains("symlink"),
        "the error must say the tracked path is a symlink, got: {}",
        err
    );
    assert!(
        err.to_string().contains("link.txt"),
        "the error must name the offending path, got: {}",
        err
    );
    assert!(
        link_path
            .symlink_metadata()
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false),
        "cat must not delete or replace the committed symlink"
    );
    assert_eq!(
        std::fs::read(&outside_file).unwrap(),
        b"VICTIM-SSH-PRIVATE-KEY".as_slice(),
        "the file outside the repo must be untouched"
    );

    let _ = std::fs::remove_file(&outside_file);
}

#[test]
fn changes_refuses_tracked_symlink() {
    let (repo_temp, key_store, owner_pub, outside_file, link_path) =
        setup_tracked_symlink_repo("outside-changes.txt");

    // A planted ciphertext beside the symlink: in the vulnerable state
    // changes reads the outside file THROUGH the link and diffs it, leaking
    // its lines in the output.
    let planted = repo_temp.path().join("link.txt.secret");
    std::fs::write(
        &planted,
        encrypt_to_public_key(b"ATTACKER-PLANTED", &owner_pub).unwrap(),
    )
    .unwrap();

    let result = cmd_changes(
        repo_temp.path(),
        vec![],
        "owner@github.com",
        "origin",
        &key_store,
        None,
    );

    let err = result
        .err()
        .expect("changes must refuse to read a tracked symlink");
    assert!(
        err.to_string().contains("symlink"),
        "the error must say the tracked path is a symlink, got: {}",
        err
    );
    assert!(
        err.to_string().contains("link.txt"),
        "the error must name the offending path, got: {}",
        err
    );
    assert!(
        link_path
            .symlink_metadata()
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false),
        "changes must not delete or replace the committed symlink"
    );
    assert_eq!(
        std::fs::read(&outside_file).unwrap(),
        b"VICTIM-SSH-PRIVATE-KEY".as_slice(),
        "the file outside the repo must be untouched"
    );

    let _ = std::fs::remove_file(&outside_file);
}

#[test]
fn reveal_refuses_to_write_through_symlink() {
    let (repo_temp, key_store, owner_pub, outside_file, link_path) =
        setup_tracked_symlink_repo("outside-reveal.txt");

    let planted = repo_temp.path().join("link.txt.secret");
    std::fs::write(
        &planted,
        encrypt_to_public_key(b"pwned", &owner_pub).unwrap(),
    )
    .unwrap();

    let result = cmd_reveal(
        repo_temp.path(),
        "owner@github.com",
        "origin",
        &key_store,
        None,
    );

    let err = result
        .err()
        .expect("reveal must refuse to write through a tracked symlink");
    assert!(
        err.to_string().contains("symlink"),
        "the error must say the tracked path is a symlink, got: {}",
        err
    );
    assert!(
        err.to_string().contains("link.txt"),
        "the error must name the offending path, got: {}",
        err
    );
    assert!(
        link_path.is_symlink(),
        "reveal must not replace the committed symlink with a regular file"
    );
    assert_eq!(
        std::fs::read_link(&link_path).unwrap(),
        std::path::Path::new("../outside-reveal.txt"),
        "the link must still point where it did"
    );
    assert_eq!(
        std::fs::read(&outside_file).unwrap(),
        b"VICTIM-SSH-PRIVATE-KEY".as_slice(),
        "the link target outside the repo must be untouched"
    );

    let _ = std::fs::remove_file(&outside_file);
}

// ============================================================================
// changes: report where on-disk plaintext differs from the last hidden version
// ============================================================================

#[test]
fn changes_reports_no_changes_when_plaintext_matches() {
    let (repo_temp, key_store, _) = setup_repo_with_owner_in_keyring();

    let plaintext = "API_KEY=s3cr3t-value\nDB_PASSWORD=hunter2\n";
    std::fs::write(repo_temp.path().join("secret.env"), plaintext).unwrap();
    cmd_add(repo_temp.path(), vec!["secret.env".to_string()]).expect("cmd_add must succeed");
    cmd_hide(repo_temp.path(), "origin", &key_store).expect("cmd_hide must succeed");

    // Re-create the plaintext with IDENTICAL bytes, as if revealed and untouched.
    std::fs::write(repo_temp.path().join("secret.env"), plaintext).unwrap();

    let result = cmd_changes(
        repo_temp.path(),
        vec![],
        "owner@github.com",
        "origin",
        &key_store,
        None,
    );
    let ciphertext_still_exists = repo_temp.path().join("secret.env.secret").exists();

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
    let (repo_temp, key_store, _) = setup_repo_with_owner_in_keyring();

    std::fs::write(repo_temp.path().join("secret.env"), "API_KEY=old-value\n").unwrap();
    cmd_add(repo_temp.path(), vec!["secret.env".to_string()]).expect("cmd_add must succeed");
    cmd_hide(repo_temp.path(), "origin", &key_store).expect("cmd_hide must succeed");

    std::fs::write(
        repo_temp.path().join("secret.env"),
        "API_KEY=NEW-value\nDB=hunter2\n",
    )
    .unwrap();

    let result = cmd_changes(
        repo_temp.path(),
        vec![],
        "owner@github.com",
        "origin",
        &key_store,
        None,
    );

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
    let (repo_temp, key_store, _) = setup_repo_with_owner_in_keyring();

    std::fs::write(repo_temp.path().join("secret.env"), "API_KEY=s3cr3t\n").unwrap();
    cmd_add(repo_temp.path(), vec!["secret.env".to_string()]).expect("cmd_add must succeed");
    cmd_hide(repo_temp.path(), "origin", &key_store).expect("cmd_hide must succeed");
    // hide deleted the plaintext; it is still hidden but absent on disk.

    let result = cmd_changes(
        repo_temp.path(),
        vec![],
        "owner@github.com",
        "origin",
        &key_store,
        None,
    );

    let changed = result.expect("missing plaintext must be skipped, not an error");
    assert!(
        changed.is_empty(),
        "a file hidden with no plaintext on disk must not be reported as changed, got: {:?}",
        changed
    );
    assert!(
        repo_temp.path().join("secret.env.secret").exists(),
        "the ciphertext must remain in place after the skipped file"
    );
}

#[test]
fn changes_fails_for_untracked_file() {
    let (repo_temp, key_store, _) = setup_repo_with_owner_in_keyring();

    let result = cmd_changes(
        repo_temp.path(),
        vec!["not-tracked.env".to_string()],
        "owner@github.com",
        "origin",
        &key_store,
        None,
    );

    let err = result
        .err()
        .expect("changes for an untracked file must fail");
    assert!(
        err.to_string().contains("not tracked"),
        "the error must say the file is not tracked, got: {}",
        err
    );
}

#[test]
fn changes_detects_binary_difference() {
    let (repo_temp, key_store, _) = setup_repo_with_owner_in_keyring();

    let original: Vec<u8> = vec![0u8, 1, 2, 3, 255];
    std::fs::write(repo_temp.path().join("blob.bin"), &original).unwrap();
    cmd_add(repo_temp.path(), vec!["blob.bin".to_string()]).expect("cmd_add must succeed");
    cmd_hide(repo_temp.path(), "origin", &key_store).expect("cmd_hide must succeed");

    let modified: Vec<u8> = vec![0u8, 1, 2, 3, 254, 9];
    std::fs::write(repo_temp.path().join("blob.bin"), &modified).unwrap();

    let result = cmd_changes(
        repo_temp.path(),
        vec![],
        "owner@github.com",
        "origin",
        &key_store,
        None,
    );

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

    let key_store = tempfile::tempdir().unwrap().path().to_path_buf();

    cmd_trust(
        repo_temp.path(),
        "repo+owner@github.com",
        keyfile.to_str().unwrap(),
        "origin",
        &key_store,
    )
    .expect("cmd_trust must succeed");

    assert!(
        key_store.join("trust-pins").is_dir(),
        "the pin must live in the tool-owned key store, not inside the repo"
    );
    let pin = TrustPinStore::read_pin(&key_store, "repo+owner@github.com")
        .expect("reading the pin must not error");
    assert_eq!(
        pin.as_deref(),
        Some(extract_key_fingerprint(&owner_pub).as_str()),
        "cmd_trust must pin the trusted fingerprint for this repo on this machine"
    );
}

#[test]
fn verify_fails_closed_when_pin_missing() {
    let (repo_temp, key_store, owner_pub) = setup_repo_with_owner_in_keyring();

    // A fresh clone arrives with trust.json + signed keyring committed but
    // NO per-machine pin: simulate that by deleting the pin this machine
    // wrote during cmd_trust.
    std::fs::remove_dir_all(key_store.join("trust-pins")).unwrap();

    std::fs::write(repo_temp.path().join("secret.env"), "s3cret").unwrap();
    cmd_add(repo_temp.path(), vec!["secret.env".to_string()]).expect("cmd_add must succeed");

    let hide_result = cmd_hide(repo_temp.path(), "origin", &key_store);
    let hide_err = hide_result
        .err()
        .expect("hide without a local pin must fail closed");
    let hide_msg = hide_err.to_string();
    assert!(
        hide_msg.contains("no local pin"),
        "hide must fail with the pin-missing message, got: {}",
        hide_msg
    );
    assert!(
        hide_msg.contains("repo+owner@github.com") && hide_msg.contains("(from remote 'origin')"),
        "the pin-missing message must name the repo_id and remote, got: {}",
        hide_msg
    );
    assert!(
        hide_msg.contains("git-veil trust"),
        "the pin-missing message must state the remedy, got: {}",
        hide_msg
    );

    let reveal_result = cmd_reveal(
        repo_temp.path(),
        "owner@github.com",
        "origin",
        &key_store,
        None,
    );
    let reveal_err = reveal_result
        .err()
        .expect("reveal without a local pin must fail closed");
    let reveal_msg = reveal_err.to_string();
    assert!(
        reveal_msg.contains("no local pin")
            && reveal_msg.contains("repo+owner@github.com")
            && reveal_msg.contains("(from remote 'origin')")
            && reveal_msg.contains("git-veil trust"),
        "reveal must fail with the pin-missing message naming repo_id, remote and remedy, got: {}",
        reveal_msg
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
        &key_store,
    )
    .expect("re-running cmd_trust must succeed");

    cmd_hide(repo_temp.path(), "origin", &key_store)
        .expect("hide must succeed once the pin is re-established");
    cmd_reveal(
        repo_temp.path(),
        "owner@github.com",
        "origin",
        &key_store,
        None,
    )
    .expect("reveal must succeed once the pin is re-established");
}

#[test]
fn verify_fails_closed_when_pin_mismatches() {
    let (repo_temp, key_store, owner_pub) = setup_repo_with_owner_in_keyring();
    let owner_fingerprint = extract_key_fingerprint(&owner_pub);

    // FULL ATTACK SIMULATION: the attacker's key already exists in the
    // victim's local key store (imported for an unrelated repo).
    let (attacker_sec, attacker_pub) = generate_test_key("attacker@evil.com");
    import_key_to_store(
        &key_store,
        &attacker_pub.to_armored_string(Default::default()).unwrap(),
    )
    .unwrap();
    let attacker_fingerprint = extract_key_fingerprint(&attacker_pub);

    // (a) rewrite the committed trust.json to map the repo's repo_id to the
    // attacker's fingerprint...
    let trust_path = repo_temp.path().join(".git-veil/trust.json");
    let mut tampered_trust = TrustStore::load_from_file(&trust_path).unwrap();
    tampered_trust.add_trust(
        "repo+owner@github.com".to_string(),
        attacker_fingerprint.clone(),
    );
    tampered_trust.save_to_file(&trust_path).unwrap();

    // ...and (b) ship a keyring validly signed by that key.
    let mut attacker_ring = Keyring {
        entries: vec![KeyringEntry {
            email: "attacker@evil.com".to_string(),
            base64_key: base64_encode_public_key(&attacker_pub)
                .expect("armouring the attacker key must succeed"),
            fingerprint: attacker_fingerprint.clone(),
        }],
        signature: None,
    };
    let serialized = attacker_ring.serialize();
    let content_to_sign = extract_content_to_verify_from_keyring(&serialized)
        .expect("freshly serialized keyring must contain the END marker");
    let signature = sign_keyring_content(&content_to_sign, &attacker_sec, None)
        .expect("the attacker must be able to sign their own keyring");
    attacker_ring.signature = Some(signature);
    let keyring_path = repo_temp.path().join(".git-veil/keyring");
    std::fs::write(&keyring_path, attacker_ring.serialize()).unwrap();
    let keyring_before = std::fs::read(&keyring_path).unwrap();

    let hide_result = cmd_hide(repo_temp.path(), "origin", &key_store);
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
        msg.contains("repo+owner@github.com") && msg.contains("(from remote 'origin')"),
        "the mismatch message must name the repo_id and the remote consulted, got: {}",
        msg
    );
    assert!(
        msg.contains("re-run git-veil trust"),
        "the mismatch message must state the remedy, got: {}",
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

#[test]
fn decrypt_failure_mentions_recipient_or_passphrase_causes() {
    let (repo_temp, key_store, _owner_pub) = setup_repo_with_owner_in_keyring();

    std::fs::write(repo_temp.path().join("secret.env"), "s3cret").unwrap();
    cmd_add(repo_temp.path(), vec!["secret.env".to_string()]).expect("cmd_add must succeed");
    cmd_hide(repo_temp.path(), "origin", &key_store).expect("cmd_hide must succeed");

    // Replace the owner's secret key with a DIFFERENT valid key that claims
    // the SAME email. The keyring entry still matches by email, the trust
    // pin still verifies, but this key was never a recipient of the
    // ciphertext — the exact case where wrong-recipient and wrong-passphrase
    // are indistinguishable at the decrypt layer.
    let wrong_key = generate_test_key("owner@github.com").0;
    write_multi_key_secret_keys(&key_store, &[wrong_key]);

    let result = cmd_reveal(
        repo_temp.path(),
        "owner@github.com",
        "origin",
        &key_store,
        None,
    );
    let err = result
        .err()
        .expect("decrypting owner ciphertext with a different key must fail");
    let msg = err.to_string();

    assert!(
        msg.contains("decryption failed"),
        "the failure must be the decryption error, got: {}",
        msg
    );
    assert!(
        msg.contains("not encrypted to your key 'owner@github.com'"),
        "the message must name the key email and the not-a-recipient cause, got: {}",
        msg
    );
    assert!(
        msg.contains("needs a passphrase"),
        "the message must mention the passphrase cause, got: {}",
        msg
    );
    assert!(
        msg.contains("GITVEIL_PASSPHRASE") && msg.contains("--passphrase-stdin"),
        "the message must point at the passphrase remedies, got: {}",
        msg
    );
}

#[test]
fn trust_error_names_remote_and_repo_id() {
    let repo_temp = setup_git_repo_with_origin_remote();
    cmd_init(repo_temp.path()).expect("cmd_init must succeed");

    // Remote exists, but no trust was ever established: the gated command
    // must name the remote consulted, the derived repo_id and the remedy.
    // The key store is never touched — the failure happens at the trust check.
    let home_temp = tempfile::tempdir().unwrap();
    let result = cmd_hide(repo_temp.path(), "origin", &home_temp.path().to_path_buf());
    let err = result
        .err()
        .expect("hide on an untrusted repo must fail closed");
    let msg = err.to_string();

    assert!(
        msg.contains("no trust established for repo+owner@github.com"),
        "the error must name the derived repo_id, got: {}",
        msg
    );
    assert!(
        msg.contains("(from remote 'origin')"),
        "the error must name the remote consulted, got: {}",
        msg
    );
    assert!(
        msg.contains("git-veil trust repo+owner@github.com <keyfile>"),
        "the error must state the trust remedy, got: {}",
        msg
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
/// owner key), and whose secret key store holds every secret key (owner + all
/// collaborators). Returns (repo_temp, key_store).
fn setup_repo_with_owner_and_collaborators(
    collaborator_emails: &[&str],
) -> (tempfile::TempDir, PathBuf) {
    let repo_temp = setup_git_repo_with_origin_remote();

    cmd_init(repo_temp.path()).expect("cmd_init must succeed");

    let (owner_sec, owner_pub) = generate_test_key("owner@github.com");
    let owner_keyfile = repo_temp.path().join("owner.pub");
    write_public_key_file(&owner_pub, &owner_keyfile);

    let key_store = repo_temp.path().join("key-store");

    cmd_trust(
        repo_temp.path(),
        "repo+owner@github.com",
        owner_keyfile.to_str().unwrap(),
        "origin",
        &key_store,
    )
    .expect("cmd_trust must succeed");

    // tell signs with the trusted owner key, so the owner's secret must be
    // in the secret key store before any tell runs.
    write_multi_key_secret_keys(&key_store, std::slice::from_ref(&owner_sec));

    cmd_tell(
        repo_temp.path(),
        "owner@github.com",
        owner_keyfile.to_str().unwrap(),
        "origin",
        &key_store,
        None,
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
            &key_store,
            None,
        )
        .unwrap_or_else(|e| panic!("cmd_tell must succeed for {}: {:?}", email, e));

        collaborator_secrets.push(sec);
    }

    // Replace the secret key store with one holding every secret key (owner + all
    // collaborators) so each participant can decrypt/verify locally.
    let mut secret_keys = vec![owner_sec];
    secret_keys.extend(collaborator_secrets);
    write_multi_key_secret_keys(&key_store, &secret_keys);

    (repo_temp, key_store)
}

#[test]
fn hide_encrypts_to_every_key_in_keyring() {
    let emails = ["alice@example.com", "bob@example.com", "carol@example.com"];
    let (repo_temp, key_store) = setup_repo_with_owner_and_collaborators(&emails);

    let plaintext: &str = "SHARED_SECRET=every-collaborator-can-reveal\n";
    std::fs::write(repo_temp.path().join("secret.env"), plaintext).unwrap();
    cmd_add(repo_temp.path(), vec!["secret.env".to_string()]).expect("cmd_add must succeed");

    cmd_hide(repo_temp.path(), "origin", &key_store).expect("cmd_hide must succeed");

    let ciphertext = std::fs::read_to_string(repo_temp.path().join("secret.env.secret"))
        .expect("hide must write the ciphertext beside the plaintext");

    for email in emails {
        let secret_key = find_private_key_by_email(&key_store, email)
            .unwrap_or_else(|e| panic!("secret key store must hold {}'s secret key: {}", email, e));
        let decrypted =
            decrypt_with_private_key(&ciphertext, &secret_key, None).unwrap_or_else(|e| {
                panic!(
                    "{} must be able to decrypt the shared ciphertext: {}",
                    email, e
                )
            });
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
    let (repo_temp, key_store) = setup_repo_with_owner_and_collaborators(&emails);

    let plaintext: &str = "ROUND_TRIP=per-collaborator-reveal\n";
    std::fs::write(repo_temp.path().join("secret.env"), plaintext).unwrap();
    cmd_add(repo_temp.path(), vec!["secret.env".to_string()]).expect("cmd_add must succeed");

    for email in emails {
        cmd_hide(repo_temp.path(), "origin", &key_store)
            .unwrap_or_else(|e| panic!("cmd_hide must succeed before {}'s reveal: {:?}", email, e));
        assert!(
            !repo_temp.path().join("secret.env").exists()
                && repo_temp.path().join("secret.env.secret").exists(),
            "hide must have replaced the plaintext with ciphertext beside it before {}'s reveal",
            email
        );

        cmd_reveal(repo_temp.path(), email, "origin", &key_store, None).unwrap_or_else(|e| {
            panic!(
                "{} must be able to cmd_reveal the hidden file: {:?}",
                email, e
            )
        });

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
    let (repo_temp, key_store) = setup_repo_with_owner_and_collaborators(&emails);

    let plaintext: &str = "REVOCATION=boot-the-removed-collaborator\n";
    std::fs::write(repo_temp.path().join("secret.env"), plaintext).unwrap();
    cmd_add(repo_temp.path(), vec!["secret.env".to_string()]).expect("cmd_add must succeed");

    // Before removal: ALL three collaborators decrypt the SAME ciphertext.
    cmd_hide(repo_temp.path(), "origin", &key_store).expect("first hide must succeed");
    let ciphertext_before = std::fs::read_to_string(repo_temp.path().join("secret.env.secret"))
        .expect("ciphertext must exist after the first hide");
    for email in emails {
        let secret_key = find_private_key_by_email(&key_store, email).unwrap();
        let decrypted = decrypt_with_private_key(&ciphertext_before, &secret_key, None)
            .unwrap_or_else(|e| panic!("before removal, {} must be able to decrypt: {}", email, e));
        assert_eq!(decrypted, plaintext.as_bytes());
    }

    // Revoke Bob, then re-hide (reveal as Alice restores the plaintext first).
    cmd_removeperson(
        repo_temp.path(),
        "bob@example.com",
        "origin",
        &key_store,
        None,
    )
    .expect("cmd_removeperson must succeed");
    cmd_reveal(
        repo_temp.path(),
        "alice@example.com",
        "origin",
        &key_store,
        None,
    )
    .expect("reveal as alice must restore the plaintext for the re-hide");
    cmd_hide(repo_temp.path(), "origin", &key_store).expect("re-hide after removal must succeed");
    let ciphertext_after = std::fs::read_to_string(repo_temp.path().join("secret.env.secret"))
        .expect("ciphertext must exist after the re-hide");

    // Bob's key must now FAIL against the new ciphertext.
    let bob_key = find_private_key_by_email(&key_store, "bob@example.com").unwrap();
    assert!(
        decrypt_with_private_key(&ciphertext_after, &bob_key, None).is_err(),
        "the removed collaborator must NOT be able to decrypt ciphertext written after their removal"
    );

    // Alice and Carol must still decrypt the new ciphertext.
    for email in ["alice@example.com", "carol@example.com"] {
        let secret_key = find_private_key_by_email(&key_store, email).unwrap();
        let decrypted = decrypt_with_private_key(&ciphertext_after, &secret_key, None)
            .unwrap_or_else(|e| {
                panic!(
                    "after removal, {} must still be able to decrypt: {}",
                    email, e
                )
            });
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
            name.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '%')),
            "sanitized name for {:?} must only use safe characters, got: {:?}",
            repo_id,
            name
        );
    }
}

// ============================================================================
// In-place ciphertext storage: hide writes <plaintext>.secret BESIDE the
// plaintext, not into a gitignored mirror tree. Written Red/Green: the old
// .git-veil/secrets/<path>/<name>.asc scheme fails every test below.
// ============================================================================

fn copy_dir_all(src: &std::path::Path, dst: &std::path::Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir_all(&entry.path(), &to);
        } else {
            std::fs::copy(entry.path(), &to).unwrap();
        }
    }
}

#[test]
fn hide_writes_ciphertext_next_to_plaintext() {
    let (repo_temp, key_store, _) = setup_repo_with_owner_in_keyring();

    let cases: Vec<(&str, &str)> = vec![
        ("sub/dir/secret.env", "NESTED=1\n"),
        (".env", "DOTENV=2\n"),
        ("notes", "extensionless\n"),
    ];
    for (name, bytes) in &cases {
        std::fs::create_dir_all(repo_temp.path().join(name).parent().unwrap()).unwrap();
        std::fs::write(repo_temp.path().join(name), bytes).unwrap();
        cmd_add(repo_temp.path(), vec![name.to_string()])
            .unwrap_or_else(|e| panic!("cmd_add must succeed for {}: {:?}", name, e));
    }

    let hide_result = cmd_hide(repo_temp.path(), "origin", &key_store);
    hide_result.expect("cmd_hide must succeed");

    for (name, _) in &cases {
        assert!(
            repo_temp.path().join(format!("{}.secret", name)).exists(),
            "hide must write the ciphertext beside the plaintext as {}.secret",
            name
        );
        assert!(
            !repo_temp.path().join(name).exists(),
            "hide must delete the plaintext {}",
            name
        );
    }
    assert!(
        !repo_temp.path().join(".git-veil/secrets").exists(),
        "hide must not create a mirror secrets tree"
    );
}

#[test]
fn reveal_restores_plaintext_and_removes_secret_file() {
    let (repo_temp, key_store, _) = setup_repo_with_owner_in_keyring();

    let plaintext = "INVERSE=exact-bytes-restored\n";
    std::fs::create_dir_all(repo_temp.path().join("sub/dir")).unwrap();
    let tracked_rel = "sub/dir/secret.env";
    std::fs::write(repo_temp.path().join(tracked_rel), plaintext).unwrap();
    cmd_add(repo_temp.path(), vec![tracked_rel.to_string()]).expect("cmd_add must succeed");
    cmd_hide(repo_temp.path(), "origin", &key_store).expect("cmd_hide must succeed");
    assert!(repo_temp
        .path()
        .join(format!("{}.secret", tracked_rel))
        .exists());

    let reveal_result = cmd_reveal(
        repo_temp.path(),
        "owner@github.com",
        "origin",
        &key_store,
        None,
    );
    reveal_result.expect("cmd_reveal must succeed");

    let restored = std::fs::read(repo_temp.path().join(tracked_rel))
        .expect("reveal must restore the plaintext at the original path");
    assert_eq!(
        restored,
        plaintext.as_bytes(),
        "reveal must restore the exact original bytes"
    );
    assert!(
        !repo_temp
            .path()
            .join(format!("{}.secret", tracked_rel))
            .exists(),
        "reveal must delete the .secret file"
    );
}

#[test]
fn fresh_clone_with_secrets_but_without_plaintext_reveals() {
    let (repo_temp, key_store, _) = setup_repo_with_owner_in_keyring();

    let plaintext = "FRESH_CLONE=decryptable-by-design\n";
    std::fs::write(repo_temp.path().join("secret.env"), plaintext).unwrap();
    cmd_add(repo_temp.path(), vec!["secret.env".to_string()]).expect("cmd_add must succeed");
    cmd_hide(repo_temp.path(), "origin", &key_store).expect("cmd_hide must succeed");

    // Simulate a clone: copy .git-veil/ and every .secret ciphertext into a
    // NEW directory, but not the plaintext (hide deleted it) and not the
    // key-store. Reveal runs with the SAME key_store, so the per-machine trust
    // pin is already present — the pin is keyed by the repo_id derived from
    // the origin URL, which the clone shares, so no re-run of cmd_trust is
    // needed (this is the documented "key-store already holds the pin" path).
    let clone = tempfile::tempdir().unwrap();
    for args in [
        vec!["init"],
        vec!["remote", "add", "origin", "git@github.com:owner/repo.git"],
    ] {
        let status = std::process::Command::new("git")
            .current_dir(clone.path())
            .args(&args)
            .status()
            .expect("run git");
        assert!(status.success(), "git {:?} failed", args);
    }
    copy_dir_all(
        &repo_temp.path().join(".git-veil"),
        &clone.path().join(".git-veil"),
    );
    std::fs::copy(
        repo_temp.path().join("secret.env.secret"),
        clone.path().join("secret.env.secret"),
    )
    .expect("clone must carry the committed .secret ciphertext");
    assert!(
        !clone.path().join("secret.env").exists(),
        "the clone must not contain the plaintext"
    );

    let reveal_result = cmd_reveal(clone.path(), "owner@github.com", "origin", &key_store, None);
    reveal_result.expect("reveal in a fresh clone holding only .secret files must succeed");

    let restored = std::fs::read(clone.path().join("secret.env"))
        .expect("reveal must restore the plaintext in the clone");
    assert_eq!(
        restored,
        plaintext.as_bytes(),
        "the fresh clone must be decryptable-by-design from the committed ciphertext alone"
    );
    assert!(
        !clone.path().join("secret.env.secret").exists(),
        "reveal in the clone must delete the .secret file"
    );
}

// ============================================================================
// Passphrase-protected private keys
//
// Written Red/Green: pre-fix, decrypt_with_private_key and sign_keyring_content
// hardcode an empty passphrase, so a passphrase-protected private key is
// unusable by this tool. These tests target the NEW signatures (with an
// Option<&str> passphrase), so their first failure was a compile error.
// ============================================================================

/// Sets up a trusted repo whose owner key is protected by the given
/// passphrase (secret key store holds the protected secret; trust + public-keys.pgp are
/// public-key-only, so no passphrase is needed to establish trust).
/// Returns (repo_temp, key_store, owner_keyfile_path).
fn setup_repo_with_protected_owner(passphrase: &str) -> (tempfile::TempDir, PathBuf, PathBuf) {
    let repo_temp = setup_git_repo_with_origin_remote();

    cmd_init(repo_temp.path()).expect("cmd_init must succeed");

    let (owner_sec, owner_pub) = generate_protected_test_key("owner@github.com", passphrase);
    let owner_keyfile = repo_temp.path().join("owner.pub");
    write_public_key_file(&owner_pub, &owner_keyfile);

    let key_store = repo_temp.path().join("key-store");

    cmd_trust(
        repo_temp.path(),
        "repo+owner@github.com",
        owner_keyfile.to_str().unwrap(),
        "origin",
        &key_store,
    )
    .expect("cmd_trust must succeed");

    write_multi_key_secret_keys(&key_store, &[owner_sec]);

    (repo_temp, key_store, owner_keyfile)
}

#[test]
fn protected_key_cannot_decrypt_with_empty_passphrase() {
    let (protected_sec, protected_pub) =
        generate_protected_test_key("protected@example.com", "correct horse");
    let plaintext = b"locked payload";
    let ciphertext = encrypt_to_public_key(plaintext, &protected_pub)
        .expect("encrypting to the public key must not need the passphrase");

    let result = decrypt_with_private_key(&ciphertext, &protected_sec, None);

    let Err(err) = result else {
        panic!("a passphrase-protected key must not decrypt with an empty passphrase");
    };
    let msg = err.to_string();
    assert!(
        msg.contains("passphrase"),
        "the failure must hint that a passphrase may be missing, got: {}",
        msg
    );

    // With the correct passphrase the same ciphertext decrypts.
    let decrypted = decrypt_with_private_key(&ciphertext, &protected_sec, Some("correct horse"))
        .expect("the correct passphrase must unlock the protected key");
    assert_eq!(
        decrypted, plaintext,
        "decryption with the correct passphrase must restore the exact bytes"
    );
}

#[test]
fn signing_with_protected_key_requires_passphrase() {
    let (repo_temp, key_store, owner_keyfile) = setup_repo_with_protected_owner("correct horse");
    let owner_key_path = owner_keyfile.to_str().unwrap();

    // No passphrase at all: signing the keyring must fail with a clear hint.
    let no_passphrase = cmd_tell(
        repo_temp.path(),
        "owner@github.com",
        owner_key_path,
        "origin",
        &key_store,
        None,
    );
    let Err(err) = no_passphrase else {
        panic!("tell with a passphrase-protected owner key must fail without the passphrase");
    };
    assert!(
        err.to_string().contains("passphrase"),
        "the failure must hint that a passphrase may be missing, got: {}",
        err
    );

    // Wrong passphrase: must fail too (exact-match semantics).
    let wrong_passphrase = cmd_tell(
        repo_temp.path(),
        "owner@github.com",
        owner_key_path,
        "origin",
        &key_store,
        Some("correct horse with typo"),
    );
    assert!(
        wrong_passphrase.is_err(),
        "tell with the WRONG passphrase must not sign the keyring"
    );

    // Correct passphrase: tell succeeds and the signature verifies.
    cmd_tell(
        repo_temp.path(),
        "owner@github.com",
        owner_key_path,
        "origin",
        &key_store,
        Some("correct horse"),
    )
    .expect("tell with the correct passphrase must succeed");

    cmd_verify_keyring(repo_temp.path(), "origin", &key_store)
        .expect("the keyring signature made with the correct passphrase must verify");
}

#[test]
fn protected_key_in_secret_key_store_is_findable_without_passphrase() {
    // Parsing a passphrase-protected key via SignedSecretKey::from_string
    // must keep working without the passphrase: finding a key by email never
    // unlocks it.
    let (protected_sec, _) = generate_protected_test_key("locked@example.com", "correct horse");
    let temp = tempfile::tempdir().unwrap();
    let key_store = temp.path().to_path_buf();
    write_multi_key_secret_keys(&key_store, &[protected_sec]);

    find_private_key_by_email(&key_store, "locked@example.com")
        .expect("a passphrase-protected key must be findable (parsed) without the passphrase");
}

// ============================================================================
// Unhide — inverse of hide for ONE file
//
// Written Red/Green: pre-fix cmd_unhide did not exist, so these tests failed
// to compile (unresolved import) against the unmodified source.
// ============================================================================

#[test]
fn unhide_restores_plaintext_and_removes_secret_for_one_file() {
    let (repo_temp, key_store, _owner_pub) = setup_repo_with_owner_in_keyring();

    std::fs::write(repo_temp.path().join("a.env"), "alpha secret").unwrap();
    std::fs::write(repo_temp.path().join("b.env"), "beta secret").unwrap();
    cmd_add(
        repo_temp.path(),
        vec!["a.env".to_string(), "b.env".to_string()],
    )
    .expect("cmd_add must succeed");
    cmd_hide(repo_temp.path(), "origin", &key_store).expect("cmd_hide must succeed");

    cmd_unhide(
        repo_temp.path(),
        "a.env",
        "owner@github.com",
        "origin",
        &key_store,
        None,
    )
    .expect("cmd_unhide must succeed for a tracked, hidden file");

    assert_eq!(
        std::fs::read(repo_temp.path().join("a.env")).expect("a.env must be restored"),
        b"alpha secret",
        "unhide must restore the plaintext byte-exact"
    );
    assert!(
        !repo_temp.path().join("a.env.secret").exists(),
        "unhide must delete the ciphertext of the unhidden file"
    );
    assert!(
        repo_temp.path().join("b.env.secret").exists(),
        "unhide must leave other tracked files hidden"
    );
    assert!(
        !repo_temp.path().join("b.env").exists(),
        "unhide must not reveal files it was not asked to unhide"
    );
}

#[test]
fn unhide_fails_for_untracked_file() {
    let (repo_temp, key_store, _owner_pub) = setup_repo_with_owner_in_keyring();

    std::fs::write(repo_temp.path().join("tracked.env"), "s3cret").unwrap();
    cmd_add(repo_temp.path(), vec!["tracked.env".to_string()]).expect("cmd_add must succeed");
    cmd_hide(repo_temp.path(), "origin", &key_store).expect("cmd_hide must succeed");

    let result = cmd_unhide(
        repo_temp.path(),
        "untracked.env",
        "owner@github.com",
        "origin",
        &key_store,
        None,
    );

    let err = result.expect_err("unhide of an untracked file must fail closed");
    assert!(
        err.to_string().contains("not tracked"),
        "the failure must name the untracked path, got: {}",
        err
    );
    assert!(
        repo_temp.path().join("tracked.env.secret").exists(),
        "a failed unhide must leave the ciphertext intact"
    );
}

#[test]
fn unhide_fails_when_secret_missing() {
    let (repo_temp, key_store, _owner_pub) = setup_repo_with_owner_in_keyring();

    std::fs::write(repo_temp.path().join("tracked.env"), "s3cret").unwrap();
    cmd_add(repo_temp.path(), vec!["tracked.env".to_string()]).expect("cmd_add must succeed");
    cmd_hide(repo_temp.path(), "origin", &key_store).expect("cmd_hide must succeed");
    std::fs::remove_file(repo_temp.path().join("tracked.env.secret")).unwrap();

    let result = cmd_unhide(
        repo_temp.path(),
        "tracked.env",
        "owner@github.com",
        "origin",
        &key_store,
        None,
    );

    let err = result.expect_err("unhide without the ciphertext must fail");
    assert!(
        err.to_string().contains("Encrypted file not found"),
        "the failure must name the missing ciphertext, got: {}",
        err
    );
}

#[test]
fn base64_encode_public_key_round_trips_through_decode() {
    let (_secret, public_key) = generate_test_key("roundtrip@example.com");

    let encoded = base64_encode_public_key(&public_key)
        .expect("armouring a freshly generated key must never silently degrade to an empty blob");
    assert!(
        !encoded.is_empty(),
        "the encoded keyring entry must not be an empty blob"
    );

    let decoded = base64_decode_public_key(&encoded)
        .expect("the encoded keyring entry must decode back to a parseable key");
    assert_eq!(
        extract_key_fingerprint(&public_key),
        extract_key_fingerprint(&decoded),
        "the keyring entry must carry the real key, not an empty blob"
    );
}

// ============================================================================
// Key-validity policy: expired / revoked / unsigned keys are rejected at the
// trust, tell and hide gates (fail-closed, naming the offending key)
// ============================================================================

use git_veil::{validate_public_key_for_use, KeyUse};
use pgp::composed::{SignedKeyDetails, SignedPublicKey};
use pgp::packet::{
    KeyFlags, RevocationCode, SignatureConfig, SignatureType, Subpacket, SubpacketData,
};
use pgp::types::{KeyDetails as _, Password, SignedUser, Tag, Timestamp};

const DAY_SECS: u64 = 86_400;

/// Builds a public key identical to the freshly generated one, except the
/// self-certification over the User ID is re-created with a BACKDATED
/// creation time and a KeyExpirationTime of 30 days — i.e. the key expired
/// 60 days ago. The SecretKeyParamsBuilder in pgp 0.19 has no expiration
/// field, so the signature packet is hand-built and re-signed with the same
/// secret key (cryptographically valid, just past its expiry).
fn expired_public_key(
    email: &str,
) -> (
    pgp::composed::SignedSecretKey,
    pgp::composed::SignedPublicKey,
) {
    let (secret, public) = generate_test_key(email);
    let mut rng = thread_rng();
    let primary = secret.primary_key.public_key().clone();

    let now = Timestamp::now().as_secs() as u64;
    let created = now - 90 * DAY_SECS;
    let mut key_flags = KeyFlags::default();
    key_flags.set_certify(true);
    key_flags.set_sign(true);

    let user_id = public.details.users[0].id.clone();
    let mut config =
        SignatureConfig::from_key(&mut rng, &secret.primary_key, SignatureType::CertPositive)
            .expect("build signature config");
    config.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::from_secs(
            created as u32,
        )))
        .expect("creation time subpacket"),
        Subpacket::regular(SubpacketData::IssuerFingerprint(
            secret.primary_key.fingerprint(),
        ))
        .expect("issuer fingerprint subpacket"),
        Subpacket::regular(SubpacketData::KeyFlags(key_flags)).expect("key flags subpacket"),
        Subpacket::regular(SubpacketData::IsPrimary(true)).expect("is-primary subpacket"),
        Subpacket::regular(SubpacketData::KeyExpirationTime(
            pgp::types::Duration::from_secs((30 * DAY_SECS) as u32),
        ))
        .expect("key expiration subpacket"),
    ];
    let sig = config
        .sign_certification(
            &secret.primary_key,
            &primary,
            &Password::empty(),
            Tag::UserId,
            &user_id,
        )
        .expect("sign backdated certification");

    let details = SignedKeyDetails::new(
        vec![],
        vec![],
        vec![SignedUser::new(user_id, vec![sig])],
        vec![],
    );
    let expired = SignedPublicKey::new(primary, details, public.public_subkeys);
    (secret, expired)
}

/// Builds a public key identical to the freshly generated one, except a
/// hard (KeyCompromised) KeyRevocation self-signature over the primary key
/// has been added. The crate has no high-level "revoke this key" API, so the
/// revocation signature packet is hand-built and signed with the same secret
/// key.
fn revoked_public_key(
    email: &str,
    reason: RevocationCode,
) -> (
    pgp::composed::SignedSecretKey,
    pgp::composed::SignedPublicKey,
) {
    let (secret, public) = generate_test_key(email);
    let mut rng = thread_rng();
    let primary = secret.primary_key.public_key().clone();

    let mut config =
        SignatureConfig::from_key(&mut rng, &secret.primary_key, SignatureType::KeyRevocation)
            .expect("build revocation config");
    config.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now()))
            .expect("creation time subpacket"),
        Subpacket::regular(SubpacketData::IssuerFingerprint(
            secret.primary_key.fingerprint(),
        ))
        .expect("issuer fingerprint subpacket"),
        Subpacket::regular(SubpacketData::RevocationReason(
            reason,
            b"compromised".to_vec().into(),
        ))
        .expect("revocation reason subpacket"),
    ];
    let sig = config
        .sign_key(&secret.primary_key, &Password::empty(), &primary)
        .expect("sign revocation");

    let details = SignedKeyDetails::new(
        vec![sig],
        public.details.direct_signatures.clone(),
        public.details.users.clone(),
        public.details.user_attributes.clone(),
    );
    let revoked = SignedPublicKey::new(primary, details, public.public_subkeys);
    (secret, revoked)
}

#[test]
fn expired_key_is_rejected_by_trust() {
    let repo_temp = setup_git_repo_with_origin_remote();

    cmd_init(repo_temp.path()).expect("cmd_init must succeed");

    let (_sec, expired_pub) = expired_public_key("owner@github.com");
    let fingerprint = extract_key_fingerprint(&expired_pub);
    let keyfile = repo_temp.path().join("owner.pub");
    write_public_key_file(&expired_pub, &keyfile);

    let store_temp = tempfile::tempdir().unwrap();

    let result = cmd_trust(
        repo_temp.path(),
        "repo+owner@github.com",
        keyfile.to_str().unwrap(),
        "origin",
        &store_temp.path().to_path_buf(),
    );

    let err = result.err().expect("expired key must not be trusted");
    assert!(
        err.to_string().contains("expired"),
        "the failure must name the expiry, got: {}",
        err
    );
    assert!(
        err.to_string().contains(&fingerprint),
        "the failure must name the key fingerprint, got: {}",
        err
    );
    assert!(
        !std::fs::read_to_string(repo_temp.path().join(".git-veil/trust.json"))
            .unwrap_or_default()
            .contains(&fingerprint),
        "trust store must not record the rejected key"
    );
    assert!(
        !TrustPinStore::pin_path(store_temp.path(), "repo+owner@github.com").exists(),
        "no local trust pin may be written for a rejected key"
    );
}

#[test]
fn revoked_key_is_rejected_by_tell() {
    let (repo_temp, key_store) = setup_trusted_repo_with_secret_keys(&[]);

    let (_sec, revoked_pub) = revoked_public_key("bob@example.com", RevocationCode::KeyCompromised);
    let fingerprint = extract_key_fingerprint(&revoked_pub);
    let bob_keyfile = repo_temp.path().join("bob.pub");
    write_public_key_file(&revoked_pub, &bob_keyfile);

    let result = cmd_tell(
        repo_temp.path(),
        "bob@example.com",
        bob_keyfile.to_str().unwrap(),
        "origin",
        &key_store,
        None,
    );

    let err = result.err().expect("revoked key must not be told");
    assert!(
        err.to_string().contains("revoked"),
        "the failure must name the revocation, got: {}",
        err
    );
    assert!(
        err.to_string().contains(&fingerprint),
        "the failure must name the key fingerprint, got: {}",
        err
    );

    let keyring_text = std::fs::read_to_string(repo_temp.path().join(".git-veil/keyring")).unwrap();
    let keyring = Keyring::parse(&keyring_text).unwrap();
    assert!(
        keyring.entries.iter().all(|e| e.email != "bob@example.com"),
        "the keyring must be untouched by a rejected key, got: {:?}",
        keyring.entries
    );
}

#[test]
fn hide_fails_closed_naming_invalid_keyring_entry() {
    let (owner_sec, owner_pub) = generate_test_key("owner@github.com");
    let (alice_sec, alice_pub) = generate_test_key("alice@example.com");
    let (_bob_sec, bob_pub) = expired_public_key("bob@example.com");
    let bob_fingerprint = extract_key_fingerprint(&bob_pub);

    let repo_temp = setup_git_repo_with_origin_remote();
    cmd_init(repo_temp.path()).expect("cmd_init must succeed");

    let owner_keyfile = repo_temp.path().join("owner.pub");
    write_public_key_file(&owner_pub, &owner_keyfile);
    let key_store = repo_temp.path().join("key-store");

    cmd_trust(
        repo_temp.path(),
        "repo+owner@github.com",
        owner_keyfile.to_str().unwrap(),
        "origin",
        &key_store,
    )
    .expect("cmd_trust must succeed");

    write_multi_key_secret_keys(&key_store, &[owner_sec.clone(), alice_sec]);

    // Craft a SIGNED keyring containing the valid alice entry plus the
    // expired bob entry (as a stolen/colluding keyring commit would).
    let mut keyring = Keyring::parse(
        &std::fs::read_to_string(repo_temp.path().join(".git-veil/keyring")).unwrap(),
    )
    .unwrap();
    keyring
        .add_entry(
            "alice@example.com".to_string(),
            base64_encode_public_key(&alice_pub).unwrap(),
            extract_key_fingerprint(&alice_pub),
        )
        .unwrap();
    keyring
        .add_entry(
            "bob@example.com".to_string(),
            base64_encode_public_key(&bob_pub).unwrap(),
            bob_fingerprint.clone(),
        )
        .unwrap();
    let content =
        extract_content_to_verify_from_keyring(&keyring.serialize()).expect("extract content");
    keyring.signature =
        Some(sign_keyring_content(&content, &owner_sec, None).expect("sign keyring"));
    std::fs::write(
        repo_temp.path().join(".git-veil/keyring"),
        keyring.serialize(),
    )
    .unwrap();

    let plaintext = "API_KEY=s3cr3t-value\n";
    std::fs::write(repo_temp.path().join("secret.env"), plaintext).unwrap();
    cmd_add(repo_temp.path(), vec!["secret.env".to_string()]).expect("cmd_add must succeed");

    let hide_result = cmd_hide(repo_temp.path(), "origin", &key_store);

    let err = hide_result
        .err()
        .expect("hide must fail closed with an invalid keyring entry");
    let err_str = err.to_string();
    assert!(
        err_str.contains("bob@example.com") || err_str.contains(&bob_fingerprint),
        "the failure must name the invalid keyring entry, got: {}",
        err_str
    );
    let chain = format!("{:#}", err);
    assert!(
        chain.contains("expired"),
        "the failure must name the underlying cause, got: {}",
        chain
    );
    assert!(
        !repo_temp.path().join("secret.env.secret").exists(),
        "no ciphertext may be written when any keyring key is invalid"
    );
    assert!(
        repo_temp.path().join("secret.env").exists(),
        "hide must fail before touching any tracked plaintext"
    );
}

#[test]
fn valid_keys_still_pass_all_gates() {
    let (alice_sec, alice_pub) = generate_test_key("alice@example.com");
    let (repo_temp, key_store) = setup_trusted_repo_with_secret_keys(&[alice_sec]);

    let alice_keyfile = repo_temp.path().join("alice.pub");
    write_public_key_file(&alice_pub, &alice_keyfile);

    cmd_tell(
        repo_temp.path(),
        "alice@example.com",
        alice_keyfile.to_str().unwrap(),
        "origin",
        &key_store,
        None,
    )
    .expect("cmd_tell must succeed with a valid key");

    std::fs::write(repo_temp.path().join("secret.env"), "API_KEY=s3cr3t\n").unwrap();
    cmd_add(repo_temp.path(), vec!["secret.env".to_string()]).expect("cmd_add must succeed");

    cmd_hide(repo_temp.path(), "origin", &key_store).expect("cmd_hide must succeed");
    assert!(
        repo_temp.path().join("secret.env.secret").exists(),
        "hide must produce ciphertext for valid keys"
    );

    cmd_reveal(
        repo_temp.path(),
        "alice@example.com",
        "origin",
        &key_store,
        None,
    )
    .expect("cmd_reveal must succeed");
    assert_eq!(
        std::fs::read_to_string(repo_temp.path().join("secret.env")).unwrap(),
        "API_KEY=s3cr3t\n",
        "reveal must restore the exact plaintext"
    );
}

// ============================================================================
// Direct unit tests of validate_public_key_for_use for cases the key
// generator cannot express
// ============================================================================

#[test]
fn validate_rejects_key_without_self_signature() {
    let (_sec, public) = generate_test_key("unsigned@example.com");
    let unsigned = SignedPublicKey::new(
        public.primary_key.clone(),
        SignedKeyDetails::new(vec![], vec![], vec![], vec![]),
        public.public_subkeys.clone(),
    );

    for use_for in [KeyUse::Certify, KeyUse::Encrypt] {
        let err = validate_public_key_for_use(&unsigned, use_for)
            .expect_err("an unsigned key must be rejected");
        assert!(
            err.to_string().contains("no self-signature"),
            "the failure must name the missing self-signature, got: {}",
            err
        );
    }
}

#[test]
fn validate_rejects_hard_revocation_but_allows_soft() {
    // Hard: KeyCompromised → reject.
    let (_sec, hard) = revoked_public_key("hard@example.com", RevocationCode::KeyCompromised);
    let err = validate_public_key_for_use(&hard, KeyUse::Certify)
        .expect_err("a compromised (hard) revocation must be rejected");
    assert!(
        err.to_string().contains("revoked"),
        "the failure must name the revocation, got: {}",
        err
    );

    // No reason subpacket → unconditional hard revocation → reject.
    let (reasonless, _) = {
        let (secret, public) = generate_test_key("noreason@example.com");
        let mut rng = thread_rng();
        let primary = secret.primary_key.public_key().clone();
        let mut config =
            SignatureConfig::from_key(&mut rng, &secret.primary_key, SignatureType::KeyRevocation)
                .unwrap();
        config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now())).unwrap(),
            Subpacket::regular(SubpacketData::IssuerFingerprint(
                secret.primary_key.fingerprint(),
            ))
            .unwrap(),
        ];
        let sig = config
            .sign_key(&secret.primary_key, &Password::empty(), &primary)
            .unwrap();
        let details = SignedKeyDetails::new(
            vec![sig],
            public.details.direct_signatures.clone(),
            public.details.users.clone(),
            public.details.user_attributes.clone(),
        );
        (
            SignedPublicKey::new(primary, details, public.public_subkeys),
            (),
        )
    };
    assert!(
        validate_public_key_for_use(&reasonless, KeyUse::Certify).is_err(),
        "a reason-less revocation is a hard revocation and must be rejected"
    );

    // Soft: KeySuperseded → the key is deprecated, not invalid → allow.
    let (_sec, soft) = revoked_public_key("soft@example.com", RevocationCode::KeySuperseded);
    validate_public_key_for_use(&soft, KeyUse::Certify)
        .expect("a superseded (soft) revocation must NOT reject the key");
}

#[test]
fn validate_certify_mode_allows_signing_only_key_but_encrypt_mode_rejects_it() {
    let mut rng = thread_rng();
    let params = SecretKeyParamsBuilder::default()
        .key_type(KeyType::Ed25519)
        .can_certify(true)
        .can_sign(true)
        .primary_user_id("Signing Only <signonly@example.com>".to_string())
        .passphrase(None)
        .build()
        .expect("build key params");
    let secret = params.generate(&mut rng).expect("generate key");
    let public = secret.to_public_key();

    validate_public_key_for_use(&public, KeyUse::Certify)
        .expect("a signing-only owner key is legitimate for certify use");

    let err = validate_public_key_for_use(&public, KeyUse::Encrypt)
        .expect_err("a signing-only key must not be accepted for encryption use");
    assert!(
        err.to_string().contains("encryption-capable subkey"),
        "the failure must name the missing encryption subkey, got: {}",
        err
    );
}

#[test]
fn validate_rejects_expired_key_naming_expiry_and_fingerprint() {
    let (_sec, expired) = expired_public_key("expired-unit@example.com");
    let fingerprint = extract_key_fingerprint(&expired);

    let err = validate_public_key_for_use(&expired, KeyUse::Certify)
        .expect_err("an expired key must be rejected");
    let err_str = err.to_string();
    assert!(
        err_str.contains("expired"),
        "the failure must name the expiry, got: {}",
        err_str
    );
    assert!(
        err_str.contains(&fingerprint),
        "the failure must name the key fingerprint, got: {}",
        err_str
    );

    let err = validate_public_key_for_use(&expired, KeyUse::Encrypt)
        .expect_err("an expired key must also be rejected for encryption use");
    assert!(
        err.to_string().contains("expired"),
        "the failure must name the expiry, got: {}",
        err
    );
}

// ============================================================================
// Atomic writes (ETHOS finding: "Non-atomic writes everywhere")
// ============================================================================

/// Asserts that `dir` contains no leftover `*.tmp-*` temp files.
fn assert_no_temp_files(dir: &std::path::Path, context: &str) {
    let leftovers: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("{}: cannot read directory: {}", context, e))
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .map(|n| n.to_string_lossy().contains(".tmp-"))
                .unwrap_or(false)
        })
        .collect();
    assert!(
        leftovers.is_empty(),
        "{}: temp files were left behind: {:?}",
        context,
        leftovers
    );
}

#[test]
fn write_atomic_replaces_target_and_leaves_no_temp_files() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("state.json");

    write_atomic(&target, b"first").expect("first atomic write must succeed");
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "first");

    write_atomic(&target, b"second-and-longer").expect("second atomic write must succeed");
    assert_eq!(
        std::fs::read_to_string(&target).unwrap(),
        "second-and-longer",
        "the target must hold exactly the SECOND write's bytes"
    );

    assert_no_temp_files(temp.path(), "after two successful writes");
}

#[test]
fn write_atomic_failure_leaves_original_intact() {
    let temp = tempfile::tempdir().unwrap();

    // Phase 1 (portable): rename file-over-directory fails. The target is
    // a DIRECTORY, so temp creation succeeds but the final rename cannot
    // — write_atomic must return Err and leave an unrelated original file
    // untouched.
    std::fs::create_dir(temp.path().join("target")).unwrap();
    let original = temp.path().join("original");
    std::fs::write(&original, "original-content").unwrap();

    let result = write_atomic(&temp.path().join("target"), b"new-content");
    assert!(
        result.is_err(),
        "renaming a file over a directory must fail"
    );

    assert_eq!(
        std::fs::read_to_string(&original).unwrap(),
        "original-content",
        "the original file must be untouched after a failed write"
    );
    assert_no_temp_files(temp.path(), "after rename-failure");

    // Phase 2 (unix): the parent directory is read-only, so even temp-file
    // creation fails. The original target file must survive byte-for-byte.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let ro_dir = temp.path().join("ro");
        std::fs::create_dir(&ro_dir).unwrap();
        let original_in_ro = ro_dir.join("original");
        std::fs::write(&original_in_ro, "original-content").unwrap();

        std::fs::set_permissions(&ro_dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        let result = write_atomic(&original_in_ro, b"overwritten");
        std::fs::set_permissions(&ro_dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert!(
            result.is_err(),
            "writing through a read-only directory must fail"
        );
        assert_eq!(
            std::fs::read_to_string(&original_in_ro).unwrap(),
            "original-content",
            "the original must survive intact when the temp write cannot start"
        );
        assert_no_temp_files(&ro_dir, "after temp-creation failure");
    }

    // Honest scope note: the rename syscall itself is atomic in the kernel,
    // so "torn mid-rename" cannot be simulated from userspace — these
    // phases pin the helper's error contract (Err, no temp residue,
    // original untouched); the torn-write guarantee rests on rename's
    // atomicity, which both phases exercise at their respective edges.
}

#[test]
fn atomic_store_write_survives_simulated_tear() {
    let repo_temp = tempfile::tempdir().unwrap();
    let store_temp = tempfile::tempdir().unwrap();
    let key_store = store_temp.path().to_path_buf();
    let store_path = key_store.join("secret-keys.pgp");

    let (alice_secret, alice_pub) = generate_test_key("alice@example.com");
    let (bob_secret, bob_pub) = generate_test_key("bob@example.com");
    let alice_fp = extract_key_fingerprint(&alice_pub);
    let bob_fp = extract_key_fingerprint(&bob_pub);

    // First import: store does not exist yet, atomic create.
    let key_file_a = repo_temp.path().join("alice.asc");
    std::fs::write(
        &key_file_a,
        alice_secret.to_armored_string(Default::default()).unwrap(),
    )
    .unwrap();
    cmd_import(repo_temp.path(), &["alice.asc".to_string()], &key_store)
        .expect("first import must succeed");

    // Second import: the APPEND path — cmd_import reads the existing
    // store and writes the whole accumulated content through the same
    // atomic write hide/import use. This is the write that a torn
    // plain fs::write would brick (fail-closed: no private keys at all).
    let key_file_b = repo_temp.path().join("bob.asc");
    std::fs::write(
        &key_file_b,
        bob_secret.to_armored_string(Default::default()).unwrap(),
    )
    .unwrap();
    cmd_import(repo_temp.path(), &["bob.asc".to_string()], &key_store)
        .expect("second (append) import must succeed");

    // The final store must parse and contain BOTH keys.
    assert_eq!(
        std::fs::read_to_string(&store_path)
            .expect("store must exist")
            .trim()
            .lines()
            .filter(|l| l.contains("BEGIN PGP PRIVATE KEY BLOCK"))
            .count(),
        2,
        "the store must contain exactly two private key blocks after the append"
    );
    find_private_key_by_fingerprint(&key_store, &alice_fp)
        .expect("alice's key must parse out of the appended store");
    find_private_key_by_fingerprint(&key_store, &bob_fp)
        .expect("bob's key must parse out of the appended store");

    assert_no_temp_files(&key_store, "after the append through the atomic path");
}

// ============================================================================
// export: armoured public key handoff with no external tool involved
// ============================================================================

/// Imports a secret key into the key store via cmd_import — the way a
/// collaborator's machine normally ends up knowing its own key.
fn import_secret_key(
    repo_root: &std::path::Path,
    key_store: &PathBuf,
    secret_key: &pgp::composed::SignedSecretKey,
    file_name: &str,
) {
    let key_file = repo_root.join(file_name);
    std::fs::write(
        &key_file,
        secret_key.to_armored_string(Default::default()).unwrap(),
    )
    .expect("write armoured private key file");
    cmd_import(repo_root, &[file_name.to_string()], key_store).expect("cmd_import must succeed");
}

#[test]
fn export_writes_armoured_public_key_by_email() {
    let temp = tempfile::tempdir().unwrap();
    let key_store = temp.path().join("key-store");
    let (alice_sec, alice_pub) = generate_test_key("alice@example.com");
    let alice_fingerprint = extract_key_fingerprint(&alice_pub);
    import_secret_key(temp.path(), &key_store, &alice_sec, "alice-priv.asc");

    let armored =
        export_public_key(&key_store, "alice@example.com").expect("export by email must succeed");

    assert!(
        armored.contains("BEGIN PGP PUBLIC KEY BLOCK"),
        "exported text must be an armoured public key block, got: {}",
        armored
    );
    let reparsed =
        parse_armored_public_key(&armored).expect("exported armour must re-parse as a public key");
    assert_eq!(
        extract_key_fingerprint(&reparsed),
        alice_fingerprint,
        "the re-parsed key must have the SAME fingerprint as the imported key"
    );
}

#[test]
fn export_writes_to_output_file_atomically() {
    let temp = tempfile::tempdir().unwrap();
    let key_store = temp.path().join("key-store");
    let (alice_sec, _) = generate_test_key("alice@example.com");
    import_secret_key(temp.path(), &key_store, &alice_sec, "alice-priv.asc");

    let stdout_variant = export_public_key(&key_store, "alice@example.com")
        .expect("stdout-variant export must succeed");

    let out_path = temp.path().join("alice.pub");
    cmd_export(&key_store, "alice@example.com", Some(out_path.as_path()))
        .expect("export to an output file must succeed");

    let file_content =
        std::fs::read_to_string(&out_path).expect("output file must exist after export");
    assert_eq!(
        file_content, stdout_variant,
        "the file variant must carry content identical to the stdout variant"
    );

    let residue: Vec<String> = std::fs::read_dir(temp.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".tmp-"))
        .collect();
    assert!(
        residue.is_empty(),
        "no .tmp-* residue may remain after an atomic export, found: {:?}",
        residue
    );
}

#[test]
fn export_errors_for_unknown_identifier() {
    let temp = tempfile::tempdir().unwrap();
    let key_store = temp.path().join("key-store");
    let (alice_sec, _) = generate_test_key("alice@example.com");
    import_secret_key(temp.path(), &key_store, &alice_sec, "alice-priv.asc");

    let result = export_public_key(&key_store, "carol@example.com");

    let err = result
        .err()
        .expect("an unknown identifier must not export any key");
    assert!(
        err.to_string().contains("carol@example.com"),
        "the error must name the identifier, got: {}",
        err
    );
    assert!(
        err.to_string().contains("public-keys.pgp"),
        "the error must name the key store path, got: {}",
        err
    );
}

#[test]
fn export_errors_for_ambiguous_email() {
    let temp = tempfile::tempdir().unwrap();
    let key_store = temp.path().join("key-store");
    // Two DIFFERENT keys sharing one email (both UIDs "Test User <carol@…>"):
    // importing both puts two same-email keys in the store.
    let (carol_first, carol_first_pub) = generate_test_key("carol@example.com");
    let (carol_second, carol_second_pub) = generate_test_key("carol@example.com");
    let first_fingerprint = extract_key_fingerprint(&carol_first_pub);
    let second_fingerprint = extract_key_fingerprint(&carol_second_pub);
    import_secret_key(temp.path(), &key_store, &carol_first, "carol1-priv.asc");
    import_secret_key(temp.path(), &key_store, &carol_second, "carol2-priv.asc");

    let result = export_public_key(&key_store, "carol@example.com");

    let err = result
        .err()
        .expect("an ambiguous email must not silently export one of several keys");
    assert!(
        err.to_string().contains(first_fingerprint.as_str())
            && err.to_string().contains(second_fingerprint.as_str()),
        "the ambiguity error must list BOTH matching fingerprints, got: {}",
        err
    );
}

#[test]
fn export_never_emits_private_key_material() {
    let temp = tempfile::tempdir().unwrap();
    let key_store = temp.path().join("key-store");
    let (alice_sec, _) = generate_test_key("alice@example.com");
    import_secret_key(temp.path(), &key_store, &alice_sec, "alice-priv.asc");

    let armored = export_public_key(&key_store, "alice@example.com")
        .expect("export from a store holding the private key must still succeed");

    assert!(
        !armored.contains("PRIVATE KEY BLOCK"),
        "export must never emit private key material, got: {}",
        armored
    );
}

#[test]
fn export_by_fingerprint_selects_the_exact_key() {
    let temp = tempfile::tempdir().unwrap();
    let key_store = temp.path().join("key-store");
    let (alice_sec, _) = generate_test_key("alice@example.com");
    let (bob_sec, bob_pub) = generate_test_key("bob@example.com");
    let bob_fingerprint = extract_key_fingerprint(&bob_pub);
    import_secret_key(temp.path(), &key_store, &alice_sec, "alice-priv.asc");
    import_secret_key(temp.path(), &key_store, &bob_sec, "bob-priv.asc");

    let armored = export_public_key(&key_store, &bob_fingerprint)
        .expect("export by fingerprint must succeed");

    let reparsed = parse_armored_public_key(&armored).expect("exported armour must re-parse");
    assert_eq!(
        extract_key_fingerprint(&reparsed),
        bob_fingerprint,
        "export by fingerprint must return bob's key, not another key from the store"
    );
}

// ============================================================================
// removekey: remove a key from the local key store (destructive, local-only)
// ============================================================================

/// Writes the given public keys as the armoured public-keys.pgp store,
/// mirroring the format import_key_to_store accumulates.
fn write_public_keys_store(key_store: &PathBuf, keys: &[&pgp::composed::SignedPublicKey]) {
    std::fs::create_dir_all(key_store).unwrap();
    let mut content = String::new();
    for key in keys {
        content.push_str(&key.to_armored_string(Default::default()).unwrap());
        content.push('\n');
    }
    std::fs::write(key_store.join("public-keys.pgp"), content).unwrap();
}

/// Splits an armoured key store file into its blocks and returns each
/// block key's fingerprint — the test-side twin of the store splitters.
fn fingerprints_in_store(key_store: &PathBuf, file: &str, private: bool) -> Vec<String> {
    use pgp::composed::Deserializable;

    let content =
        std::fs::read_to_string(key_store.join(file)).expect("store file must exist to be read");
    let (begin, end_marker) = if private {
        (
            "-----BEGIN PGP PRIVATE KEY BLOCK-----",
            "-----END PGP PRIVATE KEY BLOCK-----",
        )
    } else {
        (
            "-----BEGIN PGP PUBLIC KEY BLOCK-----",
            "-----END PGP PUBLIC KEY BLOCK-----",
        )
    };
    let mut fps = Vec::new();
    let mut rest = content.as_str();
    while let Some(start) = rest.find(begin) {
        let after = &rest[start..];
        let end = after
            .find(end_marker)
            .expect("test helper needs complete blocks")
            + end_marker.len();
        let block = &after[..end];
        if private {
            let (key, _) = pgp::composed::SignedSecretKey::from_string(block).unwrap();
            fps.push(extract_key_fingerprint(&key.to_public_key()));
        } else {
            let (key, _) = pgp::composed::SignedPublicKey::from_string(block).unwrap();
            fps.push(extract_key_fingerprint(&key));
        }
        rest = &after[end..];
    }
    fps
}

#[test]
fn removekey_drops_only_matching_blocks() {
    let temp = tempfile::tempdir().unwrap();
    let key_store = temp.path().join("key-store");
    let (alice_sec, alice_pub) = generate_test_key("alice@example.com");
    let (bob_sec, bob_pub) = generate_test_key("bob@example.com");
    let alice_fingerprint = extract_key_fingerprint(&alice_pub);
    let bob_fingerprint = extract_key_fingerprint(&bob_pub);
    import_secret_key(temp.path(), &key_store, &alice_sec, "alice-priv.asc");
    import_secret_key(temp.path(), &key_store, &bob_sec, "bob-priv.asc");
    write_public_keys_store(&key_store, &[&alice_pub, &bob_pub]);

    cmd_removekey(&key_store, &bob_fingerprint, false)
        .expect("removekey by fingerprint must succeed");

    let secret_fps = fingerprints_in_store(&key_store, "secret-keys.pgp", true);
    assert!(
        secret_fps.contains(&alice_fingerprint),
        "secret-keys.pgp must retain alice's key after removing bob, got: {:?}",
        secret_fps
    );
    assert!(
        !secret_fps.contains(&bob_fingerprint),
        "secret-keys.pgp must drop bob's key, got: {:?}",
        secret_fps
    );
    let public_fps = fingerprints_in_store(&key_store, "public-keys.pgp", false);
    assert!(
        public_fps.contains(&alice_fingerprint) && !public_fps.contains(&bob_fingerprint),
        "public-keys.pgp must retain alice and drop bob, got: {:?}",
        public_fps
    );

    let alice = find_private_key_by_email(&key_store, "alice@example.com")
        .expect("the retained key must still parse out of the store and be findable");
    assert_eq!(
        extract_key_fingerprint(&alice.to_public_key()),
        alice_fingerprint,
        "the retained key must be alice's key"
    );

    assert_no_temp_files(&key_store, "after removekey");
}

#[test]
fn removekey_by_email_removes_case_insensitively() {
    let temp = tempfile::tempdir().unwrap();
    let key_store = temp.path().join("key-store");
    let (alice_sec, alice_pub) = generate_test_key("alice@example.com");
    let (bob_sec, bob_pub) = generate_test_key("bob@example.com");
    let alice_fingerprint = extract_key_fingerprint(&alice_pub);
    let bob_fingerprint = extract_key_fingerprint(&bob_pub);
    import_secret_key(temp.path(), &key_store, &alice_sec, "alice-priv.asc");
    import_secret_key(temp.path(), &key_store, &bob_sec, "bob-priv.asc");
    write_public_keys_store(&key_store, &[&alice_pub, &bob_pub]);

    cmd_removekey(&key_store, "BOB@Example.COM", false)
        .expect("removekey by email must match case-insensitively");

    let secret_fps = fingerprints_in_store(&key_store, "secret-keys.pgp", true);
    let public_fps = fingerprints_in_store(&key_store, "public-keys.pgp", false);
    assert!(
        !secret_fps.contains(&bob_fingerprint) && !public_fps.contains(&bob_fingerprint),
        "bob's key must be gone from both stores, secret: {:?}, public: {:?}",
        secret_fps,
        public_fps
    );
    assert!(
        secret_fps.contains(&alice_fingerprint) && public_fps.contains(&alice_fingerprint),
        "alice's key must be retained in both stores, secret: {:?}, public: {:?}",
        secret_fps,
        public_fps
    );
}

#[test]
fn removekey_ambiguous_email_requires_yes() {
    let temp = tempfile::tempdir().unwrap();
    let key_store = temp.path().join("key-store");
    let (carol_first, carol_first_pub) = generate_test_key("carol@example.com");
    let (carol_second, carol_second_pub) = generate_test_key("carol@example.com");
    let first_fingerprint = extract_key_fingerprint(&carol_first_pub);
    let second_fingerprint = extract_key_fingerprint(&carol_second_pub);
    import_secret_key(temp.path(), &key_store, &carol_first, "carol1-priv.asc");
    import_secret_key(temp.path(), &key_store, &carol_second, "carol2-priv.asc");
    write_public_keys_store(&key_store, &[&carol_first_pub, &carol_second_pub]);

    let secret_before = std::fs::read_to_string(key_store.join("secret-keys.pgp")).unwrap();
    let public_before = std::fs::read_to_string(key_store.join("public-keys.pgp")).unwrap();

    let result = cmd_removekey(&key_store, "carol@example.com", false);

    let err = result
        .err()
        .expect("an ambiguous email without --yes must not silently remove one of several keys");
    assert!(
        err.to_string().contains(first_fingerprint.as_str())
            && err.to_string().contains(second_fingerprint.as_str()),
        "the ambiguity error must list BOTH matching fingerprints, got: {}",
        err
    );
    assert_eq!(
        std::fs::read_to_string(key_store.join("secret-keys.pgp")).unwrap(),
        secret_before,
        "a refused removekey must leave secret-keys.pgp untouched"
    );
    assert_eq!(
        std::fs::read_to_string(key_store.join("public-keys.pgp")).unwrap(),
        public_before,
        "a refused removekey must leave public-keys.pgp untouched"
    );

    cmd_removekey(&key_store, "carol@example.com", true)
        .expect("removekey with --yes must remove ALL ambiguous matches");

    let secret_fps = fingerprints_in_store(&key_store, "secret-keys.pgp", true);
    let public_fps = fingerprints_in_store(&key_store, "public-keys.pgp", false);
    assert!(
        secret_fps.is_empty(),
        "with --yes both carol keys must be gone from secret-keys.pgp, got: {:?}",
        secret_fps
    );
    assert!(
        public_fps.is_empty(),
        "with --yes both carol keys must be gone from public-keys.pgp, got: {:?}",
        public_fps
    );
}

#[test]
fn removekey_refuses_to_destroy_last_private_key_without_yes() {
    let temp = tempfile::tempdir().unwrap();
    let key_store = temp.path().join("key-store");
    let (alice_sec, _) = generate_test_key("alice@example.com");
    import_secret_key(temp.path(), &key_store, &alice_sec, "alice-priv.asc");

    let before = std::fs::read_to_string(key_store.join("secret-keys.pgp")).unwrap();

    let result = cmd_removekey(&key_store, "alice@example.com", false);

    let err = result
        .err()
        .expect("removing the only private key without --yes must refuse");
    assert!(
        err.to_string().contains("only private key"),
        "the refusal must name the only-private-key risk, got: {}",
        err
    );
    assert!(
        err.to_string().contains("cannot decrypt"),
        "the refusal must explain the consequence, got: {}",
        err
    );
    assert!(
        err.to_string().contains("--yes"),
        "the refusal must say how to confirm, got: {}",
        err
    );
    assert_eq!(
        std::fs::read_to_string(key_store.join("secret-keys.pgp")).unwrap(),
        before,
        "a refused removekey must leave the store untouched"
    );

    cmd_removekey(&key_store, "alice@example.com", true)
        .expect("removekey --yes must proceed on the only private key");

    let after = std::fs::read_to_string(key_store.join("secret-keys.pgp"))
        .expect("the store file must still exist after removing its only key");
    assert!(
        after.is_empty(),
        "with --yes the single-key store must become empty, got: {}",
        after
    );
    let find_result = find_private_key_by_email(&key_store, "alice@example.com");
    let find_err = find_result
        .err()
        .expect("an empty store must not yield any key");
    assert!(
        find_err.to_string().contains("No private key blocks found"),
        "the empty-store error must be the clear no-blocks message, got: {}",
        find_err
    );
}

#[test]
fn removekey_leaves_corrupt_store_untouched() {
    let temp = tempfile::tempdir().unwrap();
    let key_store = temp.path().join("key-store");
    let (alice_sec, alice_pub) = generate_test_key("alice@example.com");
    let (bob_sec, _) = generate_test_key("bob@example.com");
    let alice_armored = alice_sec.to_armored_string(Default::default()).unwrap();
    let bob_armored = bob_sec.to_armored_string(Default::default()).unwrap();
    import_secret_key(temp.path(), &key_store, &alice_sec, "alice-priv.asc");
    write_public_keys_store(&key_store, &[&alice_pub]);
    // Corrupt the secret store with an unterminated (truncated) block.
    let end_marker = "-----END PGP PRIVATE KEY BLOCK-----";
    let truncated_bob = bob_armored[..bob_armored.find(end_marker).unwrap()].to_string();
    let corrupt = format!("{}\n{}", alice_armored, truncated_bob);
    std::fs::write(key_store.join("secret-keys.pgp"), &corrupt).unwrap();
    let before = std::fs::read(key_store.join("secret-keys.pgp")).unwrap();
    let public_before = std::fs::read(key_store.join("public-keys.pgp")).unwrap();

    let result = cmd_removekey(&key_store, "alice@example.com", true);

    let err = result
        .err()
        .expect("removekey must refuse a corrupt store instead of rewriting it");
    assert!(
        err.to_string().contains("Unterminated private key block"),
        "the error must name the unterminated block, got: {}",
        err
    );
    assert_eq!(
        std::fs::read(key_store.join("secret-keys.pgp")).unwrap(),
        before,
        "a corrupt store must be left byte-identical"
    );
    assert_eq!(
        std::fs::read(key_store.join("public-keys.pgp")).unwrap(),
        public_before,
        "no other store may be rewritten when one store is corrupt"
    );
}

#[test]
fn removekey_unknown_identifier_errors() {
    let temp = tempfile::tempdir().unwrap();
    let key_store = temp.path().join("key-store");
    let (alice_sec, _) = generate_test_key("alice@example.com");
    import_secret_key(temp.path(), &key_store, &alice_sec, "alice-priv.asc");

    let result = cmd_removekey(&key_store, "carol@example.com", false);

    let err = result
        .err()
        .expect("an unknown identifier must not remove anything");
    assert!(
        err.to_string().contains("carol@example.com"),
        "the error must name the identifier, got: {}",
        err
    );
    assert!(
        err.to_string().contains("secret-keys.pgp") && err.to_string().contains("public-keys.pgp"),
        "the error must name both store paths, got: {}",
        err
    );
}

// ============================================================================
// Two-phase hide/reveal (L5): a failure must leave EVERYTHING unchanged
//
// hide and reveal are destructive loops (encrypt-then-delete / write-then-
// delete per file). Written Red: pre-fix, a failure on file 2 aborts AFTER
// file 1 has already been hidden/revealed, leaving a mixed state. Post-fix,
// both commands are compute-then-commit: phase 1 validates and encrypts (or
// decrypts) EVERY file in memory and any failure aborts with nothing changed
// on disk; phase 2 writes/deletes only after every transformation succeeded.
// ============================================================================

#[test]
fn hide_failure_leaves_everything_unchanged() {
    let (alice_sec, alice_pub) = generate_test_key("alice@example.com");
    let (repo_temp, key_store) = setup_trusted_repo_with_secret_keys(&[alice_sec]);

    let alice_keyfile = repo_temp.path().join("alice.pub");
    write_public_key_file(&alice_pub, &alice_keyfile);

    cmd_tell(
        repo_temp.path(),
        "alice@example.com",
        alice_keyfile.to_str().unwrap(),
        "origin",
        &key_store,
        None,
    )
    .expect("cmd_tell must succeed");

    let one_plaintext = b"ONE=1\n".to_vec();
    std::fs::write(repo_temp.path().join("one.env"), &one_plaintext).unwrap();
    // two.env is tracked but its plaintext deliberately does not exist: hide
    // must fail on it. Pre-fix, one.env was ALREADY hidden when the failure
    // hit, leaving a mixed state.
    write_tracked_json(repo_temp.path(), &["one.env", "two.env"]);

    let result = cmd_hide(repo_temp.path(), "origin", &key_store);

    let err = result
        .err()
        .expect("hide must fail when a tracked plaintext is missing");
    assert!(
        err.to_string().contains("two.env"),
        "the error must name the offending tracked file, got: {}",
        err
    );
    assert!(
        repo_temp.path().join("one.env").is_file(),
        "hide is all-or-nothing: one.env must still be plaintext on disk"
    );
    assert_eq!(
        std::fs::read(repo_temp.path().join("one.env")).unwrap(),
        one_plaintext,
        "the surviving plaintext must be byte-identical"
    );
    assert!(
        !repo_temp.path().join("one.env.secret").exists()
            && !repo_temp.path().join("two.env.secret").exists(),
        "no ciphertext may be written when any tracked file fails phase 1"
    );
}

#[test]
fn reveal_failure_leaves_everything_unchanged() {
    let (alice_sec, alice_pub) = generate_test_key("alice@example.com");
    let (repo_temp, key_store) = setup_trusted_repo_with_secret_keys(&[alice_sec]);

    let alice_keyfile = repo_temp.path().join("alice.pub");
    write_public_key_file(&alice_pub, &alice_keyfile);

    cmd_tell(
        repo_temp.path(),
        "alice@example.com",
        alice_keyfile.to_str().unwrap(),
        "origin",
        &key_store,
        None,
    )
    .expect("cmd_tell must succeed");

    std::fs::write(repo_temp.path().join("one.env"), "ONE=1\n").unwrap();
    std::fs::write(repo_temp.path().join("two.env"), "TWO=2\n").unwrap();
    write_tracked_json(repo_temp.path(), &["one.env", "two.env"]);
    cmd_hide(repo_temp.path(), "origin", &key_store).expect("cmd_hide must succeed");

    // Delete two.env's ciphertext: reveal must refuse. Pre-fix, one.env was
    // ALREADY revealed (ciphertext deleted, plaintext restored) when the
    // missing-ciphertext failure hit, leaving a mixed state.
    std::fs::remove_file(repo_temp.path().join("two.env.secret")).unwrap();

    let result = cmd_reveal(
        repo_temp.path(),
        "alice@example.com",
        "origin",
        &key_store,
        None,
    );

    let err = result
        .err()
        .expect("reveal must fail when a tracked ciphertext is missing");
    assert!(
        err.to_string().contains("two.env.secret"),
        "the error must name the missing ciphertext, got: {}",
        err
    );
    assert!(
        !repo_temp.path().join("one.env").exists(),
        "reveal is all-or-nothing: one.env must remain hidden (no plaintext on disk)"
    );
    assert!(
        repo_temp.path().join("one.env.secret").exists(),
        "one.env's ciphertext must be untouched when any tracked file fails phase 1"
    );
}

/// The `git-veil help <cmd>` handler (main.rs) prints exactly the
/// subcommand's after_long_help followed by its short help, so asserting on
/// the after_long_help content via Cli::command() asserts the substance of
/// what `git-veil help hide` / `git-veil help reveal` render.
#[test]
fn help_text_describes_two_phase_all_or_nothing_contract() {
    use clap::CommandFactory as _;

    let root = git_veil::cli::Cli::command();
    for name in ["hide", "reveal"] {
        let sub = root
            .find_subcommand(name)
            .unwrap_or_else(|| panic!("subcommand {name} must exist"));
        let after = sub
            .get_after_long_help()
            .unwrap_or_else(|| panic!("{name} must carry after_long_help"));
        let text = after.to_string();
        assert!(
            text.to_lowercase().contains("two-phase"),
            "`help {name}` must describe the two-phase behaviour, got: {text}"
        );
        assert!(
            text.to_lowercase().contains("all-or-nothing"),
            "`help {name}` must state the all-or-nothing contract, got: {text}"
        );
    }
}
