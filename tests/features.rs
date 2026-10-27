//! Feature tests: two-phase all-or-nothing semantics, encryption to
//! multiple keys, keyring tamper detection, and subdirectory file handling.

use age::secrecy::ExposeSecret;
use git_veil::{
    cmd_add, cmd_allow, cmd_cat, cmd_changes, cmd_hide, cmd_hide_all, cmd_import, cmd_init,
    cmd_removeperson, cmd_reveal, cmd_tell, cmd_trust, cmd_unhide, cmd_verify_keyring,
    encrypt_to_x25519_public_keys, exit_code_of, extract_content_to_verify_from_keyring,
    generate_signing_keypair, generate_x25519_private_key, keyring_content_digest,
    parse_x25519_public_key, x25519_public_key_encoding, Keyring, RingPassStore, TrackedFiles,
};
use std::fs;
use std::path::Path;

// Reuse the harness from cli.rs via a minimal local copy (integration tests
// are separate crates and cannot share helpers).

struct TempDir {
    path: std::path::PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        let pid = std::process::id();
        let counter = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("git-veil-feat-{}-{}-{}", label, pid, counter));
        fs::create_dir_all(&dir).expect("create temp dir");
        Self { path: dir }
    }
    fn join(&self, rel: &str) -> std::path::PathBuf {
        self.path.join(rel)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn init_git_repo(dir: &Path) {
    let args_list: &[&[&str]] = &[
        &["init", "--quiet"],
        &["config", "user.email", "owner@example.com"],
        &["config", "user.name", "Test Owner"],
        &["remote", "add", "origin", "git@github.com:owner/fara.git"],
    ];
    for args in args_list {
        let s = std::process::Command::new("git")
            .current_dir(dir)
            .args(*args)
            .status()
            .expect("git");
        assert!(s.success());
    }
}

const TEST_REPO_ID: &str = "fara+owner@github.com";

struct Fixture {
    repo: TempDir,
    key_store: TempDir,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let repo = TempDir::new(label);
        let key_store = TempDir::new(&format!("{}-ks", label));
        init_git_repo(&repo.path);

        let identity = generate_x25519_private_key();
        let recipient = x25519_public_key_encoding(&identity);
        let (signing_key, verifying_hex) = generate_signing_keypair();

        fs::write(
            repo.join("owner.age"),
            format!("{}\n", identity.to_string().expose_secret()),
        )
        .unwrap();
        fs::create_dir_all(repo.join(".git-veil")).unwrap();
        fs::write(
            repo.join(".git-veil/owner.verifying"),
            format!("{}\n{}\n", verifying_hex, recipient),
        )
        .unwrap();
        fs::write(
            key_store.join("signing-keys.txt"),
            format!("{}\n", hex::encode(signing_key.to_bytes())),
        )
        .unwrap();

        cmd_init(&repo.path, false).expect("init");
        cmd_import(&repo.path, &["owner.age".to_string()], &key_store.path).expect("import");
        cmd_trust(&repo.path, TEST_REPO_ID, "origin", &key_store.path, false).expect("trust");

        Self { repo, key_store }
    }

    fn add_collab(&self, email: &str) -> age::x25519::Identity {
        let id = generate_x25519_private_key();
        let r = x25519_public_key_encoding(&id);
        cmd_tell(
            &self.repo.path,
            email,
            &r,
            "origin",
            &self.key_store.path,
            None,
        )
        .expect("tell");
        id
    }

    fn import_id(&self, id: &age::x25519::Identity, fname: &str) {
        fs::write(
            self.repo.join(fname),
            format!("{}\n", id.to_string().expose_secret()),
        )
        .unwrap();
        cmd_import(&self.repo.path, &[fname.to_string()], &self.key_store.path).expect("import");
    }

    fn add_file(&self, name: &str, content: &[u8]) {
        let p = self.repo.join(name);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&p, content).unwrap();
        cmd_add(
            &self.repo.path,
            vec![name.to_string()],
            "origin",
            &self.key_store.path,
        )
        .expect("add");
    }

    /// The tracked file names, as the required-form hide and reveal calls
    /// name them. Tests that act on the whole tracked set name the whole
    /// tracked set explicitly: the bare form is gone (issue 50).
    fn tracked_names(&self) -> Vec<String> {
        TrackedFiles::load(&self.repo.path.join(".git-veil/tracked.json"))
            .unwrap()
            .files
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Two-phase all-or-nothing: hide aborts if a plaintext is missing
// ---------------------------------------------------------------------------

#[test]
fn test_hide_refuses_a_name_whose_plaintext_is_absent() {
    let f = Fixture::new("hide-name-absent");

    let id = f.add_collab("alice@example.com");
    f.import_id(&id, "alice.age");

    f.add_file(".env", b"secret\n");
    f.add_file("config.yml", b"config\n");

    // Delete one plaintext before hide. The name must exist when you name
    // it (hide resolves paths the way add does), so the invocation refuses
    // before anything is encrypted.
    fs::remove_file(f.repo.join(".env")).unwrap();

    let err = cmd_hide(
        &f.repo.path,
        "origin",
        &f.key_store.path,
        false,
        vec![".env".to_string()],
    )
    .expect_err("an absent plaintext does not resolve");
    let message = format!("{:#}", err);
    assert!(
        message.contains(".env"),
        "the refusal names the unresolvable path: {message}"
    );

    assert!(
        !f.repo.join(".env.secret").exists(),
        "nothing is encrypted when the named set refuses"
    );
    assert!(
        f.repo.join("config.yml").exists(),
        "an un-named plaintext is untouched"
    );
    assert!(
        !f.repo.join("config.yml.secret").exists(),
        "an un-named file is never encrypted by a refused invocation"
    );
}

// ---------------------------------------------------------------------------
// Two-phase all-or-nothing: reveal aborts if a ciphertext is missing
// ---------------------------------------------------------------------------

#[test]
fn test_reveal_all_or_nothing_missing_ciphertext() {
    let f = Fixture::new("aon-reveal-missing");

    let id = f.add_collab("alice@example.com");
    f.import_id(&id, "alice.age");

    f.add_file(".env", b"secret\n");
    f.add_file("config.yml", b"config\n");

    cmd_hide(
        &f.repo.path,
        "origin",
        &f.key_store.path,
        true,
        f.tracked_names(),
    )
    .expect("hide");

    // Delete one ciphertext before reveal
    fs::remove_file(f.repo.join(".env.secret")).unwrap();

    let result = cmd_reveal(
        &f.repo.path,
        "alice@example.com",
        "origin",
        &f.key_store.path,
        f.tracked_names(),
    );
    assert!(
        result.is_err(),
        "reveal should abort when a ciphertext is missing"
    );

    // The other file should not be revealed (all-or-nothing).
    // config.yml still exists because hide does not delete plaintext
    assert!(
        f.repo.join("config.yml.secret").exists(),
        "config.yml.secret should still exist"
    );
    assert!(
        f.repo.join("config.yml").exists(),
        "config.yml should still exist (hide does not delete plaintext)"
    );
}

// ---------------------------------------------------------------------------
// Encryption to multiple keys: both collaborators can decrypt the same ciphertext
// ---------------------------------------------------------------------------

#[test]
fn test_multi_recipient_both_can_decrypt() {
    let f = Fixture::new("multi-both");

    let alice = f.add_collab("alice@example.com");
    let bob = f.add_collab("bob@example.com");

    f.import_id(&alice, "alice.age");
    f.import_id(&bob, "bob.age");

    let plaintext = b"shared\n";
    f.add_file(".env", plaintext);

    cmd_hide(
        &f.repo.path,
        "origin",
        &f.key_store.path,
        true,
        f.tracked_names(),
    )
    .expect("hide");

    // Alice reveals
    cmd_reveal(
        &f.repo.path,
        "alice@example.com",
        "origin",
        &f.key_store.path,
        f.tracked_names(),
    )
    .expect("alice reveal");
    assert_eq!(fs::read(f.repo.join(".env")).unwrap(), plaintext);

    // Re-hide and bob reveals (plaintext still exists, hide does not delete it)
    cmd_hide(
        &f.repo.path,
        "origin",
        &f.key_store.path,
        true,
        f.tracked_names(),
    )
    .expect("re-hide");
    cmd_reveal(
        &f.repo.path,
        "bob@example.com",
        "origin",
        &f.key_store.path,
        f.tracked_names(),
    )
    .expect("bob reveal");
    assert_eq!(fs::read(f.repo.join(".env")).unwrap(), plaintext);
}

// ---------------------------------------------------------------------------
// Keyring tamper: modifying keyring content invalidates signature
// ---------------------------------------------------------------------------

#[test]
fn test_keyring_tamper_invalidates_signature() {
    let f = Fixture::new("tamper-sig");

    f.add_collab("alice@example.com");

    let keyring_path = f.repo.join(".git-veil/keyring");
    let original = fs::read_to_string(&keyring_path).unwrap();

    // Tamper: swap the public key string
    let tampered = original.replace("age1", "age2");
    fs::write(&keyring_path, &tampered).unwrap();

    let result = cmd_verify_keyring(&f.repo.path, "origin", &f.key_store.path);
    assert!(result.is_err(), "tampered keyring should fail verification");
}

// ---------------------------------------------------------------------------
// Subdirectory files: hide/reveal works for files in subdirectories
// ---------------------------------------------------------------------------

#[test]
fn test_subdirectory_hide_reveal() {
    let f = Fixture::new("subdir");

    let id = f.add_collab("alice@example.com");
    f.import_id(&id, "alice.age");

    let plaintext = b"nested secret\n";
    f.add_file("config/secrets.yml", plaintext);

    cmd_hide(
        &f.repo.path,
        "origin",
        &f.key_store.path,
        true,
        f.tracked_names(),
    )
    .expect("hide");

    // Both copies exist, matching git-secret, which does not delete the
    // plaintext by default.
    assert!(f.repo.join("config/secrets.yml").exists());
    assert!(f.repo.join("config/secrets.yml.secret").exists());

    cmd_reveal(
        &f.repo.path,
        "alice@example.com",
        "origin",
        &f.key_store.path,
        f.tracked_names(),
    )
    .expect("reveal");

    assert_eq!(
        fs::read(f.repo.join("config/secrets.yml")).unwrap(),
        plaintext
    );
    // Both copies exist, matching git-secret, which does not delete the
    // ciphertext on reveal.
    assert!(f.repo.join("config/secrets.yml.secret").exists());
}

// ---------------------------------------------------------------------------
// Cat does not modify disk state
// ---------------------------------------------------------------------------

#[test]
fn test_cat_preserves_disk_state() {
    let f = Fixture::new("cat-preserve");

    let id = f.add_collab("alice@example.com");
    f.import_id(&id, "alice.age");

    f.add_file(".env", b"cat test\n");
    cmd_hide(
        &f.repo.path,
        "origin",
        &f.key_store.path,
        true,
        f.tracked_names(),
    )
    .expect("hide");

    let _ = cmd_cat(
        &f.repo.path,
        ".env",
        "alice@example.com",
        "origin",
        &f.key_store.path,
    )
    .expect("cat");

    // cat should not touch disk. Both plaintext and ciphertext exist.
    assert!(
        f.repo.join(".env").exists(),
        "plaintext should still exist (hide does not delete)"
    );
    assert!(
        f.repo.join(".env.secret").exists(),
        "ciphertext should not be deleted"
    );
}

// ---------------------------------------------------------------------------
// Unhide restores one file, leaves others hidden
// ---------------------------------------------------------------------------

#[test]
fn test_unhide_isolates_single_file() {
    let f = Fixture::new("unhide-iso");

    let id = f.add_collab("alice@example.com");
    f.import_id(&id, "alice.age");

    f.add_file(".env", b"first\n");
    f.add_file("config.yml", b"second\n");

    cmd_hide(
        &f.repo.path,
        "origin",
        &f.key_store.path,
        true,
        f.tracked_names(),
    )
    .expect("hide");

    cmd_unhide(
        &f.repo.path,
        ".env",
        "alice@example.com",
        "origin",
        &f.key_store.path,
    )
    .expect("unhide .env");

    // unhide restores the plaintext and does not delete the ciphertext
    // (matching git-secret).
    assert!(f.repo.join(".env").exists());
    assert!(
        f.repo.join(".env.secret").exists(),
        "ciphertext should still exist"
    );
    // other file still has both (hide does not delete plaintext)
    assert!(f.repo.join("config.yml").exists());
    assert!(f.repo.join("config.yml.secret").exists());
}

// ---------------------------------------------------------------------------
// Changes detects both text and binary differences
// ---------------------------------------------------------------------------

#[test]
fn test_changes_binary_file() {
    let f = Fixture::new("changes-bin");

    let id = f.add_collab("alice@example.com");
    f.import_id(&id, "alice.age");

    let binary = vec![0u8, 1, 2, 3, 0, 255, 254];
    f.add_file("data.bin", &binary);

    cmd_hide(
        &f.repo.path,
        "origin",
        &f.key_store.path,
        true,
        f.tracked_names(),
    )
    .expect("hide");

    // Write different binary
    fs::write(f.repo.join("data.bin"), vec![0u8, 1, 2, 3, 0, 255, 253]).unwrap();

    let changed = cmd_changes(
        &f.repo.path,
        vec![],
        "alice@example.com",
        "origin",
        &f.key_store.path,
    )
    .expect("changes");

    assert_eq!(changed.len(), 1);
}

// ---------------------------------------------------------------------------
// Multiple tell updates existing entry
// ---------------------------------------------------------------------------

#[test]
fn test_tell_updates_existing_email() {
    let f = Fixture::new("tell-update");

    let _id1 = f.add_collab("alice@example.com");

    // Tell again with a new key for the same email
    let id2 = generate_x25519_private_key();
    let r2 = x25519_public_key_encoding(&id2);
    cmd_tell(
        &f.repo.path,
        "alice@example.com",
        &r2,
        "origin",
        &f.key_store.path,
        None,
    )
    .expect("tell update");

    let keyring_text = fs::read_to_string(f.repo.join(".git-veil/keyring")).unwrap();
    let keyring = Keyring::parse(&keyring_text).expect("parse");
    assert_eq!(keyring.entries.len(), 1, "should still have one entry");
    assert_eq!(
        keyring.entries[0].public_key, r2,
        "recipient should be updated"
    );
}

// ---------------------------------------------------------------------------
// Empty keyring after removing last person still verifies
// ---------------------------------------------------------------------------

#[test]
fn test_remove_last_person_signs_empty_keyring() {
    let f = Fixture::new("remove-last");

    f.add_collab("alice@example.com");

    git_veil::cmd_removeperson(
        &f.repo.path,
        "alice@example.com",
        "origin",
        &f.key_store.path,
        None,
    )
    .expect("removeperson");

    let keyring_text = fs::read_to_string(f.repo.join(".git-veil/keyring")).unwrap();
    let keyring = Keyring::parse(&keyring_text).expect("parse");
    assert!(keyring.entries.is_empty());
    assert!(
        keyring.signature.is_some(),
        "empty keyring should still be signed"
    );

    cmd_verify_keyring(&f.repo.path, "origin", &f.key_store.path)
        .expect("verify empty signed keyring");
}

// ---------------------------------------------------------------------------
// Ignore safety: hide refuses when a .secret ciphertext is git-ignored
// ---------------------------------------------------------------------------

#[test]
fn test_hide_refuses_when_ciphertext_path_is_ignored() {
    let f = Fixture::new("hide-ignored-secret");

    let id = f.add_collab("alice@example.com");
    f.import_id(&id, "alice.age");

    // A broad parent-directory rule that would swallow the ciphertext
    fs::write(f.repo.join(".gitignore"), ".tmp/\n").unwrap();
    fs::create_dir_all(f.repo.join(".tmp")).unwrap();
    fs::write(f.repo.join(".tmp/x.txt"), b"secret-ish\n").unwrap();

    // add succeeds (it gitignores the plaintext), but warns that the
    // ciphertext path is swallowed by the .tmp/ rule
    cmd_add(
        &f.repo.path,
        vec![".tmp/x.txt".to_string()],
        "origin",
        &f.key_store.path,
    )
    .expect("add");

    // Hide fails closed before encrypting anything. Exit code 40.
    let err = cmd_hide(
        &f.repo.path,
        "origin",
        &f.key_store.path,
        true,
        f.tracked_names(),
    )
    .unwrap_err();
    let message = format!("{:#}", err);
    assert_eq!(
        exit_code_of(&err),
        git_veil::ExitCode::CiphertextIgnored as i32,
        "hide must refuse with code 40"
    );
    assert!(
        message.contains("git-ignored"),
        "states the problem: {message}"
    );
    assert!(
        !f.repo.join(".tmp/x.txt.secret").exists(),
        "nothing written before the gate"
    );

    // Removing the broad rule makes hide succeed (the appended plaintext
    // ignore line .tmp/x.txt keeps protecting the plaintext)
    fs::write(f.repo.join(".gitignore"), ".tmp/x.txt\n").unwrap();
    cmd_hide(
        &f.repo.path,
        "origin",
        &f.key_store.path,
        true,
        f.tracked_names(),
    )
    .expect("hide after fixing .gitignore");
    assert!(f.repo.join(".tmp/x.txt.secret").exists());
}

#[test]
fn test_hide_warns_but_succeeds_when_plaintext_not_ignored() {
    let f = Fixture::new("hide-plaintext-leak");

    let id = f.add_collab("alice@example.com");
    f.import_id(&id, "alice.age");

    f.add_file(".env", b"API_KEY=1\n");
    cmd_hide(
        &f.repo.path,
        "origin",
        &f.key_store.path,
        true,
        f.tracked_names(),
    )
    .expect("hide");

    // Simulate .gitignore drift. The tracked plaintext is no longer ignored.
    fs::write(f.repo.join(".gitignore"), "").unwrap();

    // A warning (error code 41), not a refusal. Hide proceeds.
    cmd_hide(
        &f.repo.path,
        "origin",
        &f.key_store.path,
        true,
        f.tracked_names(),
    )
    .expect("hide still succeeds");
    assert!(f.repo.join(".env.secret").exists());
}

#[test]
fn test_tell_fails_with_code_20_when_signing_key_missing() {
    let f = Fixture::new("tell-nosigning");
    // The fixture wrote signing-keys.txt. Simulate the fresh-machine case.
    fs::remove_file(f.key_store.join("signing-keys.txt")).unwrap();

    let id = git_veil::generate_x25519_private_key();
    let r = git_veil::x25519_public_key_encoding(&id);

    let err = cmd_tell(
        &f.repo.path,
        "bob@example.com",
        &r,
        "origin",
        &f.key_store.path,
        None,
    )
    .unwrap_err();
    let message = format!("{:#}", err);
    assert_eq!(
        exit_code_of(&err),
        git_veil::ExitCode::NoSigningKey as i32,
        "missing signing key exits 20"
    );
    assert!(
        message.contains("Create an Ed25519 signing key yourself and back it up"),
        "guidance printed: {message}"
    );
    let keyring = fs::read_to_string(f.repo.join(".git-veil/keyring")).unwrap();
    assert!(
        !keyring.contains("bob@example.com"),
        "keyring unchanged on failure"
    );
}

// ---------------------------------------------------------------------------
// Positional hide: `git-veil hide <path>...` acts on exactly the named files
// ---------------------------------------------------------------------------

#[test]
fn test_positional_hide_hides_only_named_files() {
    let f = Fixture::new("positional-hide-only");

    let id = f.add_collab("alice@example.com");
    f.import_id(&id, "alice.age");

    f.add_file(".env", b"API_KEY=1\n");
    f.add_file("config.yml", b"config\n");

    // Scoped hide covers exactly the named file.
    cmd_hide(
        &f.repo.path,
        "origin",
        &f.key_store.path,
        false,
        vec![".env".to_string()],
    )
    .expect("scoped hide");
    assert!(
        !f.repo.join(".env").exists(),
        "the named plaintext is deleted by default after the ciphertext is durable"
    );
    assert!(
        f.repo.join(".env.secret").exists(),
        "the named file is encrypted"
    );
    assert!(
        f.repo.join("config.yml").exists(),
        "an unnamed plaintext is untouched"
    );
    assert!(
        !f.repo.join("config.yml.secret").exists(),
        "an unnamed file is never encrypted by a scoped hide"
    );
}

#[test]
fn test_positional_hide_refuses_untracked_name_with_code_71() {
    let f = Fixture::new("positional-hide-untracked");

    let id = f.add_collab("alice@example.com");
    f.import_id(&id, "alice.age");

    f.add_file(".env", b"API_KEY=1\n");
    // On disk, but never passed to add, so not in the manifest.
    fs::write(f.repo.join("stray.txt"), b"not tracked\n").unwrap();

    let err = cmd_hide(
        &f.repo.path,
        "origin",
        &f.key_store.path,
        false,
        vec!["stray.txt".to_string()],
    )
    .expect_err("an untracked name must refuse");
    assert_eq!(
        exit_code_of(&err),
        git_veil::ExitCode::UnsafePath as i32,
        "an untracked name refuses with the path-safety code 71"
    );
    let message = format!("{:#}", err);
    assert!(
        message.contains("stray.txt"),
        "the refusal names the offending path: {message}"
    );
    assert!(
        !f.repo.join(".env.secret").exists(),
        "nothing is hidden when the named set refuses"
    );
    assert!(
        f.repo.join(".env").exists(),
        "no plaintext is deleted when the named set refuses"
    );
}

#[test]
fn test_positional_hide_allow_gate_is_scoped_to_named_set() {
    let f = Fixture::new("positional-hide-gate");

    let id = f.add_collab("alice@example.com");
    f.import_id(&id, "alice.age");

    // Nominate two paths directly in the committed manifest, the way the
    // exit-72 regression tests do. Neither has an allowance on this machine
    // and neither has a committed ciphertext.
    let secret_plaintext = b"FIRST_SECRET=1\n";
    let other_plaintext = b"SECOND_SECRET=2\n";
    fs::write(f.repo.join("prod-credentials"), secret_plaintext).unwrap();
    fs::write(f.repo.join("other-credentials"), other_plaintext).unwrap();
    fs::write(
        f.repo.join(".gitignore"),
        "prod-credentials\nother-credentials\n",
    )
    .unwrap();
    fs::write(
        f.repo.join(".git-veil/tracked.json"),
        "{\n  \"files\": [\n    \"prod-credentials\",\n    \"other-credentials\"\n  ]\n}",
    )
    .unwrap();

    // Scoped hide of one nominated path refuses, and names only the path in
    // the named set. The other nominated path stays out of the refusal.
    let err = cmd_hide(
        &f.repo.path,
        "origin",
        &f.key_store.path,
        true,
        vec!["other-credentials".to_string()],
    )
    .expect_err("the gate applies to the named set");
    assert_eq!(
        exit_code_of(&err),
        72,
        "the allowance gate applies to the named set with code 72"
    );
    let message = format!("{:#}", err);
    assert!(
        message.contains("other-credentials"),
        "the refusal names the offending path in the named set: {message}"
    );
    assert!(
        !message.contains("prod-credentials"),
        "the refusal must not name paths outside the named set: {message}"
    );
    assert!(
        !f.repo.join("other-credentials.secret").exists(),
        "no ciphertext is written for a refused path"
    );

    // Allowing only the named path unblocks the scoped hide. The other
    // nominated path keeps its allowance-free state.
    cmd_allow(
        &f.repo.path,
        vec!["other-credentials".to_string()],
        "origin",
        &f.key_store.path,
    )
    .expect("allow the named path deliberately");
    cmd_hide(
        &f.repo.path,
        "origin",
        &f.key_store.path,
        true,
        vec!["other-credentials".to_string()],
    )
    .expect("scoped hide succeeds once the named path is allowed");
    assert!(f.repo.join("other-credentials.secret").exists());
    assert!(
        f.repo.join("prod-credentials").exists(),
        "the un-named nominated path is untouched"
    );
    assert!(
        !f.repo.join("prod-credentials.secret").exists(),
        "the un-named nominated path is never encrypted"
    );
}

// ---------------------------------------------------------------------------
// Positional reveal: `git-veil reveal <path>...` decrypts exactly the named
// files. Reveal stays ungated: the allowance never applies.
// ---------------------------------------------------------------------------

#[test]
fn test_positional_reveal_reveals_only_named_files() {
    let f = Fixture::new("positional-reveal-only");

    let id = f.add_collab("alice@example.com");
    f.import_id(&id, "alice.age");

    f.add_file(".env", b"API_KEY=1\n");
    f.add_file("config.yml", b"config\n");

    // Hide everything. The default deletes both plaintexts. The test names
    // the whole tracked set explicitly: the bare form is gone (issue 50).
    cmd_hide(
        &f.repo.path,
        "origin",
        &f.key_store.path,
        false,
        f.tracked_names(),
    )
    .expect("hide");
    assert!(!f.repo.join(".env").exists() && !f.repo.join("config.yml").exists());

    // Scoped reveal restores exactly the named file. The plaintext is
    // absent, so the name need not exist on disk to resolve.
    cmd_reveal(
        &f.repo.path,
        "alice@example.com",
        "origin",
        &f.key_store.path,
        vec![".env".to_string()],
    )
    .expect("scoped reveal");
    assert_eq!(
        fs::read(f.repo.join(".env")).unwrap(),
        b"API_KEY=1\n",
        "the named file is revealed"
    );
    assert!(
        !f.repo.join("config.yml").exists(),
        "an un-named file is never revealed by a scoped reveal"
    );
    assert!(
        f.repo.join(".env.secret").exists() && f.repo.join("config.yml.secret").exists(),
        "reveal never deletes ciphertexts"
    );
}

#[test]
fn test_positional_reveal_refuses_untracked_name_with_code_71() {
    let f = Fixture::new("positional-reveal-untracked");

    let id = f.add_collab("alice@example.com");
    f.import_id(&id, "alice.age");

    f.add_file(".env", b"API_KEY=1\n");
    cmd_hide(
        &f.repo.path,
        "origin",
        &f.key_store.path,
        false,
        f.tracked_names(),
    )
    .expect("hide");

    // On disk or not, a name outside the manifest refuses with the
    // path-safety code.
    let err = cmd_reveal(
        &f.repo.path,
        "alice@example.com",
        "origin",
        &f.key_store.path,
        vec!["stray.txt".to_string()],
    )
    .expect_err("an untracked name must refuse");
    assert_eq!(
        exit_code_of(&err),
        git_veil::ExitCode::UnsafePath as i32,
        "an untracked name refuses with the path-safety code 71"
    );
    let message = format!("{:#}", err);
    assert!(
        message.contains("stray.txt"),
        "the refusal names the offending path: {message}"
    );
    assert!(
        !f.repo.join(".env").exists(),
        "nothing is revealed when the named set refuses"
    );
}

#[test]
fn test_positional_reveal_is_never_allowance_gated() {
    let f = Fixture::new("positional-reveal-ungated");

    let id = f.add_collab("alice@example.com");
    f.import_id(&id, "alice.age");

    // Nominate a path directly in the committed manifest, the way the
    // exit-72 regression tests do. No allowance for it exists on this
    // machine, so hide would refuse a first-encrypt of it. The ciphertext
    // here is written out of band, straight to the ring's public keys, so
    // no allow step ever runs in this test.
    fs::write(f.repo.join("nominated"), b"nominated plaintext\n").unwrap();
    fs::write(f.repo.join(".gitignore"), "nominated\n").unwrap();
    fs::write(
        f.repo.join(".git-veil/tracked.json"),
        "{\n  \"files\": [\n    \"nominated\"\n  ]\n}",
    )
    .unwrap();
    let keyring_text = fs::read_to_string(f.repo.join(".git-veil/keyring")).unwrap();
    let keyring = Keyring::parse(&keyring_text).unwrap();
    let public_keys: Vec<_> = keyring
        .entries
        .iter()
        .map(|e| parse_x25519_public_key(&e.public_key).unwrap())
        .collect();
    let ciphertext = encrypt_to_x25519_public_keys(b"nominated plaintext\n", &public_keys).unwrap();
    fs::write(f.repo.join("nominated.secret"), ciphertext).unwrap();

    // The contrast: hide of the same path refuses with the allowance code.
    let err = cmd_hide(
        &f.repo.path,
        "origin",
        &f.key_store.path,
        true,
        vec!["nominated".to_string()],
    )
    .expect_err("hide is gated on first-encrypt");
    assert_eq!(exit_code_of(&err), 72);

    // Reveal of the named path succeeds with no allow step. Ring
    // membership is the only requirement; the allowance store is never
    // consulted on the reveal path.
    cmd_reveal(
        &f.repo.path,
        "alice@example.com",
        "origin",
        &f.key_store.path,
        vec!["nominated".to_string()],
    )
    .expect("reveal is ungated: ring membership is the only requirement");
    assert_eq!(
        fs::read(f.repo.join("nominated")).unwrap(),
        b"nominated plaintext\n"
    );
}

// ---------------------------------------------------------------------------
// The ring-change ceremony: tell/removeperson stamp the pass; hide --all
// runs the whole-manifest re-encrypt once against the stamped ring.
// ---------------------------------------------------------------------------

/// The stamp holds the keyring version and the signed-content digest, and
/// tell/removeperson re-stamp it on every ring change.
#[test]
fn test_tell_and_removeperson_stamp_the_ring_change() {
    let f = Fixture::new("ring-pass-stamp");

    f.add_collab("alice@example.com");

    let keyring_text = fs::read_to_string(f.repo.join(".git-veil/keyring")).unwrap();
    let signed = extract_content_to_verify_from_keyring(&keyring_text).unwrap();
    let version = Keyring::parse(&keyring_text).unwrap().version.unwrap();
    let stamp = RingPassStore::read(&f.key_store.path, TEST_REPO_ID)
        .unwrap()
        .expect("tell stamps the ring-change pass");
    assert_eq!(
        stamp,
        (version, keyring_content_digest(&signed)),
        "the stamp names the ring tell signed"
    );

    // removeperson re-signs at the next version and re-stamps.
    cmd_removeperson(
        &f.repo.path,
        "alice@example.com",
        "origin",
        &f.key_store.path,
        None,
    )
    .expect("removeperson");
    let keyring_text = fs::read_to_string(f.repo.join(".git-veil/keyring")).unwrap();
    let signed = extract_content_to_verify_from_keyring(&keyring_text).unwrap();
    let version = Keyring::parse(&keyring_text).unwrap().version.unwrap();
    let stamp = RingPassStore::read(&f.key_store.path, TEST_REPO_ID)
        .unwrap()
        .expect("removeperson stamps the ring-change pass");
    assert_eq!(
        stamp,
        (version, keyring_content_digest(&signed)),
        "the stamp names the ring removeperson signed"
    );
}

#[test]
fn test_hide_all_runs_once_then_refuses() {
    let f = Fixture::new("hide-all-once");

    let id = f.add_collab("alice@example.com");
    f.import_id(&id, "alice.age");

    f.add_file(".env", b"API_KEY=1\n");
    f.add_file("config.yml", b"config\n");

    cmd_hide_all(&f.repo.path, "origin", &f.key_store.path, false).expect("the ceremony pass");
    assert!(f.repo.join(".env.secret").exists());
    assert!(f.repo.join("config.yml.secret").exists());
    assert!(
        !f.repo.join(".env").exists() && !f.repo.join("config.yml").exists(),
        "the pass deletes plaintexts by default, like any hide"
    );
    assert!(
        RingPassStore::read(&f.key_store.path, TEST_REPO_ID)
            .unwrap()
            .is_none(),
        "one pass consumes the stamp"
    );

    // The stamp is spent, so a second pass refuses with the policy code.
    let err = cmd_hide_all(&f.repo.path, "origin", &f.key_store.path, false)
        .expect_err("a consumed pass refuses");
    assert_eq!(
        exit_code_of(&err),
        git_veil::ExitCode::Refused as i32,
        "the stamp gate refuses with the policy code 70"
    );
    let message = format!("{:#}", err);
    assert!(
        message.contains(TEST_REPO_ID),
        "the refusal names the repository id: {message}"
    );
}

#[test]
fn test_hide_all_refuses_without_a_due_stamp() {
    let f = Fixture::new("hide-all-nostamp");

    let id = f.add_collab("alice@example.com");
    f.import_id(&id, "alice.age");

    f.add_file(".env", b"API_KEY=1\n");

    // No stamp at all: the ring changed on this machine, but the record is
    // gone. The pass refuses before anything is encrypted.
    RingPassStore::clear(&f.key_store.path, TEST_REPO_ID).unwrap();
    let err = cmd_hide_all(&f.repo.path, "origin", &f.key_store.path, false)
        .expect_err("a pass with no stamp refuses");
    assert_eq!(exit_code_of(&err), git_veil::ExitCode::Refused as i32);
    let message = format!("{:#}", err);
    assert!(
        message.contains(TEST_REPO_ID),
        "the refusal names the repository id: {message}"
    );
    assert!(
        !f.repo.join(".env.secret").exists(),
        "nothing is encrypted on refusal"
    );

    // A stamp that does not match the committed ring refuses too: the
    // stamp says which ring the pass may rotate, and the committed ring
    // moved on.
    RingPassStore::write(&f.key_store.path, TEST_REPO_ID, 999, &"a".repeat(64)).unwrap();
    let err = cmd_hide_all(&f.repo.path, "origin", &f.key_store.path, false)
        .expect_err("a pass against a ring the stamp does not name refuses");
    assert_eq!(exit_code_of(&err), git_veil::ExitCode::Refused as i32);
    assert!(
        !f.repo.join(".env.secret").exists(),
        "nothing is encrypted on refusal"
    );
}

#[test]
fn test_the_ceremony_re_encrypts_every_tracked_secret() {
    let f = Fixture::new("hide-all-reencrypt");

    let alice = f.add_collab("alice@example.com");
    f.import_id(&alice, "alice.age");

    f.add_file(".env", b"API_KEY=1\n");
    f.add_file("config.yml", b"config\n");

    // Hide to the ring as it stands, keeping plaintexts so the pass has
    // something to rotate (rotation is reveal -> ring change -> pass).
    cmd_hide(
        &f.repo.path,
        "origin",
        &f.key_store.path,
        true,
        f.tracked_names(),
    )
    .expect("hide");
    let old_ciphertext = fs::read(f.repo.join(".env.secret")).unwrap();

    // Rotate the ring: bob joins. The pass is stamped as due.
    let bob = f.add_collab("bob@example.com");
    f.import_id(&bob, "bob.age");

    cmd_hide_all(&f.repo.path, "origin", &f.key_store.path, false).expect("the ceremony pass");

    // Every tracked ciphertext was re-encrypted to the current ring: fresh
    // bytes, and bob - who was never in the old ring - can reveal.
    assert_ne!(
        fs::read(f.repo.join(".env.secret")).unwrap(),
        old_ciphertext,
        "the pass rewrote the ciphertext to the new ring"
    );
    cmd_reveal(
        &f.repo.path,
        "bob@example.com",
        "origin",
        &f.key_store.path,
        vec![".env".to_string(), "config.yml".to_string()],
    )
    .expect("the new collaborator decrypts the passed ciphertexts");
    assert_eq!(fs::read(f.repo.join(".env")).unwrap(), b"API_KEY=1\n");
    assert_eq!(fs::read(f.repo.join("config.yml")).unwrap(), b"config\n");
}

#[test]
fn test_a_scoped_hide_needs_no_stamp_and_consumes_none() {
    let f = Fixture::new("scoped-hide-stamp");

    let id = f.add_collab("alice@example.com");
    f.import_id(&id, "alice.age");

    f.add_file(".env", b"API_KEY=1\n");
    f.add_file("config.yml", b"config\n");

    // The pass is due (tell stamped it), and the scoped hide ignores the
    // stamp both ways: it runs, and it leaves the pass armed.
    cmd_hide(
        &f.repo.path,
        "origin",
        &f.key_store.path,
        false,
        vec![".env".to_string()],
    )
    .expect("scoped hide");
    assert!(f.repo.join(".env.secret").exists());
    assert!(
        !f.repo.join("config.yml.secret").exists(),
        "the scoped hide covers exactly the named file"
    );
    assert!(
        RingPassStore::read(&f.key_store.path, TEST_REPO_ID)
            .unwrap()
            .is_some(),
        "the scoped hide never consumes the stamp"
    );

    // And the ceremony still runs afterwards against the same stamp.
    cmd_hide_all(&f.repo.path, "origin", &f.key_store.path, false)
        .expect("the pass runs after a scoped hide");
    assert!(f.repo.join("config.yml.secret").exists());
}
