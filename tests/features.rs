//! Feature tests: two-phase all-or-nothing semantics, multi-recipient,
//! keyring tamper detection, and subdirectory file handling.

use age::secrecy::ExposeSecret;
use git_veil::{
    cmd_add, cmd_cat, cmd_changes, cmd_hide, cmd_import, cmd_init, cmd_reveal,
    cmd_tell, cmd_trust, cmd_unhide, cmd_verify_keyring,
    generate_identity, generate_signing_keypair,
    recipient_from_identity,
    Keyring,
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

        let identity = generate_identity();
        let recipient = recipient_from_identity(&identity);
        let (signing_key, verifying_hex) = generate_signing_keypair();

        fs::write(repo.join("owner.age"), format!("{}\n", identity.to_string().expose_secret())).unwrap();
        fs::write(repo.join("owner.signing"), format!("{}\n{}\n", verifying_hex, recipient)).unwrap();
        fs::write(
            key_store.join("signing-keys.txt"),
            format!("{}\n", hex::encode(signing_key.to_bytes())),
        )
        .unwrap();

        cmd_init(&repo.path).expect("init");
        cmd_import(&repo.path, &["owner.age".to_string()], &key_store.path).expect("import");
        cmd_trust(&repo.path, TEST_REPO_ID, "owner.signing", "origin", &key_store.path).expect("trust");

        Self { repo, key_store }
    }

    fn add_collab(&self, email: &str) -> age::x25519::Identity {
        let id = generate_identity();
        let r = recipient_from_identity(&id);
        let fname = format!("{}.recipient", email);
        fs::write(self.repo.join(&fname), &r).unwrap();
        cmd_tell(&self.repo.path, email, &fname, "origin", &self.key_store.path, None).expect("tell");
        id
    }

    fn import_id(&self, id: &age::x25519::Identity, fname: &str) {
        fs::write(self.repo.join(fname), format!("{}\n", id.to_string().expose_secret())).unwrap();
        cmd_import(&self.repo.path, &[fname.to_string()], &self.key_store.path).expect("import");
    }

    fn add_file(&self, name: &str, content: &[u8]) {
        let p = self.repo.join(name);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&p, content).unwrap();
        cmd_add(&self.repo.path, vec![name.to_string()]).expect("add");
    }
}

// ---------------------------------------------------------------------------
// Two-phase all-or-nothing: hide aborts if a plaintext is missing
// ---------------------------------------------------------------------------

#[test]
fn test_hide_all_or_nothing_missing_plaintext() {
    let f = Fixture::new("aon-missing");

    let id = f.add_collab("alice@example.com");
    f.import_id(&id, "alice.age");

    f.add_file(".env", b"secret\n");
    f.add_file("config.yml", b"config\n");

    // Delete one plaintext before hide
    fs::remove_file(f.repo.join(".env")).unwrap();

    let result = cmd_hide(&f.repo.path, "origin", &f.key_store.path, false);
    assert!(result.is_err(), "hide should abort when a plaintext is missing");

    // The other file should NOT be encrypted (all-or-nothing)
    assert!(f.repo.join("config.yml").exists(), "config.yml should still be plaintext");
    assert!(!f.repo.join("config.yml.secret").exists(), "config.yml should not be encrypted");
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

    cmd_hide(&f.repo.path, "origin", &f.key_store.path, false).expect("hide");

    // Delete one ciphertext before reveal
    fs::remove_file(f.repo.join(".env.secret")).unwrap();

    let result = cmd_reveal(
        &f.repo.path,
        "alice@example.com",
        "origin",
        &f.key_store.path,
        None,
    );
    assert!(result.is_err(), "reveal should abort when a ciphertext is missing");

    // The other file should NOT be revealed (all-or-nothing)
    // config.yml still exists because hide does NOT delete plaintext
    assert!(f.repo.join("config.yml.secret").exists(), "config.yml.secret should still exist");
    assert!(f.repo.join("config.yml").exists(), "config.yml should still exist (hide does not delete plaintext)");
}

// ---------------------------------------------------------------------------
// Multi-recipient: both collaborators can decrypt the same ciphertext
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

    cmd_hide(&f.repo.path, "origin", &f.key_store.path, false).expect("hide");

    // Alice reveals
    cmd_reveal(&f.repo.path, "alice@example.com", "origin", &f.key_store.path, None).expect("alice reveal");
    assert_eq!(fs::read(f.repo.join(".env")).unwrap(), plaintext);

    // Re-hide and bob reveals (plaintext still exists, hide does not delete it)
    cmd_hide(&f.repo.path, "origin", &f.key_store.path, false).expect("re-hide");
    cmd_reveal(&f.repo.path, "bob@example.com", "origin", &f.key_store.path, None).expect("bob reveal");
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

    // Tamper: swap the recipient string
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

    cmd_hide(&f.repo.path, "origin", &f.key_store.path, false).expect("hide");

    // git-secret does NOT delete plaintext by default -- both exist
    assert!(f.repo.join("config/secrets.yml").exists());
    assert!(f.repo.join("config/secrets.yml.secret").exists());

    cmd_reveal(&f.repo.path, "alice@example.com", "origin", &f.key_store.path, None).expect("reveal");

    assert_eq!(fs::read(f.repo.join("config/secrets.yml")).unwrap(), plaintext);
    // git-secret does NOT delete ciphertext on reveal -- both exist
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
    cmd_hide(&f.repo.path, "origin", &f.key_store.path, false).expect("hide");

    let _ = cmd_cat(
        &f.repo.path,
        ".env",
        "alice@example.com",
        "origin",
        &f.key_store.path,
        None,
    )
    .expect("cat");

    // cat should not touch disk -- both plaintext and ciphertext exist
    assert!(f.repo.join(".env").exists(), "plaintext should still exist (hide does not delete)");
    assert!(f.repo.join(".env.secret").exists(), "ciphertext should not be deleted");
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

    cmd_hide(&f.repo.path, "origin", &f.key_store.path, false).expect("hide");

    cmd_unhide(&f.repo.path, ".env", "alice@example.com", "origin", &f.key_store.path, None)
        .expect("unhide .env");

    // unhide restores plaintext, does NOT delete ciphertext (matches git-secret)
    assert!(f.repo.join(".env").exists());
    assert!(f.repo.join(".env.secret").exists(), "ciphertext should still exist");
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

    cmd_hide(&f.repo.path, "origin", &f.key_store.path, false).expect("hide");

    // Write different binary
    fs::write(f.repo.join("data.bin"), vec![0u8, 1, 2, 3, 0, 255, 253]).unwrap();

    let changed = cmd_changes(
        &f.repo.path,
        vec![],
        "alice@example.com",
        "origin",
        &f.key_store.path,
        None,
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
    let id2 = generate_identity();
    let r2 = recipient_from_identity(&id2);
    fs::write(f.repo.join("alice2.recipient"), &r2).unwrap();
    cmd_tell(&f.repo.path, "alice@example.com", "alice2.recipient", "origin", &f.key_store.path, None)
        .expect("tell update");

    let keyring_text = fs::read_to_string(f.repo.join(".git-veil/keyring")).unwrap();
    let keyring = Keyring::parse(&keyring_text).expect("parse");
    assert_eq!(keyring.entries.len(), 1, "should still have one entry");
    assert_eq!(keyring.entries[0].recipient, r2, "recipient should be updated");
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
    assert!(keyring.signature.is_some(), "empty keyring should still be signed");

    cmd_verify_keyring(&f.repo.path, "origin", &f.key_store.path)
        .expect("verify empty signed keyring");
}
