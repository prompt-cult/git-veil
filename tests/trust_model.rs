//! Trust model tests: trust pin, fail-closed on missing/mismatched pin,
//! wrong signing key rejected, re-trust replaces pin.

use age::secrecy::ExposeSecret;
use git_veil::{
    cmd_hide, cmd_import, cmd_init, cmd_tell, cmd_trust, cmd_verify_keyring,
    generate_identity, generate_signing_keypair,
    recipient_from_identity,
    TrustPinStore, TrustStore,
};
use std::fs;
use std::path::Path;

struct TempDir {
    path: std::path::PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        let pid = std::process::id();
        let counter = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("git-veil-trust-{}-{}-{}", label, pid, counter));
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

fn setup_trust(repo: &TempDir, key_store: &TempDir) -> (ed25519_dalek::SigningKey, String) {
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

    (signing_key, verifying_hex)
}

// ---------------------------------------------------------------------------
// No trust pin -> verify-keyring fails closed
// ---------------------------------------------------------------------------

#[test]
fn test_no_pin_fails_closed() {
    let repo = TempDir::new("no-pin");
    let key_store = TempDir::new("no-pin-ks");
    init_git_repo(&repo.path);
    cmd_init(&repo.path).expect("init");

    // Write trust.json with an entry but no local pin
    let mut trust = TrustStore::new();
    trust.add_trust(TEST_REPO_ID.to_string(), "deadbeefdeadbeef".to_string());
    trust.save_to_file(&repo.join(".git-veil/trust.json")).unwrap();

    let result = cmd_verify_keyring(&repo.path, "origin", &key_store.path);
    assert!(result.is_err(), "should fail without local pin");
    assert!(result.unwrap_err().to_string().contains("no local pin"));
}

// ---------------------------------------------------------------------------
// Mismatched pin -> verify-keyring fails closed
// ---------------------------------------------------------------------------

#[test]
fn test_mismatched_pin_fails_closed() {
    let repo = TempDir::new("mismatch-pin");
    let key_store = TempDir::new("mismatch-pin-ks");
    init_git_repo(&repo.path);

    let (_, _verifying_hex) = setup_trust(&repo, &key_store);

    // Overwrite the pin with a different fingerprint
    TrustPinStore::write_pin(&key_store.path, TEST_REPO_ID, "ffffffffffffffff").unwrap();

    let result = cmd_verify_keyring(&repo.path, "origin", &key_store.path);
    assert!(result.is_err(), "should fail with mismatched pin");
    assert!(result.unwrap_err().to_string().contains("changed"));
}

// ---------------------------------------------------------------------------
// Correct pin -> verify-keyring succeeds
// ---------------------------------------------------------------------------

#[test]
fn test_correct_pin_succeeds() {
    let repo = TempDir::new("correct-pin");
    let key_store = TempDir::new("correct-pin-ks");
    init_git_repo(&repo.path);

    setup_trust(&repo, &key_store);

    cmd_verify_keyring(&repo.path, "origin", &key_store.path).expect("should succeed");
}

// ---------------------------------------------------------------------------
// Re-trust with a new key replaces the pin
// ---------------------------------------------------------------------------

#[test]
fn test_retrust_replaces_pin() {
    let repo = TempDir::new("retrust");
    let key_store = TempDir::new("retrust-ks");
    init_git_repo(&repo.path);

    setup_trust(&repo, &key_store);

    let old_pin = TrustPinStore::read_pin(&key_store.path, TEST_REPO_ID).unwrap().unwrap();

    // Generate a new signing key and re-trust
    let identity = generate_identity();
    let recipient = recipient_from_identity(&identity);
    let (new_signing_key, new_verifying_hex) = generate_signing_keypair();

    fs::write(repo.join("owner2.signing"), format!("{}\n{}\n", new_verifying_hex, recipient)).unwrap();
    fs::write(
        key_store.join("signing-keys.txt"),
        format!("{}\n", hex::encode(new_signing_key.to_bytes())),
    )
    .unwrap();

    cmd_trust(&repo.path, TEST_REPO_ID, "owner2.signing", "origin", &key_store.path)
        .expect("re-trust");

    let new_pin = TrustPinStore::read_pin(&key_store.path, TEST_REPO_ID).unwrap().unwrap();
    assert_ne!(old_pin, new_pin, "pin should be replaced");

    cmd_verify_keyring(&repo.path, "origin", &key_store.path).expect("should succeed with new pin");
}

// ---------------------------------------------------------------------------
// Hide fails without trust
// ---------------------------------------------------------------------------

#[test]
fn test_hide_fails_without_trust() {
    let repo = TempDir::new("hide-no-trust");
    let key_store = TempDir::new("hide-no-trust-ks");
    init_git_repo(&repo.path);
    cmd_init(&repo.path).expect("init");

    let result = cmd_hide(&repo.path, "origin", &key_store.path);
    assert!(result.is_err(), "hide should fail without trust");
}

// ---------------------------------------------------------------------------
// Tell fails without trust
// ---------------------------------------------------------------------------

#[test]
fn test_tell_fails_without_trust() {
    let repo = TempDir::new("tell-no-trust");
    let key_store = TempDir::new("tell-no-trust-ks");
    init_git_repo(&repo.path);
    cmd_init(&repo.path).expect("init");

    let id = generate_identity();
    let r = recipient_from_identity(&id);
    fs::write(repo.join("alice.recipient"), &r).unwrap();

    let result = cmd_tell(
        &repo.path,
        "alice@example.com",
        "alice.recipient",
        "origin",
        &key_store.path,
        None,
    );
    assert!(result.is_err(), "tell should fail without trust");
}

// ---------------------------------------------------------------------------
// Unsigned keyring with entries fails verification
// ---------------------------------------------------------------------------

#[test]
fn test_unsigned_keyring_with_entries_fails() {
    let repo = TempDir::new("unsigned");
    let key_store = TempDir::new("unsigned-ks");
    init_git_repo(&repo.path);

    setup_trust(&repo, &key_store);

    // Write a keyring with entries but no signature
    let keyring_content = "-----BEGIN GIT-VEIL KEYRING-----\nalice@example.com:age1xxx:deadbeef\n-----END GIT-VEIL KEYRING-----\n";
    fs::write(repo.join(".git-veil/keyring"), keyring_content).unwrap();

    let result = cmd_verify_keyring(&repo.path, "origin", &key_store.path);
    assert!(result.is_err(), "unsigned keyring with entries should fail");
    assert!(result.unwrap_err().to_string().contains("no signature"));
}

// ---------------------------------------------------------------------------
// Empty keyring with no signature is OK (fresh-init state)
// ---------------------------------------------------------------------------

#[test]
fn test_empty_keyring_no_signature_ok() {
    let repo = TempDir::new("empty-kr");
    let key_store = TempDir::new("empty-kr-ks");
    init_git_repo(&repo.path);

    setup_trust(&repo, &key_store);

    // Fresh keyring has no entries and no signature - should verify OK
    cmd_verify_keyring(&repo.path, "origin", &key_store.path)
        .expect("empty keyring should verify");
}
