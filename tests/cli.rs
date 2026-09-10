//! CLI integration tests for the age + Ed25519 crypto stack.
//!
//! These tests exercise the full command pipeline (init -> trust -> tell -> add ->
//! hide -> reveal/cat/unhide/changes -> removeperson -> verify-keyring -> clean)
//! using temporary git repositories and in-memory age identities + Ed25519
//! signing keys. No PGP, no external key servers, no passphrases.

use age::secrecy::ExposeSecret;
use git_veil::{
    cmd_add, cmd_cat, cmd_changes, cmd_clean, cmd_hide, cmd_import, cmd_init, cmd_list_keys,
    cmd_remove, cmd_removekey, cmd_removeperson, cmd_reveal, cmd_show_repo_id, cmd_tell, cmd_trust,
    cmd_unhide, cmd_verify_keyring, cmd_whoami, export_public_key, fingerprint_for_recipient,
    generate_identity, generate_signing_keypair, recipient_from_identity, Keyring, TrackedFiles,
    TrustPinStore, TrustStore,
};
use std::fs;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Test harness helpers
// ---------------------------------------------------------------------------

/// Unique scratch directory per test, cleaned up on drop.
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        let pid = std::process::id();
        let counter = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("git-veil-test-{}-{}-{}", label, pid, counter));
        fs::create_dir_all(&dir).expect("create temp dir");
        Self { path: dir }
    }

    fn join(&self, rel: &str) -> PathBuf {
        self.path.join(rel)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Initialises a git repo with a remote so `derive_repo_id` works.
fn init_git_repo(dir: &Path) {
    let status = std::process::Command::new("git")
        .current_dir(dir)
        .args(["init", "--quiet"])
        .status()
        .expect("git init");
    assert!(status.success(), "git init failed");

    let status = std::process::Command::new("git")
        .current_dir(dir)
        .args(["config", "user.email", "owner@example.com"])
        .status()
        .expect("git config user.email");
    assert!(status.success());

    let status = std::process::Command::new("git")
        .current_dir(dir)
        .args(["config", "user.name", "Test Owner"])
        .status()
        .expect("git config user.name");
    assert!(status.success());

    let status = std::process::Command::new("git")
        .current_dir(dir)
        .args(["remote", "add", "origin", "git@github.com:owner/fara.git"])
        .status()
        .expect("git remote add");
    assert!(status.success());
}

/// The repo_id that `derive_repo_id` will produce for the test remote.
const TEST_REPO_ID: &str = "fara+owner@github.com";

/// A complete test fixture: git repo, key store, owner identity, owner signing key.
struct TestRepo {
    repo: TempDir,
    key_store: TempDir,
    _owner_identity: age::x25519::Identity,
    owner_recipient: String,
    _owner_signing_key: ed25519_dalek::SigningKey,
    _owner_verifying_key_hex: String,
}

impl TestRepo {
    /// Creates a git repo, key store, generates owner keys, writes the signing
    /// key file, runs init + trust.
    fn new(label: &str) -> Self {
        let repo = TempDir::new(label);
        let key_store = TempDir::new(&format!("{}-keys", label));

        init_git_repo(&repo.path);

        let owner_identity = generate_identity();
        let owner_recipient = recipient_from_identity(&owner_identity);

        let (owner_signing_key, owner_verifying_key_hex) = generate_signing_keypair();

        let identity_file = repo.join("owner.age");
        fs::write(
            &identity_file,
            format!("{}\n", owner_identity.to_string().expose_secret()),
        )
        .expect("write identity file");

        let signing_key_file = repo.join("owner.signing");
        fs::write(
            &signing_key_file,
            format!("{}\n{}\n", owner_verifying_key_hex, owner_recipient),
        )
        .expect("write signing key file");

        fs::write(
            key_store.join("signing-keys.txt"),
            format!("{}\n", hex::encode(owner_signing_key.to_bytes())),
        )
        .expect("write signing-keys.txt");

        cmd_init(&repo.path).expect("init");

        cmd_import(&repo.path, &["owner.age".to_string()], &key_store.path)
            .expect("import owner identity");

        cmd_trust(
            &repo.path,
            TEST_REPO_ID,
            "owner.signing",
            "origin",
            &key_store.path,
        )
        .expect("trust");

        Self {
            repo,
            key_store,
            _owner_identity: owner_identity,
            owner_recipient,
            _owner_signing_key: owner_signing_key,
            _owner_verifying_key_hex: owner_verifying_key_hex,
        }
    }

    /// Generates a collaborator identity, writes their recipient to a file,
    /// and runs tell to add them to the keyring.
    fn add_collaborator(&self, email: &str) -> (age::x25519::Identity, String) {
        let collab_identity = generate_identity();
        let collab_recipient = recipient_from_identity(&collab_identity);

        let key_file = self.repo.join(&format!("{}.recipient", email));
        fs::write(&key_file, &collab_recipient).expect("write collab recipient file");

        cmd_tell(
            &self.repo.path,
            email,
            &format!("{}.recipient", email),
            "origin",
            &self.key_store.path,
            None,
        )
        .expect("tell");

        (collab_identity, collab_recipient)
    }

    /// Imports a collaborator identity into the key store (for reveal).
    fn import_identity(&self, identity: &age::x25519::Identity, filename: &str) {
        let path = self.repo.join(filename);
        fs::write(&path, format!("{}\n", identity.to_string().expose_secret()))
            .expect("write identity file");
        cmd_import(
            &self.repo.path,
            &[filename.to_string()],
            &self.key_store.path,
        )
        .expect("import identity");
    }

    /// Creates a plaintext file and tracks it.
    fn add_file(&self, name: &str, content: &[u8]) {
        let path = self.repo.join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent dir");
        }
        fs::write(&path, content).expect("write plaintext file");
        cmd_add(&self.repo.path, vec![name.to_string()]).expect("add file");
    }
}

// ---------------------------------------------------------------------------
// init
// ---------------------------------------------------------------------------

#[test]
fn test_init_creates_state() {
    let repo = TempDir::new("init");
    init_git_repo(&repo.path);

    cmd_init(&repo.path).expect("init");

    assert!(repo.join(".git-veil").is_dir());
    assert!(repo.join(".git-veil/keyring").exists());
    assert!(repo.join(".git-veil/trust.json").exists());
    assert!(repo.join(".git-veil/tracked.json").exists());

    let keyring_text = fs::read_to_string(repo.join(".git-veil/keyring")).unwrap();
    let keyring = Keyring::parse(&keyring_text).expect("parse keyring");
    assert!(keyring.entries.is_empty());
}

#[test]
fn test_init_refuses_reinit_with_trust() {
    let repo = TempDir::new("reinit");
    init_git_repo(&repo.path);

    cmd_init(&repo.path).expect("first init");

    let mut trust = TrustStore::new();
    trust.add_trust("test+user@github.com".to_string(), "abc123".to_string());
    trust
        .save_to_file(&repo.join(".git-veil/trust.json"))
        .unwrap();

    let result = cmd_init(&repo.path);
    assert!(result.is_err(), "re-init with trust should fail");
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("already initialized"));
}

// ---------------------------------------------------------------------------
// trust
// ---------------------------------------------------------------------------

#[test]
fn test_trust_wrong_repo_id_fails() {
    let repo = TempDir::new("trust-wrong-id");
    let key_store = TempDir::new("trust-wrong-id-keys");
    init_git_repo(&repo.path);
    cmd_init(&repo.path).expect("init");

    let (signing_key, verifying_hex) = generate_signing_keypair();
    fs::write(repo.join("owner.signing"), format!("{}\n", verifying_hex)).unwrap();
    fs::write(
        key_store.join("signing-keys.txt"),
        format!("{}\n", hex::encode(signing_key.to_bytes())),
    )
    .unwrap();

    let result = cmd_trust(
        &repo.path,
        "wrong+id@github.com",
        "owner.signing",
        "origin",
        &key_store.path,
    );
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("mismatch"));
}

#[test]
fn test_trust_writes_pin() {
    let repo = TempDir::new("trust-pin");
    let key_store = TempDir::new("trust-pin-keys");
    init_git_repo(&repo.path);
    cmd_init(&repo.path).expect("init");

    let (signing_key, verifying_hex) = generate_signing_keypair();
    fs::write(repo.join("owner.signing"), format!("{}\n", verifying_hex)).unwrap();
    fs::write(
        key_store.join("signing-keys.txt"),
        format!("{}\n", hex::encode(signing_key.to_bytes())),
    )
    .unwrap();

    cmd_trust(
        &repo.path,
        TEST_REPO_ID,
        "owner.signing",
        "origin",
        &key_store.path,
    )
    .expect("trust");

    let pin = TrustPinStore::read_pin(&key_store.path, TEST_REPO_ID).unwrap();
    assert!(pin.is_some());

    let trust = TrustStore::load_from_file(&repo.join(".git-veil/trust.json")).unwrap();
    assert!(trust.get_trusted_fingerprint(TEST_REPO_ID).is_some());
}

// ---------------------------------------------------------------------------
// tell + verify-keyring
// ---------------------------------------------------------------------------

#[test]
fn test_tell_adds_collaborator() {
    let fixture = TestRepo::new("tell");

    let (_, recipient) = fixture.add_collaborator("alice@example.com");

    let keyring_text = fs::read_to_string(fixture.repo.join(".git-veil/keyring")).unwrap();
    let keyring = Keyring::parse(&keyring_text).expect("parse keyring");
    assert_eq!(keyring.entries.len(), 1);
    assert_eq!(keyring.entries[0].email, "alice@example.com");
    assert_eq!(keyring.entries[0].recipient, recipient);
    assert!(keyring.signature.is_some(), "keyring should be signed");
}

#[test]
fn test_tell_canary_encrypts_before_signing() {
    let fixture = TestRepo::new("tell-canary");

    fs::write(
        fixture.repo.join("bad.recipient"),
        "not-a-valid-recipient\n",
    )
    .unwrap();

    let result = cmd_tell(
        &fixture.repo.path,
        "bob@example.com",
        "bad.recipient",
        "origin",
        &fixture.key_store.path,
        None,
    );
    assert!(result.is_err(), "tell with bad key should fail");
}

#[test]
fn test_verify_keyring_succeeds_after_tell() {
    let fixture = TestRepo::new("verify");

    fixture.add_collaborator("alice@example.com");

    cmd_verify_keyring(&fixture.repo.path, "origin", &fixture.key_store.path)
        .expect("verify-keyring should succeed");
}

#[test]
fn test_verify_keyring_fails_without_trust() {
    let repo = TempDir::new("verify-no-trust");
    let key_store = TempDir::new("verify-no-trust-keys");
    init_git_repo(&repo.path);
    cmd_init(&repo.path).expect("init");

    let result = cmd_verify_keyring(&repo.path, "origin", &key_store.path);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// add + list + remove
// ---------------------------------------------------------------------------

#[test]
fn test_add_and_list_files() {
    let fixture = TestRepo::new("add-list");

    fs::write(fixture.repo.join(".env"), "SECRET=hello\n").unwrap();
    cmd_add(&fixture.repo.path, vec![".env".to_string()]).expect("add .env");

    fs::write(fixture.repo.join("config.yml"), "key: value\n").unwrap();
    cmd_add(&fixture.repo.path, vec!["config.yml".to_string()]).expect("add config.yml");

    let tracked = TrackedFiles::load(&fixture.repo.join(".git-veil/tracked.json")).unwrap();
    assert_eq!(tracked.files.len(), 2);
    assert!(tracked.files.contains(&PathBuf::from(".env")));
    assert!(tracked.files.contains(&PathBuf::from("config.yml")));
}

#[test]
fn test_remove_untracks_file() {
    let fixture = TestRepo::new("remove");

    fs::write(fixture.repo.join(".env"), "SECRET=hello\n").unwrap();
    cmd_add(&fixture.repo.path, vec![".env".to_string()]).expect("add");

    cmd_remove(&fixture.repo.path, vec![".env".to_string()]).expect("remove");

    let tracked = TrackedFiles::load(&fixture.repo.join(".git-veil/tracked.json")).unwrap();
    assert!(tracked.files.is_empty());
}

// ---------------------------------------------------------------------------
// hide + reveal
// ---------------------------------------------------------------------------

#[test]
fn test_hide_reveal_roundtrip() {
    let fixture = TestRepo::new("hide-reveal");

    let (collab_identity, _) = fixture.add_collaborator("alice@example.com");
    fixture.import_identity(&collab_identity, "alice.age");

    let plaintext = b"SECRET=value\nAPI_KEY=abc123\n";
    fixture.add_file(".env", plaintext);

    cmd_hide(&fixture.repo.path, "origin", &fixture.key_store.path, false).expect("hide");

    // git-secret does NOT delete plaintext by default -- both exist
    assert!(
        fixture.repo.join(".env").exists(),
        "plaintext should still exist"
    );
    assert!(
        fixture.repo.join(".env.secret").exists(),
        "ciphertext should exist"
    );

    cmd_reveal(
        &fixture.repo.path,
        "alice@example.com",
        "origin",
        &fixture.key_store.path,
    )
    .expect("reveal");

    let revealed = fs::read(fixture.repo.join(".env")).unwrap();
    assert_eq!(revealed, plaintext);
    // git-secret does NOT delete ciphertext on reveal -- both exist
    assert!(
        fixture.repo.join(".env.secret").exists(),
        "ciphertext should still exist"
    );
}

#[test]
fn test_hide_creates_valid_age_ciphertext() {
    let fixture = TestRepo::new("hide-format");

    let (collab_identity, _) = fixture.add_collaborator("alice@example.com");
    fixture.import_identity(&collab_identity, "alice.age");

    fixture.add_file(".env", b"test data\n");

    cmd_hide(&fixture.repo.path, "origin", &fixture.key_store.path, false).expect("hide");

    // age ciphertext starts with the age header bytes
    let ciphertext = fs::read(fixture.repo.join(".env.secret")).unwrap();
    assert!(!ciphertext.is_empty(), "ciphertext should not be empty");
    // age binary format starts with "age-encryption.org/v1"
    assert!(
        ciphertext.starts_with(b"age-encryption.org"),
        "should be age format"
    );
}

#[test]
fn test_hide_no_tracked_files_is_ok() {
    let fixture = TestRepo::new("hide-empty");
    fixture.add_collaborator("alice@example.com");

    cmd_hide(&fixture.repo.path, "origin", &fixture.key_store.path, false)
        .expect("hide with no tracked files");
}

#[test]
fn test_hide_no_keys_fails() {
    let repo = TempDir::new("hide-no-keys");
    let key_store = TempDir::new("hide-no-keys-keys");
    init_git_repo(&repo.path);

    let identity = generate_identity();
    let recipient = recipient_from_identity(&identity);
    let (signing_key, verifying_hex) = generate_signing_keypair();

    fs::write(
        repo.join("owner.age"),
        format!("{}\n", identity.to_string().expose_secret()),
    )
    .unwrap();
    fs::write(
        repo.join("owner.signing"),
        format!("{}\n{}\n", verifying_hex, recipient),
    )
    .unwrap();
    fs::write(
        key_store.join("signing-keys.txt"),
        format!("{}\n", hex::encode(signing_key.to_bytes())),
    )
    .unwrap();

    cmd_init(&repo.path).expect("init");
    cmd_import(&repo.path, &["owner.age".to_string()], &key_store.path).expect("import");
    cmd_trust(
        &repo.path,
        TEST_REPO_ID,
        "owner.signing",
        "origin",
        &key_store.path,
    )
    .expect("trust");

    fs::write(repo.join(".env"), "SECRET=hello\n").unwrap();
    cmd_add(&repo.path, vec![".env".to_string()]).expect("add");

    let result = cmd_hide(&repo.path, "origin", &key_store.path, false);
    assert!(result.is_err(), "hide with no keys should fail");
}

// ---------------------------------------------------------------------------
// cat
// ---------------------------------------------------------------------------

#[test]
fn test_cat_decrypts_to_stdout() {
    let fixture = TestRepo::new("cat");

    let (collab_identity, _) = fixture.add_collaborator("alice@example.com");
    fixture.import_identity(&collab_identity, "alice.age");

    let plaintext = b"cat me\n";
    fixture.add_file(".env", plaintext);

    cmd_hide(&fixture.repo.path, "origin", &fixture.key_store.path, false).expect("hide");

    let result = cmd_cat(
        &fixture.repo.path,
        ".env",
        "alice@example.com",
        "origin",
        &fixture.key_store.path,
    )
    .expect("cat");

    assert_eq!(result, plaintext);
    // cat should not touch disk -- both plaintext and ciphertext exist
    assert!(
        fixture.repo.join(".env").exists(),
        "cat should not delete plaintext"
    );
    assert!(
        fixture.repo.join(".env.secret").exists(),
        "cat should not delete ciphertext"
    );
}

#[test]
fn test_cat_untracked_file_fails() {
    let fixture = TestRepo::new("cat-untracked");

    let (collab_identity, _) = fixture.add_collaborator("alice@example.com");
    fixture.import_identity(&collab_identity, "alice.age");

    fixture.add_file(".env", b"secret\n");
    cmd_hide(&fixture.repo.path, "origin", &fixture.key_store.path, false).expect("hide");

    fs::write(fixture.repo.join("other.txt"), b"other\n").unwrap();
    let result = cmd_cat(
        &fixture.repo.path,
        "other.txt",
        "alice@example.com",
        "origin",
        &fixture.key_store.path,
    );
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// unhide
// ---------------------------------------------------------------------------

#[test]
fn test_unhide_single_file() {
    let fixture = TestRepo::new("unhide");

    let (collab_identity, _) = fixture.add_collaborator("alice@example.com");
    fixture.import_identity(&collab_identity, "alice.age");

    fixture.add_file(".env", b"unhide me\n");
    fixture.add_file("config.yml", b"keep hidden\n");

    cmd_hide(&fixture.repo.path, "origin", &fixture.key_store.path, false).expect("hide");

    cmd_unhide(
        &fixture.repo.path,
        ".env",
        "alice@example.com",
        "origin",
        &fixture.key_store.path,
    )
    .expect("unhide");

    // unhide restores plaintext, does NOT delete ciphertext (matches git-secret)
    assert!(fixture.repo.join(".env").exists());
    assert!(
        fixture.repo.join(".env.secret").exists(),
        "ciphertext should still exist"
    );
    // other file still has both plaintext and ciphertext
    assert!(fixture.repo.join("config.yml").exists());
    assert!(fixture.repo.join("config.yml.secret").exists());
}

// ---------------------------------------------------------------------------
// changes
// ---------------------------------------------------------------------------

#[test]
fn test_changes_detects_modification() {
    let fixture = TestRepo::new("changes");

    let (collab_identity, _) = fixture.add_collaborator("alice@example.com");
    fixture.import_identity(&collab_identity, "alice.age");

    fixture.add_file(".env", b"ORIGINAL=value\n");

    cmd_hide(&fixture.repo.path, "origin", &fixture.key_store.path, false).expect("hide");

    fs::write(fixture.repo.join(".env"), b"MODIFIED=different\n").unwrap();

    let changed = cmd_changes(
        &fixture.repo.path,
        vec![],
        "alice@example.com",
        "origin",
        &fixture.key_store.path,
    )
    .expect("changes");

    assert_eq!(changed.len(), 1);
    assert_eq!(changed[0], PathBuf::from(".env"));
}

#[test]
fn test_changes_no_modification() {
    let fixture = TestRepo::new("changes-none");

    let (collab_identity, _) = fixture.add_collaborator("alice@example.com");
    fixture.import_identity(&collab_identity, "alice.age");

    fixture.add_file(".env", b"SAME=value\n");

    cmd_hide(&fixture.repo.path, "origin", &fixture.key_store.path, false).expect("hide");

    fs::write(fixture.repo.join(".env"), b"SAME=value\n").unwrap();

    let changed = cmd_changes(
        &fixture.repo.path,
        vec![],
        "alice@example.com",
        "origin",
        &fixture.key_store.path,
    )
    .expect("changes");

    assert!(changed.is_empty(), "no changes expected");
}

// ---------------------------------------------------------------------------
// removeperson
// ---------------------------------------------------------------------------

#[test]
fn test_removeperson_removes_from_keyring() {
    let fixture = TestRepo::new("removeperson");

    fixture.add_collaborator("alice@example.com");
    fixture.add_collaborator("bob@example.com");

    cmd_removeperson(
        &fixture.repo.path,
        "alice@example.com",
        "origin",
        &fixture.key_store.path,
        None,
    )
    .expect("removeperson");

    let keyring_text = fs::read_to_string(fixture.repo.join(".git-veil/keyring")).unwrap();
    let keyring = Keyring::parse(&keyring_text).expect("parse keyring");
    assert_eq!(keyring.entries.len(), 1);
    assert_eq!(keyring.entries[0].email, "bob@example.com");
    assert!(keyring.signature.is_some(), "keyring should be re-signed");
}

#[test]
fn test_removeperson_not_in_keyring_fails() {
    let fixture = TestRepo::new("removeperson-missing");

    fixture.add_collaborator("alice@example.com");

    let result = cmd_removeperson(
        &fixture.repo.path,
        "nobody@example.com",
        "origin",
        &fixture.key_store.path,
        None,
    );
    assert!(result.is_err());
}

#[test]
fn test_removeperson_re_signs_keyring() {
    let fixture = TestRepo::new("removeperson-resign");

    fixture.add_collaborator("alice@example.com");

    let before = fs::read_to_string(fixture.repo.join(".git-veil/keyring")).unwrap();

    cmd_removeperson(
        &fixture.repo.path,
        "alice@example.com",
        "origin",
        &fixture.key_store.path,
        None,
    )
    .expect("removeperson");

    let after = fs::read_to_string(fixture.repo.join(".git-veil/keyring")).unwrap();
    assert_ne!(before, after);

    cmd_verify_keyring(&fixture.repo.path, "origin", &fixture.key_store.path)
        .expect("verify after removeperson");
}

// ---------------------------------------------------------------------------
// list-keys
// ---------------------------------------------------------------------------

#[test]
fn test_list_keys_succeeds() {
    let fixture = TestRepo::new("list-keys");

    fixture.add_collaborator("alice@example.com");
    fixture.add_collaborator("bob@example.com");

    cmd_list_keys(&fixture.repo.path, "origin", &fixture.key_store.path).expect("list-keys");
}

// ---------------------------------------------------------------------------
// show-repo-id
// ---------------------------------------------------------------------------

#[test]
fn test_show_repo_id() {
    let fixture = TestRepo::new("show-repo-id");

    cmd_show_repo_id(&fixture.repo.path, "origin").expect("show-repo-id");
}

// ---------------------------------------------------------------------------
// whoami
// ---------------------------------------------------------------------------

#[test]
fn test_whoami() {
    let fixture = TestRepo::new("whoami");

    cmd_whoami(&fixture.repo.path, None, &fixture.key_store.path).expect("whoami");
}

// ---------------------------------------------------------------------------
// export
// ---------------------------------------------------------------------------

#[test]
fn test_export_by_recipient() {
    let fixture = TestRepo::new("export");

    let (_, recipient) = fixture.add_collaborator("alice@example.com");

    // Import the collaborator's recipient to the key store so export can find it
    git_veil::import_recipient_to_store(&fixture.key_store.path, &recipient).unwrap();

    let exported = export_public_key(&fixture.key_store.path, &recipient).unwrap();
    assert_eq!(exported.trim(), recipient);
}

#[test]
fn test_export_by_fingerprint() {
    let fixture = TestRepo::new("export-fp");

    let (_, recipient) = fixture.add_collaborator("alice@example.com");
    let fingerprint = fingerprint_for_recipient(&recipient);

    // Import the collaborator's recipient to the key store so export can find it
    git_veil::import_recipient_to_store(&fixture.key_store.path, &recipient).unwrap();

    let exported = export_public_key(&fixture.key_store.path, &fingerprint).unwrap();
    assert_eq!(exported.trim(), recipient);
}

#[test]
fn test_export_not_found_fails() {
    let fixture = TestRepo::new("export-missing");

    let result = export_public_key(&fixture.key_store.path, "age1nonexistent");
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// removekey
// ---------------------------------------------------------------------------

#[test]
fn test_removekey_by_fingerprint() {
    let fixture = TestRepo::new("removekey");

    let (collab_identity, recipient) = fixture.add_collaborator("alice@example.com");
    fixture.import_identity(&collab_identity, "alice.age");

    let fingerprint = fingerprint_for_recipient(&recipient);

    cmd_removekey(&fixture.key_store.path, &fingerprint, false).expect("removekey");

    // The collaborator's identity should be gone; the owner's identity remains
    let identities = git_veil::load_identities_from_store(&fixture.key_store.path).unwrap();
    let collab_recipient = recipient_from_identity(&collab_identity);
    let found = identities.iter().any(|(_, r)| *r == collab_recipient);
    assert!(!found, "collaborator identity should be removed");
}

#[test]
fn test_removekey_refuses_corrupt_identity_line_and_names_it() {
    let fixture = TestRepo::new("removekey-corrupt");

    let (_collab_identity, recipient) = fixture.add_collaborator("alice@example.com");
    fixture.import_identity(&_collab_identity, "alice.age");
    let fingerprint = fingerprint_for_recipient(&recipient);

    // Corrupt the store: a truncated identity line the tool cannot parse
    let identities_path = fixture.key_store.path.join("identities.txt");
    let corrupt =
        fs::read_to_string(&identities_path).unwrap() + "AGE-SECRET-KEY-1TRUNCATEDGARBAGE\n";
    fs::write(&identities_path, &corrupt).unwrap();

    // Removing any key must refuse, exit 62, and name the corrupt line
    let err = cmd_removekey(&fixture.key_store.path, &fingerprint, false)
        .expect_err("removekey must refuse a corrupt store");
    let message = format!("{:#}", err);
    assert_eq!(
        git_veil::exit_code_of(&err),
        git_veil::ExitCode::KeyParseFailure as i32,
        "corrupt store line exits 62: {message}"
    );
    assert!(
        message.contains("AGE-SECRET-KEY-1TRUNCATEDGARBAGE"),
        "error names the corrupt line: {message}"
    );
    assert!(
        message.contains("identities.txt"),
        "error names the store file: {message}"
    );

    // The store is untouched: removekey never rewrites what it cannot parse
    let after = fs::read_to_string(&identities_path).unwrap();
    assert_eq!(after, corrupt, "store unchanged by the refused run");
}

#[test]
fn test_removekey_refuses_corrupt_recipient_line_and_names_it() {
    let fixture = TestRepo::new("removekey-corrupt-recipients");

    let (_identity, recipient) = fixture.add_collaborator("alice@example.com");
    let fingerprint = fingerprint_for_recipient(&recipient);
    git_veil::import_recipient_to_store(&fixture.key_store.path, &recipient).unwrap();

    // Corrupt the recipients store with a line that is not a parseable
    // age1... recipient
    let recipients_path = fixture.key_store.path.join("recipients.txt");
    let corrupt = fs::read_to_string(&recipients_path).unwrap() + "not-a-recipient\n";
    fs::write(&recipients_path, &corrupt).unwrap();

    let err = cmd_removekey(&fixture.key_store.path, &fingerprint, false)
        .expect_err("removekey must refuse a corrupt recipients store");
    let message = format!("{:#}", err);
    assert_eq!(
        git_veil::exit_code_of(&err),
        git_veil::ExitCode::KeyParseFailure as i32,
        "corrupt recipients.txt line exits 62: {message}"
    );
    assert!(
        message.contains("not-a-recipient"),
        "error names the corrupt line: {message}"
    );

    // The store is untouched: removekey never rewrites what it cannot parse
    let after = fs::read_to_string(&recipients_path).unwrap();
    assert_eq!(after, corrupt, "store unchanged by the refused run");
}

#[test]
fn test_removekey_only_identity_refuses_without_yes() {
    let fixture = TestRepo::new("removekey-only");

    let fingerprint = fingerprint_for_recipient(&fixture.owner_recipient);

    let result = cmd_removekey(&fixture.key_store.path, &fingerprint, false);
    assert!(result.is_err(), "should refuse to remove only identity");
    assert!(result.unwrap_err().to_string().contains("only identity"));
}

#[test]
fn test_removekey_only_identity_with_yes() {
    let fixture = TestRepo::new("removekey-only-yes");

    let fingerprint = fingerprint_for_recipient(&fixture.owner_recipient);

    cmd_removekey(&fixture.key_store.path, &fingerprint, true).expect("removekey with --yes");

    let identities = git_veil::load_identities_from_store(&fixture.key_store.path).unwrap();
    assert!(identities.is_empty());
}

// ---------------------------------------------------------------------------
// clean
// ---------------------------------------------------------------------------

#[test]
fn test_clean_refuses_without_yes() {
    let fixture = TestRepo::new("clean-refuse");

    fixture.add_collaborator("alice@example.com");
    fixture.add_file(".env", b"secret\n");

    let result = cmd_clean(&fixture.repo.path, false);
    assert!(result.is_err(), "clean should refuse without --yes");
}

#[test]
fn test_clean_with_yes() {
    let fixture = TestRepo::new("clean-yes");

    fixture.add_collaborator("alice@example.com");
    fixture.add_file(".env", b"secret\n");

    cmd_clean(&fixture.repo.path, true).expect("clean");

    assert!(!fixture.repo.join(".git-veil").exists());
}

#[test]
fn test_clean_empty_repo_no_yes_ok() {
    let fixture = TestRepo::new("clean-empty");

    cmd_clean(&fixture.repo.path, false).expect("clean empty repo");
    assert!(!fixture.repo.join(".git-veil").exists());
}

// ---------------------------------------------------------------------------
// Multi-recipient encryption
// ---------------------------------------------------------------------------

#[test]
fn test_multi_recipient_hide_reveal() {
    let fixture = TestRepo::new("multi-recipient");

    let (alice_identity, _) = fixture.add_collaborator("alice@example.com");
    let (bob_identity, _) = fixture.add_collaborator("bob@example.com");

    fixture.import_identity(&alice_identity, "alice.age");
    fixture.import_identity(&bob_identity, "bob.age");

    let plaintext = b"shared secret\n";
    fixture.add_file(".env", plaintext);

    cmd_hide(&fixture.repo.path, "origin", &fixture.key_store.path, false).expect("hide");

    cmd_reveal(
        &fixture.repo.path,
        "alice@example.com",
        "origin",
        &fixture.key_store.path,
    )
    .expect("alice reveal");

    let revealed = fs::read(fixture.repo.join(".env")).unwrap();
    assert_eq!(revealed, plaintext);

    // Re-hide for bob (plaintext still exists, hide does not delete it)
    cmd_hide(&fixture.repo.path, "origin", &fixture.key_store.path, false).expect("re-hide");

    cmd_reveal(
        &fixture.repo.path,
        "bob@example.com",
        "origin",
        &fixture.key_store.path,
    )
    .expect("bob reveal");

    let revealed = fs::read(fixture.repo.join(".env")).unwrap();
    assert_eq!(revealed, plaintext);
}

// ---------------------------------------------------------------------------
// Keyring tamper detection
// ---------------------------------------------------------------------------

#[test]
fn test_tampered_keyring_fails_verify() {
    let fixture = TestRepo::new("tamper");

    fixture.add_collaborator("alice@example.com");

    let keyring_path = fixture.repo.join(".git-veil/keyring");
    let original = fs::read_to_string(&keyring_path).unwrap();
    let tampered = original.replace("alice@example.com", "mallory@example.com");
    fs::write(&keyring_path, &tampered).unwrap();

    let result = cmd_verify_keyring(&fixture.repo.path, "origin", &fixture.key_store.path);
    assert!(result.is_err(), "tampered keyring should fail verification");
}

// ---------------------------------------------------------------------------
// Full lifecycle
// ---------------------------------------------------------------------------

#[test]
fn test_full_lifecycle() {
    let fixture = TestRepo::new("lifecycle");

    let (alice_identity, _) = fixture.add_collaborator("alice@example.com");
    let (bob_identity, _) = fixture.add_collaborator("bob@example.com");

    fixture.import_identity(&alice_identity, "alice.age");
    fixture.import_identity(&bob_identity, "bob.age");

    fixture.add_file(".env", b"ENV=production\n");
    fixture.add_file("config/secrets.yml", b"api_key: abc123\n");

    cmd_hide(&fixture.repo.path, "origin", &fixture.key_store.path, false).expect("hide");

    // git-secret does NOT delete plaintext by default -- both exist
    assert!(fixture.repo.join(".env").exists());
    assert!(fixture.repo.join(".env.secret").exists());
    assert!(fixture.repo.join("config/secrets.yml").exists());
    assert!(fixture.repo.join("config/secrets.yml.secret").exists());

    cmd_reveal(
        &fixture.repo.path,
        "alice@example.com",
        "origin",
        &fixture.key_store.path,
    )
    .expect("reveal");

    assert_eq!(
        fs::read(fixture.repo.join(".env")).unwrap(),
        b"ENV=production\n"
    );
    assert_eq!(
        fs::read(fixture.repo.join("config/secrets.yml")).unwrap(),
        b"api_key: abc123\n"
    );

    cmd_removeperson(
        &fixture.repo.path,
        "bob@example.com",
        "origin",
        &fixture.key_store.path,
        None,
    )
    .expect("removeperson");

    cmd_verify_keyring(&fixture.repo.path, "origin", &fixture.key_store.path)
        .expect("verify after removeperson");

    cmd_clean(&fixture.repo.path, true).expect("clean");
    assert!(!fixture.repo.join(".git-veil").exists());
}

// ---------------------------------------------------------------------------
// git-secret behavioural alignment tests
// ---------------------------------------------------------------------------

#[test]
fn test_hide_does_not_delete_plaintext() {
    let fixture = TestRepo::new("hide-keeps-plaintext");

    let (collab_identity, _) = fixture.add_collaborator("alice@example.com");
    fixture.import_identity(&collab_identity, "alice.age");

    fixture.add_file(".env", b"SECRET=value\n");

    cmd_hide(&fixture.repo.path, "origin", &fixture.key_store.path, false).expect("hide");

    assert!(
        fixture.repo.join(".env").exists(),
        "plaintext must NOT be deleted by hide"
    );
    assert!(
        fixture.repo.join(".env.secret").exists(),
        "ciphertext must exist"
    );
}

#[test]
fn test_hide_dangerously_delete_plaintext() {
    let fixture = TestRepo::new("hide-dangerously-delete");

    let (collab_identity, _) = fixture.add_collaborator("alice@example.com");
    fixture.import_identity(&collab_identity, "alice.age");

    fixture.add_file(".env", b"SECRET=value\n");

    cmd_hide(&fixture.repo.path, "origin", &fixture.key_store.path, true)
        .expect("hide with --dangerously-delete-plaintext");

    assert!(
        fixture.repo.join(".env.secret").exists(),
        "ciphertext must exist"
    );
    assert!(
        !fixture.repo.join(".env").exists(),
        "plaintext must be deleted by --dangerously-delete-plaintext"
    );
}

#[test]
fn test_reveal_does_not_delete_ciphertext() {
    let fixture = TestRepo::new("reveal-keeps-ciphertext");

    let (collab_identity, _) = fixture.add_collaborator("alice@example.com");
    fixture.import_identity(&collab_identity, "alice.age");

    fixture.add_file(".env", b"SECRET=value\n");

    cmd_hide(&fixture.repo.path, "origin", &fixture.key_store.path, false).expect("hide");

    cmd_reveal(
        &fixture.repo.path,
        "alice@example.com",
        "origin",
        &fixture.key_store.path,
    )
    .expect("reveal");

    assert!(
        fixture.repo.join(".env").exists(),
        "plaintext must exist after reveal"
    );
    assert!(
        fixture.repo.join(".env.secret").exists(),
        "ciphertext must NOT be deleted by reveal"
    );
}

#[test]
fn test_unhide_does_not_delete_ciphertext() {
    let fixture = TestRepo::new("unhide-keeps-ciphertext");

    let (collab_identity, _) = fixture.add_collaborator("alice@example.com");
    fixture.import_identity(&collab_identity, "alice.age");

    fixture.add_file(".env", b"SECRET=value\n");

    cmd_hide(&fixture.repo.path, "origin", &fixture.key_store.path, false).expect("hide");

    cmd_unhide(
        &fixture.repo.path,
        ".env",
        "alice@example.com",
        "origin",
        &fixture.key_store.path,
    )
    .expect("unhide");

    assert!(
        fixture.repo.join(".env").exists(),
        "plaintext must exist after unhide"
    );
    assert!(
        fixture.repo.join(".env.secret").exists(),
        "ciphertext must NOT be deleted by unhide"
    );
}

#[test]
fn test_add_auto_gitignores_file() {
    let fixture = TestRepo::new("add-gitignore");

    fs::write(fixture.repo.join("newsecret.txt"), b"secret\n").unwrap();

    // .gitignore does NOT contain newsecret.txt yet
    let gitignore = fs::read_to_string(fixture.repo.join(".gitignore")).unwrap_or_default();
    assert!(!gitignore.contains("newsecret.txt"));

    cmd_add(&fixture.repo.path, vec!["newsecret.txt".to_string()]).expect("add");

    // git-secret auto-adds the file to .gitignore -- git-veil must match
    let gitignore = fs::read_to_string(fixture.repo.join(".gitignore")).unwrap_or_default();
    assert!(
        gitignore.contains("newsecret.txt"),
        "add must auto-add file to .gitignore"
    );

    // git check-ignore must confirm
    let output = std::process::Command::new("git")
        .current_dir(&fixture.repo.path)
        .args(["check-ignore", "newsecret.txt"])
        .output()
        .expect("git check-ignore");
    assert!(
        output.status.success(),
        "git check-ignore must confirm the file is ignored"
    );
}

#[test]
fn test_cat_does_not_touch_disk() {
    let fixture = TestRepo::new("cat-no-disk");

    let (collab_identity, _) = fixture.add_collaborator("alice@example.com");
    fixture.import_identity(&collab_identity, "alice.age");

    fixture.add_file(".env", b"SECRET=value\n");

    cmd_hide(&fixture.repo.path, "origin", &fixture.key_store.path, false).expect("hide");

    let _ = cmd_cat(
        &fixture.repo.path,
        ".env",
        "alice@example.com",
        "origin",
        &fixture.key_store.path,
    )
    .expect("cat");

    assert!(
        fixture.repo.join(".env").exists(),
        "plaintext must not be touched by cat"
    );
    assert!(
        fixture.repo.join(".env.secret").exists(),
        "ciphertext must not be touched by cat"
    );
}
