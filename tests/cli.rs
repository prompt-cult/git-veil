//! CLI integration tests for the age + Ed25519 crypto stack.
//!
//! These tests exercise the full command pipeline (init -> trust -> tell -> add ->
//! hide -> reveal/cat/unhide/changes -> removeperson -> verify-keyring -> clean)
//! using temporary git repositories and in-memory X25519 private keys and
//! Ed25519 signing keys. No PGP, no external key servers, no passphrases.

use age::secrecy::ExposeSecret;
use clap::Parser as _;
use git_veil::cli::{Cli, Commands};
use git_veil::{
    cmd_add, cmd_cat, cmd_changes, cmd_clean, cmd_hide, cmd_import, cmd_init, cmd_list_keys,
    cmd_remove, cmd_removekey, cmd_removeperson, cmd_reveal, cmd_show_repo_id, cmd_tell, cmd_trust,
    cmd_unhide, cmd_verify_keyring, cmd_whoami, export_public_key, generate_signing_keypair,
    generate_x25519_private_key, x25519_public_key_encoding, Keyring, TrackedFiles, TrustStore,
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

/// A complete test fixture: git repo, key store, owner X25519 private key, owner signing key.
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

        let owner_identity = generate_x25519_private_key();
        let owner_recipient = x25519_public_key_encoding(&owner_identity);

        let (owner_signing_key, owner_verifying_key_hex) = generate_signing_keypair();

        let identity_file = repo.join("owner.age");
        fs::write(
            &identity_file,
            format!("{}\n", owner_identity.to_string().expose_secret()),
        )
        .expect("write identity file");

        // The committed owner.verifying: verifying key hex on line 1, the
        // owner's X25519 public key encoding on line 2. trust proves
        // possession of the matching seed and pins the key.
        fs::write(
            repo.join("owner.verifying"),
            format!("{}\n{}\n", owner_verifying_key_hex, owner_recipient),
        )
        .expect("write owner.verifying");

        fs::write(
            key_store.join("signing-keys.txt"),
            format!("{}\n", hex::encode(owner_signing_key.to_bytes())),
        )
        .expect("write signing-keys.txt");

        cmd_init(&repo.path, false).expect("init");

        cmd_import(&repo.path, &["owner.age".to_string()], &key_store.path)
            .expect("import owner identity");

        cmd_trust(&repo.path, TEST_REPO_ID, "origin", &key_store.path, false).expect("trust");

        Self {
            repo,
            key_store,
            _owner_identity: owner_identity,
            owner_recipient,
            _owner_signing_key: owner_signing_key,
            _owner_verifying_key_hex: owner_verifying_key_hex,
        }
    }

    /// Generates a collaborator key, writes the X25519 public key encoding
    /// to a file, and runs tell to add them to the keyring.
    fn add_collaborator(&self, email: &str) -> (age::x25519::Identity, String) {
        let collab_identity = generate_x25519_private_key();
        let collab_recipient = x25519_public_key_encoding(&collab_identity);

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

    /// Imports a collaborator's X25519 private key into the key store (for
    /// reveal).
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
// init
// ---------------------------------------------------------------------------

#[test]
fn test_init_creates_state() {
    let repo = TempDir::new("init");
    init_git_repo(&repo.path);

    cmd_init(&repo.path, false).expect("init");

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

    cmd_init(&repo.path, false).expect("first init");

    let mut trust = TrustStore::new();
    trust.set_owner_fingerprint("test+user@github.com".to_string(), "abc123".to_string());
    trust
        .save_to_file(&repo.join(".git-veil/trust.json"))
        .unwrap();

    let result = cmd_init(&repo.path, false);
    assert!(result.is_err(), "re-init with trust should fail");
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("already initialized"));
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
    assert_eq!(keyring.entries[0].public_key, recipient);
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
    cmd_init(&repo.path, false).expect("init");

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
    cmd_add(
        &fixture.repo.path,
        vec![".env".to_string()],
        "origin",
        &fixture.key_store.path,
    )
    .expect("add .env");

    fs::write(fixture.repo.join("config.yml"), "key: value\n").unwrap();
    cmd_add(
        &fixture.repo.path,
        vec!["config.yml".to_string()],
        "origin",
        &fixture.key_store.path,
    )
    .expect("add config.yml");

    let tracked = TrackedFiles::load(&fixture.repo.join(".git-veil/tracked.json")).unwrap();
    assert_eq!(tracked.files.len(), 2);
    assert!(tracked.files.contains(&PathBuf::from(".env")));
    assert!(tracked.files.contains(&PathBuf::from("config.yml")));
}

#[test]
fn test_remove_untracks_file() {
    let fixture = TestRepo::new("remove");

    fs::write(fixture.repo.join(".env"), "SECRET=hello\n").unwrap();
    cmd_add(
        &fixture.repo.path,
        vec![".env".to_string()],
        "origin",
        &fixture.key_store.path,
    )
    .expect("add");

    cmd_remove(&fixture.repo.path, vec![".env".to_string()], false).expect("remove");

    let tracked = TrackedFiles::load(&fixture.repo.join(".git-veil/tracked.json")).unwrap();
    assert!(tracked.files.is_empty());
}

// ---------------------------------------------------------------------------
// allow
// ---------------------------------------------------------------------------

#[test]
fn test_allow_parses_files_and_remote() {
    let cli = Cli::try_parse_from(["git-veil", "allow", ".env", "--remote", "upstream"])
        .expect("allow parses");
    match cli.command {
        Commands::Allow { files, remote } => {
            assert_eq!(files, vec![".env".to_string()]);
            assert_eq!(remote, "upstream");
        }
        _ => panic!("expected the Allow subcommand"),
    }
}

#[test]
fn test_allow_requires_a_file_argument() {
    let err = Cli::try_parse_from(["git-veil", "allow"]).unwrap_err();
    assert!(
        err.use_stderr(),
        "allow without files must be a usage error"
    );
}

#[test]
fn test_add_implies_allow_hide_does_not_refuse() {
    // The full pipeline: init -> trust -> tell -> add -> hide. add records
    // the allowance on this machine, so hide first-encrypts without an
    // exit-72 refusal. Without the allowance this hide would refuse: the
    // ciphertext is not in the git index yet.
    let fixture = TestRepo::new("add-implies-allow");

    let (collab_identity, _) = fixture.add_collaborator("alice@example.com");
    fixture.import_identity(&collab_identity, "alice.age");

    let plaintext = b"SECRET=value\n";
    fixture.add_file(".env", plaintext);

    cmd_hide(
        &fixture.repo.path,
        "origin",
        &fixture.key_store.path,
        true,
        fixture.tracked_names(),
    )
    .expect("hide must not refuse a path the user added on this machine");
    assert!(fixture.repo.join(".env.secret").exists());
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

    cmd_hide(
        &fixture.repo.path,
        "origin",
        &fixture.key_store.path,
        true,
        fixture.tracked_names(),
    )
    .expect("hide");

    // Both copies exist, matching git-secret, which does not delete the
    // plaintext by default.
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
        fixture.tracked_names(),
    )
    .expect("reveal");

    let revealed = fs::read(fixture.repo.join(".env")).unwrap();
    assert_eq!(revealed, plaintext);
    // Both copies exist, matching git-secret, which does not delete the
    // ciphertext on reveal.
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

    cmd_hide(
        &fixture.repo.path,
        "origin",
        &fixture.key_store.path,
        true,
        fixture.tracked_names(),
    )
    .expect("hide");

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
fn test_hide_no_keys_fails() {
    let repo = TempDir::new("hide-no-keys");
    let key_store = TempDir::new("hide-no-keys-keys");
    init_git_repo(&repo.path);

    let identity = generate_x25519_private_key();
    let recipient = x25519_public_key_encoding(&identity);
    let (signing_key, verifying_hex) = generate_signing_keypair();

    fs::write(
        repo.join("owner.age"),
        format!("{}\n", identity.to_string().expose_secret()),
    )
    .unwrap();
    fs::write(
        repo.join("owner.verifying"),
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

    fs::write(repo.join(".env"), "SECRET=hello\n").unwrap();
    cmd_add(
        &repo.path,
        vec![".env".to_string()],
        "origin",
        &key_store.path,
    )
    .expect("add");

    let result = cmd_hide(
        &repo.path,
        "origin",
        &key_store.path,
        true,
        vec![".env".to_string()],
    );
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

    cmd_hide(
        &fixture.repo.path,
        "origin",
        &fixture.key_store.path,
        true,
        fixture.tracked_names(),
    )
    .expect("hide");

    let result = cmd_cat(
        &fixture.repo.path,
        ".env",
        "alice@example.com",
        "origin",
        &fixture.key_store.path,
    )
    .expect("cat");

    assert_eq!(result, plaintext);
    // cat should not touch disk. Both plaintext and ciphertext exist.
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
    cmd_hide(
        &fixture.repo.path,
        "origin",
        &fixture.key_store.path,
        true,
        fixture.tracked_names(),
    )
    .expect("hide");

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

    cmd_hide(
        &fixture.repo.path,
        "origin",
        &fixture.key_store.path,
        true,
        fixture.tracked_names(),
    )
    .expect("hide");

    cmd_unhide(
        &fixture.repo.path,
        ".env",
        "alice@example.com",
        "origin",
        &fixture.key_store.path,
    )
    .expect("unhide");

    // unhide restores the plaintext and does not delete the ciphertext
    // (matching git-secret).
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

    cmd_hide(
        &fixture.repo.path,
        "origin",
        &fixture.key_store.path,
        true,
        fixture.tracked_names(),
    )
    .expect("hide");

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

    cmd_hide(
        &fixture.repo.path,
        "origin",
        &fixture.key_store.path,
        true,
        fixture.tracked_names(),
    )
    .expect("hide");

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
// --signing-key parse shape: full verifying key only
// ---------------------------------------------------------------------------

#[test]
fn test_tell_signing_key_index_form_is_a_parse_error() {
    let err = Cli::try_parse_from([
        "git-veil",
        "tell",
        "alice@example.com",
        "alice.pub",
        "--signing-key",
        "1",
    ])
    .unwrap_err();
    assert!(err.use_stderr(), "the index form must be rejected");
}

#[test]
fn test_tell_signing_key_fingerprint_form_is_a_parse_error() {
    // The 16-hex fingerprint form is not accepted. It must not even parse.
    let err = Cli::try_parse_from([
        "git-veil",
        "tell",
        "alice@example.com",
        "alice.pub",
        "--signing-key",
        "ABCDEF0123456789",
    ])
    .unwrap_err();
    assert!(err.use_stderr(), "the fingerprint form must be rejected");
}

#[test]
fn test_tell_signing_key_verifying_key_form_parses_normalized() {
    let cli = Cli::try_parse_from([
        "git-veil",
        "tell",
        "alice@example.com",
        "alice.pub",
        "--signing-key",
        &"A".repeat(64),
    ])
    .expect("the full verifying key form parses");
    match cli.command {
        Commands::Tell { signing_key, .. } => {
            assert_eq!(signing_key.as_deref(), Some("a".repeat(64).as_str()));
        }
        _ => panic!("expected the Tell subcommand"),
    }
}

#[test]
fn test_removeperson_signing_key_index_form_is_a_parse_error() {
    let err = Cli::try_parse_from([
        "git-veil",
        "removeperson",
        "alice@example.com",
        "--signing-key",
        "2",
    ])
    .unwrap_err();
    assert!(err.use_stderr(), "the index form must be rejected");
}

#[test]
fn test_removeperson_signing_key_fingerprint_form_is_a_parse_error() {
    let err = Cli::try_parse_from([
        "git-veil",
        "removeperson",
        "alice@example.com",
        "--signing-key",
        "0123456789abcdef",
    ])
    .unwrap_err();
    assert!(err.use_stderr(), "the fingerprint form must be rejected");
}

#[test]
fn test_removeperson_signing_key_verifying_key_form_parses() {
    let cli = Cli::try_parse_from([
        "git-veil",
        "removeperson",
        "alice@example.com",
        "--signing-key",
        &"b".repeat(64),
    ])
    .expect("the full verifying key form parses");
    match cli.command {
        Commands::RemovePerson { signing_key, .. } => {
            assert_eq!(signing_key.as_deref(), Some("b".repeat(64).as_str()));
        }
        _ => panic!("expected the RemovePerson subcommand"),
    }
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

/// The principal label is committed in the public keyring. It is a public
/// repository fact, so whoami prints it. This test drives the built
/// binary because the label is asserted on stdout.
#[test]
fn test_whoami_prints_the_principal_label() {
    let key_store = TempDir::new("whoami-principal-ks");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_git-veil"))
        .arg("whoami")
        .arg("--email")
        .arg("alice@example.com")
        .arg("--key-store")
        .arg(&key_store.path)
        .env("GIT_VEIL_SKIP_PERMISSIONS", "1")
        .output()
        .expect("run git-veil whoami");
    assert!(
        output.status.success(),
        "whoami failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    assert!(
        stdout.contains("alice@example.com"),
        "whoami prints the principal label: {stdout}"
    );
}

// ---------------------------------------------------------------------------
// export
// ---------------------------------------------------------------------------

#[test]
fn test_export_by_recipient() {
    let fixture = TestRepo::new("export");

    let (_, recipient) = fixture.add_collaborator("alice@example.com");

    // Import the collaborator's public key into the key store so export can
    // find it
    git_veil::import_x25519_public_key_to_store(&fixture.key_store.path, &recipient).unwrap();

    let exported = export_public_key(&fixture.key_store.path, &recipient).unwrap();
    assert_eq!(exported.trim(), recipient);
}

#[test]
fn test_export_by_fingerprint_is_not_an_identifier() {
    // Export selects by public key string only. A 64-hex binding
    // fingerprint is not an export identifier.
    let fixture = TestRepo::new("export-fp");

    let (_, recipient) = fixture.add_collaborator("alice@example.com");
    let fingerprint = git_veil::fingerprint_for_public_key("alice@example.com", &recipient);

    git_veil::import_x25519_public_key_to_store(&fixture.key_store.path, &recipient).unwrap();

    let result = export_public_key(&fixture.key_store.path, &fingerprint);
    assert!(
        result.is_err(),
        "a fingerprint must not select a key for export"
    );
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
fn test_removekey_by_recipient() {
    let fixture = TestRepo::new("removekey");

    let (collab_identity, recipient) = fixture.add_collaborator("alice@example.com");
    fixture.import_identity(&collab_identity, "alice.age");

    cmd_removekey(&fixture.key_store.path, &recipient, false).expect("removekey");

    // The collaborator's private key should be gone. The owner's private
    // key remains.
    let identities =
        git_veil::load_x25519_private_keys_from_store(&fixture.key_store.path).unwrap();
    let collab_recipient = x25519_public_key_encoding(&collab_identity);
    let found = identities.iter().any(|(_, r)| *r == collab_recipient);
    assert!(!found, "collaborator identity should be removed");
}

#[test]
fn test_removekey_by_fingerprint_is_not_an_identifier() {
    // Removekey selects by public key string only. A 64-hex binding
    // fingerprint removes nothing.
    let fixture = TestRepo::new("removekey-fp");

    let (collab_identity, recipient) = fixture.add_collaborator("alice@example.com");
    fixture.import_identity(&collab_identity, "alice.age");
    let fingerprint = git_veil::fingerprint_for_public_key("alice@example.com", &recipient);

    let result = cmd_removekey(&fixture.key_store.path, &fingerprint, false);
    assert!(
        result.is_err(),
        "a fingerprint must not select a key for removekey"
    );

    // Nothing was removed.
    let identities =
        git_veil::load_x25519_private_keys_from_store(&fixture.key_store.path).unwrap();
    let collab_recipient = x25519_public_key_encoding(&collab_identity);
    assert!(identities.iter().any(|(_, r)| *r == collab_recipient));
}

#[test]
fn test_removekey_refuses_corrupt_identity_line_and_names_it() {
    let fixture = TestRepo::new("removekey-corrupt");

    let (_collab_identity, recipient) = fixture.add_collaborator("alice@example.com");
    fixture.import_identity(&_collab_identity, "alice.age");

    // Corrupt the store: a truncated identities.txt line the tool cannot
    // parse
    let identities_path = fixture.key_store.path.join("identities.txt");
    let corrupt =
        fs::read_to_string(&identities_path).unwrap() + "AGE-SECRET-KEY-1TRUNCATEDGARBAGE\n";
    fs::write(&identities_path, &corrupt).unwrap();

    // Removing any key must refuse, exit 62, and name the corrupt line
    let err = cmd_removekey(&fixture.key_store.path, &recipient, false)
        .expect_err("removekey must refuse a corrupt store");
    let message = format!("{:#}", err);
    assert_eq!(
        git_veil::exit_code_of(&err),
        git_veil::ExitCode::KeyParseFailure as i32,
        "corrupt store line exits 62: {message}"
    );
    assert!(
        message.contains("corrupt key store line"),
        "error states the corrupt line: {message}"
    );

    // The store is untouched: removekey never rewrites what it cannot parse
    let after = fs::read_to_string(&identities_path).unwrap();
    assert_eq!(after, corrupt, "store unchanged by the refused run");
}

#[test]
fn test_removekey_refuses_corrupt_recipient_line_and_names_it() {
    let fixture = TestRepo::new("removekey-corrupt-recipients");

    let (_identity, recipient) = fixture.add_collaborator("alice@example.com");
    git_veil::import_x25519_public_key_to_store(&fixture.key_store.path, &recipient).unwrap();

    // Corrupt recipients.txt with a line that is not a parseable
    // age1... public key encoding
    let recipients_path = fixture.key_store.path.join("recipients.txt");
    let corrupt = fs::read_to_string(&recipients_path).unwrap() + "not-a-recipient\n";
    fs::write(&recipients_path, &corrupt).unwrap();

    let err = cmd_removekey(&fixture.key_store.path, &recipient, false)
        .expect_err("removekey must refuse a corrupt recipients store");
    let message = format!("{:#}", err);
    assert_eq!(
        git_veil::exit_code_of(&err),
        git_veil::ExitCode::KeyParseFailure as i32,
        "corrupt recipients.txt line exits 62: {message}"
    );
    assert!(
        message.contains("corrupt key store line"),
        "error states the corrupt line: {message}"
    );

    // The store is untouched: removekey never rewrites what it cannot parse
    let after = fs::read_to_string(&recipients_path).unwrap();
    assert_eq!(after, corrupt, "store unchanged by the refused run");
}

#[test]
fn test_removekey_only_private_key_refuses_without_yes() {
    let fixture = TestRepo::new("removekey-only");

    let result = cmd_removekey(&fixture.key_store.path, &fixture.owner_recipient, false);
    assert!(result.is_err(), "should refuse to remove only private key");
    assert!(result.unwrap_err().to_string().contains("only private key"));
}

#[test]
fn test_removekey_only_private_key_with_yes() {
    let fixture = TestRepo::new("removekey-only-yes");

    cmd_removekey(&fixture.key_store.path, &fixture.owner_recipient, true)
        .expect("removekey with --yes");

    let identities =
        git_veil::load_x25519_private_keys_from_store(&fixture.key_store.path).unwrap();
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
// Encryption to multiple keys
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

    cmd_hide(
        &fixture.repo.path,
        "origin",
        &fixture.key_store.path,
        true,
        fixture.tracked_names(),
    )
    .expect("hide");

    cmd_reveal(
        &fixture.repo.path,
        "alice@example.com",
        "origin",
        &fixture.key_store.path,
        fixture.tracked_names(),
    )
    .expect("alice reveal");

    let revealed = fs::read(fixture.repo.join(".env")).unwrap();
    assert_eq!(revealed, plaintext);

    // Re-hide for bob (plaintext still exists, hide does not delete it)
    cmd_hide(
        &fixture.repo.path,
        "origin",
        &fixture.key_store.path,
        true,
        fixture.tracked_names(),
    )
    .expect("re-hide");

    cmd_reveal(
        &fixture.repo.path,
        "bob@example.com",
        "origin",
        &fixture.key_store.path,
        fixture.tracked_names(),
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

    cmd_hide(
        &fixture.repo.path,
        "origin",
        &fixture.key_store.path,
        true,
        fixture.tracked_names(),
    )
    .expect("hide");

    // Both copies exist, matching git-secret, which does not delete the
    // plaintext by default.
    assert!(fixture.repo.join(".env").exists());
    assert!(fixture.repo.join(".env.secret").exists());
    assert!(fixture.repo.join("config/secrets.yml").exists());
    assert!(fixture.repo.join("config/secrets.yml.secret").exists());

    cmd_reveal(
        &fixture.repo.path,
        "alice@example.com",
        "origin",
        &fixture.key_store.path,
        fixture.tracked_names(),
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
// Plaintext lifecycle tests
//
// Hide deletes the plaintext by default. --keep-plaintext leaves both
// copies in place, matching git-secret.
// ---------------------------------------------------------------------------

#[test]
fn test_hide_keep_plaintext_leaves_both_copies() {
    let fixture = TestRepo::new("hide-keeps-plaintext");

    let (collab_identity, _) = fixture.add_collaborator("alice@example.com");
    fixture.import_identity(&collab_identity, "alice.age");

    fixture.add_file(".env", b"SECRET=value\n");

    cmd_hide(
        &fixture.repo.path,
        "origin",
        &fixture.key_store.path,
        true,
        fixture.tracked_names(),
    )
    .expect("hide");

    assert!(
        fixture.repo.join(".env").exists(),
        "plaintext must NOT be deleted by hide --keep-plaintext"
    );
    assert!(
        fixture.repo.join(".env.secret").exists(),
        "ciphertext must exist"
    );
}

#[test]
fn test_hide_deletes_plaintext_by_default() {
    let fixture = TestRepo::new("hide-deletes-plaintext");

    let (collab_identity, _) = fixture.add_collaborator("alice@example.com");
    fixture.import_identity(&collab_identity, "alice.age");

    fixture.add_file(".env", b"SECRET=value\n");

    cmd_hide(
        &fixture.repo.path,
        "origin",
        &fixture.key_store.path,
        false,
        fixture.tracked_names(),
    )
    .expect("hide (default deletes plaintext)");

    assert!(
        fixture.repo.join(".env.secret").exists(),
        "ciphertext must exist"
    );
    assert!(
        !fixture.repo.join(".env").exists(),
        "plaintext must be deleted by hide by default"
    );
}

#[test]
fn test_hide_of_an_already_hidden_name_refuses_at_resolution() {
    let fixture = TestRepo::new("hide-already-hidden");

    let (collab_identity, _) = fixture.add_collaborator("alice@example.com");
    fixture.import_identity(&collab_identity, "alice.age");

    fixture.add_file(".env", b"SECRET=value\n");
    cmd_hide(
        &fixture.repo.path,
        "origin",
        &fixture.key_store.path,
        false,
        vec![".env".to_string()],
    )
    .expect("hide");
    assert!(!fixture.repo.join(".env").exists());

    // The plaintext is deleted, so the name no longer exists on disk.
    // Naming it refuses: hide resolves paths the way add does. Reveal
    // restores the plaintext, then hide re-encrypts.
    let err = cmd_hide(
        &fixture.repo.path,
        "origin",
        &fixture.key_store.path,
        false,
        vec![".env".to_string()],
    )
    .expect_err("an absent plaintext does not resolve");
    assert!(
        format!("{:#}", err).contains(".env"),
        "the refusal names the unresolvable path"
    );
    assert!(
        fixture.repo.join(".env.secret").exists(),
        "ciphertext untouched by the refusal"
    );
}

#[test]
fn test_reveal_does_not_delete_ciphertext() {
    let fixture = TestRepo::new("reveal-keeps-ciphertext");

    let (collab_identity, _) = fixture.add_collaborator("alice@example.com");
    fixture.import_identity(&collab_identity, "alice.age");

    fixture.add_file(".env", b"SECRET=value\n");

    cmd_hide(
        &fixture.repo.path,
        "origin",
        &fixture.key_store.path,
        true,
        fixture.tracked_names(),
    )
    .expect("hide");

    cmd_reveal(
        &fixture.repo.path,
        "alice@example.com",
        "origin",
        &fixture.key_store.path,
        fixture.tracked_names(),
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

    cmd_hide(
        &fixture.repo.path,
        "origin",
        &fixture.key_store.path,
        true,
        fixture.tracked_names(),
    )
    .expect("hide");

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

    // .gitignore does not contain newsecret.txt yet
    let gitignore = fs::read_to_string(fixture.repo.join(".gitignore")).unwrap_or_default();
    assert!(!gitignore.contains("newsecret.txt"));

    cmd_add(
        &fixture.repo.path,
        vec!["newsecret.txt".to_string()],
        "origin",
        &fixture.key_store.path,
    )
    .expect("add");

    // git-secret auto-adds the file to .gitignore. git-veil must match.
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

    cmd_hide(
        &fixture.repo.path,
        "origin",
        &fixture.key_store.path,
        true,
        fixture.tracked_names(),
    )
    .expect("hide");

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
