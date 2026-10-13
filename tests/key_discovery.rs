//! Key discovery tests: git-veil never generates keys - a missing key
//! fails with a documented exit code and the create-and-back-up recipe;
//! selection honours the pinned fingerprint and the explicit verifying
//! key form.

use git_veil::{
    discover_signing_key, discover_signing_key_explicit, discover_x25519_private_key, exit_code_of,
    fingerprint_for_public_key, generate_signing_keypair, load_signing_keys, parse_signing_key,
    ExitCode,
};
use std::fs;
use std::path::PathBuf;

/// The repository id used as the fingerprint label in these tests.
const TEST_REPO_ID: &str = "fara+owner@github.com";

struct TempDir {
    path: std::path::PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        let pid = std::process::id();
        let counter = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("git-veil-disc-{}-{}-{}", label, pid, counter));
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

fn code_of(err: anyhow::Error) -> i32 {
    exit_code_of(&err)
}

fn write_signing_keys(store: &TempDir, seeds: &[String]) {
    fs::write(
        store.join("signing-keys.txt"),
        seeds.iter().map(|s| format!("{}\n", s)).collect::<String>(),
    )
    .unwrap();
}

#[test]
fn test_missing_signing_key_fails_with_code_20_and_recipe() {
    let store = TempDir::new("nosigning");
    let err = discover_signing_key(&store.path, TEST_REPO_ID, &"0".repeat(64)).unwrap_err();
    let message = format!("{:#}", err);
    assert_eq!(code_of(err), 20);
    assert!(
        message.contains("Create an Ed25519 signing key yourself and back it up"),
        "guidance printed: {message}"
    );
    assert!(
        message.contains("signing-keys.txt"),
        "store path in message: {message}"
    );
    assert!(
        message.to_lowercase().contains("back it up"),
        "backup instruction: {message}"
    );
}

#[test]
fn test_garbage_signing_keys_file_is_an_error_not_a_missing_key() {
    let store = TempDir::new("garbage");
    fs::write(store.join("signing-keys.txt"), "not-hex-at-all\n").unwrap();
    // A present-but-garbage line is a parse error, never silently "no keys"
    assert!(load_signing_keys(&store.path).is_err());
}

#[test]
fn test_pinned_fingerprint_selects_the_trusted_key() {
    let store = TempDir::new("pinned");
    let (first, _) = generate_signing_keypair();
    let (second, _) = generate_signing_keypair();
    write_signing_keys(
        &store,
        &[
            hex::encode(first.to_bytes()),
            hex::encode(second.to_bytes()),
        ],
    );

    let pinned = fingerprint_for_public_key(
        TEST_REPO_ID,
        &hex::encode(second.verifying_key().to_bytes()),
    );
    let selected = discover_signing_key(&store.path, TEST_REPO_ID, &pinned).unwrap();
    assert_eq!(selected.to_bytes(), second.to_bytes());

    // A pin no stored key matches: code 20, never a wrong-key signature
    let err = discover_signing_key(&store.path, TEST_REPO_ID, &"0".repeat(64)).unwrap_err();
    assert_eq!(code_of(err), 20);

    // The pin binds the repository id: the same key's fingerprint under a
    // different label selects nothing.
    let foreign = fingerprint_for_public_key(
        "other+owner@github.com",
        &hex::encode(second.verifying_key().to_bytes()),
    );
    let err = discover_signing_key(&store.path, TEST_REPO_ID, &foreign).unwrap_err();
    assert_eq!(code_of(err), 20);
}

#[test]
fn test_explicit_verifying_key_selects_the_named_key() {
    let store = TempDir::new("explicit-fp");
    let (first, _) = generate_signing_keypair();
    let (second, _) = generate_signing_keypair();
    write_signing_keys(
        &store,
        &[
            hex::encode(first.to_bytes()),
            hex::encode(second.to_bytes()),
        ],
    );

    let wanted = hex::encode(second.verifying_key().to_bytes());
    let selected = discover_signing_key_explicit(&store.path, &wanted).unwrap();
    assert_eq!(selected.to_bytes(), second.to_bytes());
}

#[test]
fn test_explicit_verifying_key_is_reorder_invariant() {
    let store = TempDir::new("explicit-fp-reorder");
    let (first, _) = generate_signing_keypair();
    let (second, _) = generate_signing_keypair();
    let first_hex = hex::encode(first.to_bytes());
    let second_hex = hex::encode(second.to_bytes());
    write_signing_keys(&store, &[first_hex.clone(), second_hex.clone()]);

    let wanted = hex::encode(second.verifying_key().to_bytes());
    let before = discover_signing_key_explicit(&store.path, &wanted).unwrap();

    fs::write(
        store.join("signing-keys.txt"),
        format!("{}\n{}\n", second_hex, first_hex),
    )
    .unwrap();
    let after = discover_signing_key_explicit(&store.path, &wanted).unwrap();

    assert_eq!(
        before.to_bytes(),
        after.to_bytes(),
        "reordering signing-keys.txt must not change what a verifying key selects"
    );
    assert_eq!(after.to_bytes(), second.to_bytes());
}

#[test]
fn test_explicit_verifying_key_no_match_refuses_code_20() {
    let store = TempDir::new("explicit-fp-miss");
    let (key, _) = generate_signing_keypair();
    write_signing_keys(&store, &[hex::encode(key.to_bytes())]);

    let err = discover_signing_key_explicit(&store.path, &"0".repeat(64)).unwrap_err();
    assert_eq!(code_of(err), 20);
}

#[test]
fn test_explicit_verifying_key_ambiguous_refuses_code_70() {
    let store = TempDir::new("explicit-fp-dup");
    let (key, _) = generate_signing_keypair();
    let seed_hex = hex::encode(key.to_bytes());
    write_signing_keys(&store, &[seed_hex.clone(), seed_hex]);

    let wanted = hex::encode(key.verifying_key().to_bytes());
    let err = discover_signing_key_explicit(&store.path, &wanted).unwrap_err();
    assert_eq!(code_of(err), ExitCode::Refused as i32);
}

#[test]
fn test_comments_and_blank_lines_skipped() {
    let store = TempDir::new("comments");
    let (key, _) = generate_signing_keypair();
    fs::write(
        store.join("signing-keys.txt"),
        format!(
            "# owner signing key (backup this seed!)\n\n{}\n",
            hex::encode(key.to_bytes())
        ),
    )
    .unwrap();
    let loaded = load_signing_keys(&store.path).unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].to_bytes(), key.to_bytes());
}

#[test]
fn test_missing_private_key_fails_with_code_21_and_recipe() {
    let store = TempDir::new("noidentity");
    let err = match discover_x25519_private_key(&store.path, "age1qqnotpresent") {
        Ok(_) => panic!("private key discovery must fail for an absent private key"),
        Err(err) => err,
    };
    let message = format!("{:#}", err);
    assert_eq!(code_of(err), ExitCode::NoX25519PrivateKey as i32);
    assert!(
        message.contains("Create your own X25519 private key (age identity) and back it up"),
        "guidance printed: {message}"
    );
    assert!(
        message.contains("import"),
        "import step mentioned: {message}"
    );
    assert!(
        message.to_lowercase().contains("back it up"),
        "backup instruction: {message}"
    );
}

#[test]
fn test_corrupt_private_key_store_line_refused_with_code_62_not_21() {
    let store = TempDir::new("corruptidentities");
    fs::write(
        store.join("identities.txt"),
        "AGE-SECRET-KEY-1TRUNCATEDGARBAGE\n",
    )
    .unwrap();

    // A corrupt store is NOT reported as a missing private key (21 +
    // recipe): it is a parse refusal (62) naming the corrupt line to
    // delete.
    let err = match discover_x25519_private_key(&store.path, "age1qqnotpresent") {
        Ok(_) => panic!("a corrupt private key line must fail discovery"),
        Err(err) => err,
    };
    let message = format!("{:#}", err);
    assert_eq!(code_of(err), ExitCode::KeyParseFailure as i32);
    assert!(
        message.contains("corrupt key store line"),
        "error states the corrupt line: {message}"
    );
    assert!(
        !message.contains("age-keygen"),
        "recipe must not replace the parse refusal: {message}"
    );
}

#[test]
fn test_parse_signing_key_roundtrip() {
    let (key, verifying_hex) = generate_signing_keypair();
    let parsed = parse_signing_key(&hex::encode(key.to_bytes())).unwrap();
    assert_eq!(
        parsed.verifying_key().to_bytes(),
        key.verifying_key().to_bytes(),
        "the parsed seed derives the same verifying key as the original key"
    );
    assert_eq!(
        hex::encode(parsed.verifying_key().to_bytes()),
        verifying_hex
    );
    assert_eq!(parsed.to_bytes(), key.to_bytes());
}
