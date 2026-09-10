//! Key discovery tests: git-veil never generates keys — a missing key
//! fails with a documented exit code and the create-and-back-up recipe;
//! selection honours the pinned fingerprint, an explicit --signing-key,
//! and the first-key default.

use git_veil::{
    discover_identity, discover_signing_key, exit_code_of, fingerprint_for_verifying_key,
    generate_signing_keypair, load_signing_keys, parse_signing_key, ExitCode,
};
use std::fs;
use std::path::PathBuf;

struct TempDir {
    path: std::path::PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        let pid = std::process::id();
        let counter = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "git-veil-disc-{}-{}-{}",
            label, pid, counter
        ));
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
        seeds
            .iter()
            .map(|s| format!("{}\n", s))
            .collect::<String>(),
    )
    .unwrap();
}

#[test]
fn test_missing_signing_key_fails_with_code_20_and_recipe() {
    let store = TempDir::new("nosigning");
    let err = discover_signing_key(&store.path, None, None).unwrap_err();
    let message = format!("{:#}", err);
    assert_eq!(code_of(err), 20);
    assert!(message.contains("openssl genpkey"), "recipe printed: {message}");
    assert!(message.contains("signing-keys.txt"), "store path in message: {message}");
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
fn test_single_key_used_without_explicit_selection() {
    let store = TempDir::new("single");
    let (key, _) = generate_signing_keypair();
    write_signing_keys(&store, &[hex::encode(key.to_bytes())]);

    let loaded = load_signing_keys(&store.path).unwrap();
    assert_eq!(loaded.len(), 1);

    // No pin, no explicit selection: the single key is used
    let selected = discover_signing_key(&store.path, None, None).unwrap();
    assert_eq!(
        selected.to_bytes(),
        key.to_bytes(),
        "the only key is selected"
    );
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

    let pinned = fingerprint_for_verifying_key(&second.verifying_key());
    let selected =
        discover_signing_key(&store.path, None, Some(&pinned)).unwrap();
    assert_eq!(selected.to_bytes(), second.to_bytes());

    // A pin no stored key matches: code 20, never a wrong-key signature
    let err = discover_signing_key(&store.path, None, Some(&"0".repeat(64)))
        .unwrap_err();
    assert_eq!(code_of(err), 20);
}

#[test]
fn test_explicit_signing_key_selection_by_index_and_seed() {
    let store = TempDir::new("explicit");
    let (first, _) = generate_signing_keypair();
    let (second, _) = generate_signing_keypair();
    let first_hex = hex::encode(first.to_bytes());
    let second_hex = hex::encode(second.to_bytes());
    write_signing_keys(&store, &[first_hex.clone(), second_hex.clone()]);

    // 1-based index
    let by_index = discover_signing_key(&store.path, Some("2"), None).unwrap();
    assert_eq!(by_index.to_bytes(), second.to_bytes());

    // Full seed (case-insensitive hex)
    let by_seed = discover_signing_key(&store.path, Some(&second_hex.to_uppercase()), None)
        .unwrap();
    assert_eq!(by_seed.to_bytes(), second.to_bytes());

    // Out-of-range index fails without falling back to a default
    assert!(discover_signing_key(&store.path, Some("9"), None).is_err());
    assert!(discover_signing_key(&store.path, Some("0"), None).is_err());
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
fn test_missing_identity_fails_with_code_21_and_recipe() {
    let store = TempDir::new("noidentity");
    let err = match discover_identity(&store.path, "age1qqnotpresent") {
        Ok(_) => panic!("identity discovery must fail for an absent identity"),
        Err(err) => err,
    };
    let message = format!("{:#}", err);
    assert_eq!(
        code_of(err),
        ExitCode::NoAgeIdentity as i32
    );
    assert!(message.contains("age-keygen"), "recipe printed: {message}");
    assert!(message.contains("import"), "import step printed: {message}");
    assert!(
        message.to_lowercase().contains("back it up"),
        "backup instruction: {message}"
    );
}

#[test]
fn test_corrupt_identity_store_line_refused_with_code_62_not_21() {
    let store = TempDir::new("corruptidentities");
    fs::write(
        store.join("identities.txt"),
        "AGE-SECRET-KEY-1TRUNCATEDGARBAGE\n",
    )
    .unwrap();

    // A corrupt store is NOT reported as a missing identity (21 + recipe):
    // it is a parse refusal (62) naming the corrupt line to delete.
    let err = match discover_identity(&store.path, "age1qqnotpresent") {
        Ok(_) => panic!("a corrupt identity line must fail discovery"),
        Err(err) => err,
    };
    let message = format!("{:#}", err);
    assert_eq!(code_of(err), ExitCode::KeyParseFailure as i32);
    assert!(
        message.contains("AGE-SECRET-KEY-1TRUNCATEDGARBAGE"),
        "error names the corrupt line: {message}"
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
        fingerprint_for_verifying_key(&parsed.verifying_key()),
        fingerprint_for_verifying_key(&key.verifying_key()),
        "the parsed seed has the same fingerprint as the original key"
    );
    assert_eq!(
        hex::encode(parsed.verifying_key().to_bytes()),
        verifying_hex
    );
    assert_eq!(parsed.to_bytes(), key.to_bytes());
}
