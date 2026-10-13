//! Trust model tests for the possession-proof pin creation (issue #28):
//! proof is the only direct pin-creation mode, the keyfile argument is a
//! parse error, export-pin/import carry pins to store-less machines, and
//! the three import consistency checks refuse every mismatch.

use age::secrecy::ExposeSecret;
use git_veil::cli::Cli;
use git_veil::{
    cmd_export_pin, cmd_hide, cmd_import, cmd_init, cmd_reveal, cmd_tell, cmd_trust,
    cmd_trust_import, cmd_verify_keyring, exit_code_of, generate_identity,
    generate_signing_keypair, owner_key_fingerprint, recipient_from_identity, PinFile,
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
        let dir =
            std::env::temp_dir().join(format!("git-veil-trust-{}-{}-{}", label, pid, counter));
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

/// A fully-trusted fixture: git repo, key store holding the owner's seed,
/// committed owner.verifying, init + possession-proof trust.
struct Fixture {
    repo: TempDir,
    key_store: TempDir,
    signing_key: ed25519_dalek::SigningKey,
    verifying_hex: String,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let repo = TempDir::new(label);
        let key_store = TempDir::new(&format!("{}-ks", label));
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

        Self {
            repo,
            key_store,
            signing_key,
            verifying_hex,
        }
    }
}

// ---------------------------------------------------------------------------
// The keyfile argument is gone: the parser rejects it
// ---------------------------------------------------------------------------

#[test]
fn test_trust_keyfile_argument_is_a_parse_error() {
    use clap::Parser as _;
    // `git-veil trust <repo-id> <keyfile>` — the old self-anchoring form —
    // must not even parse.
    let result = Cli::try_parse_from(["git-veil", "trust", TEST_REPO_ID, "owner.verifying"]);
    assert!(
        result.is_err(),
        "trust with a keyfile argument must be a parse error"
    );

    // The two pin-creation paths parse; nothing else does.
    assert!(Cli::try_parse_from(["git-veil", "trust", TEST_REPO_ID]).is_ok());
    assert!(
        Cli::try_parse_from(["git-veil", "trust", "--import", "/tmp/fara.pin"]).is_ok(),
        "trust --import <pin-file> must parse"
    );
    // Bare trust, and --import combined with a repo-id, are usage errors.
    assert!(Cli::try_parse_from(["git-veil", "trust"]).is_err());
    assert!(Cli::try_parse_from([
        "git-veil",
        "trust",
        TEST_REPO_ID,
        "--import",
        "/tmp/fara.pin"
    ])
    .is_err());
}

// ---------------------------------------------------------------------------
// Possession proof: match -> pin; no match -> refusal, no pin
// ---------------------------------------------------------------------------

#[test]
fn test_trust_proof_writes_pin_and_verifies() {
    let f = Fixture::new("proof");

    let pin = TrustPinStore::read_pin(&f.key_store.path, TEST_REPO_ID)
        .unwrap()
        .expect("proof must write the pin");
    let trust = TrustStore::load_from_file(&f.repo.join(".git-veil/trust.json")).unwrap();
    assert_eq!(
        trust.get_trusted_fingerprint(TEST_REPO_ID).unwrap(),
        pin,
        "the committed record and the pin must agree"
    );
    assert_eq!(
        trust.get_owner_fingerprint(TEST_REPO_ID).unwrap(),
        owner_key_fingerprint(TEST_REPO_ID, &f.signing_key.verifying_key()),
        "the metadata must record the owner fingerprint under the single derivation"
    );
    cmd_verify_keyring(&f.repo.path, "origin", &f.key_store.path)
        .expect("verify-keyring passes after a proven pin");
}

#[test]
fn test_trust_without_matching_seed_refuses() {
    let repo = TempDir::new("no-seed");
    let key_store = TempDir::new("no-seed-ks");
    init_git_repo(&repo.path);

    // The repository's owner.verifying is keypair A's public half; the
    // store holds keypair B's seed — possession of A is NOT proven.
    let (owner_signing_key, owner_verifying_hex) = generate_signing_keypair();
    let (unrelated_signing_key, _) = generate_signing_keypair();
    fs::write(
        repo.join("owner.verifying"),
        format!("{}\n", owner_verifying_hex),
    )
    .unwrap();
    fs::write(
        key_store.join("signing-keys.txt"),
        format!("{}\n", hex::encode(unrelated_signing_key.to_bytes())),
    )
    .unwrap();
    let _ = owner_signing_key;
    cmd_init(&repo.path, false).expect("init");

    let err = cmd_trust(&repo.path, TEST_REPO_ID, "origin", &key_store.path, false)
        .expect_err("trust must refuse without a matching seed");
    assert_eq!(exit_code_of(&err), 20);
    assert!(
        err.to_string()
            .contains("no local signing key matches this repository owner key"),
        "the refusal must name the proof failure: {err}"
    );
    assert!(
        TrustPinStore::read_pin(&key_store.path, TEST_REPO_ID)
            .unwrap()
            .is_none(),
        "no pin may be written on refusal"
    );
}

#[test]
fn test_trust_ambiguous_seeds_refuse() {
    let repo = TempDir::new("ambiguous");
    let key_store = TempDir::new("ambiguous-ks");
    init_git_repo(&repo.path);

    let (signing_key, verifying_hex) = generate_signing_keypair();
    fs::write(repo.join("owner.verifying"), format!("{}\n", verifying_hex)).unwrap();
    // The same seed twice: the match is ambiguous, so refuse rather than pick.
    let seed = hex::encode(signing_key.to_bytes());
    fs::write(
        key_store.join("signing-keys.txt"),
        format!("{}\n{}\n", seed, seed),
    )
    .unwrap();
    cmd_init(&repo.path, false).expect("init");

    let err = cmd_trust(&repo.path, TEST_REPO_ID, "origin", &key_store.path, false)
        .expect_err("ambiguous seed matches must refuse");
    assert_eq!(exit_code_of(&err), 70);
    assert!(TrustPinStore::read_pin(&key_store.path, TEST_REPO_ID)
        .unwrap()
        .is_none());
}

#[test]
fn test_trust_wrong_repo_id_fails() {
    let repo = TempDir::new("wrong-id");
    let key_store = TempDir::new("wrong-id-ks");
    init_git_repo(&repo.path);

    let (signing_key, verifying_hex) = generate_signing_keypair();
    fs::write(repo.join("owner.verifying"), format!("{}\n", verifying_hex)).unwrap();
    fs::write(
        key_store.join("signing-keys.txt"),
        format!("{}\n", hex::encode(signing_key.to_bytes())),
    )
    .unwrap();
    cmd_init(&repo.path, false).expect("init");

    let err = cmd_trust(
        &repo.path,
        "wrong+id@github.com",
        "origin",
        &key_store.path,
        false,
    )
    .expect_err("repo-id mismatch must refuse");
    assert_eq!(exit_code_of(&err), 13);
}

#[test]
fn test_retrust_replaces_pin() {
    let f = Fixture::new("retrust");

    let old_pin = TrustPinStore::read_pin(&f.key_store.path, TEST_REPO_ID)
        .unwrap()
        .unwrap();

    // Key rotation: new seed, new committed owner.verifying, re-prove.
    let (new_signing_key, new_verifying_hex) = generate_signing_keypair();
    fs::write(
        f.repo.join("owner.verifying"),
        format!("{}\n", new_verifying_hex),
    )
    .unwrap();
    fs::write(
        f.key_store.join("signing-keys.txt"),
        format!("{}\n", hex::encode(new_signing_key.to_bytes())),
    )
    .unwrap();

    cmd_trust(
        &f.repo.path,
        TEST_REPO_ID,
        "origin",
        &f.key_store.path,
        false,
    )
    .expect("re-trust");

    let new_pin = TrustPinStore::read_pin(&f.key_store.path, TEST_REPO_ID)
        .unwrap()
        .unwrap();
    assert_ne!(old_pin, new_pin, "the pin must be replaced");
    cmd_verify_keyring(&f.repo.path, "origin", &f.key_store.path)
        .expect("verify passes with the new pin");
}

// ---------------------------------------------------------------------------
// export-pin: proof required, and never into the repository
// ---------------------------------------------------------------------------

#[test]
fn test_export_pin_without_matching_seed_refuses() {
    let repo = TempDir::new("export-no-seed");
    let key_store = TempDir::new("export-no-seed-ks");
    let elsewhere = TempDir::new("export-no-seed-out");
    init_git_repo(&repo.path);

    // The repository's owner.verifying is keypair A's public half; the
    // store holds keypair B's seed — export must refuse.
    let (owner_signing_key, owner_verifying_hex) = generate_signing_keypair();
    let (unrelated_signing_key, _) = generate_signing_keypair();
    fs::write(
        repo.join("owner.verifying"),
        format!("{}\n", owner_verifying_hex),
    )
    .unwrap();
    fs::write(
        key_store.join("signing-keys.txt"),
        format!("{}\n", hex::encode(unrelated_signing_key.to_bytes())),
    )
    .unwrap();
    let _ = owner_signing_key;
    cmd_init(&repo.path, false).expect("init");

    let out = elsewhere.join("fara.pin");
    let err = cmd_export_pin(&repo.path, TEST_REPO_ID, &out, "origin", &key_store.path)
        .expect_err("export-pin must require the possession proof");
    assert_eq!(exit_code_of(&err), 20);
    assert!(
        !out.exists(),
        "no pin-file may be written on refusal — store-less machines are consumers, never producers"
    );
}

#[test]
fn test_export_pin_inside_repo_refuses() {
    let f = Fixture::new("export-inside");

    let out = f.repo.join("committed-pin.txt");
    let err = cmd_export_pin(
        &f.repo.path,
        TEST_REPO_ID,
        &out,
        "origin",
        &f.key_store.path,
    )
    .expect_err("export-pin must refuse a path inside the repository");
    assert_eq!(exit_code_of(&err), 71);
    assert!(!out.exists(), "no pin-file may be written inside the repo");
}

#[test]
fn test_export_pin_writes_importable_pin_file() {
    let f = Fixture::new("export-ok");
    let elsewhere = TempDir::new("export-ok-out");

    let out = elsewhere.join("fara.pin");
    cmd_export_pin(
        &f.repo.path,
        TEST_REPO_ID,
        &out,
        "origin",
        &f.key_store.path,
    )
    .expect("export-pin with a matching seed succeeds");

    let content = fs::read_to_string(&out).unwrap();
    let pin_file = PinFile::parse(&content).expect("exported pin-file parses");
    assert_eq!(pin_file.repo_id, TEST_REPO_ID);
    assert_eq!(
        hex::encode(pin_file.verifying_key.to_bytes()),
        f.verifying_hex.to_lowercase()
    );
}

// ---------------------------------------------------------------------------
// trust --import: three mandatory consistency checks
// ---------------------------------------------------------------------------

/// A store-less machine's key store: no signing key at all.
fn storeless(label: &str) -> TempDir {
    TempDir::new(&format!("{}-storeless", label))
}

#[test]
fn test_import_inside_repo_refuses() {
    let f = Fixture::new("import-inside");

    // An attacker commits a bogus pin-file to the repository; the victim
    // is told to import it from the working tree.
    let in_repo = f.repo.join("bogus.pin");
    fs::write(
        &in_repo,
        PinFile {
            repo_id: TEST_REPO_ID.to_string(),
            verifying_key: f.signing_key.verifying_key(),
        }
        .serialize(),
    )
    .unwrap();

    let err = cmd_trust_import(&f.repo.path, &in_repo, "origin", &f.key_store.path, false)
        .expect_err("import must refuse a path inside the repository");
    assert_eq!(exit_code_of(&err), 71);
}

#[test]
fn test_import_happy_path_on_storeless_machine() {
    let f = Fixture::new("import-ok");
    let fresh_store = storeless("import-ok");
    let elsewhere = TempDir::new("import-ok-out");

    let pin_file_path = elsewhere.join("fara.pin");
    cmd_export_pin(
        &f.repo.path,
        TEST_REPO_ID,
        &pin_file_path,
        "origin",
        &f.key_store.path,
    )
    .expect("export-pin on the signing machine");

    // The store-less machine has no signing key anywhere — import is its
    // only pin-creation path, and it must work.
    assert!(!fresh_store.path.join("signing-keys.txt").exists());
    cmd_trust_import(
        &f.repo.path,
        &pin_file_path,
        "origin",
        &fresh_store.path,
        false,
    )
    .expect("import with all three checks passing writes the pin");

    assert!(
        TrustPinStore::read_pin(&fresh_store.path, TEST_REPO_ID)
            .unwrap()
            .is_some(),
        "the pin must be written"
    );
    cmd_verify_keyring(&f.repo.path, "origin", &fresh_store.path)
        .expect("verify-keyring passes with the imported pin");
}

#[test]
fn test_import_repo_id_mismatch_refuses() {
    let f = Fixture::new("import-repo-id");
    let fresh_store = storeless("import-repo-id");
    let elsewhere = TempDir::new("import-repo-id-out");

    // A pin-file exported for a DIFFERENT repository.
    let pin_file_path = elsewhere.join("other.pin");
    fs::write(
        &pin_file_path,
        PinFile {
            repo_id: "other+owner@github.com".to_string(),
            verifying_key: f.signing_key.verifying_key(),
        }
        .serialize(),
    )
    .unwrap();

    let err = cmd_trust_import(
        &f.repo.path,
        &pin_file_path,
        "origin",
        &fresh_store.path,
        false,
    )
    .expect_err("import must refuse a pin-file for another repository");
    assert_eq!(exit_code_of(&err), 70);
    assert!(
        err.to_string()
            .contains("One of the two channels is compromised"),
        "the refusal must name the compromise: {err}"
    );
    assert!(
        TrustPinStore::read_pin(&fresh_store.path, TEST_REPO_ID)
            .unwrap()
            .is_none(),
        "no pin may be written on refusal"
    );
}

#[test]
fn test_import_key_mismatch_refuses() {
    let f = Fixture::new("import-key");
    let fresh_store = storeless("import-key");
    let elsewhere = TempDir::new("import-key-out");

    // A pin-file whose verifying key differs from the repository's
    // committed owner.verifying (check b).
    let (other_signing_key, _) = generate_signing_keypair();
    let pin_file_path = elsewhere.join("swapped.pin");
    fs::write(
        &pin_file_path,
        PinFile {
            repo_id: TEST_REPO_ID.to_string(),
            verifying_key: other_signing_key.verifying_key(),
        }
        .serialize(),
    )
    .unwrap();

    let err = cmd_trust_import(
        &f.repo.path,
        &pin_file_path,
        "origin",
        &fresh_store.path,
        false,
    )
    .expect_err("import must refuse a key that differs from the committed owner key");
    assert_eq!(exit_code_of(&err), 70);
    assert!(err
        .to_string()
        .contains("One of the two channels is compromised"));
    assert!(TrustPinStore::read_pin(&fresh_store.path, TEST_REPO_ID)
        .unwrap()
        .is_none());
}

#[test]
fn test_import_fingerprint_mismatch_refuses() {
    let f = Fixture::new("import-fp");
    let fresh_store = storeless("import-fp");
    let elsewhere = TempDir::new("import-fp-out");

    let pin_file_path = elsewhere.join("fara.pin");
    cmd_export_pin(
        &f.repo.path,
        TEST_REPO_ID,
        &pin_file_path,
        "origin",
        &f.key_store.path,
    )
    .expect("export-pin");

    // Tamper the committed metadata fingerprint (check c): the pin-file
    // and the committed key still agree, but the recorded fingerprint —
    // the human verification token — does not.
    let trust_path = f.repo.join(".git-veil/trust.json");
    let mut trust = TrustStore::load_from_file(&trust_path).unwrap();
    trust.set_owner_fingerprint(TEST_REPO_ID.to_string(), "00".repeat(32));
    trust.save_to_file(&trust_path).unwrap();

    let err = cmd_trust_import(
        &f.repo.path,
        &pin_file_path,
        "origin",
        &fresh_store.path,
        false,
    )
    .expect_err("import must refuse a fingerprint mismatch against the metadata");
    assert_eq!(exit_code_of(&err), 70);
    assert!(err
        .to_string()
        .contains("One of the two channels is compromised"));
    assert!(TrustPinStore::read_pin(&fresh_store.path, TEST_REPO_ID)
        .unwrap()
        .is_none());
}

#[test]
fn test_import_missing_metadata_fingerprint_refuses() {
    let f = Fixture::new("import-no-fp");
    let fresh_store = storeless("import-no-fp");
    let elsewhere = TempDir::new("import-no-fp-out");

    let pin_file_path = elsewhere.join("fara.pin");
    cmd_export_pin(
        &f.repo.path,
        TEST_REPO_ID,
        &pin_file_path,
        "origin",
        &f.key_store.path,
    )
    .expect("export-pin");

    // Metadata predating the fingerprint field: the owner must refresh it
    // by re-running trust on a seed-holding machine before anyone imports.
    let trust_path = f.repo.join(".git-veil/trust.json");
    let legacy = serde_json::json!({
        "trusted_keys": {
            TEST_REPO_ID: TrustPinStore::read_pin(&f.key_store.path, TEST_REPO_ID)
                .unwrap()
                .unwrap()
        }
    });
    fs::write(&trust_path, serde_json::to_string_pretty(&legacy).unwrap()).unwrap();

    let err = cmd_trust_import(
        &f.repo.path,
        &pin_file_path,
        "origin",
        &fresh_store.path,
        false,
    )
    .expect_err("import must refuse when the metadata fingerprint field is absent");
    assert_eq!(exit_code_of(&err), 70);
    assert!(TrustPinStore::read_pin(&fresh_store.path, TEST_REPO_ID)
        .unwrap()
        .is_none());
}

// ---------------------------------------------------------------------------
// Fail-closed semantics around the pin
// ---------------------------------------------------------------------------

#[test]
fn test_no_pin_fails_closed() {
    let repo = TempDir::new("no-pin");
    let key_store = TempDir::new("no-pin-ks");
    init_git_repo(&repo.path);
    cmd_init(&repo.path, false).expect("init");

    // Committed trust.json entry, but no local pin.
    let mut trust = TrustStore::new();
    trust.add_trust(TEST_REPO_ID.to_string(), "deadbeefdeadbeef".to_string());
    trust
        .save_to_file(&repo.join(".git-veil/trust.json"))
        .unwrap();

    let result = cmd_verify_keyring(&repo.path, "origin", &key_store.path);
    let err = result.expect_err("should fail without local pin");
    let message = err.to_string();
    assert!(
        message.contains("no trust pin exists on this machine"),
        "the error states the missing pin: {message}"
    );
    // Public repository facts (issue #42): the refusal names the derived
    // repository identity and the remote it came from.
    assert!(
        message.contains(TEST_REPO_ID),
        "the error names the derived repository identity: {message}"
    );
    assert!(
        message.contains("origin"),
        "the error names the remote the identity derived from: {message}"
    );
}

#[test]
fn test_mismatched_pin_fails_closed() {
    let f = Fixture::new("mismatch-pin");

    TrustPinStore::write_pin(&f.key_store.path, TEST_REPO_ID, &"ff".repeat(32)).unwrap();

    let result = cmd_verify_keyring(&f.repo.path, "origin", &f.key_store.path);
    assert!(result.is_err(), "should fail with mismatched pin");
    assert!(result.unwrap_err().to_string().contains("changed"));
}

#[test]
fn test_hide_and_tell_fail_without_trust() {
    let repo = TempDir::new("no-trust");
    let key_store = TempDir::new("no-trust-ks");
    init_git_repo(&repo.path);
    cmd_init(&repo.path, false).expect("init");

    assert!(
        cmd_hide(&repo.path, "origin", &key_store.path, true).is_err(),
        "hide should fail without trust"
    );

    let id = generate_identity();
    let r = recipient_from_identity(&id);
    fs::write(repo.join("alice.recipient"), &r).unwrap();
    assert!(
        cmd_tell(
            &repo.path,
            "alice@example.com",
            "alice.recipient",
            "origin",
            &key_store.path,
            None,
        )
        .is_err(),
        "tell should fail without trust"
    );
}

#[test]
fn test_unsigned_keyring_with_entries_fails() {
    let f = Fixture::new("unsigned");

    let keyring_content = "-----BEGIN GIT-VEIL KEYRING-----\nalice@example.com:age1xxx\n-----END GIT-VEIL KEYRING-----\n";
    fs::write(f.repo.join(".git-veil/keyring"), keyring_content).unwrap();

    let result = cmd_verify_keyring(&f.repo.path, "origin", &f.key_store.path);
    assert!(result.is_err(), "unsigned keyring with entries should fail");
    assert!(result.unwrap_err().to_string().contains("no signature"));
}

#[test]
fn test_empty_keyring_no_signature_ok() {
    let f = Fixture::new("empty-kr");
    cmd_verify_keyring(&f.repo.path, "origin", &f.key_store.path)
        .expect("empty keyring should verify");
}

// ---------------------------------------------------------------------------
// reveal's no-pin error: states the missing pin and names the public facts
// (the derived repository identity and the remote it came from), but prints
// no command line and names no removed path
// ---------------------------------------------------------------------------

#[test]
fn test_reveal_no_pin_error_names_both_paths() {
    let repo = TempDir::new("reveal-no-pin");
    let key_store = TempDir::new("reveal-no-pin-ks");
    init_git_repo(&repo.path);
    cmd_init(&repo.path, false).expect("init");

    let mut trust = TrustStore::new();
    trust.add_trust(TEST_REPO_ID.to_string(), "deadbeefdeadbeef".to_string());
    trust
        .save_to_file(&repo.join(".git-veil/trust.json"))
        .unwrap();

    let err = cmd_reveal(&repo.path, "owner@example.com", "origin", &key_store.path)
        .expect_err("reveal without a pin must fail");
    let message = err.to_string();
    assert!(
        message.contains("no trust pin exists on this machine"),
        "the error must state the missing pin: {message}"
    );
    assert!(
        message.contains(TEST_REPO_ID),
        "the error names the derived repository identity: {message}"
    );
    assert!(
        message.contains("origin"),
        "the error names the remote the identity derived from: {message}"
    );
    assert!(
        !message.contains("git-veil trust"),
        "the error must not print a command line: {message}"
    );
    assert!(
        !message.to_lowercase().contains("keyfile"),
        "the error must not name any removed path: {message}"
    );
}

// ---------------------------------------------------------------------------
// An attacker-consistent repository cannot anchor itself on a machine
// holding the real seed
// ---------------------------------------------------------------------------

#[test]
fn test_attacker_consistent_repo_refused_on_machine_with_real_seed() {
    // The REAL owner's machine: holds the real seed, no pin yet.
    let real_store = TempDir::new("attacker-real-ks");
    let (real_signing_key, _real_verifying_hex) = generate_signing_keypair();
    fs::write(
        real_store.join("signing-keys.txt"),
        format!("{}\n", hex::encode(real_signing_key.to_bytes())),
    )
    .unwrap();

    // The attacker's repository: self-consistent — its own signing key,
    // its own committed owner.verifying, its own signed keyring, its own
    // metadata fingerprint, and a bogus pin-file committed in-repo.
    let attacked = TempDir::new("attacker-repo");
    init_git_repo(&attacked.path);
    cmd_init(&attacked.path, false).expect("init");

    let (attacker_signing_key, attacker_verifying_hex) = generate_signing_keypair();
    fs::write(
        attacked.join("owner.verifying"),
        format!("{}\n", attacker_verifying_hex),
    )
    .unwrap();
    let mut trust = TrustStore::new();
    trust.add_trust(
        TEST_REPO_ID.to_string(),
        owner_key_fingerprint(TEST_REPO_ID, &attacker_signing_key.verifying_key()),
    );
    trust.set_owner_fingerprint(
        TEST_REPO_ID.to_string(),
        owner_key_fingerprint(TEST_REPO_ID, &attacker_signing_key.verifying_key()),
    );
    trust
        .save_to_file(&attacked.join(".git-veil/trust.json"))
        .unwrap();
    fs::write(
        attacked.join("pinned.pin"),
        PinFile {
            repo_id: TEST_REPO_ID.to_string(),
            verifying_key: attacker_signing_key.verifying_key(),
        }
        .serialize(),
    )
    .unwrap();

    // The repository supplies its own trust anchor -> the proof fails:
    // the real seed does not derive the attacker's key.
    let err = cmd_trust(
        &attacked.path,
        TEST_REPO_ID,
        "origin",
        &real_store.path,
        false,
    )
    .expect_err("a self-consistent attacker repo must not be pinnable by proof");
    assert_eq!(exit_code_of(&err), 20);
    assert!(err
        .to_string()
        .contains("no local signing key matches this repository owner key"));
    assert!(
        TrustPinStore::read_pin(&real_store.path, TEST_REPO_ID)
            .unwrap()
            .is_none(),
        "no pin may be written for the attacker's repo"
    );

    // And the committed bogus pin-file cannot be imported either: it lives
    // inside the repository.
    let err = cmd_trust_import(
        &attacked.path,
        &attacked.join("pinned.pin"),
        "origin",
        &real_store.path,
        false,
    )
    .expect_err("an in-repo pin-file must not be importable");
    assert_eq!(exit_code_of(&err), 71);
}

// ---------------------------------------------------------------------------
// Repo rename / remote change: the existing trust record names a different
// repo-id. The error states the suspicion and STOPS — no remedy is printed,
// because the remedy is exactly what an attacker would want the operator to
// run without thinking. The operator reads the docs and fixes it with their
// brain engaged.
// ---------------------------------------------------------------------------

/// Changes the fixture's remote URL, as a GitHub rename does, so the
/// derived repo-id no longer matches the committed trust record.
fn rename_remote(repo: &Path, new_url: &str) {
    let s = std::process::Command::new("git")
        .current_dir(repo)
        .args(["remote", "set-url", "origin", new_url])
        .status()
        .expect("git");
    assert!(s.success());
}

#[test]
fn test_rename_suspicion_no_remedy_on_gated_commands() {
    let f = Fixture::new("rename-verify");
    rename_remote(&f.repo.path, "git@github.com:owner/fara-moved.git");

    let err = cmd_verify_keyring(&f.repo.path, "origin", &f.key_store.path)
        .expect_err("a renamed repo must not verify against the old trust record");
    assert_eq!(exit_code_of(&err), 10);
    let message = format!("{:#}", err);
    assert!(
        message.contains("This looks like a rename or a remote change"),
        "the error must state the rename suspicion: {message}"
    );
    assert!(
        message.contains(TEST_REPO_ID) && message.contains("fara-moved+owner@github.com"),
        "public repository facts are named as the clue: {message}"
    );
    assert!(
        !message.contains("git-veil trust"),
        "the error must NOT hand out the remedy: {message}"
    );
}

#[test]
fn test_rename_suspicion_no_remedy_on_import() {
    let f = Fixture::new("rename-import");
    let fresh_store = storeless("rename-import");
    rename_remote(&f.repo.path, "git@github.com:owner/fara-moved.git");
    let new_repo_id = "fara-moved+owner@github.com";
    let elsewhere = TempDir::new("rename-import-out");

    // A pin-file for the RENAMED repo-id, carrying the repository's true
    // committed key: check (a) passes, but the committed metadata still
    // records the owner fingerprint under the OLD repo-id.
    let pin_file_path = elsewhere.join("moved.pin");
    fs::write(
        &pin_file_path,
        PinFile {
            repo_id: new_repo_id.to_string(),
            verifying_key: f.signing_key.verifying_key(),
        }
        .serialize(),
    )
    .unwrap();

    let err = cmd_trust_import(
        &f.repo.path,
        &pin_file_path,
        "origin",
        &fresh_store.path,
        false,
    )
    .expect_err("import must refuse while the committed metadata names the old repo-id");
    assert_eq!(exit_code_of(&err), 70);
    let message = format!("{:#}", err);
    assert!(
        message.contains("This looks like a rename or a remote change"),
        "the error must state the rename suspicion: {message}"
    );
    assert!(
        message.contains(TEST_REPO_ID) && message.contains(new_repo_id),
        "public repository facts are named as the clue: {message}"
    );
    assert!(
        !message.contains("git-veil trust"),
        "the error must NOT hand out the remedy: {message}"
    );
    assert!(
        TrustPinStore::read_pin(&fresh_store.path, new_repo_id)
            .unwrap()
            .is_none(),
        "no pin may be written on refusal"
    );
}

// ---------------------------------------------------------------------------
// Stale-entry reconcile (issue #43): when trust writes the owner fingerprint
// metadata it also reconciles trusted_keys — entries whose repository id no
// configured remote derives are pruned, the removal is printed, and entries
// matching any configured remote are kept.
// ---------------------------------------------------------------------------

#[test]
fn test_reconcile_trusted_keys_removes_only_non_live_ids() {
    let mut store = TrustStore::new();
    store.add_trust("a+owner@github.com".to_string(), "f".to_string());
    store.add_trust("b+owner@github.com".to_string(), "f".to_string());
    store.add_trust("c+owner@github.com".to_string(), "f".to_string());

    let live = std::collections::BTreeSet::from([
        "a+owner@github.com".to_string(),
        "c+owner@github.com".to_string(),
    ]);
    let pruned = store.reconcile_trusted_keys(&live);

    assert_eq!(
        pruned,
        vec!["b+owner@github.com".to_string()],
        "the pruned ids are returned in sorted order"
    );
    assert!(store
        .get_trusted_fingerprint("a+owner@github.com")
        .is_some());
    assert!(store
        .get_trusted_fingerprint("b+owner@github.com")
        .is_none());
    assert!(store
        .get_trusted_fingerprint("c+owner@github.com")
        .is_some());
}

/// The observed-live scenario: the repository moved, the old id is a stale
/// entry in the committed store, and the owner re-runs the possession proof
/// under the new id. Drives the built binary so the printed removal can be
/// asserted on stdout.
#[test]
fn test_trust_after_a_move_prunes_the_stale_entry_and_prints_the_removal() {
    let f = Fixture::new("prune-move");
    rename_remote(&f.repo.path, "git@github.com:owner/fara-moved.git");
    let new_repo_id = "fara-moved+owner@github.com";

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_git-veil"))
        .current_dir(&f.repo.path)
        .args([
            "--dangerously-skip-permissions-check",
            "trust",
            new_repo_id,
            "--key-store",
            f.key_store.path.to_str().unwrap(),
        ])
        .output()
        .expect("run git-veil trust");
    assert!(
        output.status.success(),
        "trust runs: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    let expected_line = format!("pruned the stale trusted key entry for {}", TEST_REPO_ID);
    assert!(
        stdout.contains(&expected_line),
        "the removal is printed at reconcile time and names the pruned id: {stdout}"
    );

    let trust = TrustStore::load_from_file(&f.repo.join(".git-veil/trust.json")).unwrap();
    assert!(
        trust.get_trusted_fingerprint(TEST_REPO_ID).is_none(),
        "the stale entry left by the move is gone"
    );
    assert!(
        trust.get_trusted_fingerprint(new_repo_id).is_some(),
        "the entry matching the configured remote is kept"
    );
    assert_eq!(
        trust.trusted_keys.len(),
        1,
        "the committed store names exactly the ids the remotes derive"
    );
    // The reconcile is scoped to trusted_keys: the owner fingerprint
    // metadata is not pruned by it.
    assert!(
        trust.get_owner_fingerprint(TEST_REPO_ID).is_some(),
        "owner_fingerprints is outside the reconcile scope"
    );
    assert!(trust.get_owner_fingerprint(new_repo_id).is_some());
}

#[test]
fn test_trust_reconcile_keeps_one_entry_per_configured_remote() {
    let f = Fixture::new("prune-multi");
    let upstream_id = "fara-mirror+owner@github.com";

    // A second configured remote: the repository is also pushed elsewhere.
    let s = std::process::Command::new("git")
        .current_dir(&f.repo.path)
        .args([
            "remote",
            "add",
            "upstream",
            "git@github.com:owner/fara-mirror.git",
        ])
        .status()
        .expect("git");
    assert!(s.success());

    // The committed store records one entry per configured remote.
    let trust_path = f.repo.join(".git-veil/trust.json");
    let mut store = TrustStore::load_from_file(&trust_path).unwrap();
    store.add_trust(upstream_id.to_string(), "ab".repeat(32));
    store.save_to_file(&trust_path).unwrap();

    cmd_trust(
        &f.repo.path,
        TEST_REPO_ID,
        "origin",
        &f.key_store.path,
        false,
    )
    .expect("re-trust");

    let store = TrustStore::load_from_file(&trust_path).unwrap();
    assert!(
        store.get_trusted_fingerprint(TEST_REPO_ID).is_some(),
        "the origin entry is kept"
    );
    assert!(
        store.get_trusted_fingerprint(upstream_id).is_some(),
        "the upstream entry is kept: a multi-remote repository keeps one entry per remote"
    );
    assert_eq!(store.trusted_keys.len(), 2);
}
