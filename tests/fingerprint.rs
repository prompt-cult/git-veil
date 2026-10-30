//! Fingerprint tests: the single derivation
//! FP = SHA-256( UTF8(label) + ":" + UTF8(public-key-encoding) )
//! asserted against golden vectors produced by the documented coreutils
//! one-liners, the pure `git-veil fingerprint` command, the hostile
//! refusal of legacy 16-hex pins, and the list-keys binding fingerprint.

use age::secrecy::ExposeSecret;
use git_veil::{
    cmd_add_key, cmd_import, cmd_init, cmd_verify_keys, exit_code_of, fingerprint_for_public_key,
    generate_signing_keypair, generate_x25519_private_key, is_16_hex_pin_shape,
    owner_key_fingerprint, parse_verifying_key, x25519_public_key_encoding, ExitCode,
    TrustPinStore, TrustStore,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The golden vectors: (label, public-key-encoding, expected fingerprint)
/// triples produced by the documented stock-tool one-liners, printed in
/// docs/design.md ("Fingerprints"):
///
/// ```text
/// printf '%s:%s' 'alice@example.com' "$(age-keygen -y identity.txt)" | sha256sum
/// printf '%s:%s' 'demo+example@github.com' "$(head -n 1 .git-veil/owner.verifying)" | sha256sum
/// ```
///
/// The first vector's public key is a real age-keygen X25519 public key.
/// The second's is a real openssl-generated Ed25519 verifying key, as the
/// raw 32 verifying key bytes in lowercase hex. The expected values are the
/// sha256sum output over exactly those bytes, so the code must equal the
/// stock tools. Provenance, verified by hand for every vector:
///
/// - GNU coreutils 9.11 `sha256sum` over the printf bytes: both vectors.
/// - uutils coreutils 0.9.0 `uu-sha256sum`, fed the same printf bytes
///   (also cross-checked through `uu-printf`): both vectors.
const GOLDEN_VECTORS: [(&str, &str, &str); 2] = [
    (
        "alice@example.com",
        "age1ga9us2r837a445htpvmuvxnygc8mrxglvtzrfwk0kyy7q55r3ypqlt28nk",
        "263e683748d60e61ea89a6470e209f697c5ec23452e8bc8f222e2aff48e0d36b",
    ),
    (
        "demo+example@github.com",
        "92cf641b35021f2c38fa5016fe9c413d4a399bfdc67c6832b4f9fdd019ccebdb",
        "b7480ed036c6ab15e0446b8caa694faeb2983959bb49e7920a94d14b6bb773d1",
    ),
];

// ---------------------------------------------------------------------------
// Golden vectors: the Rust implementation is byte-identical to coreutils
// ---------------------------------------------------------------------------

#[test]
fn test_golden_vectors_match_coreutils() {
    for (label, public_key, expected) in GOLDEN_VECTORS {
        assert_eq!(
            fingerprint_for_public_key(label, public_key),
            expected,
            "the Rust derivation must equal the stock-tool one-liner for {label}"
        );
    }
}

/// The same derivation under uutils coreutils. Feeds the printf bytes of
/// each golden vector to `uu-sha256sum` and demands the vector's hex.
/// Skips cleanly when the uutils binary is absent, the way the interop
/// suite skips when age or rage is absent.
#[test]
fn test_golden_vectors_match_uutils_sha256sum() {
    let probe = Command::new("uu-sha256sum").arg("--version").output();
    if probe.is_err() {
        eprintln!("skipped: uu-sha256sum is not on PATH");
        return;
    }
    if !probe.expect("probe ran").status.success() {
        eprintln!("skipped: uu-sha256sum did not run cleanly");
        return;
    }
    for (label, public_key, expected) in GOLDEN_VECTORS {
        let mut child = Command::new("uu-sha256sum")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("uu-sha256sum spawned");
        use std::io::Write;
        child
            .stdin
            .as_mut()
            .expect("stdin piped")
            .write_all(format!("{label}:{public_key}").as_bytes())
            .expect("wrote the printf bytes");
        let out = child.wait_with_output().expect("uu-sha256sum ran");
        assert!(out.status.success(), "uu-sha256sum exited zero");
        let line = String::from_utf8(out.stdout).expect("output is utf8");
        let digest = line.split_whitespace().next().expect("digest present");
        assert_eq!(
            digest, expected,
            "uutils sha256sum must equal the Rust derivation for {label}"
        );
    }
}

#[test]
fn test_owner_key_fingerprint_is_the_same_derivation_with_repo_id_label() {
    let (label, public_key, expected) = GOLDEN_VECTORS[1];
    let verifying_key = parse_verifying_key(public_key).expect("the vector key parses");
    assert_eq!(
        owner_key_fingerprint(label, &verifying_key),
        expected,
        "the Ed25519 out-of-band token is the same derivation, repository id as label"
    );
}

#[test]
fn test_fingerprint_shape_and_label_binding() {
    let (label, public_key, expected) = GOLDEN_VECTORS[0];

    // 64 lowercase hex characters.
    assert_eq!(expected.len(), 64);
    assert!(expected
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));

    // Deterministic: a pure function of the two inputs.
    assert_eq!(
        fingerprint_for_public_key(label, public_key),
        fingerprint_for_public_key(label, public_key)
    );

    // The label binds: the same public key under another label is another
    // fingerprint.
    assert_ne!(
        fingerprint_for_public_key("bob@example.com", public_key),
        fingerprint_for_public_key(label, public_key)
    );

    // Verbatim inputs: no trimming, no case folding.
    assert_ne!(
        fingerprint_for_public_key(label, &public_key.to_uppercase()),
        fingerprint_for_public_key(label, public_key)
    );
}

#[test]
fn test_legacy_pin_shape_detection() {
    assert!(is_16_hex_pin_shape("deadbeefdeadbeef"));
    assert!(is_16_hex_pin_shape("0123456789ABCDEF"));
    assert!(!is_16_hex_pin_shape(GOLDEN_VECTORS[0].2));
    assert!(!is_16_hex_pin_shape("deadbeef")); // 8 hex chars: never a fingerprint
    assert!(!is_16_hex_pin_shape("0123456789abcdefg")); // 17 chars
    assert!(!is_16_hex_pin_shape("zzzzzzzzzzzzzzzz")); // not hex
}

// ---------------------------------------------------------------------------
// The git-veil fingerprint command: pure function, no flags
// ---------------------------------------------------------------------------

#[test]
fn test_fingerprint_command_prints_exactly_the_hex() {
    let (label, public_key, expected) = GOLDEN_VECTORS[0];
    let output = Command::new(env!("CARGO_BIN_EXE_git-veil"))
        .args(["fingerprint", label, public_key])
        .output()
        .expect("run git-veil fingerprint");
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("{}\n", expected),
        "the command prints the 64-hex fingerprint and nothing else"
    );
    assert!(output.stderr.is_empty(), "no stderr chatter");
}

#[test]
fn test_fingerprint_command_matches_owner_vector() {
    let (label, public_key, expected) = GOLDEN_VECTORS[1];
    let output = Command::new(env!("CARGO_BIN_EXE_git-veil"))
        .args(["fingerprint", label, public_key])
        .output()
        .expect("run git-veil fingerprint");
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("{}\n", expected)
    );
}

#[test]
fn test_fingerprint_command_has_no_flags() {
    // One mode, no flags: key store, remote and output options do not exist.
    for args in [
        vec!["fingerprint", "a", "b", "--key-store", "/tmp/x"],
        vec!["fingerprint", "a", "b", "--output", "/tmp/x"],
        vec!["fingerprint", "a", "b", "c"],
        vec!["fingerprint", "only-one-arg"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_git-veil"))
            .args(&args)
            .output()
            .expect("run git-veil fingerprint");
        assert!(
            !output.status.success(),
            "fingerprint must refuse extra arguments or flags: {args:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Fixture for the gated-command tests
// ---------------------------------------------------------------------------

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "git-veil-fp-{}-{}-{}",
            label,
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
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

fn init_git_repo(dir: &Path) {
    for args in [
        vec!["init", "--quiet"],
        vec!["config", "user.email", "owner@example.com"],
        vec!["config", "user.name", "Test Owner"],
        vec!["remote", "add", "origin", "git@github.com:owner/fara.git"],
    ] {
        let status = Command::new("git")
            .current_dir(dir)
            .args(&args)
            .status()
            .expect("git");
        assert!(status.success());
    }
}

const TEST_REPO_ID: &str = "fara+owner@github.com";

/// A trusted fixture: git repo + key store with the owner's seed, init +
/// possession-proof trust. Returns (repo, key_store).
fn trusted_fixture(label: &str) -> (TempDir, TempDir) {
    let repo = TempDir::new(label);
    let key_store = TempDir::new(&format!("{label}-ks"));
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
        key_store.join("signing-keys.txt"),
        format!("{}\n", hex::encode(signing_key.to_bytes())),
    )
    .unwrap();
    fs::write(
        key_store.join("owner.verifying"),
        format!("{}\n{}\n", verifying_hex, recipient),
    )
    .unwrap();

    cmd_init(
        &repo.path,
        &key_store.join("owner.verifying"),
        "origin",
        &key_store.path,
        false,
        false,
    )
    .expect("init copies the owner key in and pins");
    cmd_import(&repo.path, &["owner.age".to_string()], &key_store.path).expect("import");

    (repo, key_store)
}

// ---------------------------------------------------------------------------
// Legacy 16-hex pins refuse as hostile
// ---------------------------------------------------------------------------

/// Asserts the refusal names the derivation change, names no command, and
/// is plain ASCII.
fn assert_legacy_refusal(err: &anyhow::Error) {
    assert_eq!(
        exit_code_of(err),
        ExitCode::Refused as i32,
        "a legacy pin refuses with the documented refusal code"
    );
    let message = format!("{:#}", err);
    assert!(
        message.contains("16 hex character"),
        "the refusal names the retired format: {message}"
    );
    assert!(
        message.contains("SHA-256"),
        "the refusal names the derivation change: {message}"
    );
    assert!(
        !message.contains("git-veil"),
        "the refusal names no command: {message}"
    );
    assert!(message.is_ascii(), "the refusal is plain ASCII: {message}");
}

#[test]
fn test_legacy_pin_and_record_refuse_as_hostile_and_nothing_is_rewritten() {
    let (repo, key_store) = trusted_fixture("legacy-both");

    // The legacy state: a 16-hex pin with the agreeing committed record.
    let legacy = "0123456789abcdef";
    let pin_path = TrustPinStore::pin_path(&key_store.path, TEST_REPO_ID);
    TrustPinStore::write_pin(&key_store.path, TEST_REPO_ID, legacy).unwrap();
    let trust_path = repo.join(".git-veil/trust.json");
    let mut trust = TrustStore::load_from_file(&trust_path).unwrap();
    trust.set_owner_fingerprint(TEST_REPO_ID.to_string(), legacy.to_string());
    trust.save_to_file(&trust_path).unwrap();
    let pin_before = fs::read_to_string(&pin_path).unwrap();
    let record_before = fs::read_to_string(&trust_path).unwrap();

    let err = cmd_verify_keys(&repo.path, "origin", &key_store.path)
        .expect_err("a legacy pin must refuse as hostile");
    assert_legacy_refusal(&err);

    // Nothing is rewritten silently: the pin and the committed record are
    // byte-identical before and after the refusal.
    assert_eq!(fs::read_to_string(&pin_path).unwrap(), pin_before);
    assert_eq!(fs::read_to_string(&trust_path).unwrap(), record_before);

    // Recovery is re-establishing trust: a fresh init with the owner key
    // file rewrites the pin, and the gated command passes with the new pin.
    fs::remove_dir_all(repo.join(".git-veil")).unwrap();
    cmd_init(
        &repo.path,
        &key_store.join("owner.verifying"),
        "origin",
        &key_store.path,
        false,
        false,
    )
    .expect("re-init re-establishes trust");
    let pin_after = fs::read_to_string(&pin_path).unwrap();
    assert_eq!(pin_after.trim().len(), 64, "the rewritten pin is 64-hex");
    cmd_verify_keys(&repo.path, "origin", &key_store.path)
        .expect("verify passes once trust is re-established");
}

#[test]
fn test_legacy_pin_alone_refuses() {
    let (repo, key_store) = trusted_fixture("legacy-pin-only");

    // The committed record carries the current derivation. Only the
    // per-machine pin is a legacy 16-hex value.
    TrustPinStore::write_pin(&key_store.path, TEST_REPO_ID, "deadbeefdeadbeef").unwrap();

    let err = cmd_verify_keys(&repo.path, "origin", &key_store.path)
        .expect_err("a legacy pin must refuse even against a current record");
    assert_legacy_refusal(&err);
}

#[test]
fn test_legacy_record_alone_refuses() {
    let (repo, key_store) = trusted_fixture("legacy-record-only");

    // The per-machine pin carries the current derivation. Only the committed
    // record is a legacy 16-hex value.
    let trust_path = repo.join(".git-veil/trust.json");
    let mut trust = TrustStore::load_from_file(&trust_path).unwrap();
    trust.set_owner_fingerprint(TEST_REPO_ID.to_string(), "deadbeefdeadbeef".to_string());
    trust.save_to_file(&trust_path).unwrap();

    let err = cmd_verify_keys(&repo.path, "origin", &key_store.path)
        .expect_err("a legacy committed record must refuse");
    assert_legacy_refusal(&err);
}

// ---------------------------------------------------------------------------
// list-keys prints the computed 64-hex binding fingerprint per principal
// ---------------------------------------------------------------------------

#[test]
fn test_list_keys_prints_the_binding_fingerprint_per_principal() {
    let (repo, key_store) = trusted_fixture("list-keys-fp");

    // Two collaborators with known public key encodings.
    let mut recipients = Vec::new();
    for email in ["alice@example.com", "bob@example.com"] {
        let identity = generate_x25519_private_key();
        let recipient = x25519_public_key_encoding(&identity);
        cmd_add_key(
            &repo.path,
            email,
            &recipient,
            "origin",
            &key_store.path,
            None,
        )
        .expect("add-key");
        recipients.push((email, recipient));
    }

    let output = Command::new(env!("CARGO_BIN_EXE_git-veil"))
        .current_dir(&repo.path)
        .args([
            "--dangerously-skip-permissions-check",
            "list-keys",
            "--key-store",
            key_store.path.to_str().unwrap(),
        ])
        .output()
        .expect("run git-veil list-keys");
    assert!(
        output.status.success(),
        "list-keys runs: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    for (email, recipient) in &recipients {
        let expected_line = format!("{} {}", email, fingerprint_for_public_key(email, recipient));
        assert!(
            stdout.contains(&expected_line),
            "list-keys prints the computed 64-hex binding fingerprint for {email}: {stdout}"
        );
    }
}
