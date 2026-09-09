//! Interop tests: age identity/recipient roundtrip, key store import/export,
//! keyring serialization format, and cross-implementation interoperability
//! with the `age` and `rage` CLI tools.

use age::secrecy::ExposeSecret;
use git_veil::{
    decrypt_with_identity, encrypt_to_recipient, encrypt_to_recipients,
    export_public_key, generate_identity,
    import_identity_to_store, import_recipient_to_store,
    load_identities_from_store, load_recipients_from_store,
    parse_identity, parse_recipient,
    recipient_from_identity, fingerprint_for_recipient,
    find_identity_by_recipient, find_identity_by_fingerprint,
    find_recipient_by_fingerprint,
    Keyring,
};
use std::fs;
use std::path::PathBuf;
use std::process::Command;

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        let pid = std::process::id();
        let counter = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("git-veil-interop-{}-{}-{}", label, pid, counter));
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

/// Returns true if a CLI tool is available on PATH.
fn has_tool(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// ===========================================================================
// Pure Rust interop (no external tools)
// ===========================================================================

#[test]
fn test_identity_recipient_roundtrip() {
    let identity = generate_identity();
    let identity_str = identity.to_string().expose_secret().to_string();
    let recipient_str = recipient_from_identity(&identity);

    let parsed = parse_identity(&identity_str).expect("parse identity");
    let parsed_recipient = recipient_from_identity(&parsed);
    assert_eq!(parsed_recipient, recipient_str);

    let _recipient = parse_recipient(&recipient_str).expect("parse recipient");
}

#[test]
fn test_encrypt_recipient_decrypt_identity() {
    let identity = generate_identity();
    let recipient_str = recipient_from_identity(&identity);
    let recipient = parse_recipient(&recipient_str).unwrap();

    let plaintext = b"interop test\n";
    let ciphertext = encrypt_to_recipient(plaintext, &recipient).unwrap();
    let decrypted = decrypt_with_identity(&ciphertext, &identity).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_multi_recipient_all_decrypt() {
    let ids: Vec<_> = (0..3).map(|_| generate_identity()).collect();
    let recipients: Vec<_> = ids.iter()
        .map(|id| parse_recipient(&recipient_from_identity(id)).unwrap())
        .collect();

    let plaintext = b"multi\n";
    let ciphertext = encrypt_to_recipients(plaintext, &recipients).unwrap();

    for id in &ids {
        let decrypted = decrypt_with_identity(&ciphertext, id).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}

#[test]
fn test_key_store_import_load_identity() {
    let store = TempDir::new("ks-id");
    let identity = generate_identity();
    let identity_str = identity.to_string().expose_secret().to_string();
    let recipient_str = recipient_from_identity(&identity);

    import_identity_to_store(&store.path, &identity_str).unwrap();

    let loaded = load_identities_from_store(&store.path).unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].1, recipient_str);
}

#[test]
fn test_key_store_import_load_recipient() {
    let store = TempDir::new("ks-rcpt");
    let identity = generate_identity();
    let recipient_str = recipient_from_identity(&identity);

    import_recipient_to_store(&store.path, &recipient_str).unwrap();

    let loaded = load_recipients_from_store(&store.path).unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].1, recipient_str);
}

#[test]
fn test_find_identity_by_recipient() {
    let store = TempDir::new("ks-find-rcpt");
    let identity = generate_identity();
    let identity_str = identity.to_string().expose_secret().to_string();
    let recipient_str = recipient_from_identity(&identity);

    import_identity_to_store(&store.path, &identity_str).unwrap();

    let found = find_identity_by_recipient(&store.path, &recipient_str).unwrap();
    let found_recipient = recipient_from_identity(&found);
    assert_eq!(found_recipient, recipient_str);
}

#[test]
fn test_find_identity_by_fingerprint() {
    let store = TempDir::new("ks-find-fp");
    let identity = generate_identity();
    let identity_str = identity.to_string().expose_secret().to_string();
    let recipient_str = recipient_from_identity(&identity);
    let fingerprint = fingerprint_for_recipient(&recipient_str);

    import_identity_to_store(&store.path, &identity_str).unwrap();

    let found = find_identity_by_fingerprint(&store.path, &fingerprint).unwrap();
    let found_recipient = recipient_from_identity(&found);
    assert_eq!(found_recipient, recipient_str);
}

#[test]
fn test_find_recipient_by_fingerprint() {
    let store = TempDir::new("ks-find-rcpt-fp");
    let identity = generate_identity();
    let recipient_str = recipient_from_identity(&identity);
    let fingerprint = fingerprint_for_recipient(&recipient_str);

    import_recipient_to_store(&store.path, &recipient_str).unwrap();

    let found = find_recipient_by_fingerprint(&store.path, &fingerprint).unwrap();
    assert_eq!(found, recipient_str);
}

#[test]
fn test_export_by_recipient_str() {
    let store = TempDir::new("ks-export");
    let identity = generate_identity();
    let recipient_str = recipient_from_identity(&identity);

    import_recipient_to_store(&store.path, &recipient_str).unwrap();

    let exported = export_public_key(&store.path, &recipient_str).unwrap();
    assert_eq!(exported.trim(), recipient_str);
}

#[test]
fn test_keyring_serialize_parse_roundtrip() {
    let identity = generate_identity();
    let recipient_str = recipient_from_identity(&identity);
    let fingerprint = fingerprint_for_recipient(&recipient_str);

    let mut keyring = Keyring::new();
    keyring.add_entry(
        "alice@example.com".to_string(),
        recipient_str.clone(),
        fingerprint.clone(),
    )
    .unwrap();

    let serialized = keyring.serialize();
    let parsed = Keyring::parse(&serialized).unwrap();

    assert_eq!(parsed.entries.len(), 1);
    assert_eq!(parsed.entries[0].email, "alice@example.com");
    assert_eq!(parsed.entries[0].recipient, recipient_str);
    assert_eq!(parsed.entries[0].fingerprint, fingerprint);
}

#[test]
fn test_keyring_with_signature_roundtrip() {
    let identity = generate_identity();
    let recipient_str = recipient_from_identity(&identity);
    let fingerprint = fingerprint_for_recipient(&recipient_str);

    let mut keyring = Keyring::new();
    keyring.add_entry(
        "bob@example.com".to_string(),
        recipient_str,
        fingerprint,
    )
    .unwrap();
    keyring.signature = Some("-----BEGIN GIT-VEIL SIGNATURE-----\ndGVzdA==\n-----END GIT-VEIL SIGNATURE-----\n".to_string());

    let serialized = keyring.serialize();
    let parsed = Keyring::parse(&serialized).unwrap();

    assert!(parsed.signature.is_some());
    assert!(parsed.signature.unwrap().contains("GIT-VEIL SIGNATURE"));
}

#[test]
fn test_keyring_rejects_colon_in_email() {
    let mut keyring = Keyring::new();
    let result = keyring.add_entry(
        "alice:evil@example.com".to_string(),
        "age1xxx".to_string(),
        "deadbeef".to_string(),
    );
    assert!(result.is_err());
}

#[test]
fn test_keyring_remove_clears_signature() {
    let mut keyring = Keyring::new();
    keyring.add_entry("alice@example.com".to_string(), "age1xxx".to_string(), "deadbeef".to_string()).unwrap();
    keyring.signature = Some("sig".to_string());

    let removed = keyring.remove_entry("alice@example.com");
    assert!(removed);
    assert!(keyring.signature.is_none(), "signature should be cleared on remove");
    assert!(keyring.entries.is_empty());
}

#[test]
fn test_keyring_find_case_insensitive() {
    let mut keyring = Keyring::new();
    keyring.add_entry("Alice@Example.COM".to_string(), "age1xxx".to_string(), "deadbeef".to_string()).unwrap();

    assert!(keyring.find_by_email("alice@example.com").is_some());
    assert!(keyring.find_by_email("ALICE@EXAMPLE.COM").is_some());
    assert!(keyring.find_by_email("Alice@Example.COM").is_some());
    assert!(keyring.find_by_email("bob@example.com").is_none());
}

#[test]
fn test_fingerprint_format() {
    let identity = generate_identity();
    let recipient_str = recipient_from_identity(&identity);
    let fingerprint = fingerprint_for_recipient(&recipient_str);

    assert_eq!(fingerprint.len(), 16, "fingerprint should be 16 hex chars");
    assert!(fingerprint.chars().all(|c| c.is_ascii_hexdigit()), "fingerprint should be hex");
}

#[test]
fn test_different_identities_different_fingerprints() {
    let id1 = generate_identity();
    let id2 = generate_identity();
    let fp1 = fingerprint_for_recipient(&recipient_from_identity(&id1));
    let fp2 = fingerprint_for_recipient(&recipient_from_identity(&id2));
    assert_ne!(fp1, fp2);
}

// ===========================================================================
// CLI interop: age-keygen / rage-keygen keys work with git-veil
// ===========================================================================

/// Generates an age identity file using `age-keygen` and returns (identity_str, recipient_str).
fn age_keygen(dir: &TempDir, filename: &str) -> (String, String) {
    let path = dir.join(filename);
    let status = Command::new("age-keygen")
        .arg("-o")
        .arg(&path)
        .status()
        .expect("age-keygen");
    assert!(status.success(), "age-keygen failed");

    let content = fs::read_to_string(&path).unwrap();
    let identity_str = content
        .lines()
        .find(|l| l.starts_with("AGE-SECRET-KEY-"))
        .expect("identity line")
        .trim()
        .to_string();
    let recipient_str = content
        .lines()
        .find(|l| l.starts_with("# public key:"))
        .map(|l| l.trim_start_matches("# public key: ").trim().to_string())
        .expect("recipient line");

    (identity_str, recipient_str)
}

/// Generates an age identity file using `rage-keygen` and returns (identity_str, recipient_str).
fn rage_keygen(dir: &TempDir, filename: &str) -> (String, String) {
    let path = dir.join(filename);
    let status = Command::new("rage-keygen")
        .arg("-o")
        .arg(&path)
        .status()
        .expect("rage-keygen");
    assert!(status.success(), "rage-keygen failed");

    let content = fs::read_to_string(&path).unwrap();
    let identity_str = content
        .lines()
        .find(|l| l.starts_with("AGE-SECRET-KEY-"))
        .expect("identity line")
        .trim()
        .to_string();
    let recipient_str = content
        .lines()
        .find(|l| l.starts_with("# public key:"))
        .map(|l| l.trim_start_matches("# public key: ").trim().to_string())
        .expect("recipient line");

    (identity_str, recipient_str)
}

#[test]
fn test_age_keygen_identity_works_with_git_veil() {
    if !has_tool("age-keygen") {
        eprintln!("skipping: age-keygen not installed");
        return;
    }

    let dir = TempDir::new("age-keygen");
    let (identity_str, recipient_str) = age_keygen(&dir, "key.txt");

    // git-veil can parse the identity
    let identity = parse_identity(&identity_str).expect("git-veil parse age-keygen identity");

    // git-veil can derive the same recipient
    let derived = recipient_from_identity(&identity);
    assert_eq!(derived, recipient_str, "git-veil recipient should match age-keygen recipient");

    // git-veil can parse the recipient
    let _recipient = parse_recipient(&recipient_str).expect("git-veil parse age-keygen recipient");
}

#[test]
fn test_rage_keygen_identity_works_with_git_veil() {
    if !has_tool("rage-keygen") {
        eprintln!("skipping: rage-keygen not installed");
        return;
    }

    let dir = TempDir::new("rage-keygen");
    let (identity_str, recipient_str) = rage_keygen(&dir, "key.txt");

    let identity = parse_identity(&identity_str).expect("git-veil parse rage-keygen identity");
    let derived = recipient_from_identity(&identity);
    assert_eq!(derived, recipient_str, "git-veil recipient should match rage-keygen recipient");

    let _recipient = parse_recipient(&recipient_str).expect("git-veil parse rage-keygen recipient");
}

#[test]
fn test_git_veil_identity_works_with_age_keygen_recipient() {
    if !has_tool("age-keygen") {
        eprintln!("skipping: age-keygen not installed");
        return;
    }

    let dir = TempDir::new("gv-age-keygen");
    let (identity_str, recipient_str) = age_keygen(&dir, "key.txt");

    // git-veil encrypts with the age-keygen recipient
    let recipient = parse_recipient(&recipient_str).unwrap();
    let plaintext = b"encrypted by git-veil, key from age-keygen\n";
    let ciphertext = encrypt_to_recipient(plaintext, &recipient).unwrap();

    // git-veil decrypts with the age-keygen identity
    let identity = parse_identity(&identity_str).unwrap();
    let decrypted = decrypt_with_identity(&ciphertext, &identity).unwrap();
    assert_eq!(decrypted, plaintext);
}

// ===========================================================================
// CLI interop: git-veil encrypts, age/rage CLI decrypts
// ===========================================================================

/// Writes an age identity file in the format age/rage CLI expects.
fn write_identity_file(dir: &TempDir, filename: &str, identity_str: &str, recipient_str: &str) -> PathBuf {
    let path = dir.join(filename);
    fs::write(&path, format!("# created: 2026-01-01T00:00:00+00:00\n# public key: {}\n{}\n", recipient_str, identity_str)).unwrap();
    path
}

#[test]
fn test_git_veil_encrypts_age_cli_decrypts() {
    if !has_tool("age") {
        eprintln!("skipping: age not installed");
        return;
    }

    let dir = TempDir::new("gv-enc-age-dec");
    let identity = generate_identity();
    let identity_str = identity.to_string().expose_secret().to_string();
    let recipient_str = recipient_from_identity(&identity);

    // git-veil encrypts
    let recipient = parse_recipient(&recipient_str).unwrap();
    let plaintext = b"git-veil encrypted, age CLI decrypted\n";
    let ciphertext = encrypt_to_recipient(plaintext, &recipient).unwrap();

    // Write ciphertext to file
    let ct_path = dir.join("ciphertext.bin");
    fs::write(&ct_path, &ciphertext).unwrap();

    // Write identity file for age CLI
    let id_path = write_identity_file(&dir, "identity.txt", &identity_str, &recipient_str);

    // age CLI decrypts
    let output = Command::new("age")
        .arg("-d")
        .arg("-i")
        .arg(&id_path)
        .arg(&ct_path)
        .output()
        .expect("age");
    assert!(output.status.success(), "age decrypt failed: {}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(output.stdout, plaintext);
}

#[test]
fn test_git_veil_encrypts_rage_cli_decrypts() {
    if !has_tool("rage") {
        eprintln!("skipping: rage not installed");
        return;
    }

    let dir = TempDir::new("gv-enc-rage-dec");
    let identity = generate_identity();
    let identity_str = identity.to_string().expose_secret().to_string();
    let recipient_str = recipient_from_identity(&identity);

    let recipient = parse_recipient(&recipient_str).unwrap();
    let plaintext = b"git-veil encrypted, rage CLI decrypted\n";
    let ciphertext = encrypt_to_recipient(plaintext, &recipient).unwrap();

    let ct_path = dir.join("ciphertext.bin");
    fs::write(&ct_path, &ciphertext).unwrap();

    let id_path = write_identity_file(&dir, "identity.txt", &identity_str, &recipient_str);

    let output = Command::new("rage")
        .arg("-d")
        .arg("-i")
        .arg(&id_path)
        .arg(&ct_path)
        .output()
        .expect("rage");
    assert!(output.status.success(), "rage decrypt failed: {}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(output.stdout, plaintext);
}

// ===========================================================================
// CLI interop: age/rage CLI encrypts, git-veil decrypts
// ===========================================================================

#[test]
fn test_age_cli_encrypts_git_veil_decrypts() {
    if !has_tool("age") {
        eprintln!("skipping: age not installed");
        return;
    }

    let dir = TempDir::new("age-enc-gv-dec");
    let identity = generate_identity();
    let identity_str = identity.to_string().expose_secret().to_string();
    let recipient_str = recipient_from_identity(&identity);

    // Write plaintext
    let pt_path = dir.join("plaintext.txt");
    let plaintext = b"age CLI encrypted, git-veil decrypted\n";
    fs::write(&pt_path, plaintext).unwrap();

    // age CLI encrypts
    let ct_path = dir.join("ciphertext.bin");
    let status = Command::new("age")
        .arg("-r")
        .arg(&recipient_str)
        .arg("-o")
        .arg(&ct_path)
        .arg(&pt_path)
        .status()
        .expect("age");
    assert!(status.success(), "age encrypt failed");

    // git-veil decrypts
    let ciphertext = fs::read(&ct_path).unwrap();
    let identity = parse_identity(&identity_str).unwrap();
    let decrypted = decrypt_with_identity(&ciphertext, &identity).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_rage_cli_encrypts_git_veil_decrypts() {
    if !has_tool("rage") {
        eprintln!("skipping: rage not installed");
        return;
    }

    let dir = TempDir::new("rage-enc-gv-dec");
    let identity = generate_identity();
    let identity_str = identity.to_string().expose_secret().to_string();
    let recipient_str = recipient_from_identity(&identity);

    let pt_path = dir.join("plaintext.txt");
    let plaintext = b"rage CLI encrypted, git-veil decrypted\n";
    fs::write(&pt_path, plaintext).unwrap();

    let ct_path = dir.join("ciphertext.bin");
    let status = Command::new("rage")
        .arg("-r")
        .arg(&recipient_str)
        .arg("-o")
        .arg(&ct_path)
        .arg(&pt_path)
        .status()
        .expect("rage");
    assert!(status.success(), "rage encrypt failed");

    let ciphertext = fs::read(&ct_path).unwrap();
    let identity = parse_identity(&identity_str).unwrap();
    let decrypted = decrypt_with_identity(&ciphertext, &identity).unwrap();
    assert_eq!(decrypted, plaintext);
}

// ===========================================================================
// CLI interop: age-keygen key, rage CLI encrypts, git-veil decrypts
// ===========================================================================

#[test]
fn test_age_keygen_rage_encrypt_git_veil_decrypt() {
    if !has_tool("age-keygen") || !has_tool("rage") {
        eprintln!("skipping: age-keygen or rage not installed");
        return;
    }

    let dir = TempDir::new("agk-rage-gv");
    let (identity_str, recipient_str) = age_keygen(&dir, "key.txt");

    let pt_path = dir.join("plaintext.txt");
    let plaintext = b"age-keygen key, rage encrypted, git-veil decrypted\n";
    fs::write(&pt_path, plaintext).unwrap();

    let ct_path = dir.join("ciphertext.bin");
    let status = Command::new("rage")
        .arg("-r")
        .arg(&recipient_str)
        .arg("-o")
        .arg(&ct_path)
        .arg(&pt_path)
        .status()
        .expect("rage");
    assert!(status.success(), "rage encrypt failed");

    let ciphertext = fs::read(&ct_path).unwrap();
    let identity = parse_identity(&identity_str).unwrap();
    let decrypted = decrypt_with_identity(&ciphertext, &identity).unwrap();
    assert_eq!(decrypted, plaintext);
}

// ===========================================================================
// CLI interop: rage-keygen key, age CLI encrypts, git-veil decrypts
// ===========================================================================

#[test]
fn test_rage_keygen_age_encrypt_git_veil_decrypt() {
    if !has_tool("rage-keygen") || !has_tool("age") {
        eprintln!("skipping: rage-keygen or age not installed");
        return;
    }

    let dir = TempDir::new("rgk-age-gv");
    let (identity_str, recipient_str) = rage_keygen(&dir, "key.txt");

    let pt_path = dir.join("plaintext.txt");
    let plaintext = b"rage-keygen key, age encrypted, git-veil decrypted\n";
    fs::write(&pt_path, plaintext).unwrap();

    let ct_path = dir.join("ciphertext.bin");
    let status = Command::new("age")
        .arg("-r")
        .arg(&recipient_str)
        .arg("-o")
        .arg(&ct_path)
        .arg(&pt_path)
        .status()
        .expect("age");
    assert!(status.success(), "age encrypt failed");

    let ciphertext = fs::read(&ct_path).unwrap();
    let identity = parse_identity(&identity_str).unwrap();
    let decrypted = decrypt_with_identity(&ciphertext, &identity).unwrap();
    assert_eq!(decrypted, plaintext);
}

// ===========================================================================
// CLI interop: git-veil generates key, age CLI uses it
// ===========================================================================

#[test]
fn test_git_veil_key_age_cli_encrypts_and_decrypts() {
    if !has_tool("age") {
        eprintln!("skipping: age not installed");
        return;
    }

    let dir = TempDir::new("gv-key-age-cli");
    let identity = generate_identity();
    let identity_str = identity.to_string().expose_secret().to_string();
    let recipient_str = recipient_from_identity(&identity);

    // Write identity file in age CLI format
    let id_path = write_identity_file(&dir, "identity.txt", &identity_str, &recipient_str);

    let pt_path = dir.join("plaintext.txt");
    let plaintext = b"git-veil key, age CLI encrypt and decrypt\n";
    fs::write(&pt_path, plaintext).unwrap();

    // age CLI encrypts using git-veil's recipient
    let ct_path = dir.join("ciphertext.bin");
    let status = Command::new("age")
        .arg("-r")
        .arg(&recipient_str)
        .arg("-o")
        .arg(&ct_path)
        .arg(&pt_path)
        .status()
        .expect("age");
    assert!(status.success(), "age encrypt failed");

    // age CLI decrypts using git-veil's identity
    let output = Command::new("age")
        .arg("-d")
        .arg("-i")
        .arg(&id_path)
        .arg(&ct_path)
        .output()
        .expect("age");
    assert!(output.status.success(), "age decrypt failed: {}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(output.stdout, plaintext);

    // git-veil also decrypts the age-CLI-encrypted file
    let ciphertext = fs::read(&ct_path).unwrap();
    let identity = parse_identity(&identity_str).unwrap();
    let decrypted = decrypt_with_identity(&ciphertext, &identity).unwrap();
    assert_eq!(decrypted, plaintext);
}

// ===========================================================================
// CLI interop: git-veil generates key, rage CLI uses it
// ===========================================================================

#[test]
fn test_git_veil_key_rage_cli_encrypts_and_decrypts() {
    if !has_tool("rage") {
        eprintln!("skipping: rage not installed");
        return;
    }

    let dir = TempDir::new("gv-key-rage-cli");
    let identity = generate_identity();
    let identity_str = identity.to_string().expose_secret().to_string();
    let recipient_str = recipient_from_identity(&identity);

    let id_path = write_identity_file(&dir, "identity.txt", &identity_str, &recipient_str);

    let pt_path = dir.join("plaintext.txt");
    let plaintext = b"git-veil key, rage CLI encrypt and decrypt\n";
    fs::write(&pt_path, plaintext).unwrap();

    let ct_path = dir.join("ciphertext.bin");
    let status = Command::new("rage")
        .arg("-r")
        .arg(&recipient_str)
        .arg("-o")
        .arg(&ct_path)
        .arg(&pt_path)
        .status()
        .expect("rage");
    assert!(status.success(), "rage encrypt failed");

    let output = Command::new("rage")
        .arg("-d")
        .arg("-i")
        .arg(&id_path)
        .arg(&ct_path)
        .output()
        .expect("rage");
    assert!(output.status.success(), "rage decrypt failed: {}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(output.stdout, plaintext);

    // git-veil also decrypts the rage-CLI-encrypted file
    let ciphertext = fs::read(&ct_path).unwrap();
    let identity = parse_identity(&identity_str).unwrap();
    let decrypted = decrypt_with_identity(&ciphertext, &identity).unwrap();
    assert_eq!(decrypted, plaintext);
}

// ===========================================================================
// CLI interop: multi-recipient git-veil encrypts, age CLI decrypts one
// ===========================================================================

#[test]
fn test_git_veil_multi_recipient_age_cli_decrypts() {
    if !has_tool("age") {
        eprintln!("skipping: age not installed");
        return;
    }

    let dir = TempDir::new("gv-multi-age");
    let id1 = generate_identity();
    let id2 = generate_identity();
    let id1_str = id1.to_string().expose_secret().to_string();
    let r1_str = recipient_from_identity(&id1);
    let r2_str = recipient_from_identity(&id2);

    let r1 = parse_recipient(&r1_str).unwrap();
    let r2 = parse_recipient(&r2_str).unwrap();

    let plaintext = b"multi-recipient git-veil encrypted, age CLI decrypted\n";
    let ciphertext = encrypt_to_recipients(plaintext, &[r1, r2]).unwrap();

    let ct_path = dir.join("ciphertext.bin");
    fs::write(&ct_path, &ciphertext).unwrap();

    // age CLI decrypts with id1
    let id1_path = write_identity_file(&dir, "id1.txt", &id1_str, &r1_str);
    let output = Command::new("age")
        .arg("-d")
        .arg("-i")
        .arg(&id1_path)
        .arg(&ct_path)
        .output()
        .expect("age");
    assert!(output.status.success(), "age decrypt with id1 failed: {}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(output.stdout, plaintext);

    // age CLI decrypts with id2
    let id2_path = write_identity_file(&dir, "id2.txt", &id2.to_string().expose_secret(), &r2_str);
    let output = Command::new("age")
        .arg("-d")
        .arg("-i")
        .arg(&id2_path)
        .arg(&ct_path)
        .output()
        .expect("age");
    assert!(output.status.success(), "age decrypt with id2 failed: {}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(output.stdout, plaintext);
}

// ===========================================================================
// CLI interop: age-keygen identity file importable by git-veil import
// ===========================================================================

#[test]
fn test_age_keygen_file_importable_by_git_veil() {
    if !has_tool("age-keygen") {
        eprintln!("skipping: age-keygen not installed");
        return;
    }

    let dir = TempDir::new("agk-import");
    let (identity_str, recipient_str) = age_keygen(&dir, "key.txt");

    // git-veil's import_identity_to_store should accept the identity string
    let store = TempDir::new("agk-import-store");
    import_identity_to_store(&store.path, &identity_str).unwrap();

    // Verify it loads back
    let loaded = load_identities_from_store(&store.path).unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].1, recipient_str);
}

#[test]
fn test_rage_keygen_file_importable_by_git_veil() {
    if !has_tool("rage-keygen") {
        eprintln!("skipping: rage-keygen not installed");
        return;
    }

    let dir = TempDir::new("rgk-import");
    let (identity_str, recipient_str) = rage_keygen(&dir, "key.txt");

    let store = TempDir::new("rgk-import-store");
    import_identity_to_store(&store.path, &identity_str).unwrap();

    let loaded = load_identities_from_store(&store.path).unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].1, recipient_str);
}
