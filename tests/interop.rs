//! Interop tests: age identity/recipient roundtrip, key store import/export,
//! and keyring serialization format.

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
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

// ---------------------------------------------------------------------------
// Identity -> recipient -> identity roundtrip
// ---------------------------------------------------------------------------

#[test]
fn test_identity_recipient_roundtrip() {
    let identity = generate_identity();
    let identity_str = identity.to_string().expose_secret().to_string();
    let recipient_str = recipient_from_identity(&identity);

    // Parse identity back
    let parsed = parse_identity(&identity_str).expect("parse identity");
    let parsed_recipient = recipient_from_identity(&parsed);
    assert_eq!(parsed_recipient, recipient_str);

    // Parse recipient
    let _recipient = parse_recipient(&recipient_str).expect("parse recipient");
}

// ---------------------------------------------------------------------------
// Encrypt with recipient, decrypt with identity
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Multi-recipient encryption: all identities can decrypt
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Key store: import and load identity
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Key store: import and load recipient
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Key store: find identity by recipient
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Key store: find identity by fingerprint
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Key store: find recipient by fingerprint
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Key store: export by recipient string
// ---------------------------------------------------------------------------

#[test]
fn test_export_by_recipient_str() {
    let store = TempDir::new("ks-export");
    let identity = generate_identity();
    let recipient_str = recipient_from_identity(&identity);

    import_recipient_to_store(&store.path, &recipient_str).unwrap();

    let exported = export_public_key(&store.path, &recipient_str).unwrap();
    assert_eq!(exported.trim(), recipient_str);
}

// ---------------------------------------------------------------------------
// Keyring serialize/parse roundtrip
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Keyring with signature serialize/parse roundtrip
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Keyring add_entry rejects email with colon
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Keyring remove_entry clears signature
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Keyring find_by_email is case-insensitive
// ---------------------------------------------------------------------------

#[test]
fn test_keyring_find_case_insensitive() {
    let mut keyring = Keyring::new();
    keyring.add_entry("Alice@Example.COM".to_string(), "age1xxx".to_string(), "deadbeef".to_string()).unwrap();

    assert!(keyring.find_by_email("alice@example.com").is_some());
    assert!(keyring.find_by_email("ALICE@EXAMPLE.COM").is_some());
    assert!(keyring.find_by_email("Alice@Example.COM").is_some());
    assert!(keyring.find_by_email("bob@example.com").is_none());
}

// ---------------------------------------------------------------------------
// Fingerprint is deterministic and 16 hex chars
// ---------------------------------------------------------------------------

#[test]
fn test_fingerprint_format() {
    let identity = generate_identity();
    let recipient_str = recipient_from_identity(&identity);
    let fingerprint = fingerprint_for_recipient(&recipient_str);

    assert_eq!(fingerprint.len(), 16, "fingerprint should be 16 hex chars");
    assert!(fingerprint.chars().all(|c| c.is_ascii_hexdigit()), "fingerprint should be hex");
}

// ---------------------------------------------------------------------------
// Different identities produce different fingerprints
// ---------------------------------------------------------------------------

#[test]
fn test_different_identities_different_fingerprints() {
    let id1 = generate_identity();
    let id2 = generate_identity();
    let fp1 = fingerprint_for_recipient(&recipient_from_identity(&id1));
    let fp2 = fingerprint_for_recipient(&recipient_from_identity(&id2));
    assert_ne!(fp1, fp2);
}
