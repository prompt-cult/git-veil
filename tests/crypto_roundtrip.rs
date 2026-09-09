use age::secrecy::ExposeSecret;
use git_veil::{
    encrypt_to_recipient, encrypt_to_recipients, decrypt_with_identity,
    parse_recipient, parse_identity, recipient_from_identity,
    generate_identity, fingerprint_for_recipient,
    create_signature_block, extract_content_to_verify_from_keyring,
    extract_signature_from_keyring, verify_keyring_signature,
    parse_signing_key, parse_verifying_key,
    generate_signing_keypair,
};

#[test]
fn test_age_encrypt_decrypt_roundtrip() {
    let identity = generate_identity();
    let recipient_str = recipient_from_identity(&identity);
    let recipient = parse_recipient(&recipient_str).unwrap();

    let plaintext = b"Hello, age encryption!";
    let ciphertext = encrypt_to_recipient(plaintext, &recipient).unwrap();
    let decrypted = decrypt_with_identity(&ciphertext, &identity).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_age_multi_recipient_roundtrip() {
    let id1 = generate_identity();
    let id2 = generate_identity();
    let r1 = parse_recipient(&recipient_from_identity(&id1)).unwrap();
    let r2 = parse_recipient(&recipient_from_identity(&id2)).unwrap();

    let plaintext = b"Multi-recipient secret";
    let recipients = vec![r1, r2];
    let ciphertext = encrypt_to_recipients(plaintext, &recipients).unwrap();

    // Both identities can decrypt
    let d1 = decrypt_with_identity(&ciphertext, &id1).unwrap();
    let d2 = decrypt_with_identity(&ciphertext, &id2).unwrap();
    assert_eq!(d1, plaintext);
    assert_eq!(d2, plaintext);
}

#[test]
fn test_age_decrypt_with_wrong_key_fails() {
    let id1 = generate_identity();
    let id2 = generate_identity();
    let r1 = parse_recipient(&recipient_from_identity(&id1)).unwrap();

    let plaintext = b"Secret for id1 only";
    let ciphertext = encrypt_to_recipient(plaintext, &r1).unwrap();

    // id2 cannot decrypt
    let result = decrypt_with_identity(&ciphertext, &id2);
    assert!(result.is_err());
}

#[test]
fn test_fingerprint_is_consistent() {
    let identity = generate_identity();
    let recipient_str = recipient_from_identity(&identity);
    let fp1 = fingerprint_for_recipient(&recipient_str);
    let fp2 = fingerprint_for_recipient(&recipient_str);
    assert_eq!(fp1, fp2);
}

#[test]
fn test_ed25519_sign_verify_roundtrip() {
    let (signing_key, verifying_key_hex) = generate_signing_keypair();
    let verifying_key = parse_verifying_key(&verifying_key_hex).unwrap();

    let content = "-----BEGIN GIT-VEIL KEYRING-----\nalice:age1xxx:deadbeef\n-----END GIT-VEIL KEYRING-----";
    let sig_block = create_signature_block(content, &signing_key).unwrap();

    // Extract and verify
    let full_text = format!("{}\n{}", content, sig_block);
    let content_to_verify = extract_content_to_verify_from_keyring(&full_text).unwrap();
    let sig_b64 = extract_signature_from_keyring(&full_text).unwrap();

    verify_keyring_signature(&content_to_verify, &sig_b64, &verifying_key).unwrap();
}

#[test]
fn test_ed25519_verify_tampered_content_fails() {
    let (signing_key, verifying_key_hex) = generate_signing_keypair();
    let verifying_key = parse_verifying_key(&verifying_key_hex).unwrap();

    let content = "-----BEGIN GIT-VEIL KEYRING-----\nalice:age1xxx:deadbeef\n-----END GIT-VEIL KEYRING-----";
    let sig_block = create_signature_block(content, &signing_key).unwrap();

    // Tamper with content
    let tampered = content.replace("alice", "mallory");
    let full_text = format!("{}\n{}", tampered, sig_block);
    let content_to_verify = extract_content_to_verify_from_keyring(&full_text).unwrap();
    let sig_b64 = extract_signature_from_keyring(&full_text).unwrap();

    let result = verify_keyring_signature(&content_to_verify, &sig_b64, &verifying_key);
    assert!(result.is_err());
}

#[test]
fn test_ed25519_verify_wrong_key_fails() {
    let (signing_key, _) = generate_signing_keypair();
    let (_, other_verifying_key_hex) = generate_signing_keypair();
    let other_verifying_key = parse_verifying_key(&other_verifying_key_hex).unwrap();

    let content = "-----BEGIN GIT-VEIL KEYRING-----\nalice:age1xxx:deadbeef\n-----END GIT-VEIL KEYRING-----";
    let sig_block = create_signature_block(content, &signing_key).unwrap();

    let full_text = format!("{}\n{}", content, sig_block);
    let content_to_verify = extract_content_to_verify_from_keyring(&full_text).unwrap();
    let sig_b64 = extract_signature_from_keyring(&full_text).unwrap();

    let result = verify_keyring_signature(&content_to_verify, &sig_b64, &other_verifying_key);
    assert!(result.is_err());
}

#[test]
fn test_parse_identity_and_recipient() {
    let identity = generate_identity();
    let identity_str = identity.to_string().expose_secret().to_string();
    let recipient_str = recipient_from_identity(&identity);

    // Round-trip: parse identity, get recipient
    let parsed_identity = parse_identity(&identity_str).unwrap();
    let parsed_recipient_str = recipient_from_identity(&parsed_identity);
    assert_eq!(parsed_recipient_str, recipient_str);

    // Parse recipient
    let _parsed_recipient = parse_recipient(&recipient_str).unwrap();
}

#[test]
fn test_signing_key_roundtrip() {
    let (signing_key, verifying_key_hex) = generate_signing_keypair();
    let signing_key_hex = hex::encode(signing_key.to_bytes());

    // Round-trip: parse signing key, verify it produces the same verifying key
    let parsed_signing_key = parse_signing_key(&signing_key_hex).unwrap();
    let parsed_verifying_key = parsed_signing_key.verifying_key();
    assert_eq!(parsed_verifying_key.to_bytes(), signing_key.verifying_key().to_bytes());

    // Verify the hex matches
    let parsed_verifying_key_hex = hex::encode(parsed_verifying_key.to_bytes());
    assert_eq!(parsed_verifying_key_hex, verifying_key_hex);
}
