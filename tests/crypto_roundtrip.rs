use age::secrecy::ExposeSecret;
use git_veil::{
    create_signature_block, decrypt_with_x25519_private_key, encrypt_to_x25519_public_key,
    encrypt_to_x25519_public_keys, extract_content_to_verify_from_keyring,
    extract_signature_from_keyring, generate_signing_keypair, generate_x25519_private_key,
    parse_signing_key, parse_verifying_key, parse_x25519_private_key, parse_x25519_public_key,
    verify_keyring_signature, x25519_public_key_encoding,
};

#[test]
fn test_age_encrypt_decrypt_roundtrip() {
    let identity = generate_x25519_private_key();
    let recipient_str = x25519_public_key_encoding(&identity);
    let recipient = parse_x25519_public_key(&recipient_str).unwrap();

    let plaintext = b"Hello, age encryption!";
    let ciphertext = encrypt_to_x25519_public_key(plaintext, &recipient).unwrap();
    let decrypted = decrypt_with_x25519_private_key(&ciphertext, &identity).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_age_multi_recipient_roundtrip() {
    let id1 = generate_x25519_private_key();
    let id2 = generate_x25519_private_key();
    let r1 = parse_x25519_public_key(&x25519_public_key_encoding(&id1)).unwrap();
    let r2 = parse_x25519_public_key(&x25519_public_key_encoding(&id2)).unwrap();

    let plaintext = b"Multi-recipient secret";
    let recipients = vec![r1, r2];
    let ciphertext = encrypt_to_x25519_public_keys(plaintext, &recipients).unwrap();

    // Both private keys can decrypt
    let d1 = decrypt_with_x25519_private_key(&ciphertext, &id1).unwrap();
    let d2 = decrypt_with_x25519_private_key(&ciphertext, &id2).unwrap();
    assert_eq!(d1, plaintext);
    assert_eq!(d2, plaintext);
}

#[test]
fn test_age_decrypt_with_wrong_key_fails() {
    let id1 = generate_x25519_private_key();
    let id2 = generate_x25519_private_key();
    let r1 = parse_x25519_public_key(&x25519_public_key_encoding(&id1)).unwrap();

    let plaintext = b"Secret for id1 only";
    let ciphertext = encrypt_to_x25519_public_key(plaintext, &r1).unwrap();

    // id2 cannot decrypt
    let result = decrypt_with_x25519_private_key(&ciphertext, &id2);
    assert!(result.is_err());
}

#[test]
fn test_ed25519_sign_verify_roundtrip() {
    let (signing_key, verifying_key_hex) = generate_signing_keypair();
    let verifying_key = parse_verifying_key(&verifying_key_hex).unwrap();

    let content = "-----BEGIN GIT-VEIL KEYRING-----\nalice:age1xxx\n-----END GIT-VEIL KEYRING-----";
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

    let content = "-----BEGIN GIT-VEIL KEYRING-----\nalice:age1xxx\n-----END GIT-VEIL KEYRING-----";
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

    let content = "-----BEGIN GIT-VEIL KEYRING-----\nalice:age1xxx\n-----END GIT-VEIL KEYRING-----";
    let sig_block = create_signature_block(content, &signing_key).unwrap();

    let full_text = format!("{}\n{}", content, sig_block);
    let content_to_verify = extract_content_to_verify_from_keyring(&full_text).unwrap();
    let sig_b64 = extract_signature_from_keyring(&full_text).unwrap();

    let result = verify_keyring_signature(&content_to_verify, &sig_b64, &other_verifying_key);
    assert!(result.is_err());
}

#[test]
fn test_parse_x25519_private_and_public_key() {
    let private_key = generate_x25519_private_key();
    let private_key_str = private_key.to_string().expose_secret().to_string();
    let public_key_str = x25519_public_key_encoding(&private_key);

    // Round-trip: parse the private key, derive the public key encoding
    let parsed_private_key = parse_x25519_private_key(&private_key_str).unwrap();
    let parsed_public_key_str = x25519_public_key_encoding(&parsed_private_key);
    assert_eq!(parsed_public_key_str, public_key_str);

    // Parse the public key encoding
    let _parsed_public_key = parse_x25519_public_key(&public_key_str).unwrap();
}

#[test]
fn test_signing_key_roundtrip() {
    let (signing_key, verifying_key_hex) = generate_signing_keypair();
    let signing_key_hex = hex::encode(signing_key.to_bytes());

    // Round-trip: parse signing key, verify it produces the same verifying key
    let parsed_signing_key = parse_signing_key(&signing_key_hex).unwrap();
    let parsed_verifying_key = parsed_signing_key.verifying_key();
    assert_eq!(
        parsed_verifying_key.to_bytes(),
        signing_key.verifying_key().to_bytes()
    );

    // Verify the hex matches
    let parsed_verifying_key_hex = hex::encode(parsed_verifying_key.to_bytes());
    assert_eq!(parsed_verifying_key_hex, verifying_key_hex);
}
