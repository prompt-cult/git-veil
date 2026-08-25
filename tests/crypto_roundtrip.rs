//! Integration tests for encrypt/decrypt roundtrip using pgp crate.
//!
//! These tests verify that our crypto operations work correctly with
//! keys generated on-the-fly using the pure Rust `pgp` crate.

use pgp::composed::{
    Deserializable, EncryptionCaps, Message, MessageBuilder, SecretKeyParamsBuilder,
    SignedPublicKey, SignedSecretKey, SubkeyParamsBuilder,
};
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::types::{KeyDetails, Password};
use rand::thread_rng;

/// Generate a test Ed25519 key pair (primary key for certify, encryption subkey).
fn generate_ed25519_test_key() -> (SignedSecretKey, SignedPublicKey) {
    let mut rng = thread_rng();

    let encrypt_subkey = SubkeyParamsBuilder::default()
        .key_type(pgp::composed::KeyType::X25519)
        .can_encrypt(EncryptionCaps::All)
        .build()
        .expect("build encrypt subkey params");

    let secret_key_params = SecretKeyParamsBuilder::default()
        .key_type(pgp::composed::KeyType::Ed25519)
        .can_certify(true)
        .can_sign(true)
        .primary_user_id("test <test@example.com>".into())
        .passphrase(None)
        .subkeys(vec![encrypt_subkey])
        .build()
        .expect("build key params");

    let signed_secret_key = secret_key_params
        .generate(&mut rng)
        .expect("generate key");

    let public_key = signed_secret_key.to_public_key();

    (signed_secret_key, public_key)
}

/// Generate a test RSA-4096 key pair.
fn generate_rsa_test_key() -> (SignedSecretKey, SignedPublicKey) {
    let mut rng = thread_rng();

    let encrypt_subkey = SubkeyParamsBuilder::default()
        .key_type(pgp::composed::KeyType::Rsa(2048))
        .can_encrypt(EncryptionCaps::All)
        .build()
        .expect("build encrypt subkey params");

    let secret_key_params = SecretKeyParamsBuilder::default()
        .key_type(pgp::composed::KeyType::Rsa(2048))
        .can_certify(true)
        .can_sign(true)
        .primary_user_id("test <test@example.com>".into())
        .passphrase(None)
        .subkeys(vec![encrypt_subkey])
        .build()
        .expect("build key params");

    let signed_secret_key = secret_key_params
        .generate(&mut rng)
        .expect("generate key");

    let public_key = signed_secret_key.to_public_key();

    (signed_secret_key, public_key)
}

/// Find the first encryption subkey from a public key.
fn find_encryption_subkey(public_key: &SignedPublicKey) -> &pgp::composed::SignedPublicSubKey {
    public_key
        .public_subkeys
        .iter()
        .find(|sk| {
            sk.signatures
                .iter()
                .any(|sig| sig.key_flags().encrypt_comms() || sig.key_flags().encrypt_storage())
        })
        .expect("No encryption subkey found")
}

/// Encrypt plaintext to a public key, returning armored ciphertext.
fn encrypt_to_key(plaintext: &[u8], public_key: &SignedPublicKey) -> String {
    let mut rng = thread_rng();

    let encryption_subkey = find_encryption_subkey(public_key);

    let builder = MessageBuilder::from_bytes("file", plaintext.to_vec());
    let mut builder = builder.seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
    builder
        .encrypt_to_key(&mut rng, &encryption_subkey.key)
        .expect("encrypt to key");

    builder
        .to_armored_string(&mut rng, Default::default())
        .expect("armor encrypted message")
}

/// Decrypt armored ciphertext with a secret key, returning plaintext.
fn decrypt_with_key(ciphertext: &str, secret_key: &SignedSecretKey) -> Vec<u8> {
    let passphrase = Password::empty();

    let message = Message::from_string(ciphertext)
        .expect("parse message")
        .0;

    let mut decrypted = message
        .decrypt(&passphrase, secret_key)
        .expect("decrypt message");

    decrypted.as_data_vec().expect("extract plaintext")
}

#[test]
fn test_ed25519_encrypt_decrypt_roundtrip() {
    let (secret_key, public_key) = generate_ed25519_test_key();

    let plaintext = b"Hello, this is a secret message!";

    let ciphertext = encrypt_to_key(plaintext, &public_key);
    assert!(ciphertext.contains("-----BEGIN PGP MESSAGE-----"));

    let decrypted = decrypt_with_key(&ciphertext, &secret_key);
    assert_eq!(decrypted, plaintext.to_vec());
}

#[test]
fn test_rsa_encrypt_decrypt_roundtrip() {
    let (secret_key, public_key) = generate_rsa_test_key();

    let plaintext = b"RSA encrypted secret data";

    let ciphertext = encrypt_to_key(plaintext, &public_key);
    assert!(ciphertext.contains("-----BEGIN PGP MESSAGE-----"));

    let decrypted = decrypt_with_key(&ciphertext, &secret_key);
    assert_eq!(decrypted, plaintext.to_vec());
}

#[test]
fn test_encrypt_empty_message() {
    let (secret_key, public_key) = generate_ed25519_test_key();

    let plaintext = b"";

    let ciphertext = encrypt_to_key(plaintext, &public_key);
    let decrypted = decrypt_with_key(&ciphertext, &secret_key);

    assert_eq!(decrypted, plaintext.to_vec());
}

#[test]
fn test_encrypt_binary_data() {
    let (secret_key, public_key) = generate_ed25519_test_key();

    let plaintext: Vec<u8> = (0..=255).cycle().take(1024).collect();

    let ciphertext = encrypt_to_key(&plaintext, &public_key);
    let decrypted = decrypt_with_key(&ciphertext, &secret_key);

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_public_key_can_be_armored_and_reloaded() {
    let (_, public_key) = generate_ed25519_test_key();

    let armored = public_key
        .to_armored_string(Default::default())
        .expect("armor public key");

    assert!(armored.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----"));

    let (reloaded, _headers) =
        SignedPublicKey::from_string(&armored).expect("parse armored public key");

    assert_eq!(public_key.fingerprint(), reloaded.fingerprint());
}

#[test]
fn test_secret_key_can_be_armored_and_reloaded() {
    let (secret_key, _) = generate_ed25519_test_key();

    let armored = secret_key
        .to_armored_string(Default::default())
        .expect("armor secret key");

    assert!(armored.contains("-----BEGIN PGP PRIVATE KEY BLOCK-----"));

    let (reloaded, _headers) =
        SignedSecretKey::from_string(&armored).expect("parse armored secret key");

    assert_eq!(secret_key.fingerprint(), reloaded.fingerprint());

    let plaintext = b"Test after reload";
    let ciphertext = encrypt_to_key(plaintext, &secret_key.to_public_key());
    let decrypted = decrypt_with_key(&ciphertext, &reloaded);
    assert_eq!(decrypted, plaintext.to_vec());
}
