#![no_main]

use libfuzzer_sys::fuzz_target;
use git_veil::decrypt_with_private_key;
use pgp::composed::{EncryptionCaps, KeyType, SecretKeyParamsBuilder, SubkeyParamsBuilder};
use rand::thread_rng;
use std::sync::LazyLock;

/// One fixed in-harness generated key, created lazily on first input so the
/// crypto cost is paid once per process, not per exec.
static FIXED_SECRET_KEY: LazyLock<pgp::composed::SignedSecretKey> = LazyLock::new(|| {
    let mut rng = thread_rng();
    let encrypt_subkey = SubkeyParamsBuilder::default()
        .key_type(KeyType::X25519)
        .can_encrypt(EncryptionCaps::All)
        .build()
        .expect("build encrypt subkey params");
    let params = SecretKeyParamsBuilder::default()
        .key_type(KeyType::Ed25519)
        .can_certify(true)
        .can_sign(true)
        .primary_user_id("Fuzz Target <fuzz@example.com>".to_string())
        .passphrase(None)
        .subkeys(vec![encrypt_subkey])
        .build()
        .expect("build key params");
    params.generate(&mut rng).expect("generate key")
});

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    if let Err(err) = decrypt_with_private_key(s, &FIXED_SECRET_KEY, None) {
        let message = format!("{err:#}");
        // the empty string is a substring of everything — only meaningful
        // for non-trivial inputs
        if !s.is_empty() {
            assert!(
                !message.contains(s),
                "error messages must never echo the ciphertext"
            );
        }
        assert!(
            !message.contains("BEGIN PGP PRIVATE KEY"),
            "error messages must never echo key material"
        );
    }
});
