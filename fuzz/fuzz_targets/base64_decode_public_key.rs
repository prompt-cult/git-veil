#![no_main]

use libfuzzer_sys::fuzz_target;
use git_gpg::{base64_decode_public_key, base64_encode_public_key, extract_key_fingerprint};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    // non-base64, non-UTF-8-after-decode, and non-armour inputs must all be
    // Err — never Ok and never panic
    if let Ok(key) = base64_decode_public_key(s) {
        if let Ok(enc) = base64_encode_public_key(&key) {
            let re = base64_decode_public_key(&enc)
                .expect("encode∘decode must succeed for a decoded key");
            assert_eq!(
                extract_key_fingerprint(&re),
                extract_key_fingerprint(&key),
                "decode∘encode∘decode roundtrip must preserve the fingerprint"
            );
        }
    }
});
