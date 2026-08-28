#![no_main]

use libfuzzer_sys::fuzz_target;
use git_veil::{
    base64_decode_public_key, base64_encode_public_key, extract_key_fingerprint,
    extract_key_identities, parse_armored_public_key, validate_public_key_for_use, KeyUse,
};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    if let Ok(key) = parse_armored_public_key(s) {
        // the trust gate must never panic; expiry/revocation logic rejects,
        // never "warn and proceed", so we only care that it returns
        let _ = validate_public_key_for_use(&key, KeyUse::Certify);
        let _ = validate_public_key_for_use(&key, KeyUse::Encrypt);
        let _ = extract_key_identities(&key);
        let _ = extract_key_fingerprint(&key);
        // base64 roundtrip must hold for anything that parsed
        if let Ok(enc) = base64_encode_public_key(&key) {
            let re = base64_decode_public_key(&enc)
                .expect("encode∘decode must succeed for a parsed key");
            assert_eq!(
                extract_key_fingerprint(&re),
                extract_key_fingerprint(&key),
                "encode∘decode roundtrip must preserve the fingerprint"
            );
        }
    }
});
