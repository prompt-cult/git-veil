#![no_main]

use libfuzzer_sys::fuzz_target;
use git_gpg::Keyring;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    if let Ok(k) = Keyring::parse(s) {
        // a colon in any email would brick the keyring line format
        // (add_entry guards it; parse must never let one through)
        for e in &k.entries {
            assert!(!e.email.contains(':'), "parsed email must not contain ':'");
        }
        // roundtrip oracle: serialize∘parse must be stable, field for field
        let reparsed = Keyring::parse(&k.serialize())
            .expect("serialize(parse(x)) must re-parse");
        assert_eq!(reparsed.entries.len(), k.entries.len());
        for (a, b) in reparsed.entries.iter().zip(&k.entries) {
            assert_eq!(a.email, b.email);
            assert_eq!(a.base64_key, b.base64_key);
            assert_eq!(a.fingerprint, b.fingerprint);
        }
        assert_eq!(reparsed.signature.is_some(), k.signature.is_some());
    }
});
