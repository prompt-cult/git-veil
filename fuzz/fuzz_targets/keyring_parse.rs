//! Attacks the committed signed keyring (`.git-veil/keyring`) with random
//! data: repo content an attacker can substitute. Every push to main runs
//! this target in the Fuzz Smoke job at
//! `.github/workflows/fuzz-smoke.yml`; this file is the target's only home.
#![no_main]

use git_veil::Keyring;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(k) = Keyring::parse(s) {
        // a colon in any email would break the two-field line format.
        // add_entry guards it. Parse must never let one through.
        for e in &k.entries {
            assert!(!e.email.contains(':'), "parsed email must not contain ':'");
        }
        // roundtrip oracle. Serialize then parse must be stable, field for field.
        let reparsed = Keyring::parse(&k.serialize()).expect("serialize(parse(x)) must re-parse");
        assert_eq!(reparsed.entries.len(), k.entries.len());
        for (a, b) in reparsed.entries.iter().zip(&k.entries) {
            assert_eq!(a.email, b.email);
            assert_eq!(a.public_key, b.public_key);
        }
        assert_eq!(reparsed.signature.is_some(), k.signature.is_some());
    }
});
