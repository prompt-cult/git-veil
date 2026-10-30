//! Attacks the committed trust record (.git-veil/trust.json) with random
//! data: repo content an attacker can substitute. Every push to main runs
//! this target in the Fuzz Smoke job at
//! .github/workflows/fuzz-smoke.yml; this file is the target's only home.
#![no_main]

use git_veil::TrustStore;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(store) = TrustStore::deserialize(s) {
        // roundtrip: serialize then deserialize must be stable
        let serialized = store.serialize().expect("serialize of a valid store");
        let reparsed = TrustStore::deserialize(&serialized).expect("re-serialize must re-parse");
        assert_eq!(reparsed.owner_fingerprints, store.owner_fingerprints);
    }
});
