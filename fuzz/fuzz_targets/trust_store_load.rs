#![no_main]

use libfuzzer_sys::fuzz_target;
use git_veil::TrustStore;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    if let Ok(store) = TrustStore::deserialize(s) {
        // roundtrip: serialize∘deserialize must be stable
        let serialized = store.serialize().expect("serialize of a valid store");
        let reparsed =
            TrustStore::deserialize(&serialized).expect("re-serialize must re-parse");
        assert_eq!(reparsed.trusted_keys, store.trusted_keys);
    }
});
