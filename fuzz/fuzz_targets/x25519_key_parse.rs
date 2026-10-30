//! Attacks the X25519 public key strings passed to the CLI with random
//! data: add-key, fingerprint and export take a key as an argument (the
//! age public key encoding, age1...). Parser refusals name the fixed
//! message; panics are wounds. Every push to main runs this target in
//! the Fuzz Smoke job at .github/workflows/fuzz-smoke.yml; this file is
//! the target's only home.
#![no_main]

use git_veil::parse_x25519_public_key;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let _ = parse_x25519_public_key(s);
});
