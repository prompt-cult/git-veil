//! Attacks verifying key files with random data: the committed
//! `.git-veil/owner.verifying` and the file passed to `git-veil init`.
//! The key they name drives every signature check in the tool, so the
//! parser must either accept or refuse, never wound. Every push to main
//! runs this target in the Fuzz Smoke job at
//! .github/workflows/fuzz-smoke.yml; this file is the target's only home.
#![no_main]

use git_veil::parse_verifying_key;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let _ = parse_verifying_key(s);
});
