//! Attacks committed CODEOWNERS content with random data: repo files an
//! attacker can substitute to flip the CODEOWNERS coverage verdict. The
//! bytes are staged at every location the finder looks and the finder and
//! coverage decision must survive them unwounded. Every push to main runs
//! this target in the Fuzz Smoke job at
//! .github/workflows/fuzz-smoke.yml; this file is the target's only home.
#![no_main]

use git_veil::{covers_trust_critical_paths, find_codeowners, CODEOWNERS_LOCATIONS};
use libfuzzer_sys::fuzz_target;
use std::fs;

fuzz_target!(|data: &[u8]| {
    let dir = std::env::temp_dir().join(format!(
        "git-veil-fuzz-codeowners-{}-{}",
        std::process::id(),
        0
    ));
    if fs::create_dir_all(&dir).is_err() {
        return;
    }
    // the same hostile content at each candidate location: whichever the
    // finder prefers, the verdict is trained on the attacker's bytes
    for location in CODEOWNERS_LOCATIONS {
        let path = dir.join(location);
        if path
            .parent()
            .is_some_and(|p| fs::create_dir_all(p).is_err())
        {
            continue;
        }
        let _ = fs::write(path, data);
    }
    let _ = find_codeowners(&dir);
    let _ = covers_trust_critical_paths(&dir); // must never panic
    let _ = fs::remove_dir_all(&dir);
});
