#![no_main]

use libfuzzer_sys::fuzz_target;
use git_gpg::{validate_tracked_path, TrackedFiles};
use std::path::PathBuf;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };

    // direct path fuzzing: validate_tracked_path must never panic and must
    // confine anything it accepts under the repo root
    let path = PathBuf::from(s);
    if validate_tracked_path(&path).is_ok() {
        let joined = PathBuf::from("/repo").join(&path);
        assert!(
            joined.starts_with("/repo"),
            "an accepted tracked path must stay inside the repo root: {s}"
        );
    }

    // TrackedFiles::load contract: Ok ⇒ every entry passed validation.
    // load() reads from a file, so stage the fuzzed JSON in a temp file.
    let temp = std::env::temp_dir().join(format!("git-gpg-fuzz-tracked-{}", std::process::id()));
    if std::fs::write(&temp, data).is_ok() {
        if let Ok(tracked) = TrackedFiles::load(&temp) {
            for file in &tracked.files {
                assert!(
                    validate_tracked_path(file).is_ok(),
                    "TrackedFiles::load returned Ok with an unvalidated path: {:?}",
                    file
                );
            }
        }
        let _ = std::fs::remove_file(&temp);
    }
});
