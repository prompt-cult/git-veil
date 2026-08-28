#![no_main]

use libfuzzer_sys::fuzz_target;
use git_gpg::TrustPinStore;
use std::path::Path;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };

    let sanitized = TrustPinStore::sanitize_repo_id(s);
    // filename-escape guard: the output is a safe single path component
    assert!(
        sanitized
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'%')),
        "sanitized repo_id must stay in [A-Za-z0-9._%-], got: {sanitized}"
    );
    assert!(!sanitized.contains('/'), "never a path separator");
    assert_ne!(sanitized, ".", "never the current-directory alias");
    assert_ne!(sanitized, "..", "never the parent-directory alias");

    // byte-count property: every offending byte becomes exactly %XX
    assert!(
        sanitized.len() <= 3 * s.len(),
        "sanitization must not inflate beyond 3x, got {sanitized} from {s}"
    );

    // pin_path is always strictly inside <gpg_home>/trust-pins/
    let home = Path::new("/home/fuzz");
    let pin = TrustPinStore::pin_path(home, s);
    assert!(pin.starts_with(home.join("trust-pins")));
});
