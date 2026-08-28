#![no_main]

use libfuzzer_sys::fuzz_target;
use git_gpg::{
    extract_content_to_verify_from_keyring, extract_signature_from_keyring, SIG_BEGIN, SIG_END,
};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };

    // the rfind back-search must hold under mutation: the extracted block is
    // exactly SIG_BEGIN..SIG_END inclusive
    if let Ok(sig) = extract_signature_from_keyring(s) {
        assert!(sig.starts_with(SIG_BEGIN), "signature block must start at BEGIN");
        assert!(sig.ends_with(SIG_END), "signature block must end at END");
    }

    // the verify content always ends with the keyring END marker
    if let Ok(content) = extract_content_to_verify_from_keyring(s) {
        assert!(
            content.ends_with(git_gpg::END_MARKER),
            "verify content must end with the END GIT-GPG KEYRING marker"
        );
    }
});
