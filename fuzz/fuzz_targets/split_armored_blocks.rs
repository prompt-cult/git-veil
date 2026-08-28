#![no_main]

use libfuzzer_sys::fuzz_target;
use git_gpg::{
    split_armored_private_key_blocks, split_armored_public_key_blocks, PRIVATE_KEY_BEGIN,
    PRIVATE_KEY_END, PUBLIC_KEY_BEGIN, PUBLIC_KEY_END,
};
use std::path::Path;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    let path = Path::new("fuzz");

    check_public(s, path);
    check_private(s, path);
});

fn check_public(s: &str, path: &Path) {
    if let Ok(blocks) = split_armored_public_key_blocks(s, path) {
        for block in &blocks {
            assert!(
                block.starts_with(PUBLIC_KEY_BEGIN),
                "every returned block must start with the BEGIN marker"
            );
            assert!(
                block.ends_with(PUBLIC_KEY_END),
                "every returned block must end with the END marker"
            );
        }
        // truncation-attack invariant: an Ok here implies no BEGIN marker
        // was left unterminated (a BEGIN inside a previous block's span is
        // body, but it still has an END after it somewhere in the store)
        assert_every_begin_terminated(s, PUBLIC_KEY_BEGIN, PUBLIC_KEY_END);
    }
}

fn check_private(s: &str, path: &Path) {
    if let Ok(blocks) = split_armored_private_key_blocks(s, path) {
        for block in &blocks {
            assert!(
                block.starts_with(PRIVATE_KEY_BEGIN),
                "every returned block must start with the BEGIN marker"
            );
            assert!(
                block.ends_with(PRIVATE_KEY_END),
                "every returned block must end with the END marker"
            );
        }
        assert_every_begin_terminated(s, PRIVATE_KEY_BEGIN, PRIVATE_KEY_END);
    }
}

fn assert_every_begin_terminated(s: &str, begin: &str, end: &str) {
    let mut search = 0;
    while let Some(p) = s[search..].find(begin) {
        let abs = search + p;
        assert!(
            s[abs..].contains(end),
            "splitter returned Ok despite an unterminated BEGIN at byte {abs}"
        );
        search = abs + begin.len();
    }
}
