//! Attacks the pin-file with random data: the artifact handed to
//! `git-veil trust --import`, which travels out of band and is
//! attacker-substitutable by definition. Every push to main runs this
//! target in the Fuzz Smoke job at .github/workflows/fuzz-smoke.yml;
//! this file is the target's only home.
#![no_main]

use git_veil::PinFile;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(pin) = PinFile::parse(s) {
        // roundtrip oracle: a parseable pin-file must serialize back to
        // an artifact that parses identically, byte for byte
        let text = pin.serialize();
        let reparsed = PinFile::parse(&text).expect("serialize(parse(x)) must re-parse");
        assert_eq!(reparsed.serialize(), text);
    }
});
