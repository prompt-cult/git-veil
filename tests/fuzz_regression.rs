//! Regression for the fuzz smoke crash of 2026-10-26
//! (run 40277860014, job 121424361347): the exact crashing unit, replayed
//! as a plain unit test.
//!
//! The fuzz target's Err branch once asserted that no 8-byte window of the
//! input may appear in the refusal text. That invariant is unsatisfiable:
//! the refusal text is a fixed constant ("...See the trust documentation."),
//! and an attacker-controlled input can always carry a chunk of that
//! constant ("t docume" sat in the fuzzer's dictionary). The never-echo
//! guarantee is exact-message equality: the refusal is one fixed string, so
//! nothing from the input is echoed beyond the words of the constant itself.
//! These tests pin that guarantee against the exact crash input.

const FIXED_REFUSAL: &str = "invalid git remote URL format. Expected a supported GitHub GitLab or Codeberg shape. See the trust documentation.";

const CRASH_INPUT: &[u8] = &[
    103, 105, 116, 64, 103, 105, 116, 104, 117, 98, 46, 99, 111, 109, 58, 115, 105, 109, 98, 111,
    49, 57, 48, 53, 47, 118, 97, 114, 97, 46, 103, 105, 116, 10, 104, 116, 116, 112, 115, 58, 47,
    47, 103, 105, 116, 104, 117, 98, 46, 99, 111, 109, 47, 117, 115, 101, 114, 47, 114, 101, 47,
    117, 115, 101, 114, 58, 112, 97, 115, 115, 64, 103, 105, 116, 104, 117, 98, 46, 99, 111, 109,
    47, 117, 115, 101, 114, 47, 114, 101, 112, 111, 46, 103, 105, 116, 10, 115, 115, 104, 58, 47,
    46, 99, 111, 109, 47, 101, 112, 111, 46, 103, 105, 116, 10, 112, 101, 19, 0, 0, 0, 0, 0, 0, 0,
    46, 115, 114, 46, 104, 116, 58, 126, 112, 101, 114, 115, 111, 110, 47, 114, 101, 112, 111, 46,
    103, 105, 116, 116, 116, 96, 115, 58, 47, 47, 10, 10, 104, 116, 116, 112, 115, 58, 47, 47, 117,
    115, 101, 114, 58, 112, 97, 115, 115, 64, 104, 111, 115, 116, 58, 56, 52, 52, 52, 47, 111, 47,
    114, 46, 103, 47, 101, 112, 111, 46, 103, 105, 116, 10, 112, 101, 19, 0, 0, 0, 0, 0, 0, 0, 46,
    115, 114, 46, 104, 116, 58, 126, 112, 101, 114, 115, 111, 110, 47, 114, 101, 112, 111, 46, 103,
    105, 116, 116, 116, 96, 115, 58, 47, 47, 10, 10, 104, 116, 116, 112, 115, 58, 47, 47, 117, 115,
    101, 114, 58, 112, 97, 115, 115, 64, 104, 111, 115, 116, 58, 56, 52, 52, 52, 47, 116, 32, 100,
    111, 99, 117, 109, 101, 10,
];

#[test]
fn the_exact_crash_input_refuses_with_the_fixed_message() {
    let input = std::str::from_utf8(CRASH_INPUT).unwrap();
    let err = git_veil::parse_git_remote_url(input).unwrap_err();
    assert_eq!(format!("{err:#}"), FIXED_REFUSAL);

    let err = git_veil::derive_repo_id(input).unwrap_err();
    assert_eq!(format!("{err:#}"), FIXED_REFUSAL);
}

#[test]
fn the_exact_crash_input_echoes_nothing_beyond_the_fixed_message() {
    // The corrected never-echo check, the one the fuzz target now runs:
    // every 8-byte window of the input that appears in the refusal text
    // must be a substring of the fixed message itself. A window that is
    // not part of the constant would be echoed input. The first test pins
    // the same guarantee from the equality side; this one states it from
    // the window side so the crash input is replayed both ways.
    let input = std::str::from_utf8(CRASH_INPUT).unwrap();
    let err = git_veil::parse_git_remote_url(input).unwrap_err();
    let message = format!("{err:#}");
    assert_eq!(message, FIXED_REFUSAL);
    for window in input.as_bytes().windows(8) {
        let echoed = message.as_bytes().windows(8).any(|w| w == window);
        assert!(
            !echoed || FIXED_REFUSAL.as_bytes().windows(8).any(|w| w == window),
            "the refusal text echoes input beyond the fixed message: {}",
            String::from_utf8_lossy(window)
        );
    }
}
