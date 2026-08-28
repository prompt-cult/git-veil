#![no_main]

use libfuzzer_sys::fuzz_target;
use git_gpg::{derive_repo_id, parse_git_remote_url};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };

    match parse_git_remote_url(s) {
        Ok((repo, user, service)) => {
            // normalize guarantee: all three components are lowercase, and
            // none of them is empty or carries userinfo/credential material
            assert!(!repo.is_empty() && !user.is_empty() && !service.is_empty());
            assert!(!repo.contains(['@', ':']) && !user.contains(['@', ':']) && !service.contains(['@', ':']),
                "no credential material may leak into the identity components");
            for c in repo.chars().chain(user.chars()).chain(service.chars()) {
                assert!(
                    !c.is_ascii_uppercase(),
                    "components must be lowercased, got {repo}/{user}/{service}"
                );
            }

            // repo_id shape: `repo+user@service`; feeding the derived id
            // back into parse must be Err (a repo_id is not a supported URL
            // — no accidental round-trip confusion)
            let repo_id = derive_repo_id(s).expect("derive_repo_id must agree with parse");
            assert_eq!(repo_id, format!("{repo}+{user}@{service}"));
            assert_eq!(derive_repo_id(s).unwrap(), repo_id, "derive must be deterministic");
            assert!(
                parse_git_remote_url(&repo_id).is_err(),
                "the derived repo_id must not re-parse as a remote URL"
            );
        }
        Err(err) => {
            // never-echo policy: on Err the error text must not contain ANY
            // substring of the raw input longer than 8 characters. Check the
            // error string against each sliding 8-char window of the input,
            // so no URL shape can leak credentials into the error message.
            let message = format!("{err:#}");
            let message_bytes = message.as_bytes();
            if s.len() < 8 {
                return;
            }
            for window in s.as_bytes().windows(8) {
                assert!(
                    !message_bytes.windows(8).any(|w| w == window),
                    "error text must not echo any part of the input (window {:?}): {message}",
                    String::from_utf8_lossy(window)
                );
            }
        }
    }
});
