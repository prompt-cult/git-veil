#![no_main]

use libfuzzer_sys::fuzz_target;
use git_veil::{derive_repo_id, parse_git_remote_url};

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

            // repo_id shape: `repo+user@service`. Feeding the derived id
            // back into parse must be Err. A repo_id is not a supported URL,
            // so there is no accidental round-trip confusion
            let repo_id = derive_repo_id(s).expect("derive_repo_id must agree with parse");
            assert_eq!(repo_id, format!("{repo}+{user}@{service}"));
            assert_eq!(derive_repo_id(s).unwrap(), repo_id, "derive must be deterministic");
            assert!(
                parse_git_remote_url(&repo_id).is_err(),
                "the derived repo_id must not re-parse as a remote URL"
            );
        }
        Err(err) => {
            // never-echo policy: on Err the refusal text is one fixed
            // message, so nothing from the input is echoed beyond the
            // words of the constant itself. Exact equality is the
            // checkable form of that guarantee: a sliding-window scan
            // cannot hold, because an attacker-controlled input can carry
            // a chunk of any constant ("t docume" vs "trust
            // documentation").
            assert_eq!(
                format!("{err:#}"),
                "invalid git remote URL format. Expected a supported GitHub GitLab or Codeberg shape. See the trust documentation.",
                "the refusal must be the fixed message; anything else echoes input"
            );
        }
    }
});
