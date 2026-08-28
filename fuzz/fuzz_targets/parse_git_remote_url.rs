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
            // credential redaction: when the URL starts with scheme
            // userinfo (`scheme://user:pass@...`), the error text must
            // never echo that credential prefix (redact_url invariant)
            let message = format!("{err:#}");
            if let Some((scheme, rest)) = s.split_once("://") {
                if scheme.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
                    && !scheme.is_empty()
                {
                    if let Some(at) = rest.find('@') {
                        let userinfo = &rest[..at];
                        if !userinfo.is_empty() && !userinfo.contains('/') {
                            let credential_prefix = format!("{scheme}://{userinfo}@");
                            if s.starts_with(&credential_prefix) {
                                assert!(
                                    !message.contains(&credential_prefix),
                                    "error text must not echo credentials: {message}"
                                );
                            }
                        }
                    }
                }
            }
        }
    }
});
