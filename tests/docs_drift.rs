//! Generated-docs ratification: the committed man pages and shell
//! completions must be exactly what the current clap definition produces,
//! and `error-codes` must print every documented exit code. These tests make
//! docs drift a CI failure instead of a silent divergence. The release
//! pipeline packages docs/man and installs docs/completions, so stale
//! artifacts would ship.

use clap::CommandFactory as _;
use git_veil::cli::Cli;
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

fn temp_dir(label: &str) -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "git-veil-docs-{}-{}-{}",
        label,
        std::process::id(),
        COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    ));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn repo_root() -> PathBuf {
    // Tests run with CWD = the crate root (cargo contract).
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Man pages: regenerate into a temp dir and compare file-for-file with the
/// committed docs/man. Any drift (missing file, extra file, byte difference)
/// fails with the offending path named.
#[test]
fn test_manpages_match_committed_docs() {
    let dir = temp_dir("man");
    git_veil::cli::run_manpages(&dir).expect("manpages");

    let committed_dir = repo_root().join("docs/man");
    let committed: BTreeSet<String> = fs::read_dir(&committed_dir)
        .expect("read docs/man")
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    let generated: BTreeSet<String> = fs::read_dir(&dir)
        .expect("read generated man dir")
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();

    assert_eq!(
        committed, generated,
        "man page file set drifted: regenerate with scripts/gen-docs.sh"
    );
    for name in &committed {
        let a = fs::read_to_string(committed_dir.join(name)).unwrap();
        let b = fs::read_to_string(dir.join(name)).unwrap();
        assert_eq!(
            a, b,
            "man page docs/man/{name} drifted from the CLI definition; regenerate with scripts/gen-docs.sh"
        );
    }

    let _ = fs::remove_dir_all(&dir);
}

/// Completions: regenerate all three shells and compare byte-for-byte with
/// the committed docs/completions.
#[test]
fn test_completions_match_committed_docs() {
    let committed_dir = repo_root().join("docs/completions");
    for shell in ["bash", "zsh", "fish"] {
        let committed =
            fs::read_to_string(committed_dir.join(format!("git-veil.{shell}"))).unwrap();
        let shell_variant = match shell {
            "bash" => clap_complete::Shell::Bash,
            "zsh" => clap_complete::Shell::Zsh,
            _ => clap_complete::Shell::Fish,
        };
        let mut cmd = Cli::command();
        let mut buf: Vec<u8> = Vec::new();
        clap_complete::generate(shell_variant, &mut cmd, "git-veil", &mut buf);
        let generated = String::from_utf8(buf).unwrap();
        assert_eq!(
            committed, generated,
            "completions for {shell} drifted from the CLI definition; regenerate with scripts/gen-docs.sh"
        );
    }
}

/// The error-codes table must list every documented code. A new code added
/// to the enum but missing from docs/design.md is a spec gap, and the table
/// is the public exit-code contract.
#[test]
fn test_error_codes_are_all_documented() {
    let design = fs::read_to_string(repo_root().join("docs/design.md")).unwrap();
    for code in git_veil::ExitCode::ALL {
        let needle_num = format!("| {} ", *code as u8);
        let found = design
            .lines()
            .any(|line| line.starts_with(&needle_num) && line.contains(code.name()));
        assert!(
            found,
            "exit code {} ({}) is missing from the docs/design.md exit-code table - the table is the public spec",
            *code as u8,
            code.name()
        );
        assert!(!code.description().is_empty());
    }
}

/// The single fingerprint derivation is the SHA-256 one in
/// src/fingerprint.rs. This grep test fails the build if any retired
/// SipHash-1-3 derivation code reappears in src/.
#[test]
fn test_no_legacy_fingerprint_code_remains_in_src() {
    let banned = [
        "DefaultHasher",
        "SipHash",
        "fingerprint_for_recipient",
        "fingerprint_for_verifying_key",
        "owner_fingerprint_for_verifying_key",
        "find_identity_by_fingerprint",
        "find_recipient_by_fingerprint",
        "extract_fingerprints",
    ];
    let mut offenders = Vec::new();
    let mut stack = vec![repo_root().join("src")];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).expect("read src directory") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                let content = fs::read_to_string(&path).expect("read source file");
                for needle in banned {
                    if content.contains(needle) {
                        offenders.push(format!("{} contains {}", path.display(), needle));
                    }
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "retired fingerprint code must not reappear in src/: {offenders:?}"
    );
}

/// The core and the code speak RFC-standard cryptography only. The
/// ageisms, the age vocabulary for key material, are forbidden in src/
/// outside user-surface string literals: `recipient` for the bech32
/// X25519 public key and `identity`/`identities` for the bech32 X25519
/// private key (docs/design.md, "Terminology"). This grep test strips
/// string and char literals from every src/*.rs. The user surface lives
/// in string literals, where the bracketed `(age ...)` spanning form is
/// allowed when advising age tooling. The test fails on any remaining
/// case-insensitive, word-boundary occurrence in code or comments.
///
/// The boundary tokens below are masked exactly, and naming them here is
/// the contract: the upstream `age` crate's own type and trait names
/// (aliased to the crypto terms at the one import site in
/// src/age_crypto.rs) and the two on-disk key store file names, which are
/// format constants documented in docs/design.md.
#[test]
fn test_no_ageisms_in_src_outside_string_literals() {
    const MASKED: &[&str] = &[
        // The upstream age crate's vocabulary: the one import site and the
        // two trait casts (src/age_crypto.rs).
        "Identity as X25519PrivateKey",
        "Recipient as X25519PublicKey",
        "age::x25519::Identity",
        "age::x25519::Recipient",
        "dyn age::Identity",
        "dyn age::Recipient",
        // The on-disk key store file names (format constants).
        "identities.txt",
        "recipients.txt",
    ];
    const FORBIDDEN: &[&str] = &["recipients", "recipient", "identities", "identity"];

    let mut offenders = Vec::new();
    let mut stack = vec![repo_root().join("src")];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).expect("read src directory") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                let content = fs::read_to_string(&path).expect("read source file");
                let mut skeleton = strip_string_literals(&content);
                for token in MASKED {
                    skeleton = skeleton.replace(token, "MASKED");
                }
                for word in FORBIDDEN {
                    for idx in word_boundary_hits(&skeleton, word) {
                        let line = skeleton[..idx].matches('\n').count() + 1;
                        offenders.push(format!("{}:{} contains `{}`", path.display(), line, word));
                    }
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "ageisms must not appear in src/ outside user-surface string literals: {offenders:?}"
    );
}

/// Every index at which `word` occurs in `haystack` on a word boundary
/// (both neighbours non-identifier), case-insensitively.
fn word_boundary_hits(haystack: &str, word: &str) -> Vec<usize> {
    let hay = haystack.to_lowercase();
    let mut hits = Vec::new();
    let mut start = 0;
    while let Some(pos) = hay[start..].find(word) {
        let idx = start + pos;
        let before_ok = idx == 0 || !is_ident_byte(hay.as_bytes()[idx - 1]);
        let after = idx + word.len();
        let after_ok = after >= hay.len() || !is_ident_byte(hay.as_bytes()[after]);
        if before_ok && after_ok {
            hits.push(idx);
        }
        start = idx + 1;
    }
    hits
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Replaces the contents of every string and char literal in `src` with
/// spaces, keeping newlines so line numbers stay meaningful. Handles
/// regular strings with escapes, raw strings (`r"..."`, `r#"..."#`, ...),
/// byte strings and byte chars. A `'x'` that is not a char literal (a
/// lifetime such as `'static`) is left alone.
fn strip_string_literals(src: &str) -> String {
    let bytes = src.as_bytes();
    let mut out: Vec<u8> = bytes.to_vec();
    let blank = |out: &mut Vec<u8>, from: usize, to: usize| {
        for b in out.iter_mut().take(to).skip(from) {
            if *b != b'\n' {
                *b = b' ';
            }
        }
    };
    let mut i = 0;
    while i < bytes.len() {
        // Raw string: r"...", r#"...", r##"..."##, ... (also br"..." /
        // br#"..."# byte raw strings).
        let raw_start = if bytes[i] == b'r' && i + 1 < bytes.len() && bytes[i + 1] == b'"' {
            Some((i, 0))
        } else if bytes[i] == b'r' && i + 1 < bytes.len() && bytes[i + 1] == b'#' {
            let mut hashes = 0;
            let mut j = i + 1;
            while j < bytes.len() && bytes[j] == b'#' {
                hashes += 1;
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'"' {
                Some((i, hashes))
            } else {
                None
            }
        } else {
            None
        };
        if let Some((from, hashes)) = raw_start {
            let open_quote = from + 1 + hashes;
            let mut j = open_quote + 1;
            while j < bytes.len() {
                if bytes[j] == b'"' {
                    let mut k = 0;
                    while k < hashes && j + 1 + k < bytes.len() && bytes[j + 1 + k] == b'#' {
                        k += 1;
                    }
                    if k == hashes {
                        blank(&mut out, from, j + 1 + hashes);
                        i = j + 1 + hashes;
                        break;
                    }
                }
                j += 1;
            }
            if j >= bytes.len() {
                blank(&mut out, from, bytes.len());
                break;
            }
            continue;
        }
        // Regular or byte string: "..." or b"..." (escapes included).
        let str_from = if bytes[i] == b'"'
            || (bytes[i] == b'b' && i + 1 < bytes.len() && bytes[i + 1] == b'"')
        {
            Some(i)
        } else {
            None
        };
        if let Some(from) = str_from {
            let mut j = if bytes[from] == b'b' {
                from + 2
            } else {
                from + 1
            };
            while j < bytes.len() {
                match bytes[j] {
                    b'\\' => j += 2,
                    b'"' => break,
                    _ => j += 1,
                }
            }
            let to = (j + 1).min(bytes.len());
            blank(&mut out, from, to);
            i = to;
            continue;
        }
        // Char or byte char literal: 'x', '\n', '\'', '\u{...}', b'x'.
        let char_from = if bytes[i] == b'\''
            || (bytes[i] == b'b' && i + 1 < bytes.len() && bytes[i + 1] == b'\'')
        {
            Some(i)
        } else {
            None
        };
        if let Some(from) = char_from {
            let quote = if bytes[from] == b'b' { from + 1 } else { from };
            // A char literal is a quote, then either an escape sequence or
            // exactly one character, then the closing quote. Anything else
            // (e.g. the `'static` lifetime) is not a literal.
            let mut j = quote + 1;
            let is_char = if j < bytes.len() && bytes[j] == b'\\' {
                j += 2; // the escaped character
                j < bytes.len() && bytes[j] == b'\''
            } else {
                j += 1;
                j < bytes.len() && bytes[j] == b'\''
            };
            if is_char {
                blank(&mut out, from, j + 1);
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }
    String::from_utf8(out).expect("blanking preserves utf8")
}

/// docs/design.md carries the crypto to ageisms mapping table, and
/// AGENTS.md carries the terminology law: the ageisms definition, the
/// boundary, and the table.
#[test]
fn test_terminology_law_is_carried() {
    let design = fs::read_to_string(repo_root().join("docs/design.md")).unwrap();
    let agents = fs::read_to_string(repo_root().join("AGENTS.md")).unwrap();
    for needle in [
        "ageism",
        "X25519 public key",
        "X25519 private key",
        "principal",
        "verifying key",
        "recipient",
        "identity",
    ] {
        assert!(
            design.contains(needle),
            "docs/design.md terminology mapping table must mention `{needle}`"
        );
        assert!(
            agents.contains(needle),
            "AGENTS.md terminology law must mention `{needle}`"
        );
    }
    assert!(
        design.contains("## Terminology"),
        "docs/design.md carries the prominent terminology section"
    );
    assert!(
        design.contains("Crypto term (git-veil core and code)"),
        "docs/design.md carries the mapping table header"
    );
}

/// Every subcommand's clap definition carries discussion help. A bare
/// subcommand with no after_long_help is a docs gap a user hits as an empty
/// help page.
#[test]
fn test_every_subcommand_has_help_discussion() {
    let root = Cli::command();
    for sub in root.get_subcommands() {
        let name = sub.get_name();
        let discussion = sub
            .get_after_long_help()
            .map(|s| format!("{s}"))
            .unwrap_or_default();
        assert!(
            !discussion.trim().is_empty(),
            "subcommand `{name}` has no after_long_help discussion - every command must document its workflow"
        );
        assert!(
            discussion.contains("EXAMPLES") || discussion.contains("git-veil"),
            "subcommand `{name}` help lacks EXAMPLES"
        );
    }
}

/// One home per fact (#57): a command's invocation token `git-veil <name>`
/// is a mechanics restatement wherever it appears outside commands.md, the
/// one mechanical reference. Scenario pages may show a transcript, so the
/// budget is generous, but a page that re-teaches a command blows through
/// it, and a command name spread across every page is drift by definition.
/// Two numbers, zero judgment: at most 8 tokens per command per non-home
/// page, and at most 18 non-home pages per command.
#[test]
fn test_docs_one_home_gate() {
    const MAX_PER_PAGE: usize = 8;
    const MAX_PAGES: usize = 18;
    const HOME: &str = "commands.md";
    let names = [
        "add-file",
        "remove-file",
        "add-key",
        "remove-key",
        "forget",
        "repo-id",
        "verify-keys",
        "hide",
        "rotate",
        "reveal",
        "cat",
        "changes",
        "list",
        "list-keys",
        "allow",
        "trust",
        "export-pin",
        "fingerprint",
        "import",
        "export",
        "init",
        "clean",
        "whoami",
        "trust-permissions",
        "error-codes",
        "completions",
        "manpages",
    ];
    let mut pages: Vec<PathBuf> = fs::read_dir(repo_root().join("docs/src"))
        .expect("read docs/src")
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "md"))
        .collect();
    pages.push(repo_root().join("README.md"));

    for name in names {
        let token = format!("git-veil {name}");
        let mut pages_with: Vec<String> = Vec::new();
        for page in &pages {
            if page
                .file_name()
                .is_some_and(|f| f.to_string_lossy() == HOME)
            {
                continue;
            }
            let content =
                fs::read_to_string(page).unwrap_or_else(|e| panic!("read {}: {e}", page.display()));
            let count = content.matches(&token).count();
            if count > MAX_PER_PAGE {
                panic!(
                    "one-home gate: `{token}` appears {count} times in {} \
                     (budget {MAX_PER_PAGE}); the mechanics restatement \
                     belongs in docs/src/{HOME} - carry a link instead",
                    page.display()
                );
            }
            if count > 0 {
                pages_with.push(page.display().to_string());
            }
        }
        if pages_with.len() > MAX_PAGES {
            panic!(
                "one-home gate: `{token}` is restated across {} pages \
                 (budget {MAX_PAGES}); consolidate to docs/src/{HOME} and \
                 link from the rest: {}",
                pages_with.len(),
                pages_with.join(", ")
            );
        }
    }
}
