//! Generated-docs ratification: the committed man pages and shell
//! completions must be EXACTLY what the current clap definition produces,
//! and `error-codes` must print every documented exit code. These tests make
//! docs drift a CI failure instead of a silent divergence — the release
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

/// The error-codes table must list every documented code — a new code added
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
            "exit code {} ({}) is missing from the docs/design.md exit-code table — the table is the public spec",
            *code as u8,
            code.name()
        );
        assert!(!code.description().is_empty());
    }
}

/// Every subcommand's clap definition carries discussion help — a bare
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
            "subcommand `{name}` has no after_long_help discussion — every command must document its workflow"
        );
        assert!(
            discussion.contains("EXAMPLES") || discussion.contains("git-veil"),
            "subcommand `{name}` help lacks EXAMPLES"
        );
    }
}
