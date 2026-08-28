//! CLI end-to-end tests.
//!
//! These spawn the real `git-gpg` binary via assert_cmd. Each test builds its
//! own temporary git repository and fake $HOME, so every child process gets an
//! isolated GNUPGHOME ($HOME/.git-gpg) without touching the test process's
//! working directory or environment — hence no #[serial] is needed.

use assert_cmd::Command;
use clap::CommandFactory as _;
use pgp::composed::{EncryptionCaps, KeyType, SecretKeyParamsBuilder, SubkeyParamsBuilder};
use rand::thread_rng;
use std::path::Path;

fn generate_test_key(email: &str) -> (pgp::composed::SignedSecretKey, pgp::composed::SignedPublicKey) {
    let mut rng = thread_rng();

    let encrypt_subkey = SubkeyParamsBuilder::default()
        .key_type(KeyType::X25519)
        .can_encrypt(EncryptionCaps::All)
        .build()
        .expect("build encrypt subkey params");

    let params = SecretKeyParamsBuilder::default()
        .key_type(KeyType::Ed25519)
        .can_certify(true)
        .can_sign(true)
        .primary_user_id(format!("Test User <{}>", email))
        .passphrase(None)
        .subkeys(vec![encrypt_subkey])
        .build()
        .expect("build key params");

    let secret_key = params.generate(&mut rng).expect("generate key");
    let public_key = secret_key.to_public_key();

    (secret_key, public_key)
}

fn generate_protected_test_key(
    email: &str,
    passphrase: &str,
) -> (pgp::composed::SignedSecretKey, pgp::composed::SignedPublicKey) {
    let mut rng = thread_rng();

    let encrypt_subkey = SubkeyParamsBuilder::default()
        .key_type(KeyType::X25519)
        .can_encrypt(EncryptionCaps::All)
        .passphrase(Some(passphrase.to_string()))
        .build()
        .expect("build encrypt subkey params");

    let params = SecretKeyParamsBuilder::default()
        .key_type(KeyType::Ed25519)
        .can_certify(true)
        .can_sign(true)
        .primary_user_id(format!("Test User <{}>", email))
        .passphrase(Some(passphrase.to_string()))
        .subkeys(vec![encrypt_subkey])
        .build()
        .expect("build key params");

    let secret_key = params.generate(&mut rng).expect("generate key");
    let public_key = secret_key.to_public_key();

    (secret_key, public_key)
}

fn write_multi_key_secret_keys(gpg_home: &Path, keys: &[pgp::composed::SignedSecretKey]) {
    let mut content = String::new();
    for key in keys {
        if !content.is_empty() {
            content.push('\n');
        }
        content.push_str(&key.to_armored_string(Default::default()).unwrap());
    }
    std::fs::create_dir_all(gpg_home).unwrap();
    std::fs::write(gpg_home.join("secret-keys.pgp"), content).unwrap();
}

fn write_public_key_file(public_key: &pgp::composed::SignedPublicKey, path: &Path) {
    let armored = public_key.to_armored_string(Default::default()).unwrap();
    std::fs::write(path, armored).unwrap();
}

fn git(repo: &Path, args: &[&str]) {
    let status = std::process::Command::new("git")
        .current_dir(repo)
        .args(args)
        .status()
        .expect("run git");
    assert!(status.success(), "git {:?} failed", args);
}

fn run(repo: &Path, home: &Path, args: &[&str]) -> std::process::Output {
    Command::cargo_bin("git-gpg")
        .expect("git-gpg binary must be buildable")
        .current_dir(repo)
        .env("HOME", home)
        .env_remove("GITGPG_PASSPHRASE")
        .args(args)
        .output()
        .expect("run git-gpg")
}

/// Runs the binary with GITGPG_PASSPHRASE set for this invocation only, so
/// env-var tests cannot leak the passphrase into other child processes.
fn run_with_passphrase_env(
    repo: &Path,
    home: &Path,
    args: &[&str],
    passphrase: &str,
) -> std::process::Output {
    Command::cargo_bin("git-gpg")
        .expect("git-gpg binary must be buildable")
        .current_dir(repo)
        .env("HOME", home)
        .env("GITGPG_PASSPHRASE", passphrase)
        .args(args)
        .output()
        .expect("run git-gpg")
}

/// Runs the binary with `input` piped to stdin (for --passphrase-stdin).
fn run_with_stdin(repo: &Path, home: &Path, args: &[&str], input: &str) -> std::process::Output {
    Command::cargo_bin("git-gpg")
        .expect("git-gpg binary must be buildable")
        .current_dir(repo)
        .env("HOME", home)
        .env_remove("GITGPG_PASSPHRASE")
        .args(args)
        .write_stdin(input)
        .output()
        .expect("run git-gpg")
}

/// Builds a temp repo (with origin remote and local user.email) plus a fake
/// home holding the owner + collaborator secret keys, runs the full CLI flow
/// init -> trust -> tell -> add -> hide, and returns (repo_temp, home_temp).
fn setup_hidden_repo() -> (tempfile::TempDir, tempfile::TempDir) {
    let repo_temp = tempfile::tempdir().unwrap();
    let home_temp = tempfile::tempdir().unwrap();

    git(repo_temp.path(), &["init"]);
    git(
        repo_temp.path(),
        &["remote", "add", "origin", "git@github.com:owner/repo.git"],
    );
    git(repo_temp.path(), &["config", "user.email", "alice@example.com"]);

    let (owner_sec, owner_pub) = generate_test_key("owner@github.com");
    let (alice_sec, alice_pub) = generate_test_key("alice@example.com");

    write_multi_key_secret_keys(&home_temp.path().join(".git-gpg"), &[owner_sec, alice_sec]);

    let owner_keyfile = repo_temp.path().join("owner.pub");
    write_public_key_file(&owner_pub, &owner_keyfile);
    let alice_keyfile = repo_temp.path().join("alice.pub");
    write_public_key_file(&alice_pub, &alice_keyfile);

    let out = run(repo_temp.path(), home_temp.path(), &["init"]);
    assert!(out.status.success(), "init failed: {:?}", out.stderr);

    let out = run(
        repo_temp.path(),
        home_temp.path(),
        &["trust", "repo+owner@github.com", "owner.pub"],
    );
    assert!(out.status.success(), "trust failed: {:?}", out.stderr);

    let out = run(
        repo_temp.path(),
        home_temp.path(),
        &["tell", "alice@example.com", "alice.pub"],
    );
    assert!(out.status.success(), "tell failed: {:?}", out.stderr);

    std::fs::write(repo_temp.path().join("secret.env"), "s3cret").unwrap();
    let out = run(repo_temp.path(), home_temp.path(), &["add", "secret.env"]);
    assert!(out.status.success(), "add failed: {:?}", out.stderr);

    let out = run(repo_temp.path(), home_temp.path(), &["hide"]);
    assert!(out.status.success(), "hide failed: {:?}", out.stderr);
    assert!(
        !repo_temp.path().join("secret.env").exists(),
        "hide must delete the plaintext file"
    );

    (repo_temp, home_temp)
}

#[test]
fn reveal_defaults_to_git_config_user_email() {
    let (repo_temp, home_temp) = setup_hidden_repo();

    // No --email: the CLI must fall back to `git config user.email`
    // (alice@example.com), not any hardcoded placeholder address.
    let out = run(repo_temp.path(), home_temp.path(), &["reveal"]);

    assert!(
        out.status.success(),
        "reveal without --email must resolve the email from git config user.email and succeed: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read(repo_temp.path().join("secret.env")).expect("revealed file must exist"),
        b"s3cret",
        "reveal must restore the original plaintext"
    );
}

#[test]
fn reveal_with_explicit_email_succeeds() {
    let (repo_temp, home_temp) = setup_hidden_repo();

    let out = run(
        repo_temp.path(),
        home_temp.path(),
        &["reveal", "--email", "alice@example.com"],
    );

    assert!(
        out.status.success(),
        "reveal with an explicit --email must succeed: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read(repo_temp.path().join("secret.env")).expect("revealed file must exist"),
        b"s3cret",
        "reveal must restore the original plaintext"
    );
}

#[test]
fn cat_outputs_plaintext_to_stdout() {
    let (repo_temp, home_temp) = setup_hidden_repo();

    let out = run(
        repo_temp.path(),
        home_temp.path(),
        &["cat", "secret.env", "--email", "alice@example.com"],
    );

    assert!(
        out.status.success(),
        "cat must exit 0: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        out.stdout, b"s3cret",
        "cat must write the exact plaintext bytes to stdout"
    );
    assert!(
        !repo_temp.path().join("secret.env").exists(),
        "cat must not write a plaintext file to disk"
    );
    assert!(
        repo_temp.path().join("secret.env.secret").exists(),
        "cat must not delete the ciphertext"
    );
}

#[test]
fn cli_help_and_version_exit_zero() {
    for args in [&["--help"][..], &["--version"][..]] {
        let out = Command::cargo_bin("git-gpg")
            .expect("git-gpg binary must be buildable")
            .args(args)
            .output()
            .expect("run git-gpg");
        assert!(
            out.status.success(),
            "git-gpg {:?} must exit 0, got {:?}",
            args,
            out.status
        );
    }
}

#[test]
fn bare_help_lists_every_command_with_one_liner() {
    // `git-gpg help` must be a table of contents: every subcommand name with
    // a one-line purpose, NOT a flag dump of the root or any subcommand.
    let out = Command::cargo_bin("git-gpg")
        .expect("git-gpg binary must be buildable")
        .args(["help"])
        .output()
        .expect("run git-gpg");

    assert!(
        out.status.success(),
        "git-gpg help must exit 0, got {:?}",
        out.status
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    for name in [
        "init",
        "import",
        "trust",
        "tell",
        "removeperson",
        "add",
        "remove",
        "list",
        "hide",
        "reveal",
        "cat",
        "unhide",
        "changes",
        "show-repo-id",
        "whoami",
        "verify-keyring",
        "list-keys",
        "clean",
        "completions",
        "manpages",
    ] {
        assert!(
            stdout.contains(name),
            "git-gpg help must list every subcommand; missing: {name}\n---\n{stdout}"
        );
    }

    // A flag dump would enumerate subcommand options here; the one-liner
    // list must not. --gpg-home is a stable marker: it belongs to several
    // subcommands but never to the table of contents.
    assert!(
        !stdout.contains("--gpg-home"),
        "git-gpg help must be a one-liner table of contents, not a flag dump\n---\n{stdout}"
    );
}

#[test]
fn help_hide_shows_workflow_and_examples() {
    // `git-gpg help hide` must show the long-form workflow discussion and
    // commented examples, not just the flag list.
    let out = Command::cargo_bin("git-gpg")
        .expect("git-gpg binary must be buildable")
        .args(["help", "hide"])
        .output()
        .expect("run git-gpg");

    assert!(
        out.status.success(),
        "git-gpg help hide must exit 0, got {:?}",
        out.status
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    for marker in ["init", "trust", "tell", "add", "secret", "#"] {
        assert!(
            stdout.contains(marker),
            "git-gpg help hide must discuss the workflow (missing: {marker})\n---\n{stdout}"
        );
    }
}

#[test]
fn help_unknown_command_exits_nonzero() {
    let out = Command::cargo_bin("git-gpg")
        .expect("git-gpg binary must be buildable")
        .args(["help", "nosuchcmd"])
        .output()
        .expect("run git-gpg");

    assert!(
        !out.status.success(),
        "git-gpg help nosuchcmd must exit nonzero, got success"
    );
}

#[test]
fn manpage_for_hide_contains_workflow_text() {
    // The committed man page must carry the same workflow discussion that
    // `git-gpg help hide` shows, because clap_mangen renders it from the
    // same clap definition.
    let man_page = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("docs/man/git-gpg-hide.1");
    let content = std::fs::read_to_string(&man_page).expect("read committed man page");

    for marker in ["init", "trust", "tell", "add", "secret"] {
        assert!(
            content.contains(marker),
            "{man_page:?} must contain the hide workflow text (missing: {marker})"
        );
    }
}

#[test]
fn cli_reports_nonzero_exit_on_failure() {
    // A directory that is not a git repo: show-repo-id must fail loudly.
    let not_a_repo = tempfile::tempdir().unwrap();

    let out = Command::cargo_bin("git-gpg")
        .expect("git-gpg binary must be buildable")
        .current_dir(not_a_repo.path())
        .args(["show-repo-id"])
        .output()
        .expect("run git-gpg");

    assert!(
        !out.status.success(),
        "show-repo-id outside a git repo must exit nonzero, got success"
    );
}

#[test]
fn home_free_subcommands_work_without_home_set() {
    // init/add/remove/list/clean never touch the key store, so they must
    // succeed even with HOME removed from the environment (previously
    // default_gpg_home() errored before command dispatch). list-keys is NOT
    // in this set any more: it verifies the keyring signature against the
    // pinned trusted key, so it consumes a gpg_home and requires trust.
    let repo_temp = tempfile::tempdir().unwrap();

    git(repo_temp.path(), &["init"]);
    git(repo_temp.path(), &["config", "user.email", "alice@example.com"]);

    let run_without_home = |args: &[&str]| {
        Command::cargo_bin("git-gpg")
            .expect("git-gpg binary must be buildable")
            .current_dir(repo_temp.path())
            .env_remove("HOME")
            .args(args)
            .output()
            .expect("run git-gpg")
    };

    let out = run_without_home(&["init"]);
    assert!(
        out.status.success(),
        "git-gpg init without HOME must exit 0: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    std::fs::write(repo_temp.path().join("secret.env"), "s3cret").unwrap();

    for args in [
        &["add", "secret.env"][..],
        &["list"][..],
        &["remove", "secret.env"][..],
        &["clean"][..],
    ] {
        let out = run_without_home(args);
        assert!(
            out.status.success(),
            "git-gpg {:?} without HOME must exit 0: stdout={:?} stderr={:?}",
            args,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

// ============================================================================
// Safety/UX: clean requires --yes before destroying secret material;
// unhide restores one hidden file
// ============================================================================

#[test]
fn cli_clean_requires_yes_flag() {
    let (repo_temp, home_temp) = setup_hidden_repo();
    assert!(repo_temp.path().join("secret.env.secret").exists());

    let out = run(repo_temp.path(), home_temp.path(), &["clean"]);
    assert!(
        !out.status.success(),
        "clean without --yes must refuse to destroy ciphertext, got success"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("--yes"),
        "the refusal must explain that --yes is required, got: {}",
        combined
    );
    assert!(
        repo_temp.path().join(".git-gpg").exists(),
        "a refused clean must leave .git-gpg intact"
    );
    assert!(
        repo_temp.path().join("secret.env.secret").exists(),
        "a refused clean must leave the ciphertext intact"
    );

    let out = run(repo_temp.path(), home_temp.path(), &["clean", "--yes"]);
    assert!(
        out.status.success(),
        "clean --yes must proceed: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !repo_temp.path().join(".git-gpg").exists(),
        "clean --yes must remove .git-gpg"
    );
}

#[test]
fn cli_unhide_decrypts_one_file() {
    let (repo_temp, home_temp) = setup_hidden_repo();

    let out = run(
        repo_temp.path(),
        home_temp.path(),
        &["unhide", "secret.env", "--email", "alice@example.com"],
    );

    assert!(
        out.status.success(),
        "unhide must exit 0: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read(repo_temp.path().join("secret.env")).expect("plaintext must be restored"),
        b"s3cret",
        "unhide must restore the original plaintext"
    );
    assert!(
        !repo_temp.path().join("secret.env.secret").exists(),
        "unhide must delete the ciphertext"
    );
}

// ============================================================================
// Passphrase-protected private keys: env var + --passphrase-stdin
//
// Written Red/Green: pre-fix the binary only unlocked keys with an empty
// passphrase, so these tests failed at runtime (unknown --passphrase-stdin
// flag; GITGPG_PASSPHRASE ignored).
// ============================================================================

/// Builds a temp repo (origin remote + local user.email) plus a fake home
/// whose key store holds ONLY a passphrase-protected owner key, then runs
/// CLI init + trust (both public-key-only, no passphrase needed).
/// Returns (repo_temp, home_temp).
fn setup_repo_with_protected_owner_key(passphrase: &str) -> (tempfile::TempDir, tempfile::TempDir) {
    let repo_temp = tempfile::tempdir().unwrap();
    let home_temp = tempfile::tempdir().unwrap();

    git(repo_temp.path(), &["init"]);
    git(
        repo_temp.path(),
        &["remote", "add", "origin", "git@github.com:owner/repo.git"],
    );
    git(repo_temp.path(), &["config", "user.email", "owner@github.com"]);

    let (owner_sec, owner_pub) = generate_protected_test_key("owner@github.com", passphrase);
    write_multi_key_secret_keys(&home_temp.path().join(".git-gpg"), &[owner_sec]);

    let owner_keyfile = repo_temp.path().join("owner.pub");
    write_public_key_file(&owner_pub, &owner_keyfile);

    let out = run(repo_temp.path(), home_temp.path(), &["init"]);
    assert!(out.status.success(), "init failed: {:?}", out.stderr);

    let out = run(
        repo_temp.path(),
        home_temp.path(),
        &["trust", "repo+owner@github.com", "owner.pub"],
    );
    assert!(out.status.success(), "trust failed: {:?}", out.stderr);

    (repo_temp, home_temp)
}

fn track_and_hide(repo: &Path, home: &Path) {
    std::fs::write(repo.join("secret.env"), "s3cret").unwrap();
    let out = run(repo, home, &["add", "secret.env"]);
    assert!(out.status.success(), "add failed: {:?}", out.stderr);
    let out = run(repo, home, &["hide"]);
    assert!(out.status.success(), "hide failed: {:?}", out.stderr);
    assert!(
        repo.join("secret.env.secret").exists(),
        "hide must write the ciphertext beside the plaintext"
    );
}

#[test]
fn protected_key_decrypts_with_passphrase_from_env_var() {
    let (repo_temp, home_temp) = setup_repo_with_protected_owner_key("correct horse");

    // tell signs the keyring with the protected owner key: needs the env var.
    let out = run_with_passphrase_env(
        repo_temp.path(),
        home_temp.path(),
        &["tell", "owner@github.com", "owner.pub"],
        "correct horse",
    );
    assert!(
        out.status.success(),
        "tell with GITGPG_PASSPHRASE must succeed: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    track_and_hide(repo_temp.path(), home_temp.path());

    // Reveal with the env var set: must decrypt.
    let out = run_with_passphrase_env(
        repo_temp.path(),
        home_temp.path(),
        &["reveal"],
        "correct horse",
    );
    assert!(
        out.status.success(),
        "reveal with GITGPG_PASSPHRASE set must succeed: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read(repo_temp.path().join("secret.env")).expect("revealed file must exist"),
        b"s3cret",
        "reveal must restore the original plaintext"
    );

    // Re-hide, then reveal WITHOUT the env var: must fail with a hint.
    track_and_hide(repo_temp.path(), home_temp.path());
    let out = run(repo_temp.path(), home_temp.path(), &["reveal"]);
    assert!(
        !out.status.success(),
        "reveal without the passphrase must fail: stdout={:?}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("passphrase"),
        "the failure must hint that a passphrase may be missing, got: {}",
        stderr
    );
    assert!(
        !stderr.contains("correct horse"),
        "the error output must never echo the passphrase value, got: {}",
        stderr
    );
}

#[test]
fn passphrase_stdin_reads_exactly_one_line() {
    let (repo_temp, home_temp) = setup_repo_with_protected_owner_key("correct horse");

    // tell reads the passphrase from stdin: exactly the first line.
    let out = run_with_stdin(
        repo_temp.path(),
        home_temp.path(),
        &["tell", "owner@github.com", "owner.pub", "--passphrase-stdin"],
        "correct horse\nIGNORED SECOND LINE\n",
    );
    assert!(
        out.status.success(),
        "tell with --passphrase-stdin must read exactly one line: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    track_and_hide(repo_temp.path(), home_temp.path());

    // Reveal with the exact passphrase on stdin: must decrypt. The extra
    // second line must be ignored (exactly-one-line semantics).
    let out = run_with_stdin(
        repo_temp.path(),
        home_temp.path(),
        &["reveal", "--passphrase-stdin"],
        "correct horse\nIGNORED SECOND LINE\n",
    );
    assert!(
        out.status.success(),
        "reveal with the exact passphrase on stdin must succeed: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read(repo_temp.path().join("secret.env")).expect("revealed file must exist"),
        b"s3cret",
        "reveal must restore the original plaintext"
    );

    // A passphrase containing spaces must match exactly: any difference
    // (extra trailing words) is a wrong passphrase -> clear failure.
    track_and_hide(repo_temp.path(), home_temp.path());
    let out = run_with_stdin(
        repo_temp.path(),
        home_temp.path(),
        &["reveal", "--passphrase-stdin"],
        "correct horse trailing words\n",
    );
    assert!(
        !out.status.success(),
        "a passphrase that differs after a space must NOT unlock the key"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("passphrase"),
        "the failure must hint that a passphrase may be missing, got: {}",
        stderr
    );

    // And a plain wrong passphrase fails too.
    let out = run_with_stdin(
        repo_temp.path(),
        home_temp.path(),
        &["reveal", "--passphrase-stdin"],
        "hunter2\n",
    );
    assert!(
        !out.status.success(),
        "a wrong passphrase on stdin must fail"
    );
}

// ============================================================================
// Docs infrastructure: `completions` and `manpages` subcommands generate
// shell completion scripts and roff man pages FROM the real clap definition.
// ============================================================================

#[test]
fn cli_completions_emit_scripts() {
    for shell in ["bash", "zsh", "fish"] {
        let out = Command::cargo_bin("git-gpg")
            .expect("git-gpg binary must be buildable")
            .args(["completions", shell])
            .output()
            .expect("run git-gpg");

        assert!(
            out.status.success(),
            "completions {} must exit 0: stderr={:?}",
            shell,
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            !out.stdout.is_empty(),
            "completions {} must emit a non-empty script",
            shell
        );
        let script = String::from_utf8_lossy(&out.stdout);
        assert!(
            script.contains("git-gpg"),
            "completions {} script must reference the binary name, got: {}",
            shell,
            script
        );
    }
}

#[test]
fn cli_manpages_write_files() {
    let dir = tempfile::tempdir().unwrap();

    let out = Command::cargo_bin("git-gpg")
        .expect("git-gpg binary must be buildable")
        .args(["manpages", dir.path().to_str().unwrap()])
        .output()
        .expect("run git-gpg");

    assert!(
        out.status.success(),
        "manpages must exit 0: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let root_page = dir.path().join("git-gpg.1");
    let root_content = std::fs::read(&root_page).expect("git-gpg.1 must exist");
    assert_th_roff(&root_content, "git-gpg.1");

    // The expected per-subcommand man pages are derived from the real clap
    // definition (the lib's Cli), not a hardcoded list that could drift.
    let mut expected: Vec<String> = git_gpg::cli::Cli::command()
        .get_subcommands()
        .map(|sub| sub.get_name().to_string())
        .collect();
    expected.sort();
    assert!(
        !expected.is_empty(),
        "the Cli definition must expose subcommands"
    );
    for name in expected {
        let page = dir.path().join(format!("git-gpg-{}.1", name));
        let content = std::fs::read(&page).unwrap_or_else(|_| {
            panic!("man page for subcommand {} must exist at {:?}", name, page)
        });
        assert_th_roff(&content, &format!("git-gpg-{}.1", name));
    }
}

/// Structural roff validation: the rendered man page must carry a `.TH`
/// title line naming the page (clap_mangen emits a groff-compatibility
/// prologue before it, so a whole-file prefix check would be wrong).
fn assert_th_roff(content: &[u8], label: &str) {
    let text = String::from_utf8_lossy(content);
    assert!(
        text.lines().any(|line| line.starts_with(".TH ")),
        "{} must be roff with a .TH title line, got: {:?}",
        label,
        text.chars().take(80).collect::<String>()
    );
}
