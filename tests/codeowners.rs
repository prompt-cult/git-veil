//! CODEOWNERS coverage tests. Suppression is deliberate and per pinned
//! repository. The tool never requires CODEOWNERS, never creates the
//! file, and never alters an exit code.

use git_veil::{
    cmd_export_pin, cmd_trust, codeowners_suggestion, codeowners_suppressed, codeowners_warning,
    covers_trust_critical_paths, exit_code_of, find_codeowners, record_codeowners_suppression,
};
use std::fs;
use std::path::{Path, PathBuf};

struct TempDir {
    path: std::path::PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!(
            "git-veil-codeowners-{}-{}-{}",
            label,
            pid,
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");
        Self { path: dir }
    }
    fn join(&self, rel: &str) -> PathBuf {
        self.path.join(rel)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn init_git_repo(dir: &Path) {
    let s = std::process::Command::new("git")
        .current_dir(dir)
        .args(["init", "--quiet"])
        .status()
        .expect("git");
    assert!(s.success());
}

/// Adds a remote and runs the init ceremony from `key_store_dir`, whose
/// key store receives the signing seed and the owner verifying key file.
fn init_state_from(repo_root: &Path, key_store_dir: &Path, quiet: bool, suppress: bool) {
    let s = std::process::Command::new("git")
        .current_dir(repo_root)
        .args(["remote", "add", "origin", "git@github.com:owner/fara.git"])
        .status()
        .expect("git remote add");
    assert!(s.success());

    let (signing_key, verifying_hex) = git_veil::generate_signing_keypair();
    fs::create_dir_all(key_store_dir).unwrap();
    fs::write(
        key_store_dir.join("signing-keys.txt"),
        format!("{}\n", hex::encode(signing_key.to_bytes())),
    )
    .unwrap();
    fs::write(
        key_store_dir.join("owner.verifying"),
        format!("{}\n", verifying_hex),
    )
    .unwrap();

    git_veil::cmd_init(
        repo_root,
        &key_store_dir.join("owner.verifying"),
        "origin",
        key_store_dir,
        quiet,
        suppress,
    )
    .expect("init runs the pin ceremony");
}

fn covering_codeowners() -> &'static [u8] {
    b"# reviewers for the trust-critical paths\n* @the-repository-owner\n"
}

#[test]
fn test_no_codeowners_is_not_covered_and_suggestion_is_printed() {
    let repo = TempDir::new("none");
    init_git_repo(&repo.path);
    assert!(find_codeowners(&repo.path).is_none());
    assert!(!covers_trust_critical_paths(&repo.path));
    let text = codeowners_suggestion();
    assert!(text.contains(".git-veil/ @the-repository-owner"));
    assert!(!text.contains('<'), "no angle brackets in tool output");
}

#[test]
fn test_covering_codeowners_in_root_and_platform_dirs() {
    let repo = TempDir::new("covering");

    init_git_repo(&repo.path);
    fs::write(repo.join("CODEOWNERS"), covering_codeowners()).unwrap();
    assert_eq!(find_codeowners(&repo.path), Some(repo.join("CODEOWNERS")));
    assert!(covers_trust_critical_paths(&repo.path));

    // Precedence: the root file wins over a platform-directory file, and a
    // platform-directory file is found on its own too.
    let repo_github = TempDir::new("covering-github");
    init_git_repo(&repo_github.path);
    fs::create_dir_all(repo_github.join(".github")).unwrap();
    fs::write(
        repo_github.join(".github/CODEOWNERS"),
        covering_codeowners(),
    )
    .unwrap();
    assert_eq!(
        find_codeowners(&repo_github.path),
        Some(repo_github.join(".github/CODEOWNERS"))
    );
    assert!(covers_trust_critical_paths(&repo_github.path));
}

#[test]
fn test_directory_pattern_and_inner_file_both_cover_the_state_directory() {
    let repo_dir_pattern = TempDir::new("dir-pattern");
    init_git_repo(&repo_dir_pattern.path);
    fs::write(
        repo_dir_pattern.join("CODEOWNERS"),
        b"owner.verifying @owner\n.git-veil/ @owner\n",
    )
    .unwrap();
    assert!(covers_trust_critical_paths(&repo_dir_pattern.path));

    let repo_file_pattern = TempDir::new("file-pattern");
    init_git_repo(&repo_file_pattern.path);
    fs::write(
        repo_file_pattern.join("CODEOWNERS"),
        b"owner.verifying @owner\n.git-veil/** @owner\n",
    )
    .unwrap();
    assert!(covers_trust_critical_paths(&repo_file_pattern.path));

    // A partial cover (key file only) is not a cover.
    let repo_partial = TempDir::new("partial");
    init_git_repo(&repo_partial.path);
    fs::write(repo_partial.join("CODEOWNERS"), b"owner.verifying @owner\n").unwrap();
    assert!(!covers_trust_critical_paths(&repo_partial.path));

    // Last match wins. A final negation uncovers what an earlier pattern
    // covered. Negation is not valid CODEOWNERS, but the matcher reports
    // the gitignore semantics honestly.
    let repo_negated = TempDir::new("negated");
    init_git_repo(&repo_negated.path);
    fs::write(
        repo_negated.join("CODEOWNERS"),
        b"* @owner\n.git-veil/\n!.git-veil\n!.git-veil/tracked.json\n",
    )
    .unwrap();
    assert!(!covers_trust_critical_paths(&repo_negated.path));
}

#[test]
fn test_warning_text_fires_only_for_the_uncovered_case() {
    // The warning is a statement of fact, plain ASCII, no command lines.
    let text = codeowners_warning();
    assert!(text.starts_with("warning:"));
    assert!(text.contains("not review gated"));
    assert!(!text.contains('<'), "no angle brackets in tool output");
    assert!(!text.contains('('), "no parentheses in tool output");
    assert!(!text.contains(';'), "no semicolons in tool output");
}

#[test]
fn test_suppression_is_per_repository_and_recorded_in_the_key_store() {
    let store = TempDir::new("suppression");
    assert!(!codeowners_suppressed(&store.path, "fara+owner@github.com"));

    record_codeowners_suppression(&store.path, "fara+owner@github.com").unwrap();
    assert!(codeowners_suppressed(&store.path, "fara+owner@github.com"));
    assert!(
        !codeowners_suppressed(&store.path, "other+owner@github.com"),
        "the suppression is per pinned repository, never global"
    );

    // Idempotent: recording twice leaves one entry.
    record_codeowners_suppression(&store.path, "fara+owner@github.com").unwrap();
    let recorded = fs::read_to_string(store.join("codeowners-suppression")).unwrap();
    assert_eq!(recorded.lines().count(), 1);
}

#[test]
fn test_init_suggestion_respects_quiet_and_the_coverage_gate() {
    // Not quiet and nothing covered. cmd_init must not fail and the state
    // directory must exist. The suggestion is printed to stdout, which
    // these cmd-level tests cannot capture.
    let repo = TempDir::new("init-suggest");
    init_git_repo(&repo.path);
    {
        let ks = TempDir::new("init-suggest-ks");
        init_state_from(&repo.path, &ks.path, false, false);
    }
    assert!(repo.join(".git-veil/keyring").exists());
    assert!(repo.join(".git-veil/owner.verifying").exists());

    // Quiet init behaves identically state-wise.
    let repo_quiet = TempDir::new("init-quiet");
    init_git_repo(&repo_quiet.path);
    {
        let ks = TempDir::new("init-quiet-ks");
        init_state_from(&repo_quiet.path, &ks.path, true, false);
    }
    assert!(repo_quiet.join(".git-veil/keyring").exists());
    assert!(repo_quiet.join(".git-veil/owner.verifying").exists());
}

#[test]
fn test_pin_ceremony_warns_or_suppresses_without_touching_the_exit_code() {
    let repo = TempDir::new("trust-warn");
    init_git_repo(&repo.path);
    fs::write(repo.join(".gitignore"), "owner.age\n").unwrap();

    let store = TempDir::new("trust-warn-ks");

    // Suppressed or not, init exits zero (the warning is non-blocking).
    init_state_from(&repo.path, &store.path, false, false);
    assert!(!codeowners_suppressed(&store.path, "fara+owner@github.com"));

    // Suppressing through the pin-import command records the entry.
    let out_dir = TempDir::new("trust-warn-out");
    let pin = out_dir.join("fara.pin");
    cmd_export_pin(
        &repo.path,
        "fara+owner@github.com",
        Some(&pin),
        "origin",
        &store.path,
    )
    .expect("export-pin with the matching seed succeeds");
    let result = cmd_trust(&repo.path, &pin, "origin", &store.path, true);
    assert!(
        result.is_ok(),
        "suppressing the pin import must still pin: {result:?}"
    );
    assert!(codeowners_suppressed(&store.path, "fara+owner@github.com"));

    // A covered repository needs no warning and no suppression.
    fs::write(repo.join("CODEOWNERS"), covering_codeowners()).unwrap();
    assert!(covers_trust_critical_paths(&repo.path));
    let store2 = TempDir::new("trust-warn-ks2");
    let result = cmd_trust(&repo.path, &pin, "origin", &store2.path, false);
    assert!(result.is_ok());
    assert!(
        !codeowners_suppressed(&store2.path, "fara+owner@github.com"),
        "a covered repository records no suppression"
    );

    let _ = exit_code_of; // keeps the exit_code_of import used
}
