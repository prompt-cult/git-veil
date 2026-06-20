//! Integration tests for all git-gpg CLI commands.
//!
//! These tests spawn the git-gpg binary and verify each command works correctly
//! by checking exit codes, stdout/stderr output, and filesystem state.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::path::Path;

/// Create a temporary test directory with a fresh git-gpg setup.
fn setup_test_dir() -> tempfile::TempDir {
    let temp = tempfile::tempdir().expect("create temp dir");

    // Initialize git-gpg
    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("init")
        .assert()
        .success()
        .stdout(predicate::str::contains("git-gpg initialized"));

    // Verify directories created
    assert!(temp.path().join(".git-gpg").exists());
    assert!(temp.path().join(".git-gpg").join("secrets").exists());
    assert!(temp.path().join(".git-gpg").join("config.json").exists());

    temp
}

/// Generate a key pair in the test directory.
fn generate_key(dir: &Path, name: &str, email: &str, key_type: &str) {
    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(dir)
        .arg("key-gen")
        .arg("--name")
        .arg(name)
        .arg("--email")
        .arg(email)
        .arg("--key-type")
        .arg(key_type)
        .assert()
        .success()
        .stdout(predicate::str::contains("Key pair generated"));

    assert!(dir.join(".git-gpg").join("public.key").exists());
    assert!(dir.join(".git-gpg").join("private.key").exists());
}

fn load_config(dir: &Path) -> serde_json::Value {
    let config_path = dir.join(".git-gpg").join("config.json");
    let config = fs::read_to_string(config_path).expect("read config");
    serde_json::from_str(&config).expect("parse config")
}

// ============================================================
// Init Command Tests
// ============================================================

#[test]
fn test_init_creates_directories() {
    let temp = tempfile::tempdir().expect("create temp dir");

    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("init")
        .assert()
        .success()
        .stdout(predicate::str::contains("git-gpg initialized"));

    assert!(temp.path().join(".git-gpg").exists());
    assert!(temp.path().join(".git-gpg").join("secrets").exists());
    assert!(temp.path().join(".git-gpg").join("secrets").join(".gitkeep").exists());
    assert!(temp.path().join(".git-gpg").join("config.json").exists());
}

#[test]
fn test_init_creates_gitignore() {
    let temp = tempfile::tempdir().expect("create temp dir");

    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("init")
        .assert()
        .success();

    let gitignore = fs::read_to_string(temp.path().join(".gitignore")).expect("read gitignore");
    assert!(gitignore.contains(".git-gpg/secrets"));
}

#[test]
fn test_init_appends_to_existing_gitignore() {
    let temp = tempfile::tempdir().expect("create temp dir");
    fs::write(temp.path().join(".gitignore"), "/target\n").expect("write gitignore");

    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("init")
        .assert()
        .success();

    let gitignore = fs::read_to_string(temp.path().join(".gitignore")).expect("read gitignore");
    assert!(gitignore.contains("/target"));
    assert!(gitignore.contains(".git-gpg/secrets"));
}

#[test]
fn test_init_idempotent() {
    let temp = tempfile::tempdir().expect("create temp dir");

    // Run init twice
    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("init")
        .assert()
        .success();

    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("init")
        .assert()
        .success();

    // Gitignore should not have duplicate entries
    let gitignore = fs::read_to_string(temp.path().join(".gitignore")).expect("read gitignore");
    let count = gitignore.matches(".git-gpg/secrets").count();
    assert_eq!(count, 1, "gitignore should not have duplicate entries");
}

// ============================================================
// KeyGen Command Tests
// ============================================================

#[test]
fn test_keygen_ed25519_default() {
    let temp = setup_test_dir();

    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("key-gen")
        .assert()
        .success()
        .stdout(predicate::str::contains("Key pair generated"))
        .stdout(predicate::str::contains("Public key:"))
        .stdout(predicate::str::contains("Private key:"));

    let pubkey = fs::read_to_string(temp.path().join(".git-gpg").join("public.key")).expect("read pubkey");
    assert!(pubkey.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----"));

    let privkey = fs::read_to_string(temp.path().join(".git-gpg").join("private.key")).expect("read privkey");
    assert!(privkey.contains("-----BEGIN PGP PRIVATE KEY BLOCK-----"));
}

#[test]
fn test_keygen_custom_name_email() {
    let temp = setup_test_dir();

    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("key-gen")
        .arg("--name")
        .arg("Alice")
        .arg("--email")
        .arg("alice@example.com")
        .assert()
        .success();
}

#[test]
fn test_keygen_rsa4096() {
    let temp = setup_test_dir();

    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("key-gen")
        .arg("--key-type")
        .arg("rsa4096")
        .assert()
        .success();
}

#[test]
fn test_keygen_invalid_type() {
    let temp = setup_test_dir();

    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("key-gen")
        .arg("--key-type")
        .arg("invalid")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Unknown key type"));
}

// ============================================================
// Add Command Tests
// ============================================================

#[test]
fn test_add_single_file() {
    let temp = setup_test_dir();
    generate_key(temp.path(), "Test", "test@test.com", "ed25519");

    let test_file = temp.path().join("secret.txt");
    fs::write(&test_file, "secret content").expect("write test file");

    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("add")
        .arg("secret.txt")
        .assert()
        .success()
        .stdout(predicate::str::contains("Added 1 file(s)"));
}

#[test]
fn test_add_multiple_files() {
    let temp = setup_test_dir();
    generate_key(temp.path(), "Test", "test@test.com", "ed25519");

    fs::write(temp.path().join("file1.txt"), "content1").expect("write file1");
    fs::write(temp.path().join("file2.txt"), "content2").expect("write file2");

    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("add")
        .arg("file1.txt")
        .arg("file2.txt")
        .assert()
        .success()
        .stdout(predicate::str::contains("Added 2 file(s)"));
}

#[test]
fn test_add_nonexistent_file_fails() {
    let temp = setup_test_dir();

    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("add")
        .arg("nonexistent.txt")
        .assert()
        .failure();
}

#[test]
fn test_add_duplicate_file() {
    let temp = setup_test_dir();
    generate_key(temp.path(), "Test", "test@test.com", "ed25519");

    let test_file = temp.path().join("secret.txt");
    fs::write(&test_file, "secret content").expect("write test file");

    // Add twice
    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("add")
        .arg("secret.txt")
        .assert()
        .success();

    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("add")
        .arg("secret.txt")
        .assert()
        .success();

    // Config should only have one entry
    let config = fs::read_to_string(temp.path().join(".git-gpg").join("config.json")).expect("read config");
    let count = config.matches("secret.txt").count();
    assert_eq!(count, 1, "config should not have duplicate entries");
}

#[test]
fn test_add_stores_absolute_paths_in_config() {
    let temp = setup_test_dir();
    generate_key(temp.path(), "Test", "test@test.com", "ed25519");

    let test_file = temp.path().join("secret.txt");
    fs::write(&test_file, "secret content").expect("write test file");

    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("add")
        .arg("secret.txt")
        .assert()
        .success();

    let config = load_config(temp.path());
    let files = config["encrypted_files"]
        .as_array()
        .expect("encrypted_files should be array");
    assert_eq!(files.len(), 1);

    let stored = files[0].as_str().expect("stored path should be string");
    assert!(stored.starts_with('/'), "tracked path should be absolute: {stored}");
    assert_eq!(stored, test_file.canonicalize().expect("canonicalize").to_str().expect("utf8 path"));
}

// ============================================================
// Remove Command Tests
// ============================================================

#[test]
fn test_remove_file() {
    let temp = setup_test_dir();
    generate_key(temp.path(), "Test", "test@test.com", "ed25519");

    let test_file = temp.path().join("secret.txt");
    fs::write(&test_file, "secret content").expect("write test file");

    // Add then remove
    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("add")
        .arg("secret.txt")
        .assert()
        .success();

    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("remove")
        .arg("secret.txt")
        .assert()
        .success()
        .stdout(predicate::str::contains("Removed 1 file(s)"));
}

#[test]
fn test_remove_nonexistent_file() {
    let temp = setup_test_dir();

    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("remove")
        .arg("nonexistent.txt")
        .assert()
        .failure();
}

// ============================================================
// List Command Tests
// ============================================================

#[test]
fn test_list_empty() {
    let temp = setup_test_dir();

    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("No files are being tracked"));
}

#[test]
fn test_list_with_files() {
    let temp = setup_test_dir();
    generate_key(temp.path(), "Test", "test@test.com", "ed25519");

    let test_file = temp.path().join("secret.txt");
    fs::write(&test_file, "secret content").expect("write test file");

    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("add")
        .arg("secret.txt")
        .assert()
        .success();

    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("Tracked files:"))
        .stdout(predicate::str::contains("secret.txt"));
}

// ============================================================
// Hide Command Tests
// ============================================================

#[test]
fn test_hide_encrypts_file() {
    let temp = setup_test_dir();
    generate_key(temp.path(), "Test", "test@test.com", "ed25519");

    let test_file = temp.path().join("secret.txt");
    fs::write(&test_file, "secret content").expect("write test file");

    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("add")
        .arg("secret.txt")
        .assert()
        .success();

    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("hide")
        .assert()
        .success()
        .stdout(predicate::str::contains("Encrypted:"))
        .stdout(predicate::str::contains("Files hidden"));

    // Original file should be removed
    assert!(!test_file.exists(), "original file should be removed");

    // Encrypted file should exist
    let encrypted = temp.path().join(".git-gpg").join("secrets").join("secret.txt.asc");
    assert!(encrypted.exists(), "encrypted file should exist");

    // Encrypted file should contain PGP message
    let content = fs::read_to_string(&encrypted).expect("read encrypted file");
    assert!(content.contains("-----BEGIN PGP MESSAGE-----"));
}

#[test]
fn test_hide_preserves_nested_relative_path_and_original_extension() {
    let temp = setup_test_dir();
    generate_key(temp.path(), "Test", "test@test.com", "ed25519");

    let nested_dir = temp.path().join("config");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let test_file = nested_dir.join("credentials.yml");
    fs::write(&test_file, "token: secret").expect("write test file");

    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("add")
        .arg("config/credentials.yml")
        .assert()
        .success();

    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("hide")
        .assert()
        .success();

    assert!(!test_file.exists(), "original file should be removed");
    assert!(
        temp.path()
            .join(".git-gpg")
            .join("secrets")
            .join("config")
            .join("credentials.yml.asc")
            .exists(),
        "encrypted nested file should preserve relative path and extension"
    );
}

#[test]
fn test_hide_no_files() {
    let temp = setup_test_dir();
    generate_key(temp.path(), "Test", "test@test.com", "ed25519");

    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("hide")
        .assert()
        .success();
}

#[test]
fn test_hide_no_key_fails() {
    let temp = setup_test_dir();

    let test_file = temp.path().join("secret.txt");
    fs::write(&test_file, "secret content").expect("write test file");

    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("add")
        .arg("secret.txt")
        .assert()
        .success();

    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("hide")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Public key not found"));
}

// ============================================================
// Reveal Command Tests
// ============================================================

#[test]
fn test_reveal_decrypts_file() {
    let temp = setup_test_dir();
    generate_key(temp.path(), "Test", "test@test.com", "ed25519");

    let test_file = temp.path().join("secret.txt");
    let original_content = "secret content";
    fs::write(&test_file, original_content).expect("write test file");

    // Add and hide
    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("add")
        .arg("secret.txt")
        .assert()
        .success();

    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("hide")
        .assert()
        .success();

    // Reveal
    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("reveal")
        .assert()
        .success()
        .stdout(predicate::str::contains("Decrypted:"))
        .stdout(predicate::str::contains("Files revealed"));

    // Original file should be restored
    assert!(test_file.exists(), "original file should be restored");

    // Content should match
    let restored = fs::read_to_string(&test_file).expect("read restored file");
    assert_eq!(restored, original_content, "content should match original");

    // Encrypted file should be removed
    let encrypted = temp.path().join(".git-gpg").join("secrets").join("secret.txt.asc");
    assert!(!encrypted.exists(), "encrypted file should be removed");
}

#[test]
fn test_reveal_missing_encrypted_file_fails() {
    let temp = setup_test_dir();
    generate_key(temp.path(), "Test", "test@test.com", "ed25519");

    let test_file = temp.path().join("secret.txt");
    fs::write(&test_file, "secret content").expect("write test file");

    // Add but don't hide
    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("add")
        .arg("secret.txt")
        .assert()
        .success();

    // Reveal should fail because encrypted file doesn't exist
    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("reveal")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Encrypted file not found"));
}

#[test]
fn test_reveal_no_key_fails() {
    let temp = setup_test_dir();

    let test_file = temp.path().join("secret.txt");
    fs::write(&test_file, "secret content").expect("write test file");

    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("add")
        .arg("secret.txt")
        .assert()
        .success();

    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("hide")
        .assert()
        .failure();
}

// ============================================================
// Clean Command Tests
// ============================================================

#[test]
fn test_clean_removes_directory() {
    let temp = setup_test_dir();

    assert!(temp.path().join(".git-gpg").exists());

    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("clean")
        .assert()
        .success()
        .stdout(predicate::str::contains("Cleaned"));

    assert!(!temp.path().join(".git-gpg").exists(), ".git-gpg should be removed");
}

#[test]
fn test_clean_idempotent() {
    let temp = setup_test_dir();

    // Clean twice
    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("clean")
        .assert()
        .success();

    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("clean")
        .assert()
        .success();
}

#[test]
fn test_clean_removes_gitignore_entry() {
    let temp = tempfile::tempdir().expect("create temp dir");
    fs::write(temp.path().join(".gitignore"), "/target\n").expect("write gitignore");

    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("init")
        .assert()
        .success();

    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("clean")
        .assert()
        .success();

    let gitignore = fs::read_to_string(temp.path().join(".gitignore")).expect("read gitignore");
    assert!(gitignore.contains("/target"));
    assert!(
        !gitignore.contains(".git-gpg/secrets"),
        "clean should remove the git-gpg secrets entry from .gitignore"
    );
}

// ============================================================
// Export Commands Tests
// ============================================================

#[test]
fn test_export_pubkey() {
    let temp = setup_test_dir();
    generate_key(temp.path(), "Test", "test@test.com", "ed25519");

    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("export-pubkey")
        .assert()
        .success()
        .stdout(predicate::str::contains("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
}

#[test]
fn test_export_privkey() {
    let temp = setup_test_dir();
    generate_key(temp.path(), "Test", "test@test.com", "ed25519");

    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("export-privkey")
        .assert()
        .success()
        .stdout(predicate::str::contains("-----BEGIN PGP PRIVATE KEY BLOCK-----"));
}

#[test]
fn test_export_pubkey_no_key_fails() {
    let temp = setup_test_dir();

    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("export-pubkey")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Public key not found"));
}

#[test]
fn test_export_privkey_no_key_fails() {
    let temp = setup_test_dir();

    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("export-privkey")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Private key not found"));
}

#[test]
fn test_help_shows_documented_commands() {
    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("init"))
        .stdout(predicate::str::contains("add"))
        .stdout(predicate::str::contains("remove"))
        .stdout(predicate::str::contains("list"))
        .stdout(predicate::str::contains("hide"))
        .stdout(predicate::str::contains("reveal"))
        .stdout(predicate::str::contains("clean"))
        .stdout(predicate::str::contains("keygen"))
        .stdout(predicate::str::contains("export-pubkey"))
        .stdout(predicate::str::contains("export-privkey"));
}

#[test]
fn test_version_flag_succeeds() {
    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("git-gpg"));
}

#[test]
fn test_keygen_documented_command_name_works() {
    let temp = setup_test_dir();

    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("keygen")
        .assert()
        .success()
        .stdout(predicate::str::contains("Key pair generated"));
}

// ============================================================
// Full Workflow Tests
// ============================================================

#[test]
fn test_full_workflow_ed25519() {
    let temp = setup_test_dir();
    generate_key(temp.path(), "Test", "test@test.com", "ed25519");

    // Create test files
    fs::write(temp.path().join("db.env"), "DB_PASS=secret123").expect("write db.env");
    fs::write(temp.path().join("api.key"), "api-key-abc123").expect("write api.key");

    // Add files
    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("add")
        .arg("db.env")
        .arg("api.key")
        .assert()
        .success();

    // Verify list
    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("db.env"))
        .stdout(predicate::str::contains("api.key"));

    // Hide
    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("hide")
        .assert()
        .success();

    // Verify originals removed
    assert!(!temp.path().join("db.env").exists());
    assert!(!temp.path().join("api.key").exists());

    // Verify encrypted files exist
    assert!(temp.path().join(".git-gpg").join("secrets").join("db.env.asc").exists());
    assert!(temp.path().join(".git-gpg").join("secrets").join("api.key.asc").exists());

    // Reveal
    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("reveal")
        .assert()
        .success();

    // Verify restored content
    let db_content = fs::read_to_string(temp.path().join("db.env")).expect("read db.env");
    assert_eq!(db_content, "DB_PASS=secret123");

    let api_content = fs::read_to_string(temp.path().join("api.key")).expect("read api.key");
    assert_eq!(api_content, "api-key-abc123");
}

#[test]
fn test_full_workflow_rsa() {
    let temp = setup_test_dir();
    generate_key(temp.path(), "Test", "test@test.com", "rsa4096");

    fs::write(temp.path().join("config.yml"), "password: supersecret").expect("write config");

    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("add")
        .arg("config.yml")
        .assert()
        .success();

    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("hide")
        .assert()
        .success();

    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("reveal")
        .assert()
        .success();

    let content = fs::read_to_string(temp.path().join("config.yml")).expect("read config");
    assert_eq!(content, "password: supersecret");
}

#[test]
fn test_add_remove_list_workflow() {
    let temp = setup_test_dir();
    generate_key(temp.path(), "Test", "test@test.com", "ed25519");

    fs::write(temp.path().join("a.txt"), "a").expect("write a");
    fs::write(temp.path().join("b.txt"), "b").expect("write b");
    fs::write(temp.path().join("c.txt"), "c").expect("write c");

    // Add all
    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("add")
        .arg("a.txt")
        .arg("b.txt")
        .arg("c.txt")
        .assert()
        .success();

    // Remove one
    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("remove")
        .arg("b.txt")
        .assert()
        .success();

    // List should show a and c but not b
    let output = Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("list")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8(output).expect("valid utf8");
    assert!(stdout.contains("a.txt"));
    assert!(!stdout.contains("b.txt"));
    assert!(stdout.contains("c.txt"));
}

#[test]
fn test_binary_file_roundtrip() {
    let temp = setup_test_dir();
    generate_key(temp.path(), "Test", "test@test.com", "ed25519");

    // Create binary file with all byte values
    let binary_data: Vec<u8> = (0..=255).cycle().take(1024).collect();
    fs::write(temp.path().join("binary.dat"), &binary_data).expect("write binary");

    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("add")
        .arg("binary.dat")
        .assert()
        .success();

    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("hide")
        .assert()
        .success();

    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("reveal")
        .assert()
        .success();

    let restored = fs::read(temp.path().join("binary.dat")).expect("read binary");
    assert_eq!(restored, binary_data, "binary content should match");
}

#[test]
fn test_empty_file_roundtrip() {
    let temp = setup_test_dir();
    generate_key(temp.path(), "Test", "test@test.com", "ed25519");

    fs::write(temp.path().join("empty.txt"), "").expect("write empty");

    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("add")
        .arg("empty.txt")
        .assert()
        .success();

    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("hide")
        .assert()
        .success();

    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("reveal")
        .assert()
        .success();

    let restored = fs::read(temp.path().join("empty.txt")).expect("read empty");
    assert!(restored.is_empty(), "empty file should be empty");
}

#[test]
fn test_multiline_file_roundtrip() {
    let temp = setup_test_dir();
    generate_key(temp.path(), "Test", "test@test.com", "ed25519");

    let content = "line1\nline2\nline3\n\nline5 with special chars: !@#$%^&*()\n";
    fs::write(temp.path().join("multiline.txt"), content).expect("write multiline");

    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("add")
        .arg("multiline.txt")
        .assert()
        .success();

    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("hide")
        .assert()
        .success();

    Command::cargo_bin("git-gpg")
        .expect("find binary")
        .current_dir(temp.path())
        .arg("reveal")
        .assert()
        .success();

    let restored = fs::read_to_string(temp.path().join("multiline.txt")).expect("read multiline");
    assert_eq!(restored, content, "multiline content should match");
}
