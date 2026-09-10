//! Key store permission tests: the gpg-style check, the git-style trust
//! acknowledgment, and the 0600-at-creation guarantee for files git-veil
//! writes holding private key material. Unix only — the check is a no-op
//! elsewhere.

#![cfg(unix)]

use age::secrecy::ExposeSecret;
use git_veil::{
    check_key_store_permissions, cmd_import, cmd_trust_permissions, exit_code_of,
    generate_identity, permissions_check_bypassed_from_env, ExitCode,
};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

struct TempDir {
    path: std::path::PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        let pid = std::process::id();
        let counter = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("git-veil-perm-{}-{}-{}", label, pid, counter));
        fs::create_dir_all(&dir).expect("create temp dir");
        Self { path: dir }
    }
    fn join(&self, rel: &str) -> std::path::PathBuf {
        self.path.join(rel)
    }
    fn set_mode(&self, mode: u32) {
        fs::set_permissions(&self.path, fs::Permissions::from_mode(mode)).unwrap();
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn code_of(err: anyhow::Error) -> i32 {
    exit_code_of(&err)
}

fn assert_clean(store: &TempDir) {
    store.set_mode(0o700);
    check_key_store_permissions(&store.path, false).expect("clean store passes");
}

#[test]
fn test_clean_store_passes() {
    let store = TempDir::new("clean");
    fs::create_dir_all(store.join("ks")).unwrap();
    let ks = TempDir {
        path: store.join("ks"),
    };
    assert_clean(&ks);

    fs::write(ks.join("identities.txt"), "AGE-SECRET-KEY-1TEST\n").unwrap();
    fs::write(ks.join("signing-keys.txt"), format!("{}\n", "a".repeat(64))).unwrap();
    ks.join("identities.txt").set_mode_0600();
    ks.join("signing-keys.txt").set_mode_0600();
    check_key_store_permissions(&ks.path, false).expect("0700 dir + 0600 files pass");
}

trait SetMode0600 {
    fn set_mode_0600(&self);
}

impl SetMode0600 for Path {
    fn set_mode_0600(&self) {
        fs::set_permissions(self, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

#[test]
fn test_group_writable_dir_fails_with_code_30() {
    let store = TempDir::new("dir755");
    fs::create_dir_all(store.join("ks")).unwrap();
    let ks = TempDir {
        path: store.join("ks"),
    };
    ks.set_mode(0o755);
    let code = code_of(check_key_store_permissions(&ks.path, false).unwrap_err());
    assert_eq!(code, ExitCode::UnsafeKeyStorePermissions as i32);
}

#[test]
fn test_world_readable_identity_fails_with_code_30() {
    let store = TempDir::new("file644");
    fs::create_dir_all(store.join("ks")).unwrap();
    let ks = TempDir {
        path: store.join("ks"),
    };
    ks.set_mode(0o700);
    fs::write(ks.join("identities.txt"), "AGE-SECRET-KEY-1TEST\n").unwrap();
    fs::set_permissions(ks.join("identities.txt"), fs::Permissions::from_mode(0o644)).unwrap();
    let code = code_of(check_key_store_permissions(&ks.path, false).unwrap_err());
    assert_eq!(code, ExitCode::UnsafeKeyStorePermissions as i32);
}

#[test]
fn test_acknowledgment_unblocks_then_mode_change_refails() {
    let store = TempDir::new("ack");
    fs::create_dir_all(store.join("ks")).unwrap();
    let ks = TempDir {
        path: store.join("ks"),
    };
    ks.set_mode(0o700);
    fs::write(ks.join("identities.txt"), "AGE-SECRET-KEY-1TEST\n").unwrap();
    fs::set_permissions(ks.join("identities.txt"), fs::Permissions::from_mode(0o644)).unwrap();

    // Refuses before acknowledgment
    let code = code_of(check_key_store_permissions(&ks.path, false).unwrap_err());
    assert_eq!(code, ExitCode::UnsafeKeyStorePermissions as i32);

    // Acknowledging the current state unblocks the check
    cmd_trust_permissions(&ks.path).expect("trust-permissions");
    check_key_store_permissions(&ks.path, false).expect("acknowledged state passes");

    // The acknowledgment file holds private-material-adjacent state: 0600
    let ack_mode = fs::metadata(ks.join("permissions-ack.json"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(ack_mode, 0o600);

    // A LATER change to anything else fails again — the ack pins the exact
    // (path, mode) pair.
    fs::set_permissions(ks.join("identities.txt"), fs::Permissions::from_mode(0o640)).unwrap();
    let code = code_of(check_key_store_permissions(&ks.path, false).unwrap_err());
    assert_eq!(code, ExitCode::UnsafeKeyStorePermissions as i32);

    // Restoring the acknowledged mode passes again
    fs::set_permissions(ks.join("identities.txt"), fs::Permissions::from_mode(0o644)).unwrap();
    check_key_store_permissions(&ks.path, false).expect("restored acknowledged mode passes");
}

#[test]
fn test_skip_bypasses_check() {
    let store = TempDir::new("skip");
    fs::create_dir_all(store.join("ks")).unwrap();
    let ks = TempDir {
        path: store.join("ks"),
    };
    ks.set_mode(0o777);
    check_key_store_permissions(&ks.path, true).expect("skip bypasses even 0777");
}

#[test]
#[serial_test::serial]
fn test_env_bypass_detected() {
    std::env::set_var("GIT_VEIL_SKIP_PERMISSIONS", "1");
    assert!(permissions_check_bypassed_from_env());
    std::env::set_var("GIT_VEIL_SKIP_PERMISSIONS", "TRUE");
    assert!(permissions_check_bypassed_from_env());
    std::env::set_var("GIT_VEIL_SKIP_PERMISSIONS", "yes");
    assert!(permissions_check_bypassed_from_env());
    std::env::set_var("GIT_VEIL_SKIP_PERMISSIONS", "0");
    assert!(!permissions_check_bypassed_from_env());
    std::env::remove_var("GIT_VEIL_SKIP_PERMISSIONS");
    assert!(!permissions_check_bypassed_from_env());
}

#[test]
fn test_import_writes_identities_0600() {
    let store = TempDir::new("import0600");
    let repo = TempDir::new("import0600-repo");
    fs::create_dir_all(store.join("ks")).unwrap();
    let ks = TempDir {
        path: store.join("ks"),
    };

    let identity = generate_identity();
    fs::write(
        repo.join("my.age"),
        format!("{}\n", identity.to_string().expose_secret()),
    )
    .unwrap();

    cmd_import(&repo.path, &["my.age".to_string()], &ks.path).expect("import");

    // Private key material: 0600 at creation, regardless of umask
    let mode = fs::metadata(ks.join("identities.txt"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
}
