//! Literal .gitignore rules for tracked paths (issue #136).

use age::secrecy::ExposeSecret;
use git_veil::{
    cmd_add_file, cmd_import, cmd_init, generate_signing_keypair, generate_x25519_private_key,
    x25519_public_key_encoding,
};
use std::fs;
use std::path::Path;

struct TempDir {
    path: std::path::PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        let pid = std::process::id();
        let counter = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir =
            std::env::temp_dir().join(format!("git-veil-gitignore-{}-{}-{}", label, pid, counter));
        fs::create_dir_all(&dir).expect("create temp dir");
        Self { path: dir }
    }
    fn join(&self, rel: &str) -> std::path::PathBuf {
        self.path.join(rel)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn init_git_repo(dir: &Path) {
    let args_list: &[&[&str]] = &[
        &["init", "--quiet"],
        &["config", "user.email", "owner@example.com"],
        &["config", "user.name", "Test Owner"],
        &["remote", "add", "origin", "git@github.com:owner/fara.git"],
    ];
    for args in args_list {
        let status = std::process::Command::new("git")
            .current_dir(dir)
            .args(*args)
            .status()
            .expect("git command");
        assert!(status.success());
    }
}

struct Fixture {
    repo: TempDir,
    key_store: TempDir,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let repo = TempDir::new(label);
        let key_store = TempDir::new(&format!("{}-ks", label));
        init_git_repo(&repo.path);

        let private_key = generate_x25519_private_key();
        let public_key = x25519_public_key_encoding(&private_key);
        let (signing_key, verifying_hex) = generate_signing_keypair();

        fs::write(
            repo.join("owner.age"),
            format!("{}\n", private_key.to_string().expose_secret()),
        )
        .unwrap();
        fs::write(
            key_store.join("signing-keys.txt"),
            format!("{}\n", hex::encode(signing_key.to_bytes())),
        )
        .unwrap();
        fs::write(
            key_store.join("owner.verifying"),
            format!("{}\n{}\n", verifying_hex, public_key),
        )
        .unwrap();

        cmd_init(
            &repo.path,
            &key_store.join("owner.verifying"),
            "origin",
            &key_store.path,
            false,
            false,
        )
        .expect("init copies the owner key in and pins");
        cmd_import(&repo.path, &["owner.age".to_string()], &key_store.path).expect("import");

        Self { repo, key_store }
    }

    fn add_file(&self, name: &str, content: &[u8]) {
        let target = self.repo.join(name);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&target, content).unwrap();
        cmd_add_file(
            &self.repo.path,
            vec![name.to_string()],
            "origin",
            &self.key_store.path,
        )
        .expect("add-file");
    }
}

#[test]
fn add_file_encodes_literal_gitignore_rules() {
    let fixture = Fixture::new("literal-rules");

    let names = [
        "#secret.txt",
        "!important.txt",
        "asterisk*.txt",
        "query?.txt",
        "bracket[1].txt",
        "space path.txt",
        "bang!later.txt",
        "escaped\\.txt",
    ];

    for name in &names {
        fixture.add_file(name, b"secret\n");
    }

    let gitignore = fs::read_to_string(fixture.repo.join(".gitignore")).unwrap();
    assert!(
        gitignore.contains("asterisk\\*.txt")
            && gitignore.contains("query\\?.txt")
            && gitignore.contains("bracket\\[1\\].txt"),
        "the rules must escape Git pattern metacharacters: {gitignore}"
    );

    for name in &names {
        let output = std::process::Command::new("git")
            .current_dir(&fixture.repo.path)
            .args(["check-ignore", "--", name])
            .output()
            .expect("git check-ignore");
        assert!(
            output.status.success(),
            "git check-ignore must confirm the literal rule for {}",
            name
        );
    }
}

#[cfg(not(target_os = "windows"))]
#[test]
fn add_file_encodes_trailing_space_rules() {
    let fixture = Fixture::new("trailing-space");

    fixture.add_file("trailing .txt ", b"secret\n");

    let output = std::process::Command::new("git")
        .current_dir(&fixture.repo.path)
        .args(["check-ignore", "--", "trailing .txt "])
        .output()
        .expect("git check-ignore");
    assert!(
        output.status.success(),
        "git check-ignore must confirm the trailing-space rule"
    );
}

#[test]
fn add_file_preserves_existing_rules() {
    let fixture = Fixture::new("preserve-rules");
    std::fs::write(fixture.repo.join(".gitignore"), "existing\n").unwrap();

    fixture.add_file("secret.txt", b"secret\n");

    let gitignore = fs::read_to_string(fixture.repo.join(".gitignore")).unwrap();
    assert!(gitignore.contains("existing"));
    assert!(gitignore.contains("secret.txt"));
}

#[test]
fn add_file_refuses_a_gitignore_read_error() {
    let fixture = Fixture::new("read-error");
    let gitignore = fixture.repo.join(".gitignore");
    if gitignore.is_file() {
        fs::remove_file(&gitignore).unwrap();
    }
    fs::create_dir(&gitignore).unwrap();
    fs::write(fixture.repo.join("secret.txt"), b"secret\n").unwrap();

    let result = cmd_add_file(
        &fixture.repo.path,
        vec!["secret.txt".to_string()],
        "origin",
        &fixture.key_store.path,
    );

    assert!(result.is_err());
    assert!(fixture.repo.join(".gitignore").is_dir());
}

#[test]
fn add_file_preserves_concurrent_rules() {
    let fixture = Fixture::new("concurrent-rules");
    fs::write(fixture.repo.join("one.txt"), b"one\n").unwrap();
    fs::write(fixture.repo.join("two.txt"), b"two\n").unwrap();

    let handles = vec![
        {
            let repo = fixture.repo.path.clone();
            let key_store = fixture.key_store.path.clone();
            std::thread::spawn(move || {
                cmd_add_file(&repo, vec!["one.txt".to_string()], "origin", &key_store)
                    .expect("add file one");
            })
        },
        {
            let repo = fixture.repo.path.clone();
            let key_store = fixture.key_store.path.clone();
            std::thread::spawn(move || {
                cmd_add_file(&repo, vec!["two.txt".to_string()], "origin", &key_store)
                    .expect("add file two");
            })
        },
    ];

    for handle in handles {
        handle.join().unwrap();
    }

    let gitignore = fs::read_to_string(fixture.repo.join(".gitignore")).unwrap();
    assert!(gitignore.contains("one.txt"));
    assert!(gitignore.contains("two.txt"));

    for entry in fs::read_dir(&fixture.repo.path).unwrap() {
        let path = entry.unwrap().path();
        let file_name = path.file_name().unwrap().to_string_lossy().to_string();
        assert!(
            !file_name.starts_with(".gitignore.tmp-"),
            "no temporary gitignore files remain: {file_name}"
        );
    }
}
