# git-veil design specification

This document is the specification of git-veil's mechanisms: what the code
actually enforces, stated precisely enough to be re-verified. It is distinct
from the README (an overview) and the tutorials under `docs/` (how-to journeys);
when prose elsewhere disagrees with this document or with the code, this
document should be corrected first, then the prose. Each claim names the
enforcing function; the named function, not any line number, is the contract.

## Repository identity

Every repository is identified by a `repo_id` derived from its git remote push
URL. The algorithm lives in `parse_git_remote_url` and `derive_repo_id`
(src/repo_identity.rs) and is exactly:

1. Two URL shapes are accepted.
   - **SCP-style SSH**: `user@host:owner/repo` (regex in
     `SCCP_LIKE_RE`, src/repo_identity.rs). The user part must be non-empty and
     must not contain `/` or `@`; any SSH user is accepted, not just `git`.
   - **Scheme URLs**: `ssh://`, `git://` or `https://`, with optional userinfo
     `user[:pass]@`, a host, an optional `:port`, then `/owner/repo` (regex in
     `URL_RE`, src/repo_identity.rs). No other scheme — in particular `http://`
     — is accepted. IPv6 literal hosts and paths with extra segments are also
     rejected.
2. **Userinfo is stripped.** Embedded credentials never become part of the
   identity and are never echoed in errors (`strip_userinfo`,
   src/repo_identity.rs).
3. **The port is discarded.** The service component is the bare host.
4. **A trailing `.git` is stripped** (only at the very end of the repo name), and
   a trailing slash is tolerated.
5. **All three components — host, owner and repo — are lowercased**
   (`derive_repo_id`, src/repo_identity.rs), so `GitHub.com/Owner/Repo` and
   `github.com/owner/repo` derive the same identity.
6. The result is formatted `repo+owner@host`, e.g.
   `git@github.com:example/demo.git` → `demo+example@github.com`.

The owner and repo components must not contain `@` or `:`, and the SCP user
must not contain `@` — credential-shaped material is *rejected*, not laundered
into the identity (regex character classes, src/repo_identity.rs). An
unsupported shape fails with a fixed message —
`invalid git remote URL format; expected a supported GitHub/GitLab/Codeberg shape — see git-veil help trust`
— that deliberately does not echo the failing URL, because echoing it could
surface embedded credentials (`parse_git_remote_url`, src/repo_identity.rs).

`show-repo-id` prints the derived id. `trust` re-derives it from the live
remote and refuses a provided `repo_id` that does not match the computed one
(`cmd_trust`, src/commands/trust.rs), so a typo cannot pin a key under the
wrong identity.

## The trust record (`trust.json`) and the per-machine pin

`trust.json` lives at `.git-veil/trust.json` and holds one JSON object:
`{"trusted_keys": { "<repo_id>": "<fingerprint>" }}` — a map of repository id
to the fingerprint of the key the owner pinned for it
(`TrustStore`, src/trust_store.rs). It is written pretty-printed and atomically
(`TrustStore::save_to_file`); a missing file reads as an empty store
(`TrustStore::load_from_file`).

Its role is **team visibility, not trust**. It is committed so every
collaborator can see which key the repository claims as its owner, and so a
changed claim is visible in git history. Because it is committed, it is
attacker-writable by anyone with write access to the repository — the docs are
explicit that it is never the anchor.

The actual anchor is the **per-machine pin**: a file at
`<key store>/trust-pins/<sanitized repo_id>` holding the fingerprint the user
chose on *this machine* (`TrustPinStore`, src/trust_store.rs). Pin filenames are
derived deterministically: bytes outside `[A-Za-z0-9._-]` are percent-encoded,
so the name can never escape the pin directory (`TrustPinStore::sanitize_repo_id`).
The pin is written only by `git-veil trust` (`TrustPinStore::write_pin`); a
fresh clone has no pin, which is why trust must be re-established per machine.

Every gated command verifies the keyring signature through
`verify_keyring_against_trust` (src/commands/verify_keyring.rs), which:

1. reads the fingerprint `trust.json` claims for the repo id;
2. reads the local pin and **fails closed** on any disagreement:
   - committed record missing → `no trust established for <repo_id> … run git-veil trust <repo_id> <keyfile>`
     (exit code 10),
   - pin missing → `no local pin for <repo_id> …` (exit code 11),
   - pin present but different (case-insensitively) from the committed
     fingerprint → `trust for <repo_id> … changed on this machine's record (<pinned> → <committed>); …`
     (exit code 12);
3. loads the pinned key from the key store (`load_verifying_key_by_fingerprint`,
   src/commands/verify_keyring.rs) and verifies the keyring signature against
   it (`verify_keyring_signature`, src/signing.rs); a keyring with entries but
   no signature is refused (exit code 63).

So an attacker who rewrites `trust.json` achieves nothing on a machine that has
a pin: the committed fingerprint no longer matches the pin and every gated
command refuses until the user explicitly re-pins. Writing trust.json *before*
the pin in `cmd_trust` (src/commands/trust.rs) keeps the crash direction
fail-closed: a death between the two writes leaves a mismatch, never a silently
accepted changed anchor. Re-pinning over a different existing fingerprint prints
a loud `replacing the previously pinned fingerprint …` notice.

## Key discovery and selection

git-veil **never generates key material**. A key the tool created is a key the
user never backed up; the tool's job on a missing key is to say so, teach the
creation recipe, and exit with a documented code — not to silently manufacture
credentials (`src/key_discovery.rs`).

**Signing keys** (`discover_signing_key`): the owner's Ed25519 signing keys are
read from `<key store>/signing-keys.txt`, one 64-hex-character seed per line
(`#` comments and blank lines skipped). `tell` and `removeperson` — the two
keyring-curating commands — select a key as follows:

1. An explicit `--signing-key <index-or-seed>` wins: a 1-based index into the
   file, or a full seed matched hex-insensitively.
2. Otherwise the TRUSTED key is used — the one whose verifying-key
   fingerprint equals the fingerprint pinned for this repository. The keyring
   must be signed with exactly the key the pin names (that is what
   verify_keyring checks against), so the pin, not list order, selects the
   key. Selection is therefore deterministic — no interactive menu is
   needed. (Where no pin applies, the fallback is the first key in the file.)
3. No usable key → the command exits with code 20 after printing, to stderr,
   the `openssl` recipe that creates the key (the last 32 bytes of the Ed25519
   DER encoding are the seed) and the instruction to **back it up**. A
   present-but-garbage line in signing-keys.txt is a parse error, never
   silently treated as "no keys".

**Age identities** (`discover_identity`): decrypting commands resolve their
keyring entry by email, then look up the matching age identity in
`<key store>/identities.txt`. No matching identity → exit code 21 after
printing the `age-keygen`/`rage-keygen` recipe, the `git-veil import` step,
and the backup instruction. A user whose email is not in the signed keyring at
all fails earlier, with exit code 22.

## Key store permissions

The key store is checked at load time the way gpg checks `~/.gnupg`
(`src/permissions.rs`, Unix only):

- the key store directory itself (`$GIT_VEIL_HOME`, `$HOME/.git-veil`, or
  `--key-store`) must carry no group or world permission bits;
- the private key files `identities.txt` and `signing-keys.txt` must carry no
  group or world permission bits.

git-veil **never chmods a file it did not create**. On a violation the command
exits with code 30, listing each offending path with its observed mode, the
`chmod` remedy, and the acknowledgment alternative. The check runs once, in
`main`, for every command that resolves a key store — before any key material
is read.

**Acknowledgment model** (git's dubious-ownership pattern): `git-veil
trust-permissions` records the current findings as exact `(path, mode)` pairs
in `<key store>/permissions-ack.json` (created mode 0600 via
`write_atomic_mode`). A later check passes only if every finding matches an
acknowledged pair exactly — permissions that later change to anything else fail
again. The check is bypassed entirely by the global
`--dangerously-skip-permissions-check` flag or a truthy `GIT_VEIL_SKIP_PERMISSIONS`
environment variable.

Files git-veil itself creates that hold private key material —
`identities.txt` (via `import` and `import_identity_to_store`) and the
acknowledgment file — are created mode 0600 at write time
(`write_atomic_mode`, src/fs_atomic.rs), independent of the process umask.
Repo working-tree files (revealed plaintext, `.secret` ciphertext) are
deliberately not permission-policed: they are ordinary repository content.

## Crash safety and durability

**Atomic writes.** Every durable state file goes through `write_atomic`
(src/fs_atomic.rs): write to a temp file `<name>.tmp-<pid>` in the same
directory (same volume, so the rename can never degrade into a copy), fsync the
file, rename it over the target, then best-effort fsync the parent directory
(directory-fsync errors are ignored — not portable). On any failure the temp
file is removed and the target is untouched. The target is therefore always
either the old content or the new content, never a mix. `write_atomic_mode` is
the same sequence with an explicit creation mode for private key material.
Covered writes: the keyring (`cmd_init`, `cmd_tell`, `cmd_removeperson`),
tracked.json (`TrackedFiles::save`), trust.json and pins (`TrustStore`,
`TrustPinStore`), the identity/recipient/verifying-key stores
(`cmd_import`, `import_identity_to_store`, `import_recipient_to_store`,
`cmd_trust`), ciphertext (`cmd_hide`), restored plaintext (`cmd_reveal`,
`cmd_unhide`), export output (`cmd_export`), the removekey rewrite
(`cmd_removekey`), and the permissions acknowledgment
(`cmd_trust_permissions`). Key-store appends are implemented as read-existing
plus `write_atomic` of the whole accumulated content — an accepted O(n) trade
so a torn private-key store (which would brick all decryption) is impossible.

**Two-phase hide/reveal.** `hide` is compute-then-commit: phase 1 reads and
validates every tracked plaintext and encrypts all of them to the full
recipient set in memory; any failure aborts with nothing changed on disk
(`cmd_hide`, src/commands/hide.rs). Phase 2 writes each `.secret` atomically;
a part-way write failure is reported with written/total counts and exits
non-zero. The plaintext is **kept** by default; with
`--dangerously-delete-plaintext` each plaintext is deleted only after its own
ciphertext is durably on disk. `reveal` mirrors this exactly: decrypt all into
memory, then write each plaintext atomically; the `.secret` ciphertext files
are left in place. `unhide` applies the same ordering to a single file. The
invariant in all three: **at worst both copies exist, never neither.**

**Crash windows that remain.** Death between a phase-2 write and its paired
delete (only in the `--dangerously-delete-plaintext` case) leaves both copies
on disk. This is stated honestly: it is a redundancy window, not a data-loss
window, and the plaintext is gitignored. The next command resolves it:
re-running `hide` re-encrypts the still-present plaintexts to the current
keyring and atomically overwrites the ciphertexts. Death during `trust` between
the trust.json write and the pin write fails closed on the next gated command
(see the ordering invariant above).

## Ignore safety

Ciphertext lives beside its plaintext as `<name>.secret` and is meant to be
committed; plaintext is meant to be gitignored. Two gates keep those
invariants true (`src/commands/add.rs`, `src/commands/hide.rs`):

1. **Add-time gitignore gate** (`ensure_gitignored`): like git-secret, `add`
   runs `git check-ignore` on the plaintext path and appends it to
   `.gitignore` when not already ignored.
2. **Ciphertext-ignored refusal**: a `.secret` path can be silently swallowed
   by an unrelated broad rule (e.g. a parent directory like `.tmp/` in
   `.gitignore`) — `add` would succeed and the ciphertext would never reach
   the repository. `add` therefore warns (exit stays 0) when the future
   `.secret` path is git-ignored, and `hide` **refuses outright** with exit
   code 40 before encrypting anything, listing every offending path.
3. **Plaintext-leak warning**: if a tracked plaintext exists on disk but is
   not gitignored (typically after a rename or a `.gitignore` edit), `hide`
   prints a warning citing exit code 41 and proceeds — the condition is a
   risk, not a tool failure. The tutorials show an optional pre-commit hook
   that turns it into a hard stop.

## Path safety

Tracked paths are repo-relative strings in `.git-veil/tracked.json`. Four
layers guard them:

1. **Tracked-path validation** — `validate_tracked_path`
   (src/tracked_files.rs) requires the path to be non-empty and relative,
   rejects every non-`Normal` path component (so `..`, `.`, absolute prefixes
   are out), and — defence in depth — requires lexical containment under the
   repository root (`ensure_within_repo_root`, src/tracked_files.rs), so if the
   component rule were ever relaxed the containment check still holds.
   Enforced when tracked.json loads (`TrackedFiles::load`) and again before
   each use in hide, reveal, unhide, cat and changes. *Threat countered:* a
   malicious committed tracked.json making git-veil read or write outside the
   repository. Exit code 71.
2. **Add-time canonicalise-and-reject** — `git-veil add` canonicalises each
   input against the canonical repository root (symlinks resolved, `..`
   collapsed) before stripping the prefix (`resolve_repo_relative_input` with
   `PathResolveMode::CanonicaliseRequireExists`, src/tracked_files.rs); a
   symlink whose target resolves outside the repo therefore fails with
   `File is outside the repository`. *Threat countered:* tracking a link to
   e.g. `/home/victim/.ssh/id_rsa`, which hide would otherwise read and
   (with `--dangerously-delete-plaintext`) delete. Exit code 71.
3. **Read-time regular-file gate** — `ensure_regular_file`
   (src/tracked_files.rs) uses `symlink_metadata` (lstat; does not follow
   links): a symlink is refused, a non-regular file is refused, and a
   *missing* path is accepted (the plaintext is normally absent while hidden).
   It fires on every use of a tracked path in hide, reveal, unhide, cat and
   changes. *Threat countered:* a tracked.json committed by one writer naming
   a path another writer committed as a symlink out of the repo — reading
   through it would exfiltrate the link target into committed ciphertext
   (hide) or print it (cat/changes), and writing through it would corrupt the
   link target or replace the link (reveal/unhide). Exit code 71.
4. **Ciphertext-beside-plaintext** — `ensure_ciphertext_beside_plaintext`
   (src/commands/hide.rs) requires the ciphertext path to be exactly
   `<plaintext>.secret` and inside the repository root; it is checked at hide,
   reveal, unhide, cat and changes. *Threat countered:* any future drift in
   the ciphertext-path math reintroducing an escape.

Which path-resolution contract each command uses (existence requirements and
which form gets validated) is pinned down per caller in `PathResolveMode`
(src/tracked_files.rs).

## Exit codes

Every deliberate failure exits with a documented code (`ExitCode`,
src/exit_codes.rs); errors without a specific code exit 1, and clap usage
errors exit 2. `git-veil error-codes` prints this table; it is public API —
codes are never renumbered, only appended.

| Code | Name                        | Meaning |
|-----:|------------------------------|---------|
| 1    | GeneralError                 | Failure without a more specific code |
| 2    | Usage                        | Command-line usage error |
| 10   | NoTrustRecord                | Committed trust.json has no entry for this repository; run `git-veil trust` |
| 11   | NoTrustPin                   | No local trust pin on this machine; run `git-veil trust` |
| 12   | TrustMismatch                | Committed trust.json disagrees with this machine's pin; re-pin if intended |
| 13   | TrustRepoIdMismatch          | repo_id argument does not match the one derived from the remote |
| 20   | NoSigningKey                 | No Ed25519 signing key in the key store; create one and back it up |
| 21   | NoAgeIdentity                | No age identity in the key store matching your keyring entry; create and import one |
| 22   | IdentityNotInKeyring         | Your email is not in the signed keyring; ask the owner to `tell` you |
| 30   | UnsafeKeyStorePermissions    | Key store directory or private key file is group/world accessible |
| 40   | CiphertextIgnored            | A `.secret` ciphertext path is git-ignored (fatal in `hide`; warning in `add`) |
| 41   | PlaintextNotIgnored          | Tracked plaintext on disk is not git-ignored (warning; exit stays 0) |
| 60   | DecryptionFailed             | Ciphertext could not be decrypted with the local identity |
| 61   | EncryptionFailed             | Encryption failed |
| 62   | KeyParseFailure              | A key, keyring or signature could not be parsed |
| 63   | SignatureVerificationFailed  | Keyring signature missing or invalid |
| 70   | Refused                      | Policy refusal (e.g. `init` over established trust, `clean` without `--yes`) |
| 71   | UnsafePath                   | Path-safety refusal (symlink, outside repository, unsafe tracked path) |
