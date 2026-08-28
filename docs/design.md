# git-veil design specification

This document is the specification of git-veil's mechanisms: what the code
actually enforces, stated precisely enough to be re-verified. It is distinct
from the README (an overview) and the tutorials under `docs/` (how-to journeys);
when prose elsewhere disagrees with this document or with the code, this
document should be corrected first, then the prose. Each claim carries a
`file:line` citation to the enforcing code, so a future change that invalidates
a claim must update both the code and its citation here. Line numbers refer to
the tree at the time of writing; the named function, not the number, is the
contract.

## Repository identity

Every repository is identified by a `repo_id` derived from its git remote push
URL. The algorithm lives in `parse_git_remote_url` and `derive_repo_id`
(src/repo_identity.rs:61-82, 110-113) and is exactly:

1. Two URL shapes are accepted.
   - **SCP-style SSH**: `user@host:owner/repo` (regex at
     src/repo_identity.rs:13-16). The user part must be non-empty and must not
     contain `/` or `@`; any SSH user is accepted, not just `git`.
   - **Scheme URLs**: `ssh://`, `git://` or `https://`, with optional userinfo
     `user[:pass]@`, a host, an optional `:port`, then `/owner/repo` (regex at
     src/repo_identity.rs:23-26). No other scheme — in particular `http://` —
     is accepted. IPv6 literal hosts and paths with extra segments are also
     rejected.
2. **Userinfo is stripped.** Embedded credentials never become part of the
   identity and are never echoed in errors (src/repo_identity.rs:18-22, 76-81).
3. **The port is discarded.** The service component is the bare host.
4. **A trailing `.git` is stripped** (only at the very end of the repo name), and
   a trailing slash is tolerated.
5. **All three components — host, owner and repo — are lowercased**
   (src/repo_identity.rs:28-36), so `GitHub.com/Owner/Repo` and
   `github.com/owner/repo` derive the same identity.
6. The result is formatted `repo+owner@host`, e.g.
   `git@github.com:example/demo.git` → `demo+example@github.com`.

The owner and repo components must not contain `@` or `:`, and the SCP user
must not contain `@` — credential-shaped material is *rejected*, not laundered
into the identity (regex character classes at src/repo_identity.rs:14, 24). An
unsupported shape fails with a fixed message —
`invalid git remote URL format; expected a supported GitHub/GitLab/Codeberg shape — see git-veil help trust`
— that deliberately does not echo the failing URL, because echoing it could
surface embedded credentials (src/repo_identity.rs:76-81).

`show-repo-id` prints the derived id. `trust` re-derives it from the live
remote and refuses a provided `repo_id` that does not match the computed one
(src/commands/trust.rs:10-20), so a typo cannot pin a key under the wrong
identity.

## The trust record (`trust.json`) and the per-machine pin

`trust.json` lives at `.git-veil/trust.json` and holds one JSON object:
`{"trusted_keys": { "<repo_id>": "<fingerprint>" }}` — a map of repository id
to the fingerprint of the key the owner pinned for it
(src/trust_store.rs:9-13). It is written pretty-printed and atomically
(src/trust_store.rs:30-43); a missing file reads as an empty store
(src/trust_store.rs:45-48).

Its role is **team visibility, not trust**. It is committed so every
collaborator can see which key the repository claims as its owner, and so a
changed claim is visible in git history. Because it is committed, it is
attacker-writable by anyone with write access to the repository — the docs are
explicit that it is never the anchor.

The actual anchor is the **per-machine pin**: a file at
`<key store>/trust-pins/<sanitized repo_id>` holding the fingerprint the user
chose on *this machine* (src/trust_store.rs:54-67). Pin filenames are derived
deterministically: bytes outside `[A-Za-z0-9._-]` are percent-encoded, so the
name can never escape the pin directory (src/trust_store.rs:73-89). The pin is
written only by `git-veil trust` (src/trust_store.rs:100-105); a fresh clone
has no pin, which is why trust must be re-established per machine.

Every gated command verifies the keyring signature through
`verify_keyring_against_trust` (src/commands/verify_keyring.rs:39-104), which:

1. reads the fingerprint `trust.json` claims for the repo id (lines 49-57);
2. reads the local pin and **fails closed** on any disagreement (lines 62-78):
   - pin missing → `no local pin for <repo_id> … run git-veil trust <repo_id> <keyfile>`,
   - pin present but different (case-insensitively) from the committed
     fingerprint → `trust for <repo_id> (from remote '<remote>') changed on this machine's record (<pinned> → <committed>); if you intended this, re-run git-veil trust <repo_id> <keyfile>`.
3. loads the pinned key from the key store and verifies the keyring signature
   against it (lines 81-101); a keyring with entries but no signature is
   refused (lines 96-101).

So an attacker who rewrites `trust.json` achieves nothing on a machine that has
a pin: the committed fingerprint no longer matches the pin and every gated
command refuses until the user explicitly re-pins. Writing trust.json *before*
the pin in `trust` (src/commands/trust.rs:63-78) keeps the crash direction
fail-closed: a death between the two writes leaves a mismatch, never a silently
accepted changed anchor. Re-pinning over a different existing fingerprint prints
a loud `⚠ replacing the previously pinned fingerprint …` notice
(src/commands/trust.rs:54-61).

## Key-validity acceptance criteria

`validate_public_key_for_use` (src/pubkey.rs:219-317) is the fail-closed
validity gate; `KeyUse` splits it into two modes (src/pubkey.rs:84-90):
`Certify` (a trust anchor) and `Encrypt` (a recipient). All rejections are
hard errors — never warn-and-proceed.

Gates common to both uses:

1. **Self-signature present** (src/pubkey.rs:224-235): at least one direct
   self-signature or User-ID self-certification must exist. Unsigned key
   material is rejected.
2. **Expiry** (src/pubkey.rs:240-257): the *newest* self-signature (by creation
   time) decides. Both the signature's own expiration and the key expiration it
   declares must lie in the future; legacy v3 `expiration days` on the key
   packet is honoured too. Renewing a key produces a newer self-signature,
   which may drop or extend the expiry.
3. **Revocation — hard only** (src/pubkey.rs:136-141, 260-264): a revocation
   with reason `KeySuperseded` or `KeyRetired` is *soft* and is ignored (the
   key is deprecated, not invalid). Every other revocation — no reason code,
   `NoReason`, `KeyCompromised`, or any unknown/private code — is *hard* and
   rejects. Documented limitation: the pgp crate exposes no "revocation
   effective at future date T" mechanism, so a soft revocation can never become
   a hard rejection through time alone (src/pubkey.rs:127-135).

Encrypt-only gate:

4. **Encryption capability** (src/pubkey.rs:266-313): the key must have an
   encryption-capable subkey whose newest binding signature grants the encrypt
   flag, or an encryption-capable primary (e.g. RSA used directly). The
   selected subkey's hard revocation and expiry are checked with the same
   policy.

Note explicitly: cryptographic verification of self-signatures is *not*
performed here — this is a validity-policy gate, not a full certificate
verifier (src/pubkey.rs:216-218).

Where the gates fire:

- `trust` — `Certify` gate before the key is imported or pinned
  (src/commands/trust.rs:42-44).
- `tell` — `Encrypt` gate before any keyring mutation (src/commands/tell.rs:62-64),
  plus an in-memory canary test-encrypted to the key to prove it can actually
  encrypt (src/commands/tell.rs:54-57).
- `hide` — `Encrypt` gate on **every** keyring entry before any file is touched
  (src/commands/hide.rs:72-86); the recipient set is never silently narrowed by
  skipping an invalid key.

## Crash safety and durability

**Atomic writes.** Every durable state file goes through `write_atomic`
(src/fs_atomic.rs:37-71): write to a temp file `<name>.tmp-<pid>` in the same
directory (same volume, so the rename can never degrade into a copy), fsync
the file, rename it over the target, then best-effort fsync the parent
directory (directory-fsync errors are ignored — not portable). On any failure
the temp file is removed and the target is untouched. The target is therefore
always either the old content or the new content, never a mix. Covered writes:
the keyring (src/commands/init.rs:41, src/commands/tell.rs:96,
src/commands/removeperson.rs:67), tracked.json (src/tracked_files.rs:265),
trust.json and pins (src/trust_store.rs:41, 103), the secret- and public-key
stores (src/commands/import.rs:106, src/gpg_integration.rs:44), ciphertext
(src/commands/hide.rs:147), restored plaintext (src/commands/reveal.rs:97,
src/commands/unhide.rs:96), export output (src/commands/export.rs:78), and the
removekey rewrite (src/commands/removekey.rs:234). Key-store appends are
implemented as read-existing plus `write_atomic` of the whole accumulated
content — an accepted O(n) trade so a torn private-key store (which would
brick all decryption) is impossible (src/fs_atomic.rs:14-19).

**Two-phase hide/reveal.** `hide` is compute-then-commit: phase 1 reads and
validates every tracked plaintext and encrypts all of them to the full
recipient set in memory; any failure aborts with nothing changed on disk
(src/commands/hide.rs:97-131). Phase 2 writes each `.secret` atomically and
deletes each plaintext only after *its own* ciphertext is durably on disk
(src/commands/hide.rs:133-175). A part-way failure is reported with counts and
the list of plaintexts left as-is, and exits non-zero
(src/commands/hide.rs:177-192). `reveal` mirrors this exactly: decrypt all
into memory, then write each plaintext atomically and delete each ciphertext
only after its plaintext is durable (src/commands/reveal.rs:42-142). `unhide`
applies the same ordering to a single file (src/commands/unhide.rs:93-101).
The invariant in all three: **at worst both copies exist, never neither.**

**Crash windows that remain.** Death between a phase-2 write and its paired
delete leaves both copies on disk (plaintext + `.secret` after `hide`; the
reverse after `reveal`). This is stated honestly: it is a redundancy window,
not a data-loss window, and the plaintext is gitignored in the hide case. The
next command resolves it: re-running `hide` re-encrypts the still-present
plaintexts to the current keyring, atomically overwrites the ciphertexts, and
deletes the plaintexts (the error message says exactly this,
src/commands/hide.rs:186); re-running `reveal` re-decrypts, overwrites the
plaintexts, and deletes the leftover ciphertexts. Death during `trust`
between the trust.json write and the pin write fails closed on the next gated
command (see the ordering invariant above).

## Path safety

Tracked paths are repo-relative strings in `.git-veil/tracked.json`. Four
layers guard them:

1. **Tracked-path validation** — `validate_tracked_path`
   (src/tracked_files.rs:24-51) requires the path to be non-empty and
   relative, rejects every non-`Normal` path component (so `..`, `.`, absolute
   prefixes are out), and — defence in depth — requires lexical containment
   under the repository root (src/tracked_files.rs:96-115), so if the
   component rule were ever relaxed the containment check still holds.
   Enforced when tracked.json loads (src/tracked_files.rs:255-258) and again
   before each use in hide (src/commands/hide.rs:106-107) and reveal
   (src/commands/reveal.rs:51-52). *Threat countered:* a malicious committed
   tracked.json making git-veil read or write outside the repository.
2. **Add-time canonicalise-and-reject** — `git-veil add` canonicalises each
   input against the canonical repository root (symlinks resolved, `..`
   collapsed) before stripping the prefix (src/commands/add.rs:18-23 via
   `PathResolveMode::CanonicaliseRequireExists`, src/tracked_files.rs:134-141,
   172-190); a symlink whose target resolves outside the repo therefore fails
   with `File is outside the repository`. *Threat countered:* tracking a link
   to e.g. `/home/victim/.ssh/id_rsa`, which hide would otherwise read and
   delete.
3. **Read-time regular-file gate** — `ensure_regular_file`
   (src/tracked_files.rs:62-89) uses `symlink_metadata` (lstat; does not
   follow links): a symlink is refused
   (`tracked path is a symlink; refusing to read — remove the link and re-add the real file`),
   a non-regular file is refused, and a *missing* path is accepted (the
   plaintext is normally absent while hidden). It fires on every use of a
   tracked path: hide (src/commands/hide.rs:112), reveal (src/commands/reveal.rs:57),
   unhide (src/commands/unhide.rs:66), cat (src/commands/cat.rs:46) and
   changes (src/commands/changes.rs:76). *Threat countered:* a tracked.json
   committed by one writer naming a path another writer committed as a
   symlink out of the repo — reading through it would exfiltrate the link
   target into committed ciphertext (hide) or print it (cat/changes), and
   writing through it would corrupt the link target or replace the link
   (reveal/unhide).
4. **Ciphertext-beside-plaintext** — `ensure_ciphertext_beside_plaintext`
   (src/commands/hide.rs:29-46) requires the ciphertext path to be exactly
   `<plaintext>.secret` and inside the repository root; it is checked at hide
   (src/commands/hide.rs:128), reveal (src/commands/reveal.rs:64), unhide
   (src/commands/unhide.rs:73), cat (src/commands/cat.rs:53) and changes
   (src/commands/changes.rs:83). *Threat countered:* any future drift in the
   ciphertext-path math reintroducing an escape.

Which path-resolution contract each command uses (existence requirements and
which form gets validated) is pinned down per caller in `PathResolveMode`
(src/tracked_files.rs:134-244).
