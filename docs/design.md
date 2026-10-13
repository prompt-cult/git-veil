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

`trust.json` lives at `.git-veil/trust.json` and holds one JSON object with
two maps (`TrustStore`, src/trust_store.rs):

- `trusted_keys`: `{ "<repo_id>": "<fingerprint>" }` — the fingerprint of
  the owner key pinned for the repository under the single derivation (see
  "Fingerprints": the repository id is the label), compared against the
  local pin by every gated command;
- `owner_fingerprints`: `{ "<repo_id>": "<owner fingerprint>" }` — the same
  value: the fingerprint of the repository's committed owner verifying key
  (`owner.verifying`) under the single derivation, used by pin-file import
  and by humans verifying out of band.

Both fields default to absent when missing (pre-0.6 files parse cleanly);
the file is written pretty-printed and atomically
(`TrustStore::save_to_file`); a missing file reads as an empty store
(`TrustStore::load_from_file`).

Its role is **team visibility, not trust**. It is committed so every
collaborator can see which key the repository claims as its owner, and so a
changed claim is visible in git history. Because it is committed, it is
attacker-writable by anyone with write access to the repository — the docs
are explicit that it is never the anchor.

The actual anchor is the **per-machine pin**: a file at
`<key store>/trust-pins/<sanitized repo_id>` holding the fingerprint the user
chose on *this machine* (`TrustPinStore`, src/trust_store.rs). Pin filenames are
derived deterministically: bytes outside `[A-Za-z0-9._-]` are percent-encoded,
so the name can never escape the pin directory (`TrustPinStore::sanitize_repo_id`).
The pin is written only by the two pin-creation paths below; a
fresh clone has no pin, which is why trust must be re-established per machine.

### Pin creation (possession proof only)

A repository can never supply its own trust anchor: there is no keyfile
argument, no compatibility mode, no feature flag. Exactly two paths create a
pin:

1. **Possession proof** — `git-veil trust <repo_id>`
   (`cmd_trust`, src/commands/trust.rs). The candidate is the repository's
   committed `owner.verifying` (64-hex Ed25519 verifying key on line 1; the
   owner's age recipient may follow on line 2). The proof is an exact match
   between that candidate and the verifying key derived from a seed in
   `<key store>/signing-keys.txt` (`prove_possession`): every seed is
   iterated, a unique match pins, zero matches refuse with
   `no local signing key matches this repository's owner key` (exit code 20),
   and more than one (a degenerate duplicated store) refuses on ambiguity
   (exit code 70). On success the verifying key is appended to
   `verifying-keys.txt`, the pin and the committed record are written, and
   the owner fingerprint is recorded in `owner_fingerprints` (the owner
   commits the updated `trust.json` alongside `owner.verifying`).

2. **Pin-file import** — `git-veil trust --import <pin-file>`
   (`cmd_trust_import`, src/commands/trust.rs). The pin-file is produced by
   `git-veil export-pin <repo_id> --output <pin-file>`
   (`cmd_export_pin`, src/commands/export_pin.rs) on a machine that passed
   the SAME possession proof — a machine without the matching seed cannot
   export at all (exit code 20), so pins originate only from machines
   holding the signing key; store-less machines are consumers, never
   producers. The pin-file format is exactly two lines
   (`PinFile`, src/pin_file.rs):

   ```
   repo-id: <repo_id>
   verifying-key: <64-hex Ed25519 verifying key>
   ```

   Import runs three mandatory consistency checks, all of which must pass:
   (a) the pin-file's repo-id matches the repository being pinned (derived
   from the live remote); (b) the pin-file's verifying key exactly matches
   the repository's committed `owner.verifying`; (c) the pin-file's
   owner key fingerprint exactly matches the owner fingerprint recorded
   in `trust.json`'s `owner_fingerprints` — an absent field is a refusal
   (the owner must re-run `trust` on a seed-holding machine and commit the
   updated metadata). Any mismatch refuses with
   `pin-file does not match this repository's committed owner key; one of
   the two channels is compromised` (exit code 70). The pin-file is the
   anchor; the repository's committed key and fingerprint are the witnesses.

**The owner fingerprint derivation is fixed and documented** so any
implementation can compute it (`owner_key_fingerprint`,
src/fingerprint.rs): the single derivation with the repository id as the
label and the canonical lowercase hex of the 32 verifying-key bytes as the
public key encoding. It is never computed over the seed, only the public
half. See "Fingerprints" for the exact construction, the stock-tool
one-liners and the golden vectors.

**Pin-files travel out of band, never through the repository.** Both
`export-pin --output` and `trust --import <pin-file>` refuse any path that
resolves inside the repository worktree (`ensure_path_outside_repo`, exit
code 71): an attacker with repo write access could otherwise commit a bogus
pin-file and have the victim import it, and since without a pin the tool
refuses all other operations, the pin cannot travel through git-veil's own
tracked-file mechanism either. Pin-file integrity rides the transport —
the same model as `known_hosts` provisioning — and the printed owner
fingerprint is the token for human out-of-band verification (read it over
the phone and compare with the committed `owner_fingerprints` value).

**Repo renames** change the repo_id (it is derived from the remote push
URL), so a new pin is required. When the committed `trust.json` records
trust for a repo_id that differs from the one the current remote derives,
the gated commands refuse with a stated suspicion — `this looks like a
rename or a remote change based on the existing trust record` (exit
code 10 on the verify path, 70 on the import path) — naming the recorded
and derived repo-ids as the clue and **nothing else**. Error text is
plain ASCII: no quoting marks, no parentheses, no path echoes, nothing
that trips a log parser or a terminal. No remedy is printed: handing an
operator a one-line fix for a trust-anchor change is exactly what an
attacker staging a repo move wants them to run without thinking. The
operator reads the docs, satisfies themselves the rename is theirs, and
fixes it with the possession proof (or a fresh pin-file export) on a
machine holding the signing key.

Every gated command verifies the keyring signature through
`verify_keyring_against_trust` (src/commands/verify_keyring.rs), which:

1. reads the fingerprint `trust.json` claims for the repo id;
2. reads the local pin and **fails closed** on any disagreement. Every
   refusal below is a plain ASCII statement that names no repository
   identity, no fingerprint, no path and no command line; the remedy is
   this document, which the operator reads deliberately:
   - committed record missing → `no trust record for this repository. See
     the trust documentation.` (exit code 10);
   - committed record present but naming a different repository identity →
     `the committed trust record names a different repository identity
     than this repository derives. This looks like a rename or a remote
     change based on the existing trust record.` (exit code 10);
   - pin missing → `no trust pin exists on this machine. See the trust
     documentation.` (exit code 11);
   - pin or committed record in the retired 16 hex character fingerprint
     format → `a trust pin or record in the retired 16 hex character
     fingerprint format was found. The fingerprint derivation changed to
     SHA-256 over the label, a colon, and the public key encoding, printed
     as 64 lowercase hex characters. Re-establish the pin as described in
     the trust documentation.` (exit code 70). Nothing is rewritten; the
     recovery is re-establishing the pin (see "Fingerprints");
   - pin present but different (case-insensitively) from the committed
     fingerprint → `the pinned repository identity changed on this
     machine. The committed trust record and this machine pin disagree. See
     the trust documentation.` (exit code 12);
3. loads the pinned key from the key store (`load_verifying_key_by_fingerprint`,
   src/commands/verify_keyring.rs) and verifies the keyring signature against
   it (`verify_keyring_signature`, src/signing.rs); a keyring with entries but
   no signature is refused (exit code 63).

So an attacker who rewrites `trust.json` — or commits a self-consistent
`owner.verifying`, signed keyring, metadata fingerprint and bogus pin-file —
achieves nothing on a machine that holds the real seed: the proof fails, and
an in-repo pin-file is refused by the path gate. Writing trust.json *before*
the pin in the pin-creation paths (src/commands/trust.rs) keeps the crash
direction fail-closed: a death between the two writes leaves a mismatch,
never a silently accepted changed anchor. Re-pinning over a different
existing fingerprint prints a loud `replacing the previously pinned
fingerprint …` notice.

## Fingerprints

Every fingerprint in git-veil is ONE derivation (`fingerprint_for_public_key`,
src/fingerprint.rs), stated exactly:

```
FP = SHA-256( UTF8(label) + ":" + UTF8(public-key-encoding) )
```

printed as 64 lowercase hex characters. The label is the principal label
for a keyring principal, or the repository id for the owner key. The
public key encoding is the bech32 X25519 public key (`age1...`) or the 64
hex character Ed25519 verifying key. Both inputs are used verbatim — no
trimming, no case folding — so the construction is reproducible outside
the tool.

The derivation is a pure function over public values: no repository, no
key store, no pin, no network. A user on a clean host reproduces the exact
value with stock OS tools:

```sh
printf '%s:%s' 'alice@example.com' "$(age-keygen -y identity.txt)" | sha256sum
printf '%s:%s' 'demo+example@github.com' "$(head -n 1 owner.verifying)" | sha256sum
```

Use `printf`, never `echo` (echo appends a newline and hashes different
bytes). Exactly one colon separates label and key. The digest is lowercase
hex. `owner.verifying` line 1 is the verifying key; `head -n 1` selects it
because the file may carry the owner's age recipient on line 2.

**Golden vectors.** These (label, public key encoding, fingerprint)
triples are produced by the one-liners above and asserted against the Rust
implementation (tests/fingerprint.rs) — code equals coreutils for every
key type. The first public key is a real age-keygen X25519 public key; the
second is a real openssl-generated Ed25519 verifying key:

| label | public key encoding | fingerprint |
|-------|---------------------|-------------|
| `alice@example.com` | `age1ga9us2r837a445htpvmuvxnygc8mrxglvtzrfwk0kyy7q55r3ypqlt28nk` | `263e683748d60e61ea89a6470e209f697c5ec23452e8bc8f222e2aff48e0d36b` |
| `demo+example@github.com` | `92cf641b35021f2c38fa5016fe9c413d4a399bfdc67c6832b4f9fdd019ccebdb` | `b7480ed036c6ab15e0446b8caa694faeb2983959bb49e7920a94d14b6bb773d1` |

`git-veil fingerprint <LABEL> <PUBLIC_KEY>` prints the value and nothing
else.

Where fingerprints are used:

- the per-machine pin and the committed `trusted_keys` record carry the
  owner key fingerprint — the derivation with the repository id as the
  label (`owner_key_fingerprint`);
- `owner_fingerprints` carries the same value: the human out-of-band token
  (`export-pin` prints it) and the pin-file import witness;
- `list-keys` prints the binding fingerprint of each keyring principal —
  the derivation with the principal label — computed at print time; the
  keyring stores only the principal and the public key (format v2), never
  a fingerprint;
- key selection in `export`, `import`, `removekey` and `--signing-key` is
  by public key string only; no fingerprint-as-identifier mode remains.

**Legacy 16 hex character values are hostile.** The retired derivations
produced 16 hex character fingerprints. A pin or committed trust record in
that format is refused by every gated command with exit code 70, in a
message naming the derivation change; nothing is rewritten silently. The
recovery is re-establishing the pin as described in "Pin creation".

## Keyring format and freshness (rollback refusal)

The keyring file is an armored block:

```
-----BEGIN GIT-VEIL KEYRING-----
version:<n>
<email>:<age-recipient>
...
-----END GIT-VEIL KEYRING-----
-----BEGIN GIT-VEIL SIGNATURE-----
<base64 Ed25519 signature over everything above, markers included>
-----END GIT-VEIL SIGNATURE-----
```

Keyring format v2 (issue #41): exactly two fields per entry — the
principal and the public key — with the signature over the pair.
Fingerprints are computed on demand (see "Fingerprints") and NEVER stored;
a legacy three-field entry carrying a stored fingerprint is a parse
refusal (exit code 62), never a silent migration.

The `version:` line (Keyring, src/keyring.rs) is a **monotonic counter
carried inside the signed payload**: the signature covers it, so a version
number cannot be forged without the owner key. `tell` and `removeperson`
write `current + 1` (current = the keyring's own version, 0 when absent) —
the counter needs no state outside the keyring it is serialised into, and no
clock, so there is no drift to reason about.

**Rollback refusal.** The signature alone proves "the owner signed this at
some point", not "this is current": a plain `git revert` of a removeperson
commit restores an old, still-validly-signed keyring, silently returning a
revoked collaborator to the recipient set. The defence is a per-machine
**freshness baseline**: the highest keyring version this machine has ever
accepted for this repo id, stored OUTSIDE the repository next to the pin
(`<key store>/trust-pins/<sanitized repo id>.ring-version`,
TrustPinStore, src/trust_store.rs). After the signature verifies,
`verify_keyring_against_trust` (src/commands/verify_keyring.rs) compares:

- keyring version **below the baseline** (a versionless pre-freshness
  keyring counts as 0) → refusal, exit code 14 (KeyringRollback);
- otherwise the baseline is advanced to the keyring's version and the
  command proceeds.

**Only a signed keyring may move the baseline.** An unsigned zero-entry
keyring (the fresh-init state) is unauthenticated repo content: it is
accepted as version 0 but never records a baseline — otherwise an attacker's
junk ring carrying `version:u64::MAX` would poison the baseline and brick
every machine past a revert of the attacker's commit. On a machine that
already has a baseline, the unsigned ring is refused outright (a rollback to
"no collaborators" fails closed); on a baseline-less machine it is accepted
as the fresh-init state it is.

**Fork detection.** The baseline file also records the SHA-256 digest of the
accepted SIGNED keyring content (`keyring_content_digest`, src/signing.rs).
An equal-version keyring whose content differs from the accepted one is
refused with exit 14: two curating machines that do not pull in between would
otherwise produce two differently-populated version-N keyrings, and the
second would silently replace the first. The refusal names the fork and the
recovery ceremony (re-`trust`); a legitimate bump to a higher version is
accepted and advances both version and digest. Baselines written before this
rule existed carry no digest and are upgraded in place on the next accepted
signed ring.

A fresh clone has no baseline: the first gated command records the current
SIGNED keyring's version as the baseline (a versionless keyring records 0) —
the same trust-on-first-use posture as the pin itself. The baseline is
machine-local state in the key store, which is exactly where it must live:
anything committed to the repo would be attacker-writable and the refusal
would be void.

**Recovery.** A legitimate rollback (the owner really does want an older
keyring state) is the same ceremony as a legitimate anchor change: re-run
`git-veil trust`, which clears the freshness baseline along with re-pinning
the key. Old keyrings written before freshness existed are accepted until
the next `tell`/`removeperson` gives them a version; from then on their
rollback is refused.

## Key discovery and selection

git-veil **never generates key material**. A key the tool created is a key the
user never backed up; the tool's job on a missing key is to say so, teach the
creation recipe, and exit with a documented code — not to silently manufacture
credentials (`src/key_discovery.rs`).

**Signing keys** (`discover_signing_key`): the owner's Ed25519 signing keys are
read from `<key store>/signing-keys.txt`, one 64-hex-character seed per line
(`#` comments and blank lines skipped). `tell` and `removeperson` — the two
keyring-curating commands — select a key as follows:

With several signing keys present, `--signing-key` names one explicitly by
its full 64 hex character Ed25519 verifying key
(`discover_signing_key_explicit`): the verifying key is public (it is the
committed `owner.verifying` content, never the seed) and stable under
reordering because it IS the key, not its position. The other selection
forms that ever existed are removed: a 1-based index is positional and
silently names a different key after the file is reordered or a key is
inserted; a full 64-hex seed puts the private key on the command line,
where it lands in shell history, `ps` output, scrollback and agent
transcripts; and the 16 hex character fingerprint form was retired with
the derivation change (issue #41). An explicit verifying key matching no
store key refuses with code 20; matching more than one (a degenerate
duplicated store) refuses with code 70 rather than silently picking one.

1. The TRUSTED key is used — the one whose owner key fingerprint equals
   the fingerprint pinned for this repository. The keyring
   must be signed with exactly the key the pin names (that is what
   verify_keyring checks against), so the pin, not list order, selects the
   key. Selection is deterministic and the pin is mandatory — no
   interactive menu is needed.
2. No usable key → the command exits with code 20 after printing, to stderr,
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
non-zero. **The plaintext is deleted by default** once every ciphertext is
durably on disk; `--keep-plaintext` opts out and leaves the plaintext beside
its ciphertext. `reveal` mirrors this exactly: decrypt all into memory, then
write each plaintext atomically; the `.secret` ciphertext files are left in
place. `unhide` applies the same ordering to a single file. The invariant in
all three: **at worst both copies exist, never neither.**

**Plaintext lifecycle.** Deleting by default is a deliberate posture: the
plaintext's only protection in the worktree is a `.gitignore` line, so the
normal loop is `reveal` → edit → `hide`, with the plaintext existing only
while it is being edited. Consequences, stated honestly:

- **Skip-and-report, not error.** A tracked path whose plaintext is absent
  and whose ciphertext exists (on disk or committed) is skipped and reported
  as "already hidden" — re-running `hide` on a hidden repo does nothing and
  succeeds. A tracked path with neither plaintext nor ciphertext is skipped
  and reported as never-hidden. Neither state is an error: absence of
  plaintext is the steady state of this lifecycle.
- **Rotation requires the plaintext.** `removeperson` + `hide` alone cannot
  re-encrypt ciphertexts whose plaintexts are gone — the correct rotation is
  `reveal` (restores plaintexts), `removeperson`, `hide` (re-encrypts to the
  new ring, deletes plaintexts again). Documented here because it is the one
  workflow that changed shape with this default.
- The intent gate (exit 72) and the code-41 plaintext-leak warning only
  apply to paths that HAVE a plaintext to encrypt; a path with no plaintext
  has nothing to exfiltrate and nothing to warn about.

**Crash windows that remain.** Death between a phase-2 write and its paired
delete (the default path) leaves both copies on disk. This is stated
honestly: it is a redundancy window, not a data-loss window, and the
plaintext is gitignored. The next command resolves it: re-running `hide`
re-encrypts the still-present plaintexts to the current keyring and atomically
overwrites the ciphertexts. Death during `trust` between the trust.json write
and the pin write fails closed on the next gated command (see the ordering
invariant above).

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
4. **Reveal-side tracked-plaintext refusal**: the inverse case is not a
   warning but a hard refusal in the decryption-write commands. A plaintext
   that is TRACKED IN GIT is ordinary repository content, not a secret
   (git-veil plaintexts are gitignored by construction; a tracked plaintext
   is exactly the state the code-41 warning flags). If `reveal` or `unhide`
   refused nothing there, a repo writer could nominate a source file — say
   `ci/deploy.sh` — in the unsigned `tracked.json` and commit a payload
   ciphertext encrypted to the ring's public recipient keys (no signing key
   needed, the keyring is untouched); the victim's `reveal` would overwrite
   the source file and the CI would execute it. `reveal` and `unhide`
   therefore refuse with exit code 43 (PlaintextTracked) when the target
   plaintext path is tracked in the git index, naming the path and the
   `git rm --cached` remedy. `cat` is not gated: it never writes. The gate
   is `ensure_not_tracked_in_git` (src/commands/reveal.rs, unhide.rs) over
   `is_tracked_in_git` (src/commands/add.rs), whose index match is
   CASE-INSENSITIVE as a fallback: on the macOS and Windows default
   filesystems a case-variant spelling (`BUILD.SH` vs `Build.sh`) resolves
   to the same file, so an exact-match miss must still refuse when any
   case-variant of the path is in the index. On case-sensitive filesystems
   the fallback can in principle false-positive two genuinely distinct
   case-variant files — for a secrets tool refusing beats overwriting.

## Orphaned ciphertext (a committed `.secret` that is not tracked)

`hide` re-encrypts only tracked paths. That makes the tracked manifest the
de-facto revocation boundary: if a path is removed from `tracked.json`, the
old ciphertext is never re-encrypted, so after a `removeperson` rotation the
stale `.secret` stays decryptable by the removed collaborator — silently,
with `hide` reporting success. Since `tracked.json` is committed and unsigned
repo content, any repo writer can cause this by deleting manifest entries.

Two mitigations close the hole:

1. **`remove` deletes the sibling ciphertext by default.** Untracking a file
   deletes `<name>.secret` from the working tree in the same step
   (`--keep-ciphertext` preserves the old leave-in-place behaviour). The
   ciphertext is committed content, so deletion is recoverable from git
   history; the honest way to keep an untracked ciphertext around is now an
   explicit flag, not a default.
2. **`hide` refuses orphaned ciphertext (exit 42).** Before encrypting,
   `hide` enumerates ciphertext paths committed to the git index and refuses
   with exit code 42 when any of them does not correspond to a tracked path,
   naming each one. The remedies are `git-veil add <path>` (the de-tracking
   was wrong) or deleting the stale ciphertext (the de-tracking was right).
   The gate runs even when `tracked.json` is empty — that is exactly the
   de-tracking-then-rotate attack shape. The index is read verbatim
   (`git -c core.quotePath=false ls-files -z`) so unicode/space names map
   back to their tracked paths; a committed file named exactly `.secret`
   (no plaintext stem — it cannot correspond to any tracked path) is warned
   about and ignored rather than fatal, so one junk file cannot brick hide.

Scope, stated honestly: the gate reads the git **index**, so it catches
committed (staged) ciphertexts — the exfiltration channel. An uncommitted
on-disk `.secret` left behind by `remove --keep-ciphertext` is not detected
until staged; a blind `git add -A` could sweep it into a commit. This is the
same risk class as the code-41 plaintext-leak warning and is documented as
such, not hidden.

## Encryption intent (refusing nominated paths)

`tracked.json` is committed and unsigned: any repo writer can add a path to
it. The victim's next `hide` would then encrypt a file the victim never
added — typically a gitignored secret — to every keyring member, including
the attacker's, and the ciphertext is committed in the ordinary flow. The
plaintext being gitignored suppresses even the code-41 warning, so the
exfiltration is silent. The manifest cannot distinguish "user intends to
track this" from "attacker nominated it" — the manifest IS the attack
surface — so intent is bound to the **victim's own action** instead:

- **`add` records intent on the machine that ran it.** Each `git-veil add`
  appends the resolved repo-relative path to a machine-local intent log,
  `<key store>/local-adds/<sanitized repo id>` (one path per line;
  `LocalAdds`, src/intent.rs). The key store is outside the repository and
  permission-checked, so repo writers cannot write or poison it, and a
  `pull` cannot alter it.
- **`hide` requires intent for first encryption.** For each tracked path
  whose ciphertext is not established and whose plaintext exists on
  disk (a path with no plaintext has nothing to exfiltrate — see "Plaintext
  lifecycle"), `hide` consults the intent log; a path with neither an
  established ciphertext nor recorded intent is refused with exit code 72
  (UnintendedEncryption), naming the paths; the remedy — deliberate `add`
  on this machine when the tracking is wanted, or restoring `tracked.json`
  when it is not — is this document, not the error text.
- **Established means the ciphertext predates the manifest entry (issue
  #19).** The git index is attacker-writable, so a committed ciphertext
  alone proves nothing: a repo writer can commit the `tracked.json`
  nomination and a dummy `<path>.secret` together and the victim's next
  `hide` would treat the path as established. A committed ciphertext is
  therefore established only when a git-history happen-before check holds:
  find the commit that introduced the `tracked.json` entry naming the path
  and require the ciphertext path to already exist in that commit's parent
  tree. A nomination and a dummy landing in one commit fail the check and
  the intent gate runs.
- **The happen-before result is cached per manifest version.** The check
  walks git history, so its result is cached in the machine-local key
  store at `<key store>/baselines/<sanitized repo id>/<sha-256 of
  tracked.json content>` (one proven repo-relative path per line;
  src/happen_before.rs). The key store either holds a baseline for that
  manifest hash or it does not — there is no clone-versus-update
  distinction anywhere in the logic. Any manifest change (add, remove,
  reorder) changes the hash, which selects a fresh cache entry, so a
  remove-and-readd is re-checked against the re-add commit with no
  invalidation logic and no garbage collection. A path that fails the
  check is never cached: every `hide` re-runs the check and refuses again.
- **Honest residual (issue #19).** The happen-before check raises the
  attacker's cost from one visible change to a crafted history: a dummy
  ciphertext committed BEFORE the nomination still predates the manifest
  entry and passes the check. The intent log remains the real anchor —
  every machine that wants to first-encrypt a path must have run `add`
  for it — and the check only removes the free ride a same-commit dummy
  otherwise gets. A stricter rule (for example binding the manifest hash
  into the signed keyring payload) is the follow-up direction.

Stated honestly, the residual trade-offs: the intent log is machine-local,
so an owner who re-hides from a machine whose key store was restored must
re-run `add` for any path without an established ciphertext; and a
malicious collaborator can still make `hide` refuse (availability) by
nominating junk paths — that is fail-closed by design, the same posture as
the code-40 gate, and each refusal names the offending paths.

## CODEOWNERS coverage for the trust-critical paths (suggested, never required)

CODEOWNERS is a platform feature, not a git feature: plain git ignores the
file. Where the platform enforces it (with branch protection), a
write-access attacker's rekey of the trust anchor becomes a review-gated
change instead of a silent push. The tool suggests and warns; it never
requires, and it works unchanged on plain-git hosting. On platforms with
no CODEOWNERS support the file simply sits there ignored, which is
harmless.

- **Locations, in platform precedence order**: the repository root,
  then `.github/`, `docs/`, `.gitlab/`, `.gitea/`, `.forgejo/` and
  `.bitbucket/`. The first file found in that order is the one evaluated
  (src/codeowners.rs).
- **Matching reuses the gitignore matcher** (gix-ignore, the gitoxide
  matcher): CODEOWNERS patterns are a subset of gitignore (no negation, no
  character ranges, no escape handling), so the matcher answers whether a
  pattern covers `owner.verifying` and the `.git-veil/` directory,
  last-match-wins. Owner strings are not validated — only the question
  does any pattern match these paths is answered. Gitea and Forgejo use a
  different pattern language; the gitignore matcher may produce false
  negatives there, and the warning is non-blocking, so a false negative
  only costs an unnecessary reminder.
- **`git-veil init` suggests, once, in plain text.** After initializing
  `.git-veil/`, a non-quiet `init` prints a suggestion naming the
  trust-critical paths and the lines to add, with no prompt, no stdin and
  no file creation. `git-veil init -q` prints nothing. The tool never
  creates a CODEOWNERS file.
- **`git-veil trust` warns when the trust anchor is not review-gated.**
  After a successful pin (proof or import), a non-blocking warning is
  printed when no CODEOWNERS file covers the trust-critical paths. The
  warning never refuses and never alters the exit code.
- **Suppression is deliberate and bound to the pin.** A user who does not
  want CODEOWNERS and does not want the reminder suppresses it per pinned
  repository: `git-veil trust --suppress-codeowners` records the
  repository id in the key store (`codeowners-suppression`, outside the
  repository and attacker-proof) at the same moment the possession proof
  or import pins the anchor. Only the pin-creation command can write the
  entry, so creating a suppression requires holding the machine that
  proved possession of the signing key — the possession proof is the
  signature on the suppression. Suppressed repositories print no
  CODEOWNERS warning.

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
   (deleted by default; the read gate applies whether or not the plaintext exists) delete. Exit code 71.
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
| 14   | KeyringRollback              | Keyring version is below this machine's freshness baseline; re-`trust` if the rollback is intended |
| 20   | NoSigningKey                 | No Ed25519 signing key in the key store; create one and back it up |
| 21   | NoAgeIdentity                | No age identity in the key store matching your keyring entry; create and import one |
| 22   | IdentityNotInKeyring         | Your email is not in the signed keyring; ask the owner to `tell` you |
| 30   | UnsafeKeyStorePermissions    | Key store directory or private key file is group/world accessible |
| 40   | CiphertextIgnored            | A `.secret` ciphertext path is git-ignored (fatal in `hide`; warning in `add`) |
| 41   | PlaintextNotIgnored          | Tracked plaintext on disk is not git-ignored (warning; exit stays 0) |
| 42   | OrphanedCiphertext           | A committed `.secret` ciphertext path is not tracked; `hide` refuses (see "Orphaned ciphertext") |
| 43   | PlaintextTracked             | The plaintext is tracked in git (fatal in `reveal`/`unhide`; see "Ignore safety" gate 4) |
| 60   | DecryptionFailed             | Ciphertext could not be decrypted with the local identity |
| 61   | EncryptionFailed             | Encryption failed |
| 62   | KeyParseFailure              | A key, keyring or signature could not be parsed |
| 63   | SignatureVerificationFailed  | Keyring signature missing or invalid |
| 70   | Refused                      | Policy refusal (e.g. `init` over established trust, `clean` without `--yes`) |
| 71   | UnsafePath                   | Path-safety refusal (symlink, outside repository, unsafe tracked path) |
| 72   | UnintendedEncryption         | `hide` refuses to encrypt a file the user never added on this machine (see "Encryption intent") |
