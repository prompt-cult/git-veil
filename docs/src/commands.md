# Commands

Every command is documented here: what it does, its options, its exit
codes and an example. The authority is the binary itself: `git-veil
--help` and `git-veil help <command>` are generated from the same clap
definition as the committed man pages (`docs/man/`), so they always match
the installed version. This page adds the workflow and the exit-code
detail the help text only gestures at.

Three contracts cover every command:

- **Fail closed.** Every command that touches secrets verifies the keyring
  signature against the pin on this machine first. Without a pin, or with
  a signature that does not verify, nothing is touched. See
  [Troubleshooting](troubleshooting.md).
- **Documented exit codes.** A deliberate failure exits with its
  documented code, never an anonymous 1. The codes are public API: they
  are never renumbered, only appended. `git-veil error-codes` prints the
  table; the specification lives in the
  [Design specification](design.md).
- **Named paths.** `hide` and `reveal` act on exactly the paths you give
  them. There is no bare whole-manifest form. The one whole-manifest pass
  is the ring-change ceremony, [rotate](#rotate).

## Global flags and environment

Accepted by every command that reads the key store (passed after the
subcommand):

| Flag | Effect |
|------|--------|
| `--key-store <dir>` | Key store directory. Default: `$GIT_VEIL_HOME` or `$HOME/.git-veil` |
| `--dangerously-skip-permissions-check` | Bypass the key store permission checks (exit 30). Also settable as `GIT_VEIL_SKIP_PERMISSIONS=1` |

Accepted by every command that resolves the repository identity:

| Flag | Effect |
|------|--------|
| `--remote <name>` | Git remote to derive the repository ID from. Default: `origin` |

Accepted by the decrypting commands (`reveal`, `cat`, `changes`) and
`whoami`:

| Flag | Effect |
|------|--------|
| `--email <address>` | Principal override. Default: `git config user.email` |

The key store directory, its pins and its allowances are one trust
boundary for every repository that uses that store. Isolate projects with
`GIT_VEIL_HOME` (for example `GIT_VEIL_HOME=~/keys/project-a`) rather than
sharing one store across repositories that do not trust each other.

## Setup

### `init`

```sh
git-veil init <verifying-key> [--remote <name>] [-q | --quiet] [--suppress-codeowners]
              [--key-store <dir>]
```

Initialises git-veil state and pins the owner key in one command. The
mandatory `verifying-key` argument is the path to the repo owner's
Ed25519 verifying key file, passed in from OUTSIDE the repository: init
creates a `.git-veil/` directory holding `keyring`, `trust.json`,
`tracked.json` and `owner.verifying` (the passed-in key), then runs the
pin ceremony the owner's key always required: the passed-in key must
exactly match the verifying key derived from a seed in the key store's
`signing-keys.txt`, and the repository id is derived from the remote
(default `origin`) to label the pin. Only the repo owner can run init.

- The verifying key file must live outside the repository worktree. The
  trust anchor travels in from outside, never through the repository
  itself. Exit 71 otherwise.
- The possession proof runs before any state is created: a machine
  without the matching signing seed refuses (exit 20) and the worktree
  is untouched. A degenerate duplicate seed store is exit 70.
- A configured remote is required; the repository id derived from it
  labels the pin, the committed trust record and the owner fingerprint.
- `--suppress-codeowners` records the CODEOWNERS warning suppression
  beside the pin. `-q`, `--quiet` suppresses the CODEOWNERS suggestion
  and other non-error output. The suggestion is worth acting on: protect
  `.git-veil/` with a CODEOWNERS file so trust-anchor changes are review
  gated on the platform.
- `init` never touches `.gitignore`. The `.secret` ciphertexts are meant
  to be committed, so gitignoring them would defeat the fresh-clone
  decryptability contract.
- Refuses to reset a repository with established trust. Remove
  `.git-veil/` explicitly if you really want a fresh start. Exit 70.

```sh
$ git-veil init "$HOME/.git-veil/owner.verifying"
git-veil initialized
trusted the repository owner key
pinned this repository owner key on this machine
suggestion: protect the trust-critical paths with a CODEOWNERS file ...
```

### `import`

```sh
git-veil import <files>... [--key-store <dir>]
```

Imports X25519 private keys (the `AGE-SECRET-KEY-1...` lines produced by
`age-keygen`) into the per-machine key store. This is where `reveal`,
`cat` and `changes` find the private key matching your keyring
entry. The store is written mode 0600 regardless of umask, is local to
this machine and is never committed. Each collaborator imports their own
private key.

- A file may contain other lines; `#` comment lines are skipped, so
  `age-keygen` output works as-is.
- A private key whose public half is already in the store is not
  duplicated.
- git-veil never generates keys. Create yours with `age-keygen` or
  `rage-keygen` and back the `AGE-SECRET-KEY-1...` line up. Without it,
  ciphertexts encrypted to you are unrecoverable. A missing private key
  exits with code 21 and prints the recipe.

```sh
$ age-keygen -o my-age-identity.txt
$ git-veil import my-age-identity.txt
+ imported: age1xxxx
Summary: 1 imported, 0 skipped
```

Exit codes: 30 (unsafe key store permissions), 62 (a key line could not be
parsed), 1 (a named file could not be read).

### `export`

```sh
git-veil export <identifier> [--output <file>] [--key-store <dir>]
```

Prints, or with `--output` writes, the X25519 public key encoding
(`age1xxxx`) for the given key, read from the local key store on this
machine. This is the key handoff between collaborators: each collaborator
runs `export` on their own machine and sends the public key encoding to
the owner, who adds it to the keyring with `add-key`. It cannot export a
collaborator's key for them; the store only holds keys this machine knows
about.

- `identifier` is the key's X25519 public key encoding, matched exactly.
- The output never contains private key material. Even when the match is
  your imported private key, `export` emits the public half only.
- Touches no repository state and needs no `init` or `trust`.

```sh
$ git-veil export age1xxxx
```

Exit codes: 30 (unsafe key store permissions), 1 (no matching key in the
store).

### `forget`

```sh
git-veil forget <identifier> [--yes] [--key-store <dir>]
```

Drops key material from the local key store: every X25519 private key in
`identities.txt` and every public key in `recipients.txt` whose public key
encoding exactly matches the identifier is removed.

- Destructive and local-only. It does not touch any repository, keyring or
  trust state, and it revokes nothing. Removing a private key does not
  make old ciphertext unreadable; whoever holds it can still decrypt with
  plain `age`. Revoking a departing collaborator is
  [remove-key](#remove-key) plus the ring-change pass; see
  [Departing](departing.md).
- Danger guard: if the target private key is the only one in
  `identities.txt`, `forget` refuses without `--yes`.
- The store rewrite is atomic and lossless for the retained lines. A
  corrupt store is refused untouched: the error names the file, the line
  number and the corrupt line, so you can delete exactly it.

```sh
$ git-veil forget age1xxxx --yes
```

Exit codes: 30, 1 (the `--yes` guard, or a corrupt store).

## Trust

### `trust`

```sh
git-veil trust --import <pin-file> [--remote <name>] [--suppress-codeowners]
              [--key-store <dir>]
```

Pins this repository's owner key on this machine by importing a pin-file
produced by [`export-pin`](#export-pin) on a machine that proved
possession. Three mandatory consistency checks: the pin-file's repo id
must match the one derived from the remote; its verifying key must
exactly match the committed `.git-veil/owner.verifying`; and its owner
key fingerprint must match the fingerprint recorded in
`.git-veil/trust.json`. Any mismatch is a refusal: one of the two
channels is compromised. Exit 70.

There is no possession-proof form: the repo owner pins at
[init](#init), and every other machine, including the owner's fresh
clones, imports. The pin-file must live outside the repository worktree
(exit 71), so it always travels out of band, the same model as
`known_hosts` provisioning. The pin lives in the key store, never
committed. A pin or trust record in the 16-hex-character fingerprint
format is refused as hostile until trust is re-established (exit 70).

`--suppress-codeowners` records the CODEOWNERS warning's suppression in
the key store next to the pin, for repositories that genuinely cannot
carry a CODEOWNERS file.

Requires [init](#init) first: it creates the `.git-veil/` directory that
holds the committed verifying key the import checks, and every trust
command must run at the repository worktree root. The verifying key
lives at `.git-veil/owner.verifying`, committed; a root-level
`owner.verifying` is not read. Typical next step: [add-key](#add-key).

```sh
$ git-veil trust --import ~/demo.pin           # pin-file from export-pin
```

Exit codes: 70 (import checks failed, a trust record in the
16-hex-character fingerprint format is refused), 71 (pin-file inside the
repository), 30.

### `export-pin`

```sh
git-veil export-pin <repo_id> > <pin-file>     # stdout, pipe anywhere
git-veil export-pin <repo_id> [--output <pin-file>] [--remote <name>]
                                         [--key-store <dir>]
```

Prints this repository's pin for import on a machine without the signing
key. The same possession proof as `trust` is required: a machine without
the matching seed cannot export at all. Store-less machines are consumers
of pins, never producers.

The pin is public material - the repository id and the owner verifying
key, the same content `.git-veil/owner.verifying` commits. So the pin
goes to stdout, artifact alone: read it, copy it, or pipe it straight to
the target machine over ssh. Redirect it somewhere else only with intent,
and never into the repository worktree.

- `--output` writes the pin to a file instead. The destination must
  point outside the repository worktree; exit 71 otherwise: a committed
  pin-file would be exactly the self-supplied anchor the pin model
  exists to prevent.
- The owner key fingerprint is printed on stderr - chatter never shares
  the artifact's stdout, so a redirect captures the pin alone. The
  fingerprint is the human out-of-band verification token: read it to
  the importing machine's operator and have them compare it with the
  fingerprint recorded in the committed `.git-veil/trust.json` before
  importing.

```sh
$ git-veil export-pin demo+example@github.com > /tmp/demo.pin
owner key fingerprint: f722e9afe322ac443cbc4c69dc236b5a03afa81f86011726b2a7285c173b63de (on stderr)
$ git-veil export-pin demo+example@github.com | ssh box 'cat > demo.pin'
$ git-veil trust --import demo.pin             # on the box
```

Exit codes: 20, 71, 30.

### `fingerprint`

```sh
git-veil fingerprint <label> <public_key>
```

Prints the single fingerprint derivation every git-veil fingerprint uses:

```
FP = SHA-256( UTF8(label) + ":" + UTF8(public-key-encoding) )
```

as 64 lowercase hex characters. The label is the principal for a keyring
entry, or the repository id for the owner key. The public key encoding is
the bech32 X25519 public key (`age1xxxx`) or the 64-hex Ed25519 verifying
key. Both arguments are used verbatim.

This is a pure function: no repository, no key store, no pin, no network.
A clean host reproduces the exact value with stock OS tools:

```sh
printf '%s:%s' 'alice@example.com' "$(age-keygen -y identity.txt)" | sha256sum
printf '%s:%s' 'demo+example@github.com' "$(head -n 1 .git-veil/owner.verifying)" | sha256sum
```

Use `printf`, never `echo` (`echo` appends a newline and hashes different
bytes). Golden vectors for the derivation live in the
[Design specification](design.md).

Exit codes: none beyond usage errors (2).

### `verify-keys`

```sh
git-veil verify-keys [--remote <name>] [--key-store <dir>]
```

Verifies the keyring's signature against the pinned trusted key for this
repository. This is the check every gated command runs before touching
secrets; running it directly is the cheap health check. Fail closed:
without a pin on this machine, or when the signature does not verify, the
command exits nonzero and nothing is touched.

```sh
$ git-veil verify-keys
```

Exit codes: 10 (no committed trust record), 11 (no local pin), 12 (the
committed record disagrees with the pin), 14 (keyring rollback below the
freshness baseline), 63 (signature missing or invalid), 70 (a trust
record in the 16-hex-character fingerprint format is refused), 30.

### `trust-permissions`

```sh
git-veil trust-permissions [--key-store <dir>]
```

Records the key store's current permission state, for the store directory
itself and for `identities.txt` / `signing-keys.txt` when they carry group
or world bits, as explicitly trusted. The acknowledgment pins the exact
(path, mode) pairs in `<key store>/permissions-ack.json` (mode 0600). The
permission check passes only while the observed modes still match those
pairs, so any later change fails again until you re-acknowledge.

git-veil never changes permissions on key material it did not create:
either `chmod` the paths right (the exit-30 error lists the exact
commands) or acknowledge the current state deliberately here.

```sh
$ git-veil trust-permissions
```

Exit codes: 30.

## Keyring membership

### `add-key`

```sh
git-veil add-key <email> <public_key> [--remote <name>]
                 [--signing-key <verifying-key>] [--key-store <dir>]
```

Adds a collaborator's X25519 public key to the repository keyring and
re-signs the keyring with the owner's Ed25519 signing key.

- The existing keyring signature is verified against the pinned trusted
  key before any modification.
- A canary is test-encrypted to the new key, so a key that cannot encrypt
  is never signed into the ring.
- The signing key used is the one whose verifying fingerprint is pinned
  for this repository. With several signing keys in the store,
  `--signing-key` names one by its full 64-hex Ed25519 verifying key (the
  public half, never the seed). A missing signing key exits with code 20
  and prints the create-and-back-up recipe.
- Adding the same email twice updates the entry instead of duplicating
  it.
- After re-signing, the ring-change pass is due on this machine, and
  [rotate](#rotate) delivers it.

The second argument is the collaborator's X25519 public key encoding
itself, the `age1xxxx` string pasted as text. [`export`](#export) prints
exactly that string.

Requires [init](#init), an established pin ([trust](#trust)) and the
signing key in the local key store.

```sh
$ git-veil add-key alice@example.com age1xxxx
added alice@example.com to the keyring
note: the keyring has changed. To re-encrypt to the updated keyring, run the rotate command.
```

Exit codes: 20 (missing signing key), 61 (the canary would not encrypt),
plus the gated-chain codes 10/11/12/14/63, plus 30.

### `remove-key`

```sh
git-veil remove-key <email> [--remote <name>]
                    [--signing-key <verifying-key>] [--key-store <dir>]
```

Removes a collaborator's entry from the keyring and re-signs it with the
owner's Ed25519 signing key. The existing keyring signature is verified
against the pinned trusted key before any modification, and removal
stamps the ring-change pass as due exactly as `add-key` does: after
re-signing, the pass is due on this machine, and [rotate](#rotate)
delivers it.

Removal is forward-looking only. Ciphertexts hidden while the person was a
member were encrypted to their key, so rotate the underlying secrets if
that matters. See [Departing](departing.md) for the full checklist and the
reasoning.

Fails closed on a tampered or unsigned keyring, and on an email that is
not in the ring.

```sh
$ git-veil remove-key bob@example.com
removed bob@example.com from the keyring
note: the keyring has changed. To re-encrypt to the updated keyring, run the rotate command.
```

Exit codes: 20 (missing signing key), 22 (email not in the ring), plus the
gated-chain codes 10/11/12/14/63, plus 30.

### `list-keys`

```sh
git-veil list-keys [--remote <name>] [--key-store <dir>]
```

Lists all keys in the keyring after verifying its signature against the
pinned trusted key. On failure the unverified content is still printed
under a loud invalid-signature banner, because an auditor must see the
tampered content, but the command exits nonzero so a script never
mistakes an audit of a tampered ring for a clean one. A repository with
no local pin fails closed like every other gated command.

```sh
$ git-veil list-keys
keyring signature verified and made by the pinned trusted key
Keys in keyring:
  example@github.com f16cbd29abdf10be29c866b943ec014d2b69312371f7f4a323e1caeccb6a35db
  alice@example.com ef8782d2038bd96851a455eb183dd8a31edb6aca728857d74e493c973e71ca54

Total: 2 keys
```

Exit codes: the gated-chain codes 10/11/12/14/63, plus 30.

## Tracking and allowance

### `add-file`

```sh
git-veil add-file <files>... [--remote <name>]
```

Tracks files for encryption in `.git-veil/tracked.json` (stored
repo-relative). Nothing is encrypted yet; [hide](#hide) does that.
The short form `add` keeps working.

- Each file must exist, and a symlink must resolve inside the repository,
  so `hide` can never be tricked into reading or deleting a file outside
  the repo. Exit 71 otherwise.
- If a tracked plaintext's `.secret` ciphertext path is git-ignored,
  `add-file` warns with error code 40: that ciphertext would silently never
  reach the repository.
- The nomination is also your standing instruction: each added path is
  recorded in the machine-local allowance store in your key store, so
  `add-file` implies [allow](#allow) and the first `hide` of a path you added
  never asks.
- `add-file` gitignores the plaintext name for you and tells you it did.

```sh
$ git-veil add-file .env
file not in .gitignore, adding: .env
added 1 files
```

Exit codes: 40 (warning; the exit stays 0), 71 (path safety).

### `allow`

```sh
git-veil allow <files>... [--remote <name>]
```

Records paths in the machine-local allowance store in your key store:
this repository, anchored by the trust pin, and this git user, have
allowed these paths for encryption.

`tracked.json` is committed and unsigned, so any repository writer can
nominate a path in it. [hide](#hide) refuses to first-encrypt a tracked
path that was never allowed on this machine (exit 72), naming the paths.
Once recorded, an allowance survives manifest changes and never needs
re-recording. It is keyed to your git user (`git config user.email`), so
with many checkouts and no common git email, you allow once per email.

`allow` resolves paths exactly like `add-file`: the file must exist and resolve
inside the repository. You only need `allow` for a path someone else
nominated, or one the `add-file`-implies-allow step did not run for.
[remove-key](#remove-key) purges the allowance record of a removed
principal.

Requires an established pin. `reveal` is never gated: decryption needs
only keyring membership.

```sh
$ git-veil allow deploy.env
allowed 1 files
```

Exit codes: 11 (no pin on this machine), 70 (the pin disagrees with the
committed record), 71 (path safety).

### `remove-file`

```sh
git-veil remove-file <files>... [--keep-ciphertext]
```

Untracks files: removes them from `.git-veil/tracked.json`. The plaintext
may already be gone, since `hide` deletes plaintexts by default, so the
file does not need to exist. The short form `rm` keeps working.

By default the sibling `<name>.secret` ciphertext is deleted too. A
de-tracked but committed ciphertext would otherwise be silently skipped by
a scoped [hide](#hide) and stay decryptable by collaborators removed in a
later rotation: the ring-change pass, [rotate](#rotate), refuses such
orphans with exit code 42. Deletion is
recoverable from git history. Pass `--keep-ciphertext` to leave the
ciphertext in place; `rotate` will refuse it as an orphan until it is
removed or the path is re-tracked.

```sh
$ git-veil remove-file .env
$ git-veil remove-file --keep-ciphertext config/credentials.yml
```

Exit codes: none beyond usage errors (2).

### `list`

```sh
git-veil list
```

Prints every file tracked in `.git-veil/tracked.json`. Whether the
plaintext or its ciphertext currently exists on disk is not checked.

```sh
$ git-veil list
.env
deploy.env
```

Exit codes: none.

## Encrypting and decrypting

### `hide`

```sh
git-veil hide <files>... [--keep-plaintext] [--remote <name>]
             [--key-store <dir>]
```

Encrypts each named tracked file to every key in the keyring and leaves a
`<name>.secret` beside where the plaintext was (`notes` becomes
`notes.secret`). You gitignore the plaintext names and commit the
`.secret` files, so a fresh clone carrying only ciphertext stays
decryptable by every keyring member via [reveal](#reveal).

- **Two-phase and all-or-nothing.** Phase 1 reads and validates every
  named plaintext and encrypts every named file to the full public key
  set in memory. If any plaintext is missing, unreadable or cannot be
  encrypted, `hide` aborts having changed nothing on disk. Phase 2, only
  after every encryption succeeded, writes each `.secret` atomically.
- **Ciphertext git-ignored is fatal.** A `<name>.secret` path swallowed by
  a parent-directory rule like `.tmp/` would silently never reach the
  repository. Exit 40.
- **Plaintext not git-ignored is a warning.** A blind `git add -A` would
  commit it. Error code 41; the exit stays 0.
- **The allowance gate.** A named tracked path that has a plaintext on
  disk, no committed ciphertext in the git index, and no allowance on
  this machine refuses with exit 72, naming the paths. Answer with
  [allow](#allow). Re-encrypting an established ciphertext never asks,
  which is why rotation on a fresh clone never asks either.
- **Unknown or untracked names refuse.** Exit 71.
- **The plaintext is deleted by default** once every ciphertext is
  durably written. `--keep-plaintext` leaves the plaintexts beside their
  ciphertexts.
- The keyring signature is verified against the pin before anything is
  encrypted.

```sh
$ git-veil hide .env
Encrypted: .env
Deleted plaintext: .env
files hidden
```

Exit codes: 40 (ciphertext git-ignored), 41 (warning: plaintext not
git-ignored), 71 (unknown or unsafe path), 72 (no allowance), plus the
crypto codes 60/61/63 and the gated-chain codes, plus 30.

### `rotate`

```sh
git-veil rotate [--remote <name>] [--key-store <dir>]
```

Delivers the due ring-change pass: re-encrypts every tracked ciphertext
to the current keyring. Each `.secret` file is decrypted in memory and
re-encrypted to every key in the keyring, in memory. The ciphertext is
the input: plaintexts are never read, written, deleted or compared, and
no plaintext is left on disk. There is no reveal step in the ceremony,
and a stale on-disk plaintext cannot enter the data path.

- **The stamp gate.** [add-key](#add-key) and [remove-key](#remove-key)
  stamp a ring-change pass as due on this machine when they re-sign the
  keyring. `rotate` verifies that the committed keyring's version and
  content digest match the stamp: the ring changed on this machine and
  no pass has consumed the change yet. Without a due stamp, or with a
  committed keyring that no longer matches one, `rotate` refuses with
  exit code 70 and names the repository id. One pass consumes one ring
  change; a second run immediately after refuses.
- **The orphan gate.** Before anything is re-encrypted, `rotate` reads
  the git index and refuses with exit 42 any committed ciphertext whose
  path is no longer tracked, naming each one.
- **No allowance question.** Every rotated ciphertext is already
  committed, so it is established: re-encryption never asks (exit 72 is
  not in this command's surface).
- **The skip note.** A tracked path with no `.secret` on disk is skipped
  with a note.
- **Two-phase and all-or-nothing.** Every ciphertext is decrypted and
  re-encrypted in memory first; the disk is written only after every
  re-encryption succeeded. The keyring signature is verified against the
  pin before anything is touched.

Run `rotate` on the machine that re-signed the keyring, then commit the
re-encrypted `.secret` files and the keyring. A scoped [hide](#hide)
never consults or consumes the stamp: for day-to-day work, name the
files you touched and reserve `rotate` for the ceremony.

```sh
$ git-veil add-key alice@example.com age1xxxx
added alice@example.com to the keyring
note: the keyring has changed. To re-encrypt to the updated keyring, run the rotate command.
$ git-veil rotate
Rotated: .env
files rotated
ring-change pass complete: every tracked ciphertext is re-encrypted to the current keyring
```

Exit codes: 70 (pass not due, or a stale stamp whose keyring version and
digest no longer match the committed ring), 42 (orphaned ciphertext),
60/61/62 (decryption, encryption, key parse), plus the gated-chain codes
10/11/12/14/63, plus 30.

### `reveal`

```sh
git-veil reveal <files>... [--email <address>] [--remote <name>]
              [--key-store <dir>]
```

Decrypts each named tracked file back to its plaintext path, using your
X25519 private key from the local key store. The keyring signature is
verified against the pin before any decryption.

- **Never gated.** Decryption needs only keyring membership, so a named
  path is revealed without any allow step.
- **Two-phase and all-or-nothing.** Every named file must have its
  `.secret` present and decrypt successfully; if any fails, `reveal`
  refuses without changing anything on disk.
- Unknown or untracked names refuse (exit 71). A plaintext tracked in git
  refuses (exit 43): `reveal` will not overwrite a file git is tracking.
- A missing private key exits with code 21 and prints the
  create-and-back-up recipe. A principal not in the keyring exits with
  code 22: check `git config user.email`, or pass `--email`, or ask the
  owner to add you with [add-key](#add-key).
- The `.secret` files stay in place.

```sh
$ git-veil reveal .env
keyring signature verified
keys in keyring: 2
Decrypted: .env
files revealed
```

Exit codes: 21 (no matching private key), 22 (principal not in the
keyring), 43 (plaintext tracked in git), 60 (decryption failed), 63
(signature verification failed), 71 (unknown or unsafe path), plus the
gated-chain codes 10/11/12/14, plus 30.

### `cat`

```sh
git-veil cat <file> [--email <address>] [--remote <name>]
            [--key-store <dir>]
```

Decrypts a single tracked file to stdout without touching disk state:
neither the plaintext nor its `.secret` ciphertext is modified. The
keyring signature is verified against the pin first, and the file must be
tracked with its ciphertext present beside it. The read-only peek for
scripts and build boxes.

```sh
$ git-veil cat .env
API_KEY=hunter2
```

Exit codes: as [reveal](#reveal), for the one file.

### `changes`

```sh
git-veil changes [files]... [--email <address>] [--remote <name>]
               [--key-store <dir>]
```

Reports where the on-disk plaintext differs from the last hidden version:
each tracked file's `.secret` ciphertext is decrypted and compared with
the plaintext beside it. Differences are data, not errors. With no
arguments it checks every tracked file; name files to check a subset.
Files with no ciphertext, or no plaintext on disk, are skipped with a
note and are not counted as changed.

```sh
$ git-veil changes
changed: .env
- API_KEY=hunter2
+ API_KEY=hunter4

1 files with changes
```

Exit codes: as [reveal](#reveal), minus the writes.

## Introspection

### `repo-id`

```sh
git-veil repo-id [--remote <name>]
```

Prints the repository ID derived from the git remote push URL: the exact
string [trust](#trust) expects as its `repo_id` argument, since `trust`
re-derives the id from the live remote and refuses a mismatch. Pass
`--remote` if your remote is not `origin`.

```sh
$ git-veil repo-id
Repository ID: demo+example@github.com
Remote: origin
Push URL: git@github.com:example/demo.git
```

Exit codes: none beyond usage errors (2).

### `whoami`

```sh
git-veil whoami [--email <address>] [--key-store <dir>]
```

Prints the principal git-veil will use for you: `git config user.email`,
or the `--email` override. The principal label is committed in the public
keyring, so naming it leaks nothing. Use it to check which keyring entry
`reveal`, `cat` and `changes` will look up before they fail on a missing
private key.

```sh
$ git-veil whoami
Your principal: example@github.com
```

Exit codes: none beyond usage errors (2).

### `error-codes`

```sh
git-veil error-codes
```

Prints the table of documented exit codes: number, enum name and meaning.
Failures without a more specific code exit 1, and command-line usage
errors exit 2. The codes are public API: they are never renumbered, only
appended, and the specification lives in the
[Design specification](design.md).

```sh
$ git-veil hide; echo $?    # a refusal exits with its documented code
```

Exit codes: none.

## Tooling

### `clean`

```sh
git-veil clean [--yes]
```

Removes the `.git-veil/` state directory: keyring, trust.json,
tracked.json and the committed `owner.verifying` verifying key that lives
beside them. `.gitignore` is never rewritten, and the in-place
`.secret` ciphertext files are ordinary committable files that `clean`
does not disown. Everything `clean` removes is recoverable from git
history on a branch that carries the commits.

The `.secret` ciphertexts can be the only remaining copy of a secret, so
a clean that would destroy tracked state or ciphertext refuses unless
`--yes` confirms it. Exit 70 without the confirmation.

```sh
$ git-veil clean --yes
```

Exit codes: 70 (would lose data without `--yes`).

### `completions`

```sh
git-veil completions <bash | zsh | fish>
```

Writes a shell completion script for the git-veil CLI to stdout. The
script is generated from the live clap definition, so it always matches
the installed binary.

```sh
$ git-veil completions bash > /etc/bash_completion.d/git-veil
$ git-veil completions zsh > "${fpath[1]}/_git-veil"
$ git-veil completions fish > ~/.config/fish/completions/git-veil.fish
```

Exit codes: none beyond usage errors (2).

### `manpages`

```sh
git-veil manpages [output_dir]
```

Writes roff man pages, `git-veil.1` plus one page per subcommand, into a
directory, all generated from the live clap definition. Defaults to
`./man` relative to the current directory. The committed pages under
`docs/man/` are regenerated with `scripts/gen-docs.sh`.

```sh
$ git-veil manpages /usr/local/share/man/man1
```

Exit codes: none beyond usage errors (2).
