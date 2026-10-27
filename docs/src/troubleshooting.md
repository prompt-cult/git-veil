# Troubleshooting

Every deliberate failure exits with a documented code. Run
`git-veil error-codes` for the table any time. Failures without a more
specific code exit 1, and command-line usage errors exit 2. The codes are
public API: they are never renumbered, only appended.

## The exit-code table

| Code | Name | Meaning |
|------|------|---------|
| 1 | GeneralError | Failure without a more specific code |
| 2 | Usage | Command-line usage error |
| 10 | NoTrustRecord | Committed trust.json has no entry for this repository; run `git-veil trust` |
| 11 | NoTrustPin | No local trust pin on this machine; run `git-veil trust` |
| 12 | TrustMismatch | Committed trust.json disagrees with this machine's pin; re-pin if intended |
| 13 | TrustRepoIdMismatch | `repo_id` argument does not match the one derived from the remote |
| 14 | KeyringRollback | Keyring version is below this machine's freshness baseline; re-`trust` if the rollback is intended |
| 20 | NoSigningKey | No Ed25519 signing key in the key store; create one and back it up |
| 21 | NoX25519PrivateKey | No X25519 private key in the key store matching your keyring entry; create and import one |
| 22 | PrincipalNotInKeyring | Your principal is not in the signed keyring; ask the owner to `tell` you |
| 30 | UnsafeKeyStorePermissions | Key store directory or private key file is group/world accessible |
| 40 | CiphertextIgnored | A `.secret` ciphertext path is git-ignored (fatal in `hide`; warning in `add`) |
| 41 | PlaintextNotIgnored | Tracked plaintext on disk is not git-ignored (warning; exit stays 0) |
| 42 | OrphanedCiphertext | A committed `.secret` ciphertext path is not tracked; the whole-manifest pass refuses it |
| 43 | PlaintextTracked | The plaintext is tracked in git, which `reveal` and `unhide` refuse |
| 60 | DecryptionFailed | Ciphertext could not be decrypted with the local private key |
| 61 | EncryptionFailed | Encryption failed |
| 62 | KeyParseFailure | A key, keyring or signature could not be parsed |
| 63 | SignatureVerificationFailed | Keyring signature missing or invalid |
| 70 | Refused | Policy refusal (init over established trust, `clean` without `--yes`) |
| 71 | UnsafePath | Path-safety refusal (symlink, outside repository, unsafe tracked path) |
| 72 | UnintendedEncryption | `hide` refuses to first-encrypt a tracked path never allowed on this machine |

The full specification of each refusal, including the paths that must
never be refused silently, is in the [Design specification](design.md).

## Key store permissions (exit 30)

git-veil checks its key store the way gpg checks `~/.gnupg`. The store is
`$GIT_VEIL_HOME` or `$HOME/.git-veil`. The store directory and the private
files (`identities.txt`, `signing-keys.txt`) must not be group- or
world-accessible. git-veil never changes permissions itself. On a
violation it exits with code 30, names the exact paths and modes at fault,
and offers the remedies.

The fix is `chmod`:

```sh
chmod 700 "$HOME/.git-veil"
chmod 600 "$HOME/.git-veil/identities.txt" "$HOME/.git-veil/signing-keys.txt"
```

If you accept the current state instead, record it as trusted:

```sh
git-veil trust-permissions
```

The acknowledgment pins the exact (path, mode) pairs in
`permissions-ack.json`. A later change fails again until you
re-acknowledge. To bypass the check for one command:
`--dangerously-skip-permissions-check` or `GIT_VEIL_SKIP_PERMISSIONS=1`.

If your own real key store has loose modes, your tests fail with exit 30.
Fix the modes; do not weaken the check.

## Trust failures (exit 10 to 14)

Every gated command verifies the keyring signature against the pin on
this machine before touching anything. The refusals, and what to do:

- **Exit 11, no local pin.** This machine has never pinned this
  repository. A fresh clone always starts here, even the owner's. Run
  `git-veil trust <repo-id>` (with the signing seed) or
  `git-veil trust --import <pin-file>` (without it).
- **Exit 70, no committed verifying key.** The message names
  `.git-veil/owner.verifying`. Either the owner has not created and
  committed it yet (step 1 of the [Solo guide](solo.md)), or the file
  sits at the repository root. The tool reads the verifying key only
  from `.git-veil/owner.verifying`; a file at the repository root is
  not read. Move it into place and commit:

  ```sh
  git mv owner.verifying .git-veil/owner.verifying && git commit -m "Move owner.verifying into .git-veil"
  ```

  The fingerprint derivation is location-independent, so every existing
  pin stays valid and no machine needs to re-run `trust`.
- **Exit 10, no committed record.** The repository's committed
  `.git-veil/trust.json` has no entry for this repository id. The owner
  must run `trust` on a machine holding the signing key and commit the
  refreshed `trust.json`.
- **Exit 12, mismatch.** The committed record disagrees with your pin.
  One of the two changed. Re-pin if the change is intended.
- **Exit 13, repo id mismatch.** The `repo_id` you passed does not match
  the one derived from the remote. Run `git-veil show-repo-id` and pass
  exactly that.
- **Exit 14, rollback.** The keyring version is below this machine's
  freshness baseline. If the rollback is genuinely yours (a branch
  rewound), re-run `trust` to reset the baseline.

A trust record whose fingerprint is 16 hex characters is refused as
hostile: re-establish trust with `trust`.

## The newcomer's failure shapes

Most "it doesn't work" cases on a fresh clone are one of these. Run
`git-veil error-codes` for the full table.

- **Exit 11** on any command: you have not pinned this repository on this
  machine. Import the owner's pin-file. See
  [Joining a team repository](joining.md).
- **Exit 22**, `user not found in the keyring`: the owner has not run
  `tell` yet, or has not pushed the updated keyring. Run `git pull`
  first; nothing on your side can fix it otherwise.
- **Exit 60**, `decryption failed. This ciphertext was not encrypted to
  your key`: the owner told you but did not deliver the ring-change pass,
  or you are on an old commit. Run `git pull`.
- **Exit 21**, no X25519 private key: your key store lacks your private
  key. The message prints the `age-keygen` recipe. Create it, import it,
  back it up.

## The hide refusals

`hide` refuses before it writes anything, so a refusal never leaves a
half-encrypted tree:

- **Exit 72, the allowance question.** The path is tracked but was never
  allowed for encryption on this machine: `tracked.json` may have been
  modified by someone else. If the tracking is wanted,
  `git-veil allow <path>` and hide again. A path you added yourself never
  asks; a path whose ciphertext is already committed never asks.
- **Exit 40**. The `.secret` ciphertext path is itself git-ignored, for
  example swallowed by a parent rule like `.tmp/`. Fix the ignore rules
  so the ciphertext will be committed.
- **Exit 42**. A committed `.secret` path is no longer tracked. Untrack
  it deliberately with `git-veil remove`, or re-track it with `add`.
- **Exit 41**, a warning only. A tracked plaintext is on disk but not
  gitignored; a blind `git add -A` would commit it. Gitignore the
  plaintext name.
- **Exit 71**. A named file is not tracked, or a path is unsafe (a
  symlink escaping the repository, a path outside it).

## Decryption and rotation (exit 60)

Exit 60 means no stanza in the ciphertext is addressed to your X25519
public key. The common causes, in order:

1. You are on an old commit. `git pull`.
2. The owner has not delivered the ring-change pass.

Remember that a removed collaborator can still decrypt every ciphertext
written while they were a member, straight out of git history. Rotation of
the secret values is the real remedy; see [Departing](departing.md).

## Undo and recovery

- **A refused command changed nothing.** `hide` and `reveal` are
  two-phase and all-or-nothing: validation and encryption happen in
  memory first, and the disk is written only after every file succeeds.
- **Plaintext deleted by `hide`.** It is not gone: the `.secret` beside
  it decrypts back. `git-veil reveal <file>` restores it.
- **Ciphertext deleted by `remove`.** Recover it from git history; the
  deletion is a normal committed deletion.
- **A corrupt key store** is refused untouched, naming the file, the line
  number and the corrupt line, so you can delete exactly that line.
  [removekey](commands.md#removekey) never rewrites a store it could not
  fully parse.
- **Lost X25519 private key with no backup.** Every ciphertext encrypted
  to it is unrecoverable. There is no recovery path, which is why the
  guides insist on the backup ritual.
