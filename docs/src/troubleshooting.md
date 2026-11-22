# Troubleshooting

Every deliberate failure exits with a documented code. Failures without a
more specific code exit 1, and command-line usage errors exit 2. The codes
are public API: they are never renumbered, only appended.

Run `git-veil error-codes` for the full table any time. The per-command
lists, which code means what for the command you just ran, are in
[Commands](commands.md). The full specification of each refusal, including
the paths that must never be refused silently, is in the
[Design specification](design.md). The sections below are the failure
stories: what each refusal means for you, and what to do.

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
re-acknowledge. The acknowledgment command, and the one-command bypass,
are documented in
[Commands - global flags and environment](commands.md#global-flags-and-environment).

If your own real key store has loose modes, your tests fail with exit 30.
Fix the modes; do not weaken the check.

## Trust failures (exit 10 to 14)

Every gated command verifies the keyring signature against the pin on
this machine before touching anything. The refusals, and what to do:

- **Exit 11, no local pin.** This machine has never pinned this
  repository. A fresh clone always starts here, even the owner's. Run
  `git-veil trust --import <pin-file>` with a pin-file a machine holding
  the signing seed exported.
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
  the one derived from the remote. Run `git-veil repo-id` and pass
  exactly that.
- **Exit 14, rollback.** The keyring version is below this machine's
  freshness baseline. If the rollback is genuinely yours (a branch
  rewound), re-run `trust` to reset the baseline.

A trust record whose fingerprint is 16 hex characters is refused as
hostile: re-establish trust with `trust`.

### Organization transfer

Moving a repository to another GitHub organization is a transfer of
control of the repository, possibly a transfer of legal ownership. git-veil
treats it as a security event, not a rename: gated commands refuse with
exit 10 and print no remedy, on purpose. No automated patch or re-pin path
exists, and none will be added.

The procedure is manual: remove `.git-veil/` from the repository and commit
the removal (the trust chain stays in git history; nothing is lost), then
re-run `git-veil init` on a machine holding the owner signing seed, re-add
the collaborator keys, and re-pin each machine with the normal `export-pin`
/ `trust --import` ceremony. In a real transfer the people change too: this
is a fresh start.

## The newcomer's failure shapes

Most "it doesn't work" cases on a fresh clone are an owner step that has
not happened yet: a missing pin, a keyring entry that was never added, a
ring-change pass that was never delivered, or a private key that was never
imported. The four shapes, what each message means and the fix, are in
[Joining - failure shapes worth knowing](joining.md#failure-shapes-worth-knowing).

## The hide refusals

`hide` refuses before it writes anything, so a refusal never leaves a
half-encrypted tree:

- **Exit 40**. The `.secret` ciphertext path is itself git-ignored, for
  example swallowed by a parent rule like `.tmp/`. Fix the ignore rules
  so the ciphertext will be committed.
- **Exit 41**, a warning only. A tracked plaintext is on disk but not
  gitignored; a blind `git add -A` would commit it. Gitignore the
  plaintext name.
- **Exit 71**. A named file is not tracked, or a path is unsafe (a
  symlink escaping the repository, a path outside it).

## Exit 72: the allowance question

Who: any repo writer can nominate a path. `tracked.json` is committed and
unsigned, so the manifest can arrive from someone else - say, a
collaborator who ran `add-file` and pushed before hiding.

Why the error: `hide` refuses with exit 72 when a path was tracked but
never allowed on this machine. Hiding it would write its plaintext into a
ciphertext every keyring member can read, so the tool makes you answer
that deliberately - as an error that names the paths, never as a blocking
prompt. Nothing is encrypted.

How to fix: allow the path, then hide again.

```sh
$ git-veil allow deploy.env
allowed 1 files
$ git-veil hide deploy.env
Encrypted: deploy.env
Deleted plaintext: deploy.env
files hidden
```

The answer is cached per machine and per git user, so a later hide of the
same path does not ask again. A path you added yourself never asks; a
path whose ciphertext is already committed never asks. Full rules are in
[Commands - allow](commands.md#allow).

## The rotate refusals

`rotate` refuses before it re-encrypts anything, so a refusal never
leaves a half-rotated tree:

- **Exit 70**. The ring-change pass is not due, or the stamp is stale:
  the committed keyring no longer matches the ring change this machine
  stamped. The pass exists to turn a ring change into ciphertext, and
  one pass consumes one change. Run `git-veil rotate` only after `add-key`
  or `remove-key`; see [Commands - rotate](commands.md#rotate).
- **Exit 42**. A committed `.secret` path is no longer tracked. Untrack
  it deliberately with `git-veil remove-file`, or re-track it with `add-file`.

## Decryption and rotation (exit 60)

Exit 60 means no stanza in the ciphertext is addressed to your X25519
public key. The common causes, in order:

1. You are on an old commit. `git pull`.
2. The owner has not delivered the ring-change pass. The owner runs
   `git-veil rotate`, then commits and pushes the fresh ciphertexts. See
   [Commands - rotate](commands.md#rotate).

Remember that a removed collaborator can still decrypt every ciphertext
written while they were a member, straight out of git history. Rotation of
the secret values is the real remedy; see [Departing](departing.md).

## Undo and recovery

- **A refused command changed nothing.** `hide` and `reveal` are
  two-phase and all-or-nothing: validation and encryption happen in
  memory first, and the disk is written only after every file succeeds.
- **Plaintext deleted by `hide`.** It is not gone: the `.secret` beside
  it decrypts back. `git-veil reveal <file>` restores it.
- **Ciphertext deleted by `remove-file`.** Recover it from git history; the
  deletion is a normal committed deletion.
- **A corrupt key store** is refused untouched, naming the file, the line
  number and the corrupt line, so you can delete exactly that line.
  [forget](commands.md#forget) never rewrites a store it could not
  fully parse.
- **Lost X25519 private key with no backup.** Every ciphertext encrypted
  to it is unrecoverable. There is no recovery path, which is why the
  guides insist on the backup ritual.
