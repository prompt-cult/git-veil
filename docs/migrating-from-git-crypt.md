# Migrating from git-crypt

Your repository is encrypted with
[git-crypt](https://github.com/AGWA/git-crypt) and you are moving its
secrets to git-veil. This page walks the move end to end, then doubles as
a cheat-sheet for translating between the two tools afterwards.

## There is no automated migration

No format compatibility. git-crypt encrypts files in place. The
committed blob at the original path is an AES-256-CTR stream produced by
git's smudge/clean filter machinery. git-veil writes `age`-encrypted
(age-encryption.org/v1) blobs into sibling `<name>.secret` files beside
where the plaintext was. Neither tool
can read the other's ciphertext. The same one-tool-per-repo rule stated in
[README.md](../README.md#compatibility-with-git-secret) for git-secret
applies to git-crypt. Migration therefore means:

> decrypt everything with git-crypt, then re-encrypt everything with git-veil.

In the following, `age` refers to the open source `age` encryption tooling,
which may be installed separately to securely create and maintain
cryptographic keys outside of the git repo; the `git-veil` software uses the
Rust `rage` library to work with the keys.

History does not migrate. Every old commit in the repository contains
git-crypt-encrypted blobs, and no command in either tool converts them.
You have three options. Pick one before you start:

1. Keep git-crypt installed on the machines that need to read
   pre-migration history. Old commits stay readable through git-crypt's
   filters. New commits use git-veil. Lowest effort, but you are running
   both tools until the last old branch dies.
2. Start fresh history. Cut a new root commit, or a new repository,
   at the migration point and archive the old one read-only. Simple and
   unambiguous. You lose `git log` continuity across the cut.
3. Rewrite history with
   [git-filter-repo](https://github.com/newren/git-filter-repo) to strip
   the old ciphertext blobs entirely. This is an advanced, destructive
   operation touching every commit and requiring a force-push and
   re-clone by every collaborator. This page deliberately does not
   tutorialize it.

## 1. In the git-crypt repo: unlock and verify

Work in a clean clone and unlock it:

```sh
git status --porcelain        # must be empty. unlock refuses a dirty worktree
git-crypt unlock
```

What happened. git-crypt decrypted the shared symmetric key with your
GPG secret key, stored it under `.git/git-crypt/`, and re-checked-out the
encrypted files so the worktree now shows plaintext.
See the [git-crypt README](https://github.com/AGWA/git-crypt/blob/master/README.md).

Verify that every encrypted file actually decrypted. The rest of this
migration builds on the worktree being fully plaintext. Spot-check the
files you know, and list what git-crypt considers encrypted:

```sh
git-crypt status -e           # every file the attributes mark as encrypted
```

`-e` shows only encrypted files.
See [git-crypt(1)](https://man.archlinux.org/man/git-crypt.1.en).

Record checksums of the plaintexts now. Collaborators will reuse them in
step 6 to prove the migration lost nothing:

```sh
shasum -a 256 .env config/credentials.yml   > plaintext-before.sha256
```

## 2. Inventory the encrypted files

```sh
git-crypt status -e > encrypted-files.txt
grep -rn 'filter=git-crypt' --include=gitattributes .
```

What happened. You now have the concrete file list to hand to
`git-veil add` in step 5, and every `.gitattributes` line to strip in
step 3. Note that git-crypt patterns can live in nested `.gitattributes`
files, not only the repo root.

Keep the list. git-crypt encrypts by pattern, through `.gitattributes`
lines like `*.key filter=git-crypt diff=git-crypt`. git-veil tracks an
explicit file list, `.git-veil/tracked.json`. Files created later are
encrypted by git-crypt automatically if they match a pattern. Under
git-veil someone must run `git-veil add` on each new secret file, or it
will simply be a normal plaintext file.

## 3. Remove git-crypt from the repository

There is no `git-crypt uninstall` command. The tool documents no removal
path. It documents `lock`, and its behaviour is verified. `lock`
deconfigures the git-crypt filters from the local
`.git/config`, deletes the decrypted key from `.git/git-crypt/keys/`, and
re-checks-out encrypted files as ciphertext.
See [commands.cpp, `lock()`](https://github.com/AGWA/git-crypt/blob/master/commands.cpp).
The procedure below uses that behavior in the right order, so the
plaintexts from step 1 are never committed and never clobbered:

```sh
# 1. Strip every git-crypt line from every .gitattributes file. Use step 2's grep.
#    Commit the attribute removal.
git commit -am "Remove git-crypt filter attributes"

# 2. Make sure the plaintext names are ignored before dropping them from the index.
echo .env >> .gitignore                    # once per encrypted path

# 3. Drop the old ciphertext blobs from the index. The worktree plaintexts stay.
while IFS= read -r f; do git rm --cached -- "$f"; done < encrypted-files.txt

# 4. Remove the committed GPG-wrapped key files.
git rm -r .git-crypt

# 5. Commit the removal.
echo encrypted-files.txt >> .gitignore
git add .gitignore
git commit -m "Remove git-crypt key files and ignore plaintext paths"
git push
```

What happened. The committed tree no longer references git-crypt at
all. No filter attributes, no `.git-crypt/` key files. The worktree still
holds the plaintexts from step 1, now untracked and gitignored, ready for
step 5. Old commits still contain git-crypt ciphertext. See the history
options at the top of this page.

Then clean up each clone, yours first:

```sh
git-crypt lock
git config --local --get-regexp 'filter\.git-crypt'   # should print nothing
```

What happened. `lock` removed the decrypted key under `.git/git-crypt/`
and deconfigured the filters locally. The empty `.git/git-crypt/` directory
may remain. It is inert. Every collaborator runs `git-crypt lock` after
pulling the removal commit. Note that `lock` refuses an unclean worktree and
`lock --force` "may lose uncommitted work".
See [commands.cpp](https://github.com/AGWA/git-crypt/blob/master/commands.cpp).
Commit or stash first.

## 4. Set up git-veil

Full walkthroughs live in [solo.md](solo.md) for one person and
[two-collaborators.md](two-collaborators.md) for owner plus collaborators.
This is the shape. Each person needs an X25519 private key, an `age`
identity, created with `age-keygen` or `rage-keygen`. The owner also needs
an Ed25519 signing key, made with `openssl`. git-veil generates no keys.

On the owner's machine:

```sh
git-veil init                                # create .git-veil/ state
git-veil import my-age-identity.txt          # owner's X25519 private key into the local key store
git-veil show-repo-id                        # print the repository ID, e.g. demo+example@github.com
git-veil trust demo+example@github.com        # possession proof. Pin the owner key.
git-veil tell example@github.com my-age-identity.txt    # the owner must be in the keyring too
git-veil tell alice@example.com alice-age-identity.txt  # once per collaborator
```

What happened. `.git-veil/` now holds a signed keyring of
collaborator public keys, the tracked-file list and trust state. `trust`
is per machine. Every collaborator re-runs it on their own clone
after step 6. The pin lives in `$HOME/.git-veil`, never in the
repository. This replaces git-crypt's model of delegating trust to your
local gpg web-of-trust. See the cheat-sheet below.

## 5. Track, hide, commit

Back on the owner's machine, using the inventory from step 2:

```sh
git-veil add .env config/credentials.yml   # every file from encrypted-files.txt
git-veil hide .env config/credentials.yml
git add .git-veil/keyring .git-veil/tracked.json .git-veil/trust.json .env.secret
git commit -m "Re-encrypt secrets with git-veil"
git push
```

What happened. `hide` encrypted each named file to every key in
the signed keyring and wrote `<name>.secret` beside where the plaintext
was, deleting the plaintext. Pass `--keep-plaintext` to keep it.
`hide` reads each tracked plaintext from disk and fails if one
is missing. Keep the worktree unlocked until this step is done: if
git-crypt re-locked some files mid-migration, unlock them first, so
every named plaintext is on disk. The `.secret` files are meant to be
committed. The plaintext names are gitignored, which step 3 did already.
Never gitignore `*.secret`. That would defeat the fresh-clone
decryptability contract.

## 6. Verify on every collaborator machine

Each collaborator, on a fresh clone. This exercises exactly what a new
hire will experience:

```sh
git clone git@github.com:example/demo.git && cd demo
git config user.email alice@example.com
git-veil import alice-age-identity.txt     # their own X25519 private key only
git-veil show-repo-id
git-veil trust --import ~/demo.pin         # pin-file exported by the owner, out of band
git-veil verify-keyring                    # exit 0 = signature matches the pin
git-veil list-keys                         # who can decrypt, after verification
git-veil reveal .env config/credentials.yml
shasum -a 256 .env config/credentials.yml  # must match plaintext-before.sha256
git-veil changes                           # "unchanged" everywhere, nothing pending
```

What happened. The clone arrived with ciphertext and a signed keyring
but no trust pin. The first gated command fails closed until `trust`
pins the owner key on that machine. `reveal` then decrypted every tracked
file, and the `.secret` files stay in place. The checksum comparison
proves byte-identical migration. When the checklists are done, delete
`plaintext-before.sha256` and the file list. A plaintext inventory does not
belong in circulation.

## Cheat-sheet: git-crypt → git-veil

| git-crypt | git-veil | Notes |
|---|---|---|
| `git-crypt init` | `git-veil init` + `git-veil trust` | git-veil additionally requires pinning the owner's signing key, per machine. |
| `.gitattributes` `filter=git-crypt` lines | `git-veil add <files>` | Explicit tracked list instead of patterns; new secret files need an explicit `add` or they stay plaintext. |
| `git-crypt add-gpg-user USER_ID` | `git-veil tell <email> <keyfile>` | git-crypt commits a GPG-wrapped copy of the shared key automatically. git-veil signs the collaborator into the keyring, and existing ciphertext must be re-encrypted to the new ring with `hide --all` to include the newcomer. |
| `git-crypt ls-gpg-users` | `git-veil list-keys` | `ls-gpg-users` was a long-open git-crypt feature request. `list-keys` verifies the keyring signature before listing. |
| `git-crypt unlock` | `git-veil reveal` | Semantics differ, see below. |
| `git-crypt lock [--force]` | `git-veil hide` | Semantics differ, see below. |
| `git-crypt status` (`-e`) | `git-veil list` + `git-veil changes` | `list` shows the tracked set, no on-disk state check. `changes` reports where plaintext drifted from the last hidden version. |
| `git-crypt export-key FILE` | deliberately no equivalent | git-crypt exports the repo-wide symmetric key for out-of-band sharing. git-veil has no shared symmetric key to export. `git-veil export` exports a collaborator's public key. A different purpose entirely. |
| `git-crypt unlock KEYFILE` (symmetric mode) | deliberately no equivalent | git-veil always decrypts with your X25519 private key from the local key store. There is no shared-key fast path. |
| `git-crypt migrate-key` | deliberately no equivalent | Migrates a shared symmetric key. git-veil has no shared symmetric key. |
| Key rotation / off-boarding | `git-veil removeperson` + `git-veil hide --all` | git-crypt explicitly supports neither. Its README says there is "no del-gpg-user command… no support for rotating the key". git-veil's forward-looking procedure and its honest history limits are in [departing.md](departing.md). |
| `diff=git-crypt` transparent plaintext diffs | deliberately no equivalent; `git-veil changes` | No smudge/clean filter exists, so git and forges see `.secret` ciphertext, never plaintext diffs. `changes` diffs your on-disk plaintext against the last hidden version, locally. |
| GPG web-of-trust (`--trusted` opt-out) | `git-veil trust` per-machine pin | git-crypt delegates trust to whatever `gpg` says. git-veil verifies the owner-signed keyring against a pin you establish on each machine, a possession proof on a signing-key machine or an out-of-band pin-file import elsewhere, and fails closed without it. |
| `.git-crypt/keys/*/*.gpg` committed wrapped keys | `.git-veil/keyring` (owner-signed) | The keyring carries each collaborator's public key, signed by the owner. Its signature is verified before any crypto operation. |

### unlock/reveal and lock/hide are not the same shape

`git-crypt unlock` puts the repository into a persistent unlocked state.
The key sits in `.git/git-crypt/`, filters decrypt on every checkout, and
`lock` ends that state. git-veil has no repository-wide state.
`git-veil reveal` is a one-shot operation on the files you name. It
verifies the keyring signature, then decrypts each named file back to
its plaintext path and leaves each `.secret` in the worktree. It fails
outright if any named ciphertext is missing. There is nothing to `lock`.
The inverse one-shot is `git-veil hide`, which re-encrypts the named
plaintexts to the whole keyring and deletes them. Pass
`--keep-plaintext` to keep them. It fails if a named plaintext is
missing. For one file at a time use `unhide`,
and `cat` prints a file to stdout without touching disk state.

## Two honest warnings

### 1. git-veil is explicit, not transparent. This is the decision point.

Under git-crypt, plaintext is the normal on-disk state and the workflow
does not change. Under git-veil the worktree churns between two states.
You have plaintexts while you work, and `.secret` ciphertext after `hide`.
The plaintexts are untracked files sitting in your checkout until you hide
again. Editing a secret means reveal or `unhide`, then edit, `hide`,
commit. git-crypt wins when secrets are edited constantly and nobody
should ever have to think. git-veil wins when the collaborator roster
changes, when you want committed state that is verifiably ciphertext, and
when you want cryptography that needs no gpg. No mis-set attribute can
silently commit plaintext through a filter that does not exist. `age`
keys are plain text files, and the only one-time tooling is `age-keygen`
or `rage-keygen`, plus `openssl` for the owner's signing key. If your
team cannot live with the
reveal/hide cycle, that is a reason to stay on git-crypt. Say so now,
not after migrating.

### 2. No smudge/clean filter means GUIs and diffs behave differently.

git-crypt's custom diff attribute shows plaintext diffs of encrypted
files in editors, GUIs and forges. git-veil has no filter, so `git diff`
on a `.secret` shows binary ciphertext, GUI clients display ciphertext,
and forge-side rendering is out of the question. Reviewing secret-file
changes happens through `git-veil changes` and `git-veil cat` on a
machine with a pin and your private key. Also note, two collaborators who
both edit and `hide` the same path produce two committed `.secret` blobs
that git merges as binaries. Resolve such conflicts by decrypting both
versions with `git-veil cat` or `git show`, merging by hand, and re-hiding.
