# git-veil

A tool for storing encrypted secrets in a git repository, written in Rust.
It uses [age] encryption (via the pure-Rust [`age` crate][age-crate]) for
secrecy and [Ed25519][ed25519] signing (via [`ed25519-dalek`][dalek]) for
keyring integrity — no PGP, no GPG, no external crypto process. All
cryptographic operations happen in-process.

[age]: https://age-encryption.org
[age-crate]: https://crates.io/crates/age
[ed25519]: https://en.wikipedia.org/wiki/EdDSA#Ed25519
[dalek]: https://crates.io/crates/ed25519-dalek

The age format is a modern, RFC-track encryption format designed by Filippo
Valsorda. git-veil's ciphertexts are standard age files: any compliant age
implementation can decrypt them, including the reference [`age`][age-cli] CLI
and the Rust [`rage`][rage] CLI.

[age-cli]: https://github.com/FiloSottile/age
[rage]: https://github.com/str4d/rage

## Trust model

Each repository is identified by a repository ID derived from its git remote
push URL, e.g. `git@github.com:example/demo.git` gives `demo+example@github.com`
(run `git-veil show-repo-id` to print it). The repository owner's signing key is
verified and pinned per machine with `git-veil trust`; the pin lives in the
local key store outside the repository and is never committed, so every
collaborator (including the owner on a fresh clone) must run `trust`
themselves. The keyring of collaborator public keys in `.git-veil/keyring` is
signed by that trusted key, and the signature is verified before any
encryption, decryption or keyring mutation. Every gated command fails closed:
without a pin, or with a signature that does not verify, nothing is touched.
The key store and its pins are the trust boundary for every repository that
uses that store, so sharing one store across mutually distrusting repositories
is not advised. Set `GIT_VEIL_HOME` to isolate a project's keys from your
default `$HOME/.git-veil` (e.g. `GIT_VEIL_HOME=~/keys/project-a`); `--key-store`
overrides both for ad-hoc use.

## Key store permissions

The key store is checked the way gpg checks `~/.gnupg`: the store directory
and the private files (`identities.txt`, `signing-keys.txt`) must not be
group- or world-accessible. git-veil never changes permissions on files it
did not create. On a violation it exits with code 30 and names the exact
paths and modes; either `chmod` them right, or acknowledge the current
state with `git-veil trust-permissions` (which pins the exact `(path,
mode)` pairs — a later change fails again), or bypass with
`--dangerously-skip-permissions-check` / `GIT_VEIL_SKIP_PERMISSIONS=1`.

## Exit codes

Failures exit with documented codes, not an anonymous 1: trust failures are
10–13, missing keys 20–22, unsafe permissions 30, gitignore collisions 40–41,
crypto failures 60–63, and policy/path refusals 70–71. `git-veil error-codes`
prints the full table with names and meanings; the specification is in
[docs/design.md](docs/design.md).

## Quick start (solo)

Prerequisite: your own keys (see [Key setup](#key-setup) below) — an age
identity and an Ed25519 signing key. git-veil generates no keys: it only
ever reads keys you created and own, and every command that needs a
missing key tells you how to make one and back it up instead.

```sh
git-veil init                                   # create .git-veil/ state
git-veil import my-age-identity.txt             # import your age identity into the local key store
git-veil show-repo-id                           # print the repository ID
git-veil trust demo+example@github.com owner.verifying   # pin the signing key
git-veil tell example@github.com my-age-identity.txt    # add yourself to the signed keyring
printf 'API_KEY=hunter2\n' > .env
git-veil add .env                               # track the file (gitignores the plaintext name)
git-veil hide                                   # encrypt: .env -> .env.secret (plaintext kept)
git add .gitignore .git-veil/keyring .git-veil/tracked.json .git-veil/trust.json .env.secret
git commit -m "Add encrypted secrets"
git-veil reveal                                 # decrypt back when you need the plaintext
```

The `.secret` ciphertext files are standard age-encrypted blobs. You can
verify interoperability with any age-compatible tool:

```sh
# git-veil encrypted, age CLI decrypts:
age -d -i my-age-identity.txt .env.secret

# age CLI encrypted, git-veil decrypts (via reveal/cat):
echo "test" | age -r age1... -o .env.secret && git-veil cat .env
```

## Installation

Build from source with cargo:

```sh
cargo build --release
```

The binary lands at `target/release/git-veil`.

Man pages and shell completions are generated from the CLI definition itself:

```sh
git-veil manpages docs/man             # write roff pages into docs/man
git-veil completions zsh > "${fpath[1]}/_git-veil"   # bash, zsh or fish, to stdout
```

`scripts/gen-docs.sh` regenerates the committed pages under `docs/man` and
`docs/completions` in one go. To install the man pages system-wide:

```sh
cp docs/man/*.1 /usr/local/share/man/man1/
```

## Key setup

git-veil uses [age] X25519 keys for encryption and a separate Ed25519 key for
keyring signing. You need both, and git-veil generates **neither**: keys the
tool created would be keys you never backed up. Create them once with standard
tools, then back the private halves up (a password-manager note is enough).

### Create an age identity (for encryption/decryption)

Use any age key generator — `age-keygen` (from the [age CLI][age-cli]) or
`rage-keygen` (from [rage]):

```sh
umask 077
age-keygen -o my-age-identity.txt
# Output includes:
#   # public key: age1...    (your recipient string — share this)
#   AGE-SECRET-KEY-1...       (your identity — keep this secret, BACK IT UP)
```

The **recipient string** (`age1...`) is your public key — safe to share with
collaborators. The **identity string** (`AGE-SECRET-KEY-1...`) is your private
key — never commit it; without a backup of it, ciphertexts are unrecoverable.
`git-veil import my-age-identity.txt` copies it into the local key store
(accepts any file containing an `AGE-SECRET-KEY-1...` line; `#` comment lines
like age-keygen's are skipped).

### Create an Ed25519 signing key (for keyring signing)

The repository owner also needs an Ed25519 keypair for signing the keyring.
git-veil never creates or manages it — you make it with `openssl` and you back
it up:

```sh
umask 077
openssl genpkey -algorithm ED25519 -out "$HOME/.git-veil/ed25519.pem"

# The seed (private — what tell/removeperson read), 64 hex characters:
openssl pkey -in "$HOME/.git-veil/ed25519.pem" -outform DER \
  | tail -c 32 | xxd -p -c 32 > "$HOME/.git-veil/signing-keys.txt"

# The verifying key (public — this file is what `git-veil trust` pins):
openssl pkey -in "$HOME/.git-veil/ed25519.pem" -pubout -outform DER \
  | tail -c 32 | xxd -p -c 32 > owner.verifying
```

The signing-key file format is one 64-hex-character Ed25519 seed per line in
`<key store>/signing-keys.txt`. tell/removeperson sign with the key whose
verifying fingerprint is pinned for the repository; with several keys
present, `--signing-key <index-or-seed>` picks explicitly. Commands that
need a missing key exit with a documented code (`git-veil error-codes`)
after printing how to create and back it up.

## Commands

git-veil is a CLI tool inspired by git-secret, yet uses the more modern and
compact `age` encryption tools rather than the older `pgp`/`gpg` tools. The
underlying algorithms are common to many tools; it is the key formats and
ergonomics that differ — such as a smaller final binary size.

| Command          | Purpose                                                                 |
|------------------|-------------------------------------------------------------------------|
| `init`           | Initialize git-veil state (`.git-veil/`) in the current repository        |
| `import`         | Import your age identity file(s) into the git-veil key store             |
| `export`         | Export an age recipient string from the local key store                 |
| `removekey`      | Remove a key from the local key store (destructive, local-only)         |
| `trust`          | Verify and pin the repository owner's signing key (per machine)         |
| `tell`           | Add a collaborator's public key to the keyring and re-sign it           |
| `removeperson`   | Remove a collaborator from the keyring and re-sign it                   |
| `add`            | Track files for encryption (auto-gitignores plaintext names)           |
| `remove`         | Untrack files (leaves any ciphertext in place)                          |
| `list`           | List all tracked files                                                  |
| `hide`           | Encrypt all tracked files to the keyring (plaintext kept; `--dangerously-delete-plaintext` to delete after; refuses when a `.secret` path is git-ignored) |
| `reveal`         | Decrypt all tracked files back to plaintext                             |
| `cat`            | Decrypt a single tracked file to stdout                                 |
| `unhide`         | Decrypt one tracked file back to plaintext (ciphertext kept)             |
| `changes`        | Report where plaintext differs from the last hidden version             |
| `show-repo-id`   | Show the repository ID derived from the git remote push URL             |
| `whoami`         | Show the identity and key store git-veil will use                        |
| `verify-keyring` | Verify the keyring signature against the pinned trusted key             |
| `list-keys`      | List keyring keys after verifying the keyring signature                 |
| `clean`          | Remove the `.git-veil` state directory (`--yes` required when data would be lost) |
| `trust-permissions` | Acknowledge the key store's current (path, mode) pairs as trusted     |
| `error-codes`    | List every documented exit code with its name and meaning               |
| `completions`    | Emit a shell completion script for the given shell to stdout            |
| `manpages`       | Write roff man pages (`git-veil.1` plus one per subcommand) to a directory |

Run `git-veil help` for the list of commands, `git-veil help <command>` for a
workflow discussion with examples, and `git-veil <command> --help` for flags.
Run `git-veil help <command>` to learn more about any command above. Rendered
man pages live in `docs/man/`.

## Tutorials

Step-by-step guides are in `docs/`:

- Solo developer: [docs/solo.md](docs/solo.md)
- Two collaborators: [docs/two-collaborators.md](docs/two-collaborators.md)
- Joining user: [docs/joining.md](docs/joining.md)
- Departing user: [docs/departing.md](docs/departing.md)
- Migrating from git-secret: [docs/migrating-from-git-secret.md](docs/migrating-from-git-secret.md)
- Migrating from git-crypt: [docs/migrating-from-git-crypt.md](docs/migrating-from-git-crypt.md)

The specification of the underlying mechanisms (repository identity, trust
anchoring, key validity, crash safety, path safety) is in
[docs/design.md](docs/design.md).

## Compatibility with age and rage

git-veil's `.secret` ciphertext files are standard age-encrypted blobs
(age-encryption.org/v1). They are fully interoperable with the reference
[`age`][age-cli] CLI and the Rust [`rage`][rage] CLI:

- A file encrypted by git-veil can be decrypted by `age -d -i identity.txt file.secret`
- A file encrypted by `age -r recipient file` can be decrypted by `git-veil reveal`
- Keys generated by `age-keygen` or `rage-keygen` can be imported with `git-veil import`
- Keys generated by git-veil can be used by `age` and `rage` directly

The cross-implementation test suite (`tests/interop.rs`) exercises every
permutation of encrypt/decrypt/keygen between git-veil, `age`, and `rage`.

## Compatibility with git-secret

git-veil does NOT maintain compatibility with git-secret's cryptographic
material: a repository's `.secret` files, keyring and trust state written by
git-secret are not readable by git-veil, and vice versa. Use one tool
consistently within any given repository.

## License

GPL-3.0-or-later (see the `license` field in [Cargo.toml](Cargo.toml)).
