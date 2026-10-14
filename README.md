# git-veil

git-veil stores encrypted secrets in a git repository. It is written in Rust.
It encrypts with [`age`][age] (via the pure-Rust [`age` crate][age-crate]) and
signs the keyring with [Ed25519][ed25519] (via [`ed25519-dalek`][dalek]).

In the following, `age` refers to the open source `age` encryption tooling,
which may be installed separately to securely create and maintain
cryptographic keys outside of the git repo; the `git-veil` software uses the
Rust `rage` library to work with the keys.

[age]: https://age-encryption.org
[age-crate]: https://crates.io/crates/age
[ed25519]: https://en.wikipedia.org/wiki/EdDSA#Ed25519
[dalek]: https://crates.io/crates/ed25519-dalek

The `age` format is an encryption format designed by Filippo Valsorda.
git-veil's ciphertexts are standard `age` files. Any compliant `age` tool can
decrypt them, including the reference [`age`][age-cli] command-line tool and
the Rust [`rage`][rage] command-line tool.

[age-cli]: https://github.com/FiloSottile/age
[rage]: https://github.com/str4d/rage

## Why

The point of git-veil is that your secret material is backed up alongside
the code. The ciphertexts are committed, so every clone carries the
secrets, and the plaintext never has to leave your machine to reach a
build box: a build or deployment script runs `git-veil reveal` on its own
key and reads what it needs.

## Trust model

Each repository has an ID derived from its git remote push URL. The remote
`git@github.com:example/demo.git` gives the ID `demo+example@github.com`.
Run `git-veil show-repo-id` to print your repository's ID.

The repository owner's signing key is pinned on each machine. A repository
can never supply its own trust anchor. The only way to create a pin directly
is a possession proof. `git-veil trust <repo-id>` checks the repository's
committed `owner.verifying` against the verifying key derived from a seed in
your local signing key store. If no seed matches, trust refuses.

Machines without the signing key get their pin by import. A machine that
holds a seed runs `git-veil export-pin <repo-id> --output <pin-file>`. The
pin-file travels out of band, never through the repository. The target
machine runs `git-veil trust --import <pin-file>`. Three consistency checks
tie the pin-file to the repository's committed key and metadata.

The pin lives in the local key store, outside the repository. It is never
committed, so every machine pins for itself.

The keyring of collaborator public keys in `.git-veil/keyring` is signed by
the trusted key. git-veil verifies the signature before any encryption,
decryption, or keyring change. Every gated command fails closed. Without a
pin, or with a signature that does not verify, nothing is touched.

The key store and its pins are the trust boundary for every repository that
uses that store. Do not share one store across repositories that do not
trust each other. Set `GIT_VEIL_HOME` to isolate a project's keys from your
default `$HOME/.git-veil` (for example `GIT_VEIL_HOME=~/keys/project-a`).
`--key-store` overrides both for one-off use.

## Key store permissions

The key store is checked the way gpg checks `~/.gnupg`. The store directory
and the private files (`identities.txt`, `signing-keys.txt`) must not be
readable or writable by group or other. git-veil never changes permissions on
files it did not create.

If the check fails, git-veil exits with code 30 and names the paths and modes
at fault. Fix them with `chmod`. To accept the current state instead, run
`git-veil trust-permissions`. It pins the exact `(path, mode)` pairs, and a
later change fails again. To bypass the check for one command, use
`--dangerously-skip-permissions-check` or set `GIT_VEIL_SKIP_PERMISSIONS=1`.

## Exit codes

Failures exit with documented codes, not an anonymous 1: trust failures are
10–13, missing keys 20–22, unsafe permissions 30, gitignore collisions 40–41,
crypto failures 60–63, and policy/path refusals 70–71. `git-veil error-codes`
prints the full table with names and meanings; the specification is in
[docs/design.md](docs/design.md).

## Quick start (solo)

Solo, git-veil is a backup of your secret material that lives alongside
the code. Every clone carries the ciphertexts. A build or deployment
script reveals on its own key.

You need two keys before you start (see [Key setup](#key-setup) below):

- an X25519 private key for encryption, made with `age-keygen`
- an Ed25519 signing key for the keyring. This is not an `age` key, and no
  `age` tool makes it. Make it with `openssl`, as shown below.

git-veil generates no keys. It only reads keys you created and own. If a
command needs a key you do not have, it tells you how to make one and how to
back it up.

```sh
git-veil init                                   # create .git-veil/ state
git-veil import my-age-identity.txt             # import your X25519 private key into the local key store
git-veil show-repo-id                           # print the repository ID
git-veil trust demo+example@github.com          # pin the owner key by possession proof
git-veil export age1... --output me.pub         # print your public key as a file
git-veil tell example@github.com me.pub         # add yourself to the signed keyring
printf 'API_KEY=hunter2\n' > .env
git-veil add .env                               # track the file (gitignores the plaintext name)
git-veil hide .env                              # encrypt: .env -> .env.secret (plaintext deleted)
git add .gitignore .git-veil/keyring .git-veil/tracked.json .git-veil/trust.json .env.secret
git commit -m "Add encrypted secrets"
git-veil reveal .env                            # decrypt back when you need the plaintext
```

The `.secret` ciphertext files are standard `age`-encrypted blobs. You can
verify interoperability with any `age`-compatible tool:

```sh
# git-veil encrypted this file. The age CLI decrypts it.
age -d -i my-age-identity.txt .env.secret

# The age CLI encrypted this file. git-veil decrypts it.
echo "test" | age -r age1... -o .env.secret && git-veil cat .env
```

## Name the file you are working with

Every `git-veil hide` and `git-veil reveal` names its file(s). There is no
bare form: the command acts on exactly the paths you give it. Naming keeps
the diff to what you touched and the decrypted plaintexts to your working
set, which matters most when the repository gains collaborators:

```sh
git-veil reveal .env    # restore one file
... edit .env ...
git-veil hide .env      # re-encrypt one file; every other ciphertext is untouched
```

Name the files explicitly; see
[docs/two-collaborators.md](docs/two-collaborators.md).

## The hide gate: allow

`hide` encrypts to every key in the keyring, so everyone in the ring can
decrypt. The tracked file list, `.git-veil/tracked.json`, is committed and
unsigned, which means anyone with write access to the repository can
nominate a path in it. Before it first-encrypts a path, `hide` stops and
asks, as an error code and never as a blocking prompt: are you sure this
file is one you want to share with the others in the keyring? The refusal
is exit code 72, and it names the paths.

You answer with `git-veil allow`:

```sh
$ git-veil hide deploy.env
error: refusing to hide: paths are tracked but were never allowed for encryption on this machine. tracked.json may have been modified by someone else. Allow the paths deliberately if the tracking is wanted. Error code 72. The offending tracked paths:
  deploy.env
$ git-veil allow deploy.env
allowed 1 files
$ git-veil hide deploy.env
Encrypted: deploy.env
Deleted plaintext: deploy.env
files hidden
```

The answer is recorded in your key store, keyed to this clone's trust pin
and your git user, so it is cached per clone per git username. Once
recorded, an allowance survives manifest changes and never needs
re-recording.

Three things keep the gate out of the way:

- Name your files. `git-veil add .env` records the allowance too, so a
  path you added on this machine never asks.
- Re-encryption needs no allowance. A tracked path whose `.secret`
  ciphertext is already committed is established, and any machine holding
  the pin re-encrypts it. That is what keeps rotation working on a fresh
  clone.
- Many checkouts with no common git email: the record keys on
  `git config user.email`, so you allow once per email.

`reveal` is never gated. Decryption needs only keyring membership.

## Installation

Prebuilt binaries are attached to every [GitHub release](https://github.com/prompt-cult/git-veil/releases):

```sh
# Linux x86_64 example. macOS binaries sit beside it in the same release.
curl -sLO https://github.com/prompt-cult/git-veil/releases/latest/download/git-veil-linux-x86_64
echo "$(curl -sL https://github.com/prompt-cult/git-veil/releases/latest/download/git-veil-linux-x86_64.sha256)  git-veil-linux-x86_64" | sha256sum -c -
chmod +x git-veil-linux-x86_64 && sudo mv git-veil-linux-x86_64 /usr/local/bin/git-veil
```

`cargo binstall git-veil` resolves the same release assets (manifest wired
into Cargo.toml). `cargo install git-veil` and a Homebrew tap are planned.

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

git-veil uses two kinds of key:

- [`age`][age] X25519 keys for encryption
- an Ed25519 key for signing the keyring. You make this one with `openssl`.

You need both. git-veil generates neither, because a key the tool created
would be a key you never backed up. Create each key once with a standard
tool, then back up the private half. A note in your password manager is
enough.

### Create an X25519 private key (for encryption/decryption)

Use any `age` key generator - `age-keygen` (from the [`age`][age-cli] CLI) or
`rage-keygen` (from [`rage`][rage]):

```sh
umask 077
age-keygen -o my-age-identity.txt
# Output includes:
#   # public key: age1...    your X25519 public key. Share it.
#   AGE-SECRET-KEY-1...       your X25519 private key. Keep it secret. Back it up.
```

The X25519 public key (`age` recipient), the `age1...` line, is safe to share
with collaborators. The X25519 private key (`age` identity), the
`AGE-SECRET-KEY-1...` line, is never committed. Without a backup of it, your
ciphertexts are unrecoverable.

`git-veil import my-age-identity.txt` copies it into the local key store. The
file may contain other lines; `#` comment lines like `age-keygen`'s are
skipped.

### Create an Ed25519 signing key (for keyring signing)

The repository owner also needs an Ed25519 keypair for signing the keyring.
This key is not an `age` key, and no `age` tool makes it. You make it with
`openssl`, and you back it up:

```sh
umask 077
openssl genpkey -algorithm ED25519 -out "$HOME/.git-veil/ed25519.pem"

# The seed. tell and removeperson read it. 64 hex characters.
openssl pkey -in "$HOME/.git-veil/ed25519.pem" -outform DER \
  | tail -c 32 | xxd -p -c 32 > "$HOME/.git-veil/signing-keys.txt"

# The verifying key. Commit this file. git-veil trust checks your seed against it.
openssl pkey -in "$HOME/.git-veil/ed25519.pem" -pubout -outform DER \
  | tail -c 32 | xxd -p -c 32 > owner.verifying
```

The signing-key file format is one 64-hex-character Ed25519 seed per line in
`<key store>/signing-keys.txt`. tell/removeperson sign with the key whose
verifying fingerprint is pinned for the repository. Commands that
need a missing key exit with a documented code (`git-veil error-codes`)
after printing how to create and back it up.

`owner.verifying` holds the 64-hex public half. Commit it to the repository.
`git-veil trust` checks your seed against it, and `trust --import`
cross-checks it. Committing it is safe. It is public material, and on its own
it can never pin anything.

## Commands

git-veil is a command-line tool in the style of git-secret. It encrypts with
`age`. The algorithms are the same kind many tools use. The key formats and
the workflow differ. One payoff is a smaller binary.

| Command          | Purpose                                                                 |
|------------------|-------------------------------------------------------------------------|
| `init`           | Initialize git-veil state (`.git-veil/`) in the current repository        |
| `import`         | Import your X25519 private key file(s) into the git-veil key store       |
| `export`         | Export an X25519 public key from the local key store                    |
| `removekey`      | Remove a key from the local key store (destructive, local-only)         |
| `trust`          | Pin the repository owner's key by possession proof, or import a pin-file (per machine) |
| `export-pin`     | Export this repository's pin-file for import on a machine without the signing key |
| `tell`           | Add a collaborator's public key to the keyring and re-sign it           |
| `removeperson`   | Remove a collaborator from the keyring and re-sign it                   |
| `add`            | Track files for encryption (auto-gitignores plaintext names; records the allowance on this machine) |
| `allow`          | Allow files for encryption on this machine (answers `hide`'s exit-72 question, cached per clone per git user) |
| `remove`         | Untrack files (deletes the sibling `.secret` unless `--keep-ciphertext`) |
| `list`           | List all tracked files                                                  |
| `hide`           | Encrypt the named tracked files to the keyring and DELETE the plaintexts (`hide --all` runs the ring-change ceremony: the gated whole-manifest pass; `--keep-plaintext` keeps the plaintexts; refuses when a `.secret` path is git-ignored; asks the exit-72 allowance question before first-encrypting a path you did not allow) |
| `reveal`         | Decrypt the named tracked files back to plaintext (never gated) |
| `cat`            | Decrypt a single tracked file to stdout                                 |
| `unhide`         | Decrypt one tracked file back to plaintext (ciphertext kept)             |
| `changes`        | Report where plaintext differs from the last hidden version             |
| `show-repo-id`   | Show the repository ID derived from the git remote push URL             |
| `whoami`         | Show the principal git-veil will use                        |
| `verify-keyring` | Verify the keyring signature against the pinned trusted key             |
| `list-keys`      | List keyring keys after verifying the keyring signature                 |
| `clean`          | Remove the `.git-veil` state directory (`--yes` required when data would be lost) |
| `trust-permissions` | Acknowledge the key store's current (path, mode) pairs as trusted     |
| `error-codes`    | List every documented exit code with its name and meaning               |
| `completions`    | Emit a shell completion script for the given shell to stdout            |
| `manpages`       | Write roff man pages (`git-veil.1` plus one per subcommand) to a directory |

Run `git-veil help` for the list of commands and `git-veil help <command>` for
a workflow discussion with examples. Rendered man pages live in `docs/man/`.

## Tutorials

Step-by-step guides are in `docs/`:

- Solo developer: [docs/solo.md](docs/solo.md)
- Two collaborators: [docs/two-collaborators.md](docs/two-collaborators.md)
- Joining user: [docs/joining.md](docs/joining.md)
- Departing user: [docs/departing.md](docs/departing.md)
- Migrating from git-secret: [docs/migrating-from-git-secret.md](docs/migrating-from-git-secret.md)
- Migrating from git-crypt: [docs/migrating-from-git-crypt.md](docs/migrating-from-git-crypt.md)

[docs/design.md](docs/design.md) specifies how repository identity, trust
anchoring, key validity, crash safety and path safety work.

## Compatibility with `age` and `rage`

git-veil's `.secret` ciphertext files are standard `age`-encrypted blobs
(age-encryption.org/v1). They are fully interoperable with the reference
[`age`][age-cli] CLI and the Rust [`rage`][rage] CLI:

- A file encrypted by git-veil can be decrypted by `age -d -i private-key.txt file.secret`
- A file encrypted by `age -r age1... file` can be decrypted by `git-veil reveal`
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
