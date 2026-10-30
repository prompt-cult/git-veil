# git-veil

git-veil stores encrypted secrets in a git repository. It is written in Rust.
It encrypt files using [`age`][age] identity keys (via the pure-Rust [`age` crate][age-crate]). The public part of the identies are committed into the git repo. That keyring of `age` public keys are signed with an [Ed25519][ed25519] (via [`ed25519-dalek`][dalek]) key pair you generate using `openssl`.

In the following, `age` refers to the open source `age` encryption tooling,
which may be installed separately to securely create and maintain
cryptographic keys outside of the git repo; the `git-veil` software uses the
Rust `rage` library to work with the keys.

The `age` format is an encryption format designed by Filippo Valsorda.
Thi means that `git-veil`'s ciphertexts are standard `age` encrypted files. Any compliant `age` tool can decrypt them.

[age]: https://age-encryption.org
[age-crate]: https://crates.io/crates/age
[ed25519]: https://en.wikipedia.org/wiki/EdDSA#Ed25519
[dalek]: https://crates.io/crates/ed25519-dalek
[age-cli]: https://github.com/FiloSottile/age
[rage]: https://github.com/str4d/rage

## Why

The point of `git-veil` is that your application deployment secret material is versioned alongside the code. The ciphertexts are committed, so every clone carries the exact secrets that work with that version of the code. The plaintext never has to leave your machine to reach a build box: you simply create a `age` identify file per CI pipeline or per enviroment or per VM. Then your deployment script or your production server can run `git-veil reveal` to use its own `age` identity to decrypt the secrets your code needs. 

Under such a model you should `ssh` into your dev, test and prod environments and run the commadns to create the `age` identity in that environment. You do not need to look at the secret part of the key nor cut and paste it or transmit it. You simply copy the public part of the key and pass it to `git veil add-key`. 

The proceeding paragraphs may read like a very radical idea. Yet consider the alternatives; you have to maintain a system to distribute and backup your deployment secrets. Your author is shocked at how many software platforms (e.g. mobile application tooling, mobile backend) have you commit plaintext certificates into a private git database. Your author has seen and used a lot of enterprise systems were certificts and crypto materials were supposed to be automated. In practice your author has often seen them stepped around:

- Testing the final deployment of production keys into production takes time and efforts and just as you got it right in some test environment does not mean it is going to go right first time in pro. The `git-veil` means that your secret management pipeline is your code depoyment pipeline. 
- The moment doing things "properly" is not "just works" people end up cutting/pasting/emailing the certs, passwords or keys around. The effort of getting your keys securely deployed should not be left at the point when you are under pressure to go live. The effort of `git-veil` is in the initial setup and in learning how to use it. Once you know the drill you can move to a model where your deployment secrets are not being pasted over slack channels. 
- Your author has many times seen crypto materials expiring some months paste go-live and lots of lost time and bad optics on trying to retractively fix the mess. This is why your author added automated testing to the mighty git-secret project. Perfection, and complexity, is the enemy or secure. 
- Your author is concinced that the net result is quite a lot of security theatre and security-by-obsecurity. Or even the worst of all worlds; a central secret management tool that is a concentration risk combined with work around that are pasting around certs when sites go down a year after go-live. 

The aim of `git-veil` is to bring self-soveriegn public-key encryption of your application deployment secrets to the masses. History tells use that it is developer hubris to build your own security tooling. Leave it to the professional cryptographers working in the open with other profession cryptographers. Your author's response to the charge of hubris is to ask that you hold my beer; but first buy me a beer for you to hold. By which I mean raise me a PR and join the discussion. 

## Trust model

Each repository has an ID derived from its git remote push URL. The remote
`git@github.com:example/demo.git` gives the ID `demo+example@github.com`.
Run `git-veil repo-id` to print your repository's ID.

The repository owner's signing key is pinned on each machine. A repository
can never supply its own trust anchor. The only command that pins by
possession proof is `git-veil init <verifying-key>`: it checks the passed-in
verifying key file against the verifying key derived from a seed in the
local signing key store, copies it to the committed
`.git-veil/owner.verifying`, and pins. If no seed matches, init refuses
before anything is written.

Machines without the signing key get their pin by import. A machine that
holds a seed runs `git-veil export-pin <repo-id>`: the pin is printed to
stdout, artifact alone, to pipe straight to the target machine. The pin
travels out of band, never through the repository. The target machine
runs `git-veil trust --import <pin-file>`. Three consistency checks
tie the pin to the repository's committed key and metadata.

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

The key store is checked the way gpg checks `~/.gnupg`: the store directory
and the private files must not be readable or writable by group or other.
git-veil never changes permissions on files it did not create. On a
violation it exits with code 30 and names the paths. The fix, the
deliberate acknowledgment and the one-command bypass are covered in
[docs/src/troubleshooting.md](docs/src/troubleshooting.md#key-store-permissions-exit-30).

## Exit codes

Failures exit with documented codes, not an anonymous 1: trust failures are
10–13, missing keys 20–22, unsafe permissions 30, gitignore collisions 40–41,
crypto failures 60–63, and policy/path refusals 70–71. `git-veil error-codes`
prints the full table with names and meanings; the specification is in
[docs/src/design.md](docs/src/design.md).

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
git-veil init ~/.git-veil/owner.verifying        # create .git-veil/ state, pin the owner key
git-veil import my-age-identity.txt             # import your X25519 private key into the local key store
git-veil repo-id                                # print the repository ID
git-veil export age1xxxx                        # print your public key string
git-veil add-key example@github.com age1xxxx    # paste the string, adds you to the signed keyring
printf 'API_KEY=hunter2\n' > .env
git-veil add-file .env                          # track the file (gitignores the plaintext name)
git-veil hide .env                              # encrypt: .env -> .env.secret (plaintext deleted)
git add .gitignore .git-veil .env.secret
git commit -m "Add encrypted secrets"
git-veil reveal .env                            # decrypt back when you need the plaintext
```

The `.secret` ciphertext files are standard `age`-encrypted blobs. You can
verify interoperability with any `age`-compatible tool:

```sh
# git-veil encrypted this file. The age CLI decrypts it.
age -d -i my-age-identity.txt .env.secret

# The age CLI encrypted this file. git-veil decrypts it.
echo "test" | age -r age1xxxx -o .env.secret && git-veil cat .env
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
[docs/src/two-collaborators.md](docs/src/two-collaborators.md).

## The hide gate: allow

The tracked file list, `.git-veil/tracked.json`, is committed and unsigned,
so anyone with write access to the repository can nominate a path in it.
Before `hide` first-encrypts a path you never allowed on this machine, it
refuses and asks, and you answer with `git-veil allow`. The full walkthrough
with real output is in
[docs/src/two-collaborators.md](docs/src/two-collaborators.md); the mechanics,
including the cases that never ask, are in
[docs/src/commands.md](docs/src/commands.md#allow).

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
#   # public key: age1xxxx    your X25519 public key. Share it.
#   AGE-SECRET-KEY-1...       your X25519 private key. Keep it secret. Back it up.
```

The X25519 public key (`age` recipient), the `age1xxxx` line, is safe to share
with collaborators. The X25519 private key (`age` identity), the
`AGE-SECRET-KEY-1...` line, is never committed. Without a backup of it, your
ciphertexts are unrecoverable.

`git-veil import my-age-identity.txt` copies it into the local key store. The
file may contain other lines; `#` comment lines like `age-keygen`'s are
skipped.

### Create an Ed25519 signing key (for keyring signing)

The repository owner also needs an Ed25519 keypair for signing the keyring.
This key is not an `age` key, and no `age` tool makes it. You make it with
`openssl`, and you back it up. Everything lives in your key store, outside
any repository; `git-veil init <verifying-key>` copies the verifying key
into a repository when you initialize it:

```sh
umask 077
openssl genpkey -algorithm ED25519 -out "$HOME/.git-veil/ed25519.pem"

# The seed. add-key and remove-key read it. 64 hex characters.
openssl pkey -in "$HOME/.git-veil/ed25519.pem" -outform DER \
  | tail -c 32 | xxd -p -c 32 > "$HOME/.git-veil/signing-keys.txt"

# The verifying key, in your key store. Commit the copy init made, never this.
# git-veil init checks your seed against it before it writes anything.
openssl pkey -in "$HOME/.git-veil/ed25519.pem" -pubout -outform DER \
  | tail -c 32 | xxd -p -c 32 > "$HOME/.git-veil/owner.verifying"
```

The signing-key file format is one 64-hex-character Ed25519 seed per line in
`<key store>/signing-keys.txt`. add-key/remove-key sign with the key whose
verifying fingerprint is pinned for the repository. Commands that
need a missing key exit with a documented code (`git-veil error-codes`)
after printing how to create and back it up.

`.git-veil/owner.verifying` holds the 64-hex public half. Commit it to the
repository beside the rest of the `.git-veil/` state.
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
| `forget`         | Delete a key from the local key store (destructive, local-only)         |
| `trust`          | Pin the repository owner's key by possession proof, or import a pin-file (per machine) |
| `export-pin`     | Print this repository's pin (stdout, `--output` optional) for import on a machine without the signing key |
| `add-key`        | Add a collaborator's public key to the keyring and re-sign it           |
| `remove-key`     | Remove a collaborator from the keyring and re-sign it                   |
| `add-file`       | Track files for encryption (auto-gitignores plaintext names; records the allowance on this machine) |
| `allow`          | Allow files for encryption on this machine (answers `hide`'s allowance question) |
| `remove-file`    | Untrack files (the sibling `.secret` ciphertext is deleted by default) |
| `list`           | List all tracked files                                                  |
| `hide`           | Encrypt the named tracked files to the keyring and DELETE the plaintexts |
| `rotate`         | Deliver the due ring-change pass: re-encrypt every tracked ciphertext to the current keyring, in memory, plaintexts untouched |
| `reveal`         | Decrypt the named tracked files back to plaintext (never gated) |
| `cat`            | Decrypt a single tracked file to stdout                                 |
| `changes`        | Report where plaintext differs from the last hidden version             |
| `repo-id`        | Show the repository ID derived from the git remote push URL             |
| `whoami`         | Show the principal git-veil will use                        |
| `verify-keys`    | Verify the keyring signature against the pinned trusted key             |
| `list-keys`      | List keyring keys after verifying the keyring signature                 |
| `clean`          | Remove the `.git-veil` state directory (guards against data loss) |
| `trust-permissions` | Acknowledge the key store's current (path, mode) pairs as trusted     |
| `error-codes`    | List every documented exit code with its name and meaning               |
| `completions`    | Emit a shell completion script for the given shell to stdout            |
| `manpages`       | Write roff man pages (`git-veil.1` plus one per subcommand) to a directory |

Run `git-veil help` for the list of commands and `git-veil help <command>` for
a workflow discussion with examples. Rendered man pages live in `docs/man/`.

## Tutorials

Step-by-step guides are in `docs/`:

- Solo developer: [docs/src/solo.md](docs/src/solo.md)
- Two collaborators: [docs/src/two-collaborators.md](docs/src/two-collaborators.md)
- Joining user: [docs/src/joining.md](docs/src/joining.md)
- Departing user: [docs/src/departing.md](docs/src/departing.md)
- Migrating from git-secret: [docs/src/migrating-from-git-secret.md](docs/src/migrating-from-git-secret.md)
- Migrating from git-crypt: [docs/src/migrating-from-git-crypt.md](docs/src/migrating-from-git-crypt.md)

[docs/src/design.md](docs/src/design.md) specifies how repository identity, trust
anchoring, key validity, crash safety and path safety work.

## Compatibility with `age` and `rage`

git-veil's `.secret` ciphertext files are standard `age`-encrypted blobs
(age-encryption.org/v1). They are fully interoperable with the reference
[`age`][age-cli] CLI and the Rust [`rage`][rage] CLI:

- A file encrypted by git-veil can be decrypted by `age -d -i private-key.txt file.secret`
- A file encrypted by `age -r age1xxxx file` can be decrypted by `git-veil reveal`
- Keys generated by `age-keygen` or `rage-keygen` can be imported with `git-veil import`
- Keys generated by git-veil can be used by `age` and `rage` directly

The cross-implementation test suite (`tests/interop.rs`) exercises every
permutation of encrypt/decrypt/keygen between git-veil, `age`, and `rage`.

## Compatibility with git-secret

git-veil does NOT maintain compatibility with git-secret's cryptographic
material: a repository's `.secret` files, keyring and trust state written by
git-secret are not readable by git-veil, and vice versa. Use one tool
consistently within any given repository.

## Responsible Disclosure

Contract the copyright holder at firstname at firstname surname dot org. 

## License

This is a FOSS security tool where I would like folks to share fixes. If you 
want to privately use your own copy somewhere be my guest. If you want to 
distribute or share then I am insisting your make the code public for inspection so that we can all benefit. 

SPDX-License-Identifier: GPL-3.0-or-later
git-veil Copyright © 2026 Simon J. Massey
