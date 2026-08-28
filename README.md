# git-veil

git-veil is a git-secret work-alike: a tool for storing encrypted secrets in a
git repository, written in Rust. It is inspired by git-secret (which is written
in bash) yet compiles against the pure-Rust [`pgp` crate][pgp] rather than
scripting or forking the `gpg` CLI — all OpenPGP operations happen in-process.

[pgp]: https://crates.io/crates/pgp

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
is not advised.

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

## Quick start (solo)

Prerequisite: an OpenPGP key pair from any tool (e.g. `gpg --quick-generate-key`).
Note that `trust` requires the signing key to carry the email identity matching
the repository ID — with the remote above, that is `example@github.com`.

```sh
git-veil init                                   # create .git-veil/ state
git-veil import my-private-key.asc              # armoured PRIVATE key into the local key store
git-veil show-repo-id                           # print the repository ID
gpg --armor --export example@github.com > me.pub
git-veil trust demo+example@github.com me.pub   # verify and pin the signing key
git-veil tell example@github.com me.pub         # add yourself to the signed keyring
echo .env >> .gitignore                        # ignore the plaintext name
git-veil add .env                               # track the file
git-veil hide                                   # encrypt: .env -> .env.secret, plaintext deleted
git add .gitignore .git-veil/keyring .git-veil/tracked.json .git-veil/trust.json .env.secret
git commit -m "Add encrypted secrets"
git-veil reveal                                 # decrypt back when you need the plaintext
```

The `.secret` ciphertext files sit beside where the plaintext was and are
meant to be committed, so a fresh clone stays decryptable by every keyring
member.

## Commands

| Command          | Purpose                                                                 |
|------------------|-------------------------------------------------------------------------|
| `init`           | Initialize git-veil state (`.git-veil/`) in the current repository        |
| `import`         | Import your private key(s) into the git-veil key store                   |
| `export`         | Export an armoured public key from the local key store                  |
| `removekey`      | Remove a key from the local key store (destructive, local-only)         |
| `trust`          | Verify and pin the repository owner's signing key (per machine)         |
| `tell`           | Add a collaborator's public key to the keyring and re-sign it           |
| `removeperson`   | Remove a collaborator from the keyring and re-sign it                   |
| `add`            | Track files for encryption                                              |
| `remove`         | Untrack files (leaves any ciphertext in place)                          |
| `list`           | List all tracked files                                                  |
| `hide`           | Encrypt all tracked files to the keyring and delete the plaintexts      |
| `reveal`         | Decrypt all tracked files back to plaintext                             |
| `cat`            | Decrypt a single tracked file to stdout                                 |
| `unhide`         | Decrypt one tracked file back to plaintext and delete its ciphertext    |
| `changes`        | Report where plaintext differs from the last hidden version             |
| `show-repo-id`   | Show the repository ID derived from the git remote push URL             |
| `whoami`         | Show the identity and key store git-veil will use                        |
| `verify-keyring` | Verify the keyring signature against the pinned trusted key             |
| `list-keys`      | List keyring keys after verifying the keyring signature                 |
| `clean`          | Remove the `.git-veil` state directory (`--yes` required when data would be lost) |
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

## Compatibility with git-secret

git-veil does NOT maintain compatibility with git-secret's cryptographic
material: a repository's `.secret` files, keyring and trust state written by
git-secret are not readable by git-veil, and vice versa. Use one tool
consistently within any given repository.

## License

GPL-3.0-or-later (see the `license` field in [Cargo.toml](Cargo.toml)).
