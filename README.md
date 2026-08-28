# git-gpg

git-gpg is a git-secret work-alike: a tool for storing encrypted secrets in a
git repository, written in Rust. It is inspired by git-secret (which is written
in bash) yet compiles against the pure-Rust [`pgp` crate][pgp] rather than
scripting or forking the `gpg` CLI — all OpenPGP operations happen in-process.

[pgp]: https://crates.io/crates/pgp

## Trust model

Each repository is identified by a repository ID derived from its git remote
push URL, e.g. `git@github.com:example/demo.git` gives `demo+example@github.com`
(run `git-gpg show-repo-id` to print it). The repository owner's signing key is
verified and pinned per machine with `git-gpg trust`; the pin lives in the
local key store outside the repository and is never committed, so every
collaborator (including the owner on a fresh clone) must run `trust`
themselves. The keyring of collaborator public keys in `.git-gpg/keyring` is
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

The binary lands at `target/release/git-gpg`.

Man pages and shell completions are generated from the CLI definition itself:

```sh
git-gpg manpages docs/man             # write roff pages into docs/man
git-gpg completions zsh > "${fpath[1]}/_git-gpg"   # bash, zsh or fish, to stdout
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
git-gpg init                                   # create .git-gpg/ state
git-gpg import my-private-key.asc              # armoured PRIVATE key into the local key store
git-gpg show-repo-id                           # print the repository ID
gpg --armor --export example@github.com > me.pub
git-gpg trust demo+example@github.com me.pub   # verify and pin the signing key
git-gpg tell example@github.com me.pub         # add yourself to the signed keyring
echo .env >> .gitignore                        # ignore the plaintext name
git-gpg add .env                               # track the file
git-gpg hide                                   # encrypt: .env -> .env.secret, plaintext deleted
git add .gitignore .git-gpg/keyring .git-gpg/tracked.json .git-gpg/trust.json .env.secret
git commit -m "Add encrypted secrets"
git-gpg reveal                                 # decrypt back when you need the plaintext
```

The `.secret` ciphertext files sit beside where the plaintext was and are
meant to be committed, so a fresh clone stays decryptable by every keyring
member.

## Commands

| Command          | Purpose                                                                 |
|------------------|-------------------------------------------------------------------------|
| `init`           | Initialize git-gpg state (`.git-gpg/`) in the current repository        |
| `import`         | Import your private key(s) into the git-gpg key store                   |
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
| `whoami`         | Show the identity and key store git-gpg will use                        |
| `verify-keyring` | Verify the keyring signature against the pinned trusted key             |
| `list-keys`      | List keyring keys after verifying the keyring signature                 |
| `clean`          | Remove the `.git-gpg` state directory (`--yes` required when data would be lost) |
| `completions`    | Emit a shell completion script for the given shell to stdout            |
| `manpages`       | Write roff man pages (`git-gpg.1` plus one per subcommand) to a directory |

Run `git-gpg help` for the list of commands, `git-gpg help <command>` for a
workflow discussion with examples, and `git-gpg <command> --help` for flags.
Run `git-gpg help <command>` to learn more about any command above. Rendered
man pages live in `docs/man/`.

## Tutorials

Step-by-step guides are in `docs/`:

- Solo developer: [docs/solo.md](docs/solo.md)
- Two collaborators: [docs/two-collaborators.md](docs/two-collaborators.md)
- Joining user: [docs/joining.md](docs/joining.md)
- Departing user: [docs/departing.md](docs/departing.md)

## Compatibility with git-secret

git-gpg does NOT maintain compatibility with git-secret's cryptographic
material: a repository's `.secret` files, keyring and trust state written by
git-secret are not readable by git-gpg, and vice versa. Use one tool
consistently within any given repository.

## License

GPL-3.0-or-later (see the `license` field in [Cargo.toml](Cargo.toml)).
