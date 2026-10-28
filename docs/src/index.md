# git-veil

git-veil stores encrypted secrets in a git repository. It is written in Rust.
It encrypts with [`age`][age] (via the pure-Rust [`age` crate][age-crate])
and signs the keyring with [Ed25519][ed25519] (via
[`ed25519-dalek`][dalek]).

In the following, `age` refers to the open source `age` encryption tooling,
which may be installed separately to securely create and maintain
cryptographic keys outside of the git repo; the `git-veil` software uses the
Rust `rage` library to work with the keys.

[age]: https://age-encryption.org
[age-crate]: https://crates.io/crates/age
[ed25519]: https://en.wikipedia.org/wiki/EdDSA#Ed25519
[dalek]: https://crates.io/crates/ed25519-dalek

The ciphertexts it commits are standard `age` files
(age-encryption.org/v1). Any compliant `age` tool can decrypt them,
including the reference [`age`][age-cli] command-line tool and the Rust
[`rage`][rage] command-line tool.

[age-cli]: https://github.com/FiloSottile/age
[rage]: https://github.com/str4d/rage

## Why

Your secret material should be backed up alongside the code. git-veil
encrypts a file in place and commits the ciphertext beside where the
plaintext was. Every clone carries the secrets. The plaintext never has to
leave your machine to reach a build box: a build or deployment script runs
`git-veil reveal` or `git-veil cat` on the box's own key and reads what it
needs.

## How it works

Three ideas carry the whole design.

1. **Encryption in place.** `hide` turns `.env` into `.env.secret`, a
   standard `age` file encrypted to every key in the keyring, and deletes
   the plaintext. You gitignore the plaintext names and commit the
   `.secret` files. `reveal` brings a plaintext back.
2. **A signed keyring.** `.git-veil/keyring` names who can decrypt. It is
   signed with the repository owner's Ed25519 key. Every gated command
   verifies that signature against a pin held in your local key store
   before it touches anything. A keyring edited by a non-owner fails
   closed.
3. **A per-machine pin.** Trust is anchored on each machine by a
   possession proof: you can only pin the owner key on a machine that
   holds the matching signing seed. Machines without the seed import a
   pin-file that travelled out of band. The pin lives outside the
   repository and is never committed.

## The two keys

You need two keys before you start. git-veil generates neither, because a
key the tool created would be a key you never backed up.

- An X25519 private key for encryption, made with `age-keygen` or
  `rage-keygen`. The public half is shared; the private half is never
  committed.
- An Ed25519 signing key for the keyring, needed only by whoever owns the
  repository. This is not an `age` key, and no `age` tool makes it. You
  make it with `openssl`.

Step 1 of the [Solo guide](solo.md) has the exact commands, and the backup
ritual. Do it once, back both private halves up in a password manager, and
you will never lose a ciphertext.

## Getting started

Install the binary first: see [Installation](installation.md). Then, in the
root of a git repository:

```sh
git-veil init                                   # creates .git-veil/ state in the repo
git-veil import private-key.txt                 # your X25519 private key, made by age-keygen
git-veil repo-id                                # prints the ID trust wants, e.g. demo+example@github.com
git-veil trust demo+example@github.com          # possession proof: pins the owner key on this machine
git-veil export age1xxxx                        # your public key string
git-veil add-key example@github.com age1xxxx    # adds you to the signed keyring
printf 'API_KEY=hunter2\n' > .env
git-veil add-file .env                          # tracks it, gitignores the plaintext name
git-veil hide .env                              # encrypts to the keyring; deletes the plaintext
git add .gitignore .git-veil .env.secret
git commit -m "Add encrypted secrets"
git-veil reveal .env                            # brings it back when you need to edit
```

Every command's behaviour, flags and exit codes are documented in
[Commands](commands.md). Two refusals are worth knowing before they
surprise you: `init` will not reset a repository with established trust,
and `hide` asks before it first-encrypts a path someone else nominated in
the tracking manifest. You answer with
[allow](commands.md#allow).

## The daily cycle

Name the file you are working with. Every `hide` and `reveal` names its
file(s); the command acts on exactly the paths you give it, so the commit
shows what you actually touched:

```sh
git-veil reveal .env          # decrypt one file in place to edit
... edit .env ...
git-veil changes              # diff plaintext against the last hidden version
git-veil hide .env            # re-encrypt one file; every other ciphertext is untouched
git add .env.secret && git commit -m "Rotate API key"
```

`cat .env` peeks at stdout without touching disk state. `list` shows what
is tracked, `list-keys` shows who can decrypt, `verify-keys` and
`changes` are the health checks. The [Solo guide](solo.md) walks the whole
loop with real output.

## Where next

- [Solo](solo.md) - the solo setup, end to end, including a build box that
  reveals on its own key.
- [Team](team.md) - sharing a repository: joining, day-to-day collaboration
  and departing.
- [Commands](commands.md) - every command documented: options, behaviour
  and exit codes.
- [Troubleshooting](troubleshooting.md) - key store permissions, the trust
  and rotate failure stories, and recovery.
- [Design specification](design.md) - how identity, trust anchoring, key
  validity, crash safety and path safety work.
