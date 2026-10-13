# git-veil

Secret management for git repositories: files are encrypted in place with
`age`-family X25519 encryption, the keyring that names who can decrypt is
Ed25519-signed, and trust is pinned per machine by a possession proof.

> In the following, `age` refers to the open source `age` encryption
> tooling, which may be installed separately to securely create and maintain
> cryptographic keys outside of the git repo. The `git-veil` software uses
> the Rust `rage` library to work with the keys.

**Run `git-veil --help` first.** Every command documents its own workflow,
examples and failure codes; this page only walks the first mile.

## 1. Install

Grab a release binary from the
[releases page](https://github.com/prompt-cult/git-veil/releases), verify its
`.sha256`, put it on your `PATH`. Man pages ship in every release as
`git-veil-man-pages.tar.gz`.

## 2. Secure a first file (the obvious one: `.env`)

```
git-veil init                                   # creates .git-veil/ state in the repo
git-veil import private-key.txt                 # your X25519 private key (age identity), made by age-keygen
git-veil trust <repo-id>                        # possession proof on the machine holding the signing key
git-veil add .env                               # tracks it, records intent, gitignores it
git-veil hide                                   # encrypts; deletes the plaintext by default
git-veil reveal                                 # brings it back when you need to edit
```

Your keys never live in the repository. `git-veil init` refuses to reset an
already-trusted repo; `git-veil trust` refuses a typo'd repo id.

## 3. Running solo

The loop is `reveal` → edit → `hide`. Hidden state is boring on purpose:
`git-veil list-keys`, `git-veil changes`, `git-veil verify-keyring` and
`git-veil show-repo-id` tell you what is in the ring, what changed, and who
the repo claims to be.

## 4. Working as a team

```
git-veil tell alice@example.com alice.recipient   # add a collaborator, re-sign the keyring
git-veil removeperson alice@example.com           # remove them, re-sign
git-veil hide                                     # re-encrypt to the new ring (rotation)
```

A machine without the signing key pins trust by importing a pin-file:
`git-veil export-pin <repo-id> --output pin` on the signing machine, move it
out of band, `git-veil trust --import pin` on the target. See the
[Solo](solo.html) and [Team](team.html) guides.

## 5. Where the details live

The tool, not this page: `git-veil <command> --help` for every command, the
man pages in each release, the full [Solo](solo.html) and [Team](team.html)
guides, and the [design specification](design.html) for what the code
actually enforces. Less is more here; the help never falls behind the
binary you are running.
