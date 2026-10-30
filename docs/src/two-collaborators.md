# Two collaborators

The owner (`example@github.com`) shares a repository with a collaborator
(`alice@example.com`), remote `git@github.com:example/demo.git`, repository
ID `demo+example@github.com`. Each person has their own machine, their own
`$HOME/.git-veil` key store, and their own keys. In the following, `age`
refers to the open source `age` encryption tooling, which may be installed
separately to securely create and maintain cryptographic keys outside of the
git repo; the `git-veil` software uses the Rust `rage` library to work with
the keys. git-veil generates no keys: each person creates their own X25519
private key, and the owner also creates an Ed25519 signing key. The recipes
are step 1 of [solo.md](solo.md). Exporting public keys needs no external
tool; see [Commands - export](commands.md#export).

## Part 1 - the owner sets the repository up

The repo owner must follow the solo steps for "One-time repo owner key creation". 

## Part 2 - the collaborator key handoff (the only manual exchange)

Public keys travel as plain text over any channel you
both trust. Alice creates her X25519 private key (`age` identity)
exactly as in step 1 of [solo.md](solo.md), imports it into her key
store, and sends the public key encoding to the owner:

```sh
age-keygen -o alice-age-identity.txt      # prints the age1xxxx public key line
git-veil import alice-age-identity.txt
git-veil export age1xxxx                  # prints the public key line again, to copy
```

The owner verifies out of band that the pasted string really is Alice's key.
Read the public key encoding or its fingerprint to her over a voice call,
or use any channel an attacker cannot rewrite. Then the owner adds her to
the keyring:

```sh
$ git-veil add-key alice@example.com age1xxxx
added alice@example.com to the keyring
note: the keyring has changed. To re-encrypt to the updated keyring, run the rotate command.
```

What happened. The keyring signature was verified against the pinned owner
key before the change, and Alice was signed in. The mechanics, including
the canary test, are in [Commands - add-key](commands.md#add-key).

Important. Adding Alice does not change ciphertext that already exists.
Files hidden before she joined were encrypted only to the owner's key. To
bring her in, the owner delivers the ring-change pass with `git-veil
rotate`; see [Commands - rotate](commands.md#rotate).

```sh
git-veil rotate
git add .git-veil/keyring .env.secret
git commit -m "Add alice to keyring and re-encrypt"
git push
```

The commit carries a fresh `.secret` for each tracked file, now encrypted
to Alice's key too. See [Commands - rotate](commands.md#rotate). For
day-to-day work, name only the files you touched; see Part 4.

The owner also exports the repository's pin-file for Alice. She holds no
signing key, so the pin-file is the only way she can pin:

```sh
$ git-veil export-pin demo+example@github.com > /tmp/demo.pin
owner key fingerprint: f722e9afe322ac443cbc4c69dc236b5a03afa81f86011726b2a7285c173b63de (stderr)
```

The owner transfers `/tmp/demo.pin` to Alice out of band, for example with
`scp`. The pin-file is never committed to the repository. The owner reads
her the printed fingerprint so she can compare it with the one recorded in
the committed `.git-veil/trust.json` before importing. She does not need
any private key of the owner's.

## Part 3 - Alice clones and decrypts

```sh
$ git clone git@github.com:example/demo.git
$ cd demo
$ git config user.email alice@example.com
$ git-veil import alice-age-identity.txt
+ imported: age1xxxx
Summary: 1 imported, 0 skipped
```

She imports only her own X25519 private key into her local key store. Exit
code 21 tells anyone missing one exactly how to create and back it up. Then
she pins the owner key. Pinning is per machine, and her machine holds no
signing key, so she imports the pin-file the owner sent her:

```sh
$ git-veil trust --import ~/demo.pin
trusted the repository owner key
pinned this repository owner key on this machine
warning: no CODEOWNERS file covers the .git-veil directory. Trust anchor changes are not review gated on the platform.
```

What happened. `trust --import` verified the pin-file against the remote,
the committed verifying key and the committed trust record, then pinned the
owner key in her `$HOME/.git-veil`, outside the repository. The three
mandatory checks are in [Commands - trust](commands.md#trust). The
committed `.git-veil/trust.json` is attacker-writable, so her local pin is
the real anchor.

Now she can decrypt:

```sh
$ git-veil reveal .env
keyring signature verified
keys in keyring: 2
Decrypted: .env
files revealed
$ git-veil cat .env        # peek to stdout. Touches no disk state.
```

## Part 4 - name the files: churn and the allow gate

### Ciphertext churn

Hide covers exactly the files you name. So the team habit is to name
only the files you touched:

```sh
$ git-veil hide .env     # re-encrypt .env only; every other ciphertext is untouched
Encrypted: .env
Deleted plaintext: .env
files hidden
$ git-veil reveal .env   # restore .env only
```

A rotation after `add-key` or `remove-key` is different work: the
ring-change pass, delivered with `git-veil rotate`. See
[Commands - rotate](commands.md#rotate).

### The exit-72 question

`tracked.json` is committed and unsigned, so any repo writer can nominate
a path in it. Before `hide` first-encrypts a path, it asks, as an error
code and never as a blocking prompt: are you sure this file is one you
want to share with the others in the keyring? The refusal is exit code 72
and it names the paths.

Here is the flow with real output. Alice nominated a second file and
pushed the manifest before hiding it:

```sh
$ printf 'DEPLOY_HOST=staging.example.com\nDEPLOY_USER=alice\n' > deploy.env
$ git-veil add-file deploy.env
file not in .gitignore, adding: deploy.env
added 1 files
$ git add .gitignore .git-veil/tracked.json
$ git commit -m "Track deploy.env"
$ git push
```

The owner keeps his own `deploy.env` on disk. He pulls Alice's manifest
change and names the file:

```sh
$ git-veil hide deploy.env
error: refusing to hide: paths are tracked but were never allowed for encryption on this machine. tracked.json may have been modified by someone else. Allow the paths deliberately if the tracking is wanted. Error code 72. The offending tracked paths:
  deploy.env
```

Nothing was encrypted. The question is exactly the right one: `deploy.env`
is a file the owner did not nominate on this machine, and hiding it would
write its contents into a ciphertext every keyring member can read. He
answers with `allow`, then names the file:

```sh
$ git-veil allow deploy.env
allowed 1 files
$ git-veil hide deploy.env
Encrypted: deploy.env
Deleted plaintext: deploy.env
files hidden
$ git add .gitignore .git-veil/tracked.json deploy.env.secret
$ git commit -m "Allow deploy.env and hide it"
$ git push
```

The answer is cached, so a later hide of the same path does not ask again:

```sh
$ git-veil reveal deploy.env
keyring signature verified
keys in keyring: 2
Decrypted: deploy.env
files revealed
$ git-veil hide deploy.env
Encrypted: deploy.env
Deleted plaintext: deploy.env
files hidden
```

Three facts keep the gate out of the way, and the rules, including the
cases that never ask, are in [Commands - allow](commands.md#allow):
`add-file` implies `allow`, re-encryption of an established ciphertext
never asks, and the record keys on your git user (`git config user.email`).

## Who can decrypt what

- Every `hide` produces one ciphertext any keyring member can reveal.
- The keyring is signed by the owner's key, and every gated command
  verifies that signature against the local pin before touching anything,
  so a keyring edited by a non-owner fails closed.
- Pinning is per machine. A collaborator who gets a new laptop imports a
  freshly exported pin-file there (the owner runs `export-pin` and
  transfers it out of band).
- The owner's own `reveal` uses the owner key; the collaborator's uses
  theirs. Neither ever sees the other's private key.
- Before `hide` first-encrypts a path you did not allow on this machine,
  it asks; see [Commands - allow](commands.md#allow).
- The reveal error `user not found in the keyring. Check the principal,
  or ask the owner to add it` means the owner
  has not yet done Part 2's re-encrypt-and-push.

## Handy checks on either side

```sh
git-veil list-keys        # who is in the keyring right now
git-veil whoami           # which principal this machine resolves to
git-veil changes          # which tracked files differ from last hide
```
