# Two collaborators

The owner (`example@github.com`) shares a repository with a collaborator
(`alice@example.com`), remote `git@github.com:example/demo.git`, repository
ID `demo+example@github.com`. Each person has their own machine, their own
`$HOME/.git-veil` key store, and their own keys. In the following, `age`
refers to the open source `age` encryption tooling, which may be installed
separately to securely create and maintain cryptographic keys outside of the
git repo; the `git-veil` software uses the Rust `rage` library to work with
the keys. git-veil generates no keys. Each person creates their own X25519
private key (`age` identity) with `age-keygen` or `rage-keygen`. The owner
also creates an Ed25519 signing key. That key is not an `age` key, and no
`age` tool makes it. The owner makes it with `openssl`. See step 1 of
[solo.md](solo.md). Exporting public keys needs no external tool. Each
person runs `git-veil export <public-key> --output <file>` from their own
key store.

## Part 1 - the owner sets the repository up

Steps 1–5 of [solo.md](solo.md) cover this in detail. The shape is:

```sh
# One-time key creation. Back up the private halves.
age-keygen -o my-age-identity.txt
umask 077
openssl genpkey -algorithm ED25519 -out "$HOME/.git-veil/ed25519.pem"
openssl pkey -in "$HOME/.git-veil/ed25519.pem" -outform DER \
  | tail -c 32 | xxd -p -c 32 > "$HOME/.git-veil/signing-keys.txt"
openssl pkey -in "$HOME/.git-veil/ed25519.pem" -pubout -outform DER \
  | tail -c 32 | xxd -p -c 32 > owner.verifying

git-veil init
git-veil import my-age-identity.txt
git-veil trust demo+example@github.com  # possession proof. The seed must match owner.verifying
git-veil export age1... --output me.pub
git-veil tell example@github.com me.pub    # the owner must be in the keyring too
git-veil add .env && git-veil hide .env
git add .gitignore .git-veil .env.secret && git commit -m "Add encrypted secrets"
git push
```

## Part 2 - the key handoff (the only manual exchange)

Public keys travel as plain text files over any channel you
both trust. Alice creates her X25519 private key (`age` identity)
exactly as in step 1 of [solo.md](solo.md), imports it into her key
store, and sends the public key encoding to the owner:

```sh
age-keygen -o alice-age-identity.txt      # prints the age1... public key line
git-veil import alice-age-identity.txt
git-veil export age1... --output alice.pub   # or just send the printed public key line
```

The owner verifies out of band that `alice.pub` really is Alice's key.
Read the public key encoding or its fingerprint to her over a voice call,
or use any channel an attacker cannot rewrite. Then the owner adds her to
the keyring:

```sh
$ git-veil tell alice@example.com alice.pub
added alice@example.com to the keyring
note: the keyring changed on this machine. A ring-change pass is due: every tracked ciphertext still needs re-encryption to the current keyring.
```

What happened. The keyring signature was verified against the pinned owner
key before the change. A canary was test-encrypted to `alice.pub`, so a key
that cannot encrypt is never signed in. The keyring was re-signed with the
owner's Ed25519 key. Telling the same email twice updates the entry instead
of duplicating it.

Important. Telling Alice does not change ciphertext that already exists.
Files hidden before she was told were encrypted only to the owner's key. To
bring her in, the owner delivers the ring-change pass. The pass re-encrypts
only tracked files with a plaintext on disk, so reveal the files first:

```sh
git-veil reveal .env && git-veil hide --all
git add .git-veil/keyring .env.secret
git commit -m "Add alice to keyring and re-encrypt"
git push
```

The pass re-encrypts every tracked file that has a plaintext on disk, so
the commit carries a fresh `.secret` for each one, now encrypted to
Alice's key too. One pass consumes the stamp `tell` wrote. For day-to-day
work, name only the files you touched; see Part 4.

The owner also exports the repository's pin-file for Alice. She holds no
signing key, so the pin-file is the only way she can pin:

```sh
$ git-veil export-pin demo+example@github.com --output /tmp/demo.pin
pin-file written to /tmp/demo.pin
owner key fingerprint: f722e9afe322ac443cbc4c69dc236b5a03afa81f86011726b2a7285c173b63de
import it on the target machine with: git-veil trust --import /tmp/demo.pin
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
+ imported: age1k7fgmcxrthltagnlh6hljsdjel0yhwczvzlfysg4d8kmkpha9qnq20ehc3
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
warning: no CODEOWNERS file covers owner.verifying and the .git-veil directory. Trust anchor changes are not review gated on the platform.
```

What happened. `trust --import` checked three things, and all three are
mandatory. The pin-file's repository ID matches her remote. Its verifying
key exactly matches the repository's committed `owner.verifying`. Its
fingerprint matches the owner fingerprint recorded in the committed
`.git-veil/trust.json`. The pin lives in her `$HOME/.git-veil`, outside the
repository. The committed `.git-veil/trust.json` is attacker-writable, so
her local pin is the real anchor. A pin-file path inside the repository is
refused outright.

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

Hide covers exactly the files you name. A whole-manifest pass - `hide
--all`, the ring-change ceremony - changes every `.secret` in the commit,
so a commit where you edited one secret looks like you edited all of them.
Reviewers cannot tell a one-file change from a repo-wide re-encryption
without reading the command that made it. So the team habit is to name
only the files you touched:

```sh
$ git-veil hide .env     # re-encrypt .env only; every other ciphertext is untouched
Encrypted: .env
Deleted plaintext: .env
files hidden
$ git-veil reveal .env   # restore .env only
```

When you mean the whole manifest - a rotation after `tell` or
`removeperson` - the ring-change ceremony owns the pass. `tell` and
`removeperson` stamp a pass as due on this machine when they re-sign the
keyring, and one `hide --all` consumes the stamp. The pass re-encrypts
every tracked file that has a plaintext on disk, so reveal the files
first:

```sh
$ git-veil reveal .env deploy.env
keyring signature verified
keys in keyring: 3
Decrypted: .env
Decrypted: deploy.env
files revealed
$ git-veil hide --all
Encrypted: .env
Encrypted: deploy.env
Deleted plaintext: .env
Deleted plaintext: deploy.env
files hidden
ring-change pass complete: every tracked ciphertext is re-encrypted to the current keyring
```

Without a due stamp, `hide --all` refuses with exit code 70 and names
the repository id: the pass exists to turn a ring change into ciphertext,
and one pass consumes one change. A scoped `hide` never consults the
stamp and never consumes it. See
[docs/design.md](design.md), "The ring-change ceremony".

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
$ git-veil add deploy.env
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

The answer is cached. It lives in the owner's key store, keyed to this
clone's trust pin and his git user, so a later hide of the same path does
not ask again:

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

Three facts keep the gate out of the way:

- `add` implies `allow`. A path you added on this machine never asks.
- Naming files keeps the question small: `git-veil hide deploy.env`
  examines the named files only, and a refusal names only the offenders
  among them. A scoped `hide` of files you named yourself never asks at
  all.
- The record keys on your git user (`git config user.email`). If you use
  many checkouts and do not set a common git email on all of them, you
  allow once per email.

Two more facts: re-encryption of an established ciphertext needs no
allowance, so a path whose `.secret` is already committed is re-encrypted
by any machine holding the pin, which is why rotation on a fresh clone
never asks; and `reveal` is never gated. Alice reveals the file the
moment its ciphertext lands. Decryption needs only keyring membership.

## Who can decrypt what

- Every `hide` produces one ciphertext. It carries one stanza for every
   key in the signed keyring. Any keyring member can reveal.
- The keyring (`.git-veil/keyring`, committed) is signed by the owner's
  key. Every gated command verifies that signature against the local pin
  before touching anything, so a keyring edited by a non-owner fails
  closed.
- Pinning is per machine. A collaborator who gets a new laptop imports a
  freshly exported pin-file there (the owner runs `export-pin` and
  transfers it out of band).
- The owner's own `reveal` uses the owner key; the collaborator's uses
  theirs. Neither ever sees the other's private key.
- `hide` first-encrypts a path only after you allowed it on this machine
  (exit code 72). `reveal` is never gated: decryption needs only keyring
  membership.
- The reveal error `user not found in the keyring. Check the principal,
  or ask the owner to add it` means the owner
  has not yet done Part 2's re-encrypt-and-push.

## Handy checks on either side

```sh
git-veil list-keys        # who is in the keyring right now
git-veil whoami           # which principal this machine resolves to
git-veil changes          # which tracked files differ from last hide
```
