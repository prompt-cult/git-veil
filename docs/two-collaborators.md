# Two collaborators

The owner (`example@github.com`) shares a repository with a collaborator
(`alice@example.com`), remote `git@github.com:example/demo.git`, repository
ID `demo+example@github.com`. Each person has their own machine, their own
`$HOME/.git-veil` key store, and their own keys. In the following, `age`
refers to the open source `age` encryption tooling, which may be installed
separately to securely create and maintain cryptographic keys outside of the
git repo; the `git-veil` software uses the Rust `rage` library to work with
the keys. git-veil generates **no**
keys: each person creates their own X25519 private key (`age` identity) with
`age-keygen` or `rage-keygen`, and the owner additionally creates an
Ed25519 signing key (`openssl`) - see step 1 of
[docs/solo.md](solo.md). Exporting public keys needs no external tool:
each person runs `git-veil export <public-key> --output <file>` from
their own key store.

## Part 1 - the owner sets the repository up

Steps 1–5 of [docs/solo.md](solo.md) cover this in detail; the shape is:

```sh
# one-time key creation (back the private halves up):
age-keygen -o my-age-identity.txt
umask 077
openssl genpkey -algorithm ED25519 -out "$HOME/.git-veil/ed25519.pem"
openssl pkey -in "$HOME/.git-veil/ed25519.pem" -outform DER \
  | tail -c 32 | xxd -p -c 32 > "$HOME/.git-veil/signing-keys.txt"
openssl pkey -in "$HOME/.git-veil/ed25519.pem" -pubout -outform DER \
  | tail -c 32 | xxd -p -c 32 > owner.verifying

git-veil init
git-veil import my-age-identity.txt
git-veil trust demo+example@github.com  # possession proof: seed matches owner.verifying
git-veil tell example@github.com my-age-identity.txt    # the owner must be in the keyring too
git-veil add .env && git-veil hide
git add .gitignore .git-veil .env.secret && git commit -m "Add encrypted secrets"
git push
```

## Part 2 - the key handoff (the only manual exchange)

Public keys travel as plain text files over any channel you
both trust. **Alice** creates her X25519 private key (`age` identity)
exactly as in step 1 of [docs/solo.md](solo.md), imports it into her key
store, and sends the public key encoding to the owner:

```sh
age-keygen -o alice-age-identity.txt      # prints: # public key: age1...
git-veil import alice-age-identity.txt
git-veil export age1... --output alice.pub   # or just send `age-keygen`'s printed public key line
```

**The owner** verifies out of band that `alice.pub` really is Alice's key
(read the public key encoding or its fingerprint to her over a voice call,
or use any channel an attacker cannot rewrite), then adds her to the
keyring:

```sh
$ git-veil tell alice@example.com alice.pub
✓ Added alice@example.com to keyring
```

What just happened: the keyring signature was verified against the pinned
owner key before the change; a canary was test-encrypted to `alice.pub` so
a key that cannot encrypt is never signed in; the keyring was re-signed
with the owner's Ed25519 key. Telling the same email twice updates the
entry instead of duplicating it.

**Important:** telling Alice does not change ciphertext that already
exists. Files hidden before she was told were encrypted only to the
owner's key. To bring her in, the owner re-hides (hide only encrypts
plaintexts present on disk, so reveal first if everything is currently
hidden):

```sh
git-veil reveal && git-veil hide
git add .git-veil/keyring .env.secret
git commit -m "Add alice to keyring and re-hide"
git push
```

The owner also exports the repository's pin-file for Alice - she holds no
signing key, so the pin-file is the only way she can pin:

```sh
$ git-veil export-pin demo+example@github.com --output /tmp/demo.pin
pin-file written to /tmp/demo.pin
owner key fingerprint: 22fb3bcb…
import it on the target machine with: git-veil trust --import /tmp/demo.pin
```

The owner transfers `/tmp/demo.pin` to Alice OUT OF BAND (e.g. `scp`)  - 
never committed to the repository - and reads her the printed
fingerprint so she can compare it with the one recorded in the committed
`.git-veil/trust.json` before importing. She does **not** need any
private key of the owner's.

## Part 3 - Alice clones and decrypts

```sh
$ git clone git@github.com:example/demo.git
$ cd demo
$ git config user.email alice@example.com
$ git-veil import alice-age-identity.txt
+ imported: age19302…daea (1a2b3c4d5e6f7a8b)
Summary: 1 imported, 0 skipped
```

She imports only her OWN X25519 private key into her local key store
(exit code 21 tells anyone missing one exactly how to create and back it
up). Then
she pins the owner key - this is per machine, and her machine holds no
signing key, so she imports the pin-file the owner sent her:

```sh
$ git-veil trust --import ~/demo.pin
✓ Trusted key for demo+example@github.com (fingerprint: 22fb3bcb…)
✓ Pinned 22fb3bcb… for demo+example@github.com on this machine
```

What just happened: `trust --import` checked that the pin-file's
repository ID matches her remote, that its verifying key exactly matches
the repository's committed `owner.verifying`, and that its fingerprint
matches the owner fingerprint recorded in the committed
`.git-veil/trust.json` - three channels, all mandatory. The pin lives in
her `$HOME/.git-veil`, outside the repository; the committed
`.git-veil/trust.json` is attacker-writable, so her local pin is the real
anchor. A pin-file path inside the repository is refused outright.

Now she can decrypt:

```sh
$ git-veil reveal
✓ Keyring signature verified
Signed by fingerprint: 22fb3bcb…
Repository ID: demo+example@github.com
Keys in keyring: 2
Decrypted: .env
✓ Files revealed
$ git-veil cat .env        # peek to stdout; touches no disk state
```

## Who can decrypt what

- Every `hide` produces ONE ciphertext carrying one stanza for
  every key in the signed keyring - any keyring member can reveal.
- The keyring (`.git-veil/keyring`, committed) is signed by the owner's
  key. Every gated command verifies that signature against the local pin
  before touching anything, so a keyring edited by a non-owner fails
  closed.
- Pinning is per machine. A collaborator who gets a new laptop imports a
  freshly exported pin-file there (the owner runs `export-pin` and
  transfers it out of band).
- The owner's own `reveal` uses the owner key; the collaborator's uses
  theirs. Neither ever sees the other's private key.
- The reveal error `user not found in the keyring. Check the principal,
  or ask the owner to add it` means the owner
  has not yet done Part 2's re-hide-and-push.

## Handy checks on either side

```sh
git-veil list-keys        # who is in the keyring right now
git-veil whoami           # which principal this machine resolves to
git-veil changes          # which tracked files differ from last hide
```
