# Two collaborators

The owner (`example@github.com`) shares a repository with a collaborator
(`alice@example.com`), remote `git@github.com:example/demo.git`, repository
ID `demo+example@github.com`. Each person has their own machine, their own
`$HOME/.git-gpg` key store, and their own key pair. Both sides need gpg
(or any OpenPGP tool) to generate keys — git-gpg itself has **no** key
generation. Exporting public keys needs no gpg: each person runs
`git-gpg export <email> --output <file>` from their own key store (below,
after their key is imported; `gpg --armor --export` works too).

## Part 1 — the owner sets the repository up

Steps 1–8 of [docs/solo.md](solo.md) cover this in detail; the shape is:

```sh
gpg --batch --pinentry-mode loopback --passphrase '' \
  --quick-generate-key "Example Owner <example@github.com>" ed25519 sign never
gpg --batch --pinentry-mode loopback --passphrase '' \
  --quick-add-key "$(gpg --with-colons --list-keys example@github.com \
  | awk -F: '/^fpr:/{print $10; exit}')" cv25519 encr never
gpg --armor --export-secret-keys example@github.com > key.asc
gpg --armor --export example@github.com > owner.pub

git-gpg init
git-gpg import key.asc
git-gpg trust demo+example@github.com owner.pub   # pins the owner key on this machine
git-gpg tell example@github.com owner.pub         # the owner must be in the keyring too
git-gpg add .env && git-gpg hide
git add .gitignore .git-gpg .env.secret && git commit -m "Add encrypted secrets"
git push
```

## Part 2 — the key handoff (the only manual exchange)

Public keys travel as armoured `.pub` files over any channel you both
trust. **Alice** generates her key pair exactly as in step 1 of
[docs/solo.md](solo.md) (primary + encryption subkey, with her own email),
then imports her private key into her key store and exports her public
key from it, and sends the file to the owner:

```sh
git-gpg import alice-private-key.asc
git-gpg export alice@example.com --output alice.pub
```

**The owner** verifies out of band that `alice.pub` really is Alice's key
(read the fingerprint to her over a voice call, or use any channel an
attacker cannot rewrite), then adds her to the keyring:

```sh
$ git-gpg tell alice@example.com alice.pub
✓ Added alice@example.com to keyring
```

What just happened: the keyring signature was verified against the pinned
owner key before the change; a canary was test-encrypted to `alice.pub` so
a key without a usable encryption subkey is never signed in; the keyring
was re-signed with the owner's key. Telling the same email twice updates
the entry instead of duplicating it.

**Important:** telling Alice does not change ciphertext that already
exists. Files hidden before she was told were encrypted only to the
owner's key. To bring her in, the owner re-hides (hide only encrypts
plaintexts present on disk, so reveal first if everything is currently
hidden):

```sh
git-gpg reveal && git-gpg hide
git add .git-gpg/keyring .env.secret
git commit -m "Add alice to keyring and re-hide"
git push
```

The owner also hands `owner.pub` to Alice (this is the file `trust` will
pin). She does **not** need any private key of the owner's.

## Part 3 — Alice clones and decrypts

```sh
$ git clone git@github.com:example/demo.git
$ cd demo
$ git config user.email alice@example.com
$ git-gpg import alice-private-key.asc
+ imported: alice@example.com (93021908BAABAD66FE6F00D0A789666FCEA8DAEA)
Summary: 1 imported, 0 skipped
```

She imports only her OWN private key into her local key store. Then she
pins the owner key — this is per machine and the clone cannot carry it:

```sh
$ git-gpg reveal
Error: no local pin for demo+example@github.com (from remote 'origin'); run git-gpg trust demo+example@github.com <keyfile> to pin this repository's key on this machine
```

(That failure is fail-closed working as designed.) Alice runs it
with the repo ID she gets from `git-gpg show-repo-id` and the `owner.pub`
file the owner gave her:

```sh
$ git-gpg show-repo-id
Repository ID: demo+example@github.com
...
$ git-gpg trust demo+example@github.com owner.pub
✓ Trusted key for demo+example@github.com (fingerprint: 22fb3bcb…)
✓ Pinned 22fb3bcb… for demo+example@github.com on this machine
```

What just happened: `trust` re-derived the repo ID from her remote,
checked it matches the argument, verified `owner.pub` carries the
repository email, and pinned the fingerprint in her `$HOME/.git-gpg`. The
committed `.git-gpg/trust.json` is attacker-writable; her local pin is the
real anchor.

Now she can decrypt:

```sh
$ git-gpg reveal
✓ Keyring signature verified
Signed by fingerprint: 22fb3bcb…
Repository ID: demo+example@github.com
Keys in keyring: 2
Decrypted: .env
✓ Files revealed
$ git-gpg cat .env        # peek to stdout; touches no disk state
```

## Who can decrypt what

- Every `hide` produces ONE ciphertext carrying a recipient packet for
  every key in the signed keyring — any keyring member can reveal.
- The keyring (`.git-gpg/keyring`, committed) is signed by the owner's
  key. Every gated command verifies that signature against the local pin
  before touching anything, so a keyring edited by a non-owner fails
  closed.
- `trust` is per machine. A collaborator who gets a new laptop runs
  `trust` again there (they need `owner.pub` — keep a copy with your
  onboarding notes, or have the owner re-send it).
- The owner's own `reveal` uses the owner key; the collaborator's uses
  theirs. Neither ever sees the other's private key.
- The reveal error `user alice@example.com not found in keyring; check
  --email, or ask the owner to add you with git-gpg tell` means the owner
  has not yet done Part 2's re-hide-and-push.

## Handy checks on either side

```sh
git-gpg list-keys        # who is in the keyring right now
git-gpg whoami           # which email/key store this machine resolves to
git-gpg changes          # which tracked files differ from last hide
```
