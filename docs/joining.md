# Joining an existing team repository

You are the new person. This page separates what **you** run from what the
**owner** must have run first — most "it doesn't work" cases are an owner
step that has not happened yet.

Example throughout: repository `git@github.com:example/demo.git`, your
email `newcomer@example.com`, owner key `example@github.com`.

## What you need from the team

1. The repository URL (so you can clone).
2. The **owner's verifying key file** (e.g. `owner.verifying` — the hex
   Ed25519 public key), via a channel where it cannot be silently swapped.

That is all. The repository ID you print yourself after cloning (step 3).
Your own age identity you create yourself (step 2) — git-veil generates no
keys, and a key it made would be a key you never backed up.

## What the owner must do FIRST (not you)

You can only reveal files that were encrypted after you were added. The
owner runs, on their machine:

```sh
$ git-veil tell newcomer@example.com newcomer.pub
✓ Added newcomer@example.com to keyring
```

(You send them your recipient string first: create an age identity as in
step 1 of [docs/solo.md](solo.md) with any key generator — git-veil has
**no** key generation — import it with `git-veil import
newcomer-age-identity.txt`, and send the `age1...` recipient line it
printed, or `git-veil export age1... --output newcomer.pub`.)

Then — critical — the owner re-hides, because files hidden before you were
told do not have you as a recipient:

```sh
$ git-veil reveal
$ git-veil hide
✓ Keyring signature verified
...
Encrypted: .env
✓ Files hidden
$ git add .git-veil/keyring .env.secret
$ git commit -m "Add newcomer to keyring and re-hide"
$ git push
```

If the owner skips the re-hide, your reveal later fails with
`decryption failed: this ciphertext was not encrypted to your key …`.

## What YOU run

### 1. Clone and set your git identity

```sh
$ git clone git@github.com:example/demo.git
$ cd demo
$ git config user.email newcomer@example.com
```

What just happened: you cloned ciphertext plus `.git-veil/` (keyring,
trust.json, tracked.json). Decrypting commands resolve your identity from
`git config user.email` — or pass `--email` explicitly.

### 2. Import your own age identity

```sh
$ git-veil import newcomer-age-identity.txt
+ imported: age1a1b2… (1a2b3c4d5e6f7a8b)
Summary: 1 imported, 0 skipped
```

What just happened: your age identity (the `AGE-SECRET-KEY-1...` line)
sits in the per-machine key store `$HOME/.git-veil/identities.txt` (never
committed, mode 0600). Import ONLY your own key; the owner's public half
arrives as the `owner.verifying` file. If you have not created an identity
yet, exit code 21 prints the `age-keygen` recipe — and back the identity
up; without it the ciphertexts are unrecoverable.

### 3. Print the repository ID

```sh
$ git-veil show-repo-id
Repository ID: demo+example@github.com
Remote: origin
Push URL: git@github.com:example/demo.git
```

What just happened: the ID is derived from the remote push URL, not from
your own email. `trust` re-derives and cross-checks it, so a typo fails
loudly. Non-`origin` remotes: add `--remote <name>`.

### 4. Pin the owner's key — per machine

```sh
$ git-veil trust demo+example@github.com owner.verifying
✓ Trusted key for demo+example@github.com (fingerprint: 22fb3bcb…)
✓ Pinned 22fb3bcb… for demo+example@github.com on this machine
```

What just happened: the verifying key was parsed (it must be a valid
Ed25519 public key, and the repo id must match the one derived from your
remote) and its fingerprint was pinned in YOUR `$HOME/.git-veil`, outside
the repository. Every gated command verifies the keyring signature against
this pin and fails closed without it (exit code 11). A new clone or
machine has no pin — run `trust` there again.

### 5. Check who is in the keyring

```sh
$ git-veil list-keys
✓ Keyring signature verified (signed by pinned trusted key)
Keys in keyring:
  example@github.com (22fb3bcb…)
  newcomer@example.com (1a2b3c4d…)
Total: 2 keys
```

What just happened: the keyring signature verified against your fresh pin
and you are listed. If your entry is missing, the owner has not run `tell`
yet — nothing on your side can fix that.

### 6. Reveal

```sh
$ git-veil reveal
✓ Keyring signature verified
Signed by fingerprint: 22fb3bcb…
Repository ID: demo+example@github.com
Keys in keyring: 2
Decrypted: .env
✓ Files revealed
```

What just happened: every tracked file's `.secret` ciphertext was
decrypted to its plaintext path; the `.secret` files stay in place. `cat
.env` prints to stdout instead without touching disk state; `unhide .env`
does one file in place; `changes` shows where your plaintext drifted from
the last hidden version.

## Failure shapes worth knowing

Run `git-veil error-codes` for the full table; the ones you will actually
meet as a newcomer:

- `no local pin for …` (exit code 11) — you have not run `trust` on this
  machine (step 4).
- `user newcomer@example.com not found in keyring; …` (exit code 22) — the
  owner has not run `tell` (or has not pushed the updated keyring;
  `git pull` first).
- `decryption failed: this ciphertext was not encrypted to your key …`
  (exit code 60) — the owner told you but did not re-`hide` (or you are on
  an old commit; `git pull`).
- `no age identity …` (exit code 21) — your key store lacks your identity;
  the message prints the creation and backup recipe. Redo step 2.

## Daily use

Identical to any other member — see [docs/solo.md](solo.md) section 6 for
the edit → `changes` → `hide` → commit → `reveal` cycle. Check with the
owner before re-hiding a shared repo: `hide` encrypts to the whole current
keyring (and deletes plaintexts only with `--dangerously-delete-plaintext`).
