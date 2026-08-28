# Joining an existing team repository

You are the new person. This page separates what **you** run from what the
**owner** must have run first — most "it doesn't work" cases are an owner
step that has not happened yet.

Example throughout: repository `git@github.com:example/demo.git`, your
email `newcomer@example.com`, owner key `example@github.com`.

## What you need from the team

1. The repository URL (so you can clone).
2. The **owner's public key file** (e.g. `owner.pub` — an armoured
   OpenPGP public key), via a channel where it cannot be silently swapped.

That is all. The repository ID you print yourself after cloning (step 3).

## What the owner must do FIRST (not you)

You can only reveal files that were encrypted after you were added. The
owner runs, on their machine:

```sh
$ git-gpg tell newcomer@example.com newcomer.pub
✓ Added newcomer@example.com to keyring
```

(You send them your public key first: generate a key pair as in step 1 of
[docs/solo.md](solo.md) with your own email, then `gpg --armor --export
newcomer@example.com > newcomer.pub`. git-gpg has no export command.)

Then — critical — the owner re-hides, because files hidden before you were
told do not have you as a recipient:

```sh
$ git-gpg reveal
$ git-gpg hide
✓ Keyring signature verified
...
Encrypted: .env
✓ Files hidden
$ git add .git-gpg/keyring .env.secret
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

What just happened: you cloned ciphertext plus `.git-gpg/` (keyring,
trust.json, tracked.json). Decrypting commands resolve your identity from
`git config user.email` — or pass `--email` explicitly.

### 2. Import your own private key

```sh
$ git-gpg import newcomer-private-key.asc
+ imported: newcomer@example.com (1A2B3C4D5E6F…)
Summary: 1 imported, 0 skipped
```

What just happened: your private key sits in the per-machine key store
`$HOME/.git-gpg/secret-keys.pgp` (never committed). Import ONLY your own
key; the owner's public half arrives as the `owner.pub` file.

### 3. Print the repository ID

```sh
$ git-gpg show-repo-id
Repository ID: demo+example@github.com
Remote: origin
Push URL: git@github.com:example/demo.git
```

What just happened: the ID is derived from the remote push URL, not from
your own email. `trust` re-derives and cross-checks it, so a typo fails
loudly. Non-`origin` remotes: add `--remote <name>`.

### 4. Pin the owner's key — per machine

```sh
$ git-gpg trust demo+example@github.com owner.pub
✓ Trusted key for demo+example@github.com (fingerprint: 22fb3bcb…)
✓ Pinned 22fb3bcb… for demo+example@github.com on this machine
```

What just happened: the owner key was verified (it must carry the
repository email and be unexpired/unrevoked/signed) and its fingerprint
was pinned in YOUR `$HOME/.git-gpg`, outside the repository. Every gated
command verifies the keyring signature against this pin and fails closed
without it. A new clone or machine has no pin — run `trust` there again.

### 5. Check who is in the keyring

```sh
$ git-gpg list-keys
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
$ git-gpg reveal
✓ Keyring signature verified
Signed by fingerprint: 22fb3bcb…
Repository ID: demo+example@github.com
Keys in keyring: 2
Decrypted: .env
✓ Files revealed
```

What just happened: every tracked file's `.secret` ciphertext was
decrypted to its plaintext path and the ciphertext deleted locally. `cat
.env` prints to stdout instead without touching disk state; `unhide .env`
does one file in place; `changes` shows where your plaintext drifted from
the last hidden version.

## Failure shapes worth knowing

- `no local pin for …` — you have not run `trust` on this machine (step 4).
- `user newcomer@example.com not found in keyring` — the owner has not run
  `tell` (or has not pushed the updated keyring; `git pull` first).
- `decryption failed: this ciphertext was not encrypted to your key …` —
  the owner told you but did not re-`hide` (or you are on an old commit;
  `git pull`).
- `No secret key found for email: …` — your key store lacks your private
  key; redo step 2. Error strings may say `git gpg <cmd>`; the binary is
  spelled `git-gpg`.

## Daily use

Identical to any other member — see [docs/solo.md](solo.md) section 6 for
the edit → `changes` → `hide` → commit → `reveal` cycle. Check with the
owner before re-hiding a shared repo: `hide` encrypts to the whole current
keyring and deletes plaintexts.
