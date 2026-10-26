# Joining an existing team repository

You are the new person. This page separates what you run from what the
owner must have run first. Most "it doesn't work" cases are an owner step
that has not happened yet.

Example throughout: repository `git@github.com:example/demo.git`, your
email `newcomer@example.com`, owner key `example@github.com`.

## What you need from the team

1. The repository URL (so you can clone).
2. The pin-file for this repository. The owner exports it with
   `git-veil export-pin` on a machine holding the signing key, and sends it
   to you out of band, for example over ssh. It is never committed to the
   repository.

That is all. You print the repository ID yourself after cloning (step 3).
You create your own X25519 private key yourself (step 2). git-veil
generates no keys. A key it made would be a key you never backed up.
In the following, `age` refers to the open source `age` encryption tooling,
which may be installed separately to securely create and maintain
cryptographic keys outside of the git repo; the `git-veil` software uses the
Rust `rage` library to work with the keys.

## What the owner must do FIRST (not you)

You can only reveal files that were encrypted after you were added. You
can only pin from a pin-file the owner exported. The owner runs this on
their machine, which holds the signing key:

```sh
$ git-veil export-pin demo+example@github.com --output /tmp/demo.pin
pin-file written to /tmp/demo.pin
owner key fingerprint: f722e9afe322ac443cbc4c69dc236b5a03afa81f86011726b2a7285c173b63de
import it on the target machine with: git-veil trust --import /tmp/demo.pin
$ git-veil tell newcomer@example.com newcomer.pub
added newcomer@example.com to the keyring
note: the keyring changed on this machine. A ring-change pass is due: every tracked ciphertext still needs re-encryption to the current keyring.
```

Send the owner your X25519 public key first. Create an X25519 private key
(`age` identity) as in step 1 of [solo.md](solo.md). git-veil has no key
generation. Import the key with `git-veil import newcomer-age-identity.txt`.
Send the `age1...` public key line it printed, or run
`git-veil export age1... --output newcomer.pub`.

The owner then transfers `/tmp/demo.pin` to you out of band, for example
with `scp`. The owner reads you the printed owner key fingerprint. A voice
call is ideal. Compare it with the fingerprint recorded in the repository's
committed `.git-veil/trust.json` before you import (step 4).

Then, and this is critical, the owner delivers the ring-change pass. The
keyring changed, so every tracked ciphertext is encrypted to a keyring
that does not include you:

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
$ git add .git-veil/keyring .env.secret deploy.env.secret
$ git commit -m "Add newcomer to keyring and re-encrypt"
$ git push
```

The pass re-encrypts every tracked file that has a plaintext on disk,
which is what a rotation is for: `reveal` restores the plaintexts, and
the pass deletes them again. One pass consumes the stamp `tell` wrote.
Run it twice and the second run refuses with exit code 70, because the
change was already delivered. For day-to-day work the owner names files
instead; see [two-collaborators.md](two-collaborators.md).

If the owner skips the ring-change pass, your reveal later fails with
`decryption failed. This ciphertext was not encrypted to your key …`.

## What YOU run

### 1. Clone and set your principal

```sh
$ git clone git@github.com:example/demo.git
$ cd demo
$ git config user.email newcomer@example.com
```

What happened. You cloned the ciphertext plus `.git-veil/`, which holds
keyring, trust.json and tracked.json. Decrypting commands resolve your
principal from `git config user.email`. You can also pass `--email`
explicitly.

### 2. Import your own X25519 private key

```sh
$ git-veil import newcomer-age-identity.txt
+ imported: age192a9fdj0l2gv0wfhqvtv8hj8ha8gvdcpgx8rw2wsdnrkcsttr5jq8n7q3n
Summary: 1 imported, 0 skipped
```

What happened. Your X25519 private key, the `AGE-SECRET-KEY-1...` line,
sits in the per-machine key store `$HOME/.git-veil/identities.txt`. It is
never committed, and it is created mode 0600. Import only your own key. The
owner's public half arrives with the clone inside `.git-veil/` as
`.git-veil/owner.verifying`. The pin-file from the team (step 4) is what lets
you pin it. If you have not created a private key yet, exit code 21 prints
the `age-keygen` recipe. Back the private key up. Without it the
ciphertexts are unrecoverable.

### 3. Print the repository ID

```sh
$ git-veil show-repo-id
Repository ID: demo+example@github.com
Remote: origin
Push URL: git@github.com:example/demo.git
```

What happened. The ID is derived from the remote push URL, not from your
own email. `trust` re-derives and cross-checks it, so a typo fails loudly.
For a non-`origin` remote, add `--remote <name>`.

### 4. Import the pin-file - per machine

```sh
$ git-veil trust --import ~/demo.pin
trusted the repository owner key
pinned this repository owner key on this machine
warning: no CODEOWNERS file covers the .git-veil directory. Trust anchor changes are not review gated on the platform.
```

What happened. Your machine holds no signing key. It never needs one.
`trust --import` ran three mandatory consistency checks. The pin-file's
repository ID matches the one derived from your remote. Its verifying key
exactly matches the repository's committed `.git-veil/owner.verifying`. Its
fingerprint matches the owner fingerprint recorded in the committed
`.git-veil/trust.json`. All three agreed, so the key was pinned in your
`$HOME/.git-veil`, outside the repository. Any mismatch is a hard refusal.
One of the two channels is compromised. The pin-file path must live outside
the repository. An in-repo pin-file is exactly the self-supplied anchor the
model refuses. Before importing, compare the fingerprint the owner read to
you with the one in `.git-veil/trust.json`. That human check is the
out-of-band anchor.

### 5. Check who is in the keyring

```sh
$ git-veil list-keys
keyring signature verified and made by the pinned trusted key
Keys in keyring:
  example@github.com f16cbd29abdf10be29c866b943ec014d2b69312371f7f4a323e1caeccb6a35db
  alice@example.com ef8782d2038bd96851a455eb183dd8a31edb6aca728857d74e493c973e71ca54
  newcomer@example.com b99513f38695d87f9bd565735aa9070ce66b39930405fab69d5519a765cbaaa4

Total: 3 keys
```

What happened. The keyring signature verified against your fresh pin, and
you are listed. If your entry is missing, the owner has not run `tell` yet.
Nothing on your side can fix that.

### 6. Reveal
```sh
$ git-veil reveal .env deploy.env
keyring signature verified
keys in keyring: 3
Decrypted: .env
Decrypted: deploy.env
files revealed
```

What happened. Every tracked file's `.secret` ciphertext was decrypted to
its plaintext path. The `.secret` files stay in place. `cat .env` prints to
stdout instead, without touching disk state. `unhide .env` does one file in
place. `changes` shows where your plaintext drifted from the last hidden
version.

## Failure shapes worth knowing

Run `git-veil error-codes` for the full table; the ones you will actually
meet as a newcomer:

- `no trust pin exists on this machine for repository identity … derived
   from remote …. See the trust documentation.` (exit code 11). You have
   not pinned this repository on this machine. The message names its
   derived repository identity and the remote it came from. Import the
   owner's pin-file (step 4).
- `user not found in the keyring. Check the principal, or ask the owner
   to add it` (exit code 22). The owner has not run `tell`, or has not
   pushed the updated keyring. Run `git pull` first.
- `decryption failed. This ciphertext was not encrypted to your key and
   no stanza in it is addressed to your X25519 public key` (exit code 60).
   The owner told you but did not deliver the ring-change pass, or your
   clone is missing the re-encrypted ciphertexts.
   Run `git pull`.
- `no X25519 private key …` (exit code 21). Your key store lacks your
   private key. The message prints the creation and backup recipe. Redo
   step 2.

## Daily use

Identical to any other member. See [solo.md](solo.md) section 6 for the
edit, `changes`, `hide`, commit, `reveal` cycle, and name the files you
work with: `git-veil hide .env` churns one ciphertext instead of the
whole manifest.

`hide` asks one question before it first-encrypts a path you did not add
on this machine: exit code 72, naming the path. Answer it with
`git-veil allow <path>`. Paths whose `.secret` ciphertext is already
committed need no allowance, so re-hiding after a rotation never asks.
`reveal` is never gated: decryption needs only keyring membership. Check
with the owner before re-hiding a shared repo. `hide` encrypts to the
whole current keyring, and deletes plaintexts by default.
`--keep-plaintext` keeps them.
