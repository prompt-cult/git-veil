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
owner key fingerprint: ad2468b2394c184e79f1f972f5a1f6939e1ba2187e9ccdb4154ec356f50550a8
import it on the target machine with: git-veil trust --import /tmp/demo.pin
$ git-veil tell newcomer@example.com newcomer.pub
added newcomer@example.com to the keyring
note: existing ciphertext does not include the new collaborator. Hide again to re-encrypt all tracked files to the current keyring.
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

Then, and this is critical, the owner re-hides. Files hidden before you
were told were not encrypted to your key:

```sh
$ git-veil reveal
$ git-veil hide
Encrypted: .env
Deleted plaintext: .env
files hidden
$ git add .git-veil/keyring .env.secret
$ git commit -m "Add newcomer to keyring and re-hide"
$ git push
```

If the owner skips the re-hide, your reveal later fails with
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
+ imported: age1pu5aefgjq753cqp6ayuamc2h0ynupzy96pt6rj4rvm42rd8z8aysnhk76u
Summary: 1 imported, 0 skipped
```

What happened. Your X25519 private key, the `AGE-SECRET-KEY-1...` line,
sits in the per-machine key store `$HOME/.git-veil/identities.txt`. It is
never committed, and it is created mode 0600. Import only your own key. The
owner's public half arrives with the clone as the committed
`owner.verifying` file. The pin-file from the team (step 4) is what lets
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
warning: no CODEOWNERS file covers owner.verifying and the .git-veil directory. Trust anchor changes are not review gated on the platform.
```

What happened. Your machine holds no signing key. It never needs one.
`trust --import` ran three mandatory consistency checks. The pin-file's
repository ID matches the one derived from your remote. Its verifying key
exactly matches the repository's committed `owner.verifying`. Its
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
  example@github.com ad2468b2394c184e79f1f972f5a1f6939e1ba2187e9ccdb4154ec356f50550a8
  newcomer@example.com ea0ab7b15666042b7e0d000b04354e866d6806a79675456cfc68e06162819b80

Total: 2 keys
```

What happened. The keyring signature verified against your fresh pin, and
you are listed. If your entry is missing, the owner has not run `tell` yet.
Nothing on your side can fix that.

### 6. Reveal
```sh
$ git-veil reveal
keyring signature verified
keys in keyring: 2
Decrypted: .env
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
   The owner told you but did not re-hide, or you are on an old commit.
   Run `git pull`.
- `no X25519 private key …` (exit code 21). Your key store lacks your
   private key. The message prints the creation and backup recipe. Redo
   step 2.

## Daily use

Identical to any other member. See [solo.md](solo.md) section 6 for the
edit, `changes`, `hide`, commit, `reveal` cycle. Check with the owner
before re-hiding a shared repo. `hide` encrypts to the whole current
keyring, and deletes plaintexts by default. `--keep-plaintext` keeps them.
