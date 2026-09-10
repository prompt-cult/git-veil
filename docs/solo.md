# Solo developer setup

You keep secrets in a repository only you can read back. One age identity,
one keyring entry: yours.

Prerequisite: build the binary (`cargo build --release`; it lands at
`target/release/git-veil`), plus two standard tools for the one-time key
creation below: `openssl` (ships with macOS and every Linux) and
`age-keygen` (or `rage-keygen`). git-veil generates **no** keys — a key
the tool made is a key you never backed up, and when your disk dies your
ciphertext dies with it. You create the keys, you own the keys, you back
up the keys.

The examples use the remote `git@github.com:example/demo.git`; substitute
your own remote and emails throughout.

## 1. Create your keys and back them up

Two keys, two jobs: an **age identity** (X25519 — encrypts and decrypts
secrets) and an **Ed25519 signing key** (signs the keyring so a rewritten
keyring is caught on this machine). Neither private half is ever
committed.

```sh
umask 077   # everything created below stays private to you

# The age identity (encryption/decryption):
age-keygen -o my-age-identity.txt
# Output includes:
#   # public key: age1...    (your recipient string — share this)
#   AGE-SECRET-KEY-1...      (your identity — keep this secret)

# The Ed25519 signing key (keyring signing):
openssl genpkey -algorithm ED25519 -out "$HOME/.git-veil/ed25519.pem"
openssl pkey -in "$HOME/.git-veil/ed25519.pem" -outform DER \
  | tail -c 32 | xxd -p -c 32 > "$HOME/.git-veil/signing-keys.txt"

# The verifying key (public half of the signing key — what `trust` pins):
openssl pkey -in "$HOME/.git-veil/ed25519.pem" -pubout -outform DER \
  | tail -c 32 | xxd -p -c 32 > owner.verifying
```

What just happened: `signing-keys.txt` holds the 64-hex-character Ed25519
seed (the last 32 bytes of the key's DER encoding); `owner.verifying`
holds the matching public key, also as hex. **Back both secrets up now** —
the `AGE-SECRET-KEY-1...` line from `my-age-identity.txt` and
`ed25519.pem`/`signing-keys.txt` (the same signing secret in two forms); a
password-manager note holding the strings is a complete backup. Lose the
age identity and every ciphertext is unrecoverable; lose the signing key
and you cannot re-sign the keyring (re-key from scratch).
`owner.verifying` is public: commit it, email it, print it.

## 2. Initialize, import, identify

```sh
$ git-veil init
✓ git-veil initialized
$ git-veil import my-age-identity.txt
+ imported: age1axmf…q5xnw2s (1a2b3c4d5e6f7a8b)
Summary: 1 imported, 0 skipped
$ git-veil show-repo-id
Repository ID: demo+example@github.com
Remote: origin
Push URL: git@github.com:example/demo.git
$ git-veil whoami
Your identity: example@github.com
Key store: /home/you/.git-veil
```

What just happened: `.git-veil/` now holds `keyring`, `trust.json` and
`tracked.json` (init never touches `.gitignore`); your age identity lives
in the per-machine key store `$HOME/.git-veil/identities.txt` (created
mode 0600), never committed — `reveal`, `cat`, `unhide` and `changes`
look their key up there. `show-repo-id` prints the exact repo ID `trust`
wants (it re-derives it from the remote and refuses a mismatch); `whoami`
shows which email decrypting commands will use — from
`git config user.email`, or `--email`.

## 3. Trust your own key

```sh
$ git-veil trust demo+example@github.com owner.verifying
✓ Trusted key for demo+example@github.com (fingerprint: 1a2b3c4d…)
✓ Pinned 1a2b3c4d… for demo+example@github.com on this machine
```

What just happened: the verifying key was parsed, its fingerprint
computed, and **pinned on this machine** in `$HOME/.git-veil/trust-pins/`
— outside the repository, never committed. Every gated command checks the
keyring signature against this pin first and fails closed without it (see
`git-veil error-codes`: a missing pin is exit code 11, a mismatch between
the committed record and your pin is 12). A fresh clone (even yours) has
no pin until you run `trust` there again.

## 4. Put yourself in the keyring

```sh
$ git-veil tell example@github.com my-age-identity.txt
✓ Added example@github.com to keyring
```

What just happened: `hide` encrypts to every key in the signed keyring,
so even solo you must be in it. `tell` found your signing key in the key
store (`signing-keys.txt`; the key whose verifying fingerprint matches
the pin `trust` wrote is used — with several keys present you can pick
explicitly with `--signing-key <index-or-seed>`), verified the existing
keyring signature against your pin, test-encrypted an in-memory canary
to the new key, and signed the updated keyring. The keyring at `.git-veil/keyring`
is committed.

## 5. Track, hide, commit

```sh
$ printf 'API_KEY=hunter2\n' > .env
$ git-veil add .env
file not in .gitignore, adding: .env
Added 1 file(s)
$ git-veil hide
✓ Keyring signature verified
Signed by fingerprint: 1a2b3c4d…
Repository ID: demo+example@github.com
Keys in keyring: 1
Encrypted: .env
✓ Files hidden
$ ls .env .env.secret
.env	.env.secret
```

What just happened: `add` gitignored the plaintext name for you
(git-secret behaviour) and `hide` encrypted `.env` to your key as
`.env.secret`, **keeping the plaintext** — deletion is opt-in with
`--dangerously-delete-plaintext`, and is only reversible with your age
identity. Two guards watch the working tree: if a tracked plaintext is on
disk but not gitignored, `hide` prints a warning (error code 41) because a
blind `git add -A` would commit it; if a `.secret` path is itself
gitignored — e.g. swallowed by a parent-directory rule like `.tmp/` —
`hide` refuses outright (error code 40), because that ciphertext would
silently never reach the repository. Commit the ciphertext and state, not
the plaintext:

```sh
git add .gitignore .git-veil/keyring .git-veil/tracked.json .git-veil/trust.json .env.secret
git commit -m "Add encrypted secrets"
```

Gitignore the plaintext names (`.env`); commit the `.secret` files and
`.git-veil/`. Never gitignore `*.secret` — that would defeat the
fresh-clone decryptability contract.

## 6. The daily cycle

Edit → check → hide → commit → reveal:

```sh
$ git-veil unhide .env          # decrypt one file in place
... edit .env ...
$ git-veil changes .env         # data, not errors:
changed: .env
- API_KEY=hunter2
+ API_KEY=hunter3
1 file(s) with changes
$ git-veil hide                 # re-encrypt (plaintext kept)
$ git add .env.secret && git commit -m "Rotate API key"
$ git-veil reveal               # bring every tracked file back as plaintext
```

What just happened: `unhide` and `reveal` decrypt ciphertext back to the
plaintext path and leave the `.secret` files in place; `changes` decrypts
each ciphertext and diffs it against the plaintext beside it
(`unchanged: …`, `no hidden version: …` and `not present on disk
(hidden): …` appear instead where applicable). To peek without disturbing
anything, `git-veil cat .env` writes the plaintext to stdout only —
neither the plaintext nor the ciphertext on disk is touched.

For the tightest solo posture — no plaintext lingering on disk — run
`git-veil hide --dangerously-delete-plaintext` in the cycle above and
treat `reveal` as the working state you re-hide from.

Because the plaintext's only protection is the `.gitignore` entry, a
pre-commit guard is worth installing:

```sh
cat > .git/hooks/pre-commit <<'EOF'
#!/bin/sh
git-veil list | while read -r f; do
  if [ -f "$f" ] && ! git check-ignore -q "$f"; then
    echo "git-veil: tracked plaintext '$f' is not gitignored; aborting" >&2
    exit 1
  fi
done
EOF
chmod +x .git/hooks/pre-commit
```

## 7. Health checks

```sh
git-veil verify-keyring   # exit 0 only if the signature matches your pin
git-veil list-keys        # who can decrypt, after the same verification
git-veil list             # which files are tracked
git-veil error-codes      # every documented exit code, number and meaning
```

## Key store permissions

git-veil checks its key store (`$GIT_VEIL_HOME` or `$HOME/.git-veil`) the
way gpg checks `~/.gnupg`: the store directory and the private files
(`identities.txt`, `signing-keys.txt`) must not be group- or
world-accessible. It never changes permissions itself. On a violation it
exits with code 30, names the exact paths and modes, and offers the
remedies: `chmod` them right, or — if you accept the risk — record the
current state as trusted:

```sh
git-veil trust-permissions
```

The acknowledgment pins the exact (path, mode) pairs in
`permissions-ack.json`; if the permissions later change to anything else,
git-veil refuses again. `--dangerously-skip-permissions-check` or
`GIT_VEIL_SKIP_PERMISSIONS=1` bypasses the check entirely. These checks
apply to the key store only; files inside your repository working tree are
yours to manage.
