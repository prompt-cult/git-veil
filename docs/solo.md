# Solo developer setup

You keep secrets in a repository that only you can read back. You need one
X25519 private key. You are the only entry in the keyring.

The point of this setup: your secret material is backed up alongside the
code. The ciphertexts are committed, so every clone carries the secrets.
A build or deployment script on another machine reveals on its own key,
with no plaintext ever travelling to it by another route.

To follow this guide you need the binary built (`cargo build --release`; it
lands at `target/release/git-veil`) and two standard tools for the one-time
key creation below. `openssl` ships with macOS and every Linux. `age-keygen`
comes with the `age` tooling. `rage-keygen` also works.

git-veil generates no keys. A key the tool made is a key you never backed up,
and when your disk dies your ciphertext dies with it. You create the keys.
You own the keys. You back up the keys.

In the following, `age` refers to the open source `age` encryption tooling,
which may be installed separately to securely create and maintain
cryptographic keys outside of the git repo; the `git-veil` software uses the
Rust `rage` library to work with the keys.

The examples use the remote `git@github.com:example/demo.git`; substitute
your own remote and emails throughout.

## 1. Create your keys and back them up

Two keys, two jobs. The X25519 private key (an `age` identity, made with the
`age` tooling) encrypts and decrypts secrets. The Ed25519 signing key signs
the keyring, so a rewritten keyring is caught on this machine. The signing
key is not an `age` key, and no `age` tool makes it. You make it with
`openssl` in the next block. Neither private half is ever committed.

The block below writes the verifying key into `.git-veil/`, so run
`git-veil init` first if you have not (step 2 creates the directory; the
`mkdir -p` here makes the recipe order-free). Run everything at the
repository worktree root.

```sh
umask 077   # everything created below stays private to you

# The X25519 private key, for encryption and decryption.
age-keygen -o my-age-identity.txt
# Output includes:
#   # public key: age1xxxx    your X25519 public key. Share it.
#   AGE-SECRET-KEY-1...      your X25519 private key. Keep it secret.

# The Ed25519 signing key, for signing the keyring. Made with openssl, not age.
openssl genpkey -algorithm ED25519 -out "$HOME/.git-veil/ed25519.pem"
openssl pkey -in "$HOME/.git-veil/ed25519.pem" -outform DER \
  | tail -c 32 | xxd -p -c 32 > "$HOME/.git-veil/signing-keys.txt"

# The verifying key, the public half of the signing key. Into .git-veil/,
# committed with the rest of the git-veil state.
mkdir -p .git-veil
openssl pkey -in "$HOME/.git-veil/ed25519.pem" -pubout -outform DER \
  | tail -c 32 | xxd -p -c 32 > .git-veil/owner.verifying
```

What happened. `signing-keys.txt` holds the 64-hex-character Ed25519 seed.
It is the last 32 bytes of the key's DER encoding. `.git-veil/owner.verifying`
holds the matching public key, also as hex.

Back both secrets up now. The backup is the `AGE-SECRET-KEY-1...` line from
`my-age-identity.txt`, plus `ed25519.pem` and `signing-keys.txt`. The last
two hold the same signing secret in two forms. A password-manager note
holding the strings is a complete backup. Lose the X25519 private key and
every ciphertext is unrecoverable. Lose the signing key and you cannot
re-sign the keyring. You would have to re-key from scratch.

`.git-veil/owner.verifying` is public. Commit it. It is the candidate that
`trust` proves your seed against.

## 2. Initialize, import, identify

```sh
$ git-veil init
git-veil initialized
suggestion: protect the trust-critical paths with a CODEOWNERS file so changes to the trust anchor are review gated on the platform
add a CODEOWNERS file at the repository root, or under the platform directory, and give the trust-critical paths an owner, for example:
.git-veil/ @the-repository-owner
$ git-veil import my-age-identity.txt
+ imported: age1xxxx
Summary: 1 imported, 0 skipped
$ git-veil repo-id
Repository ID: demo+example@github.com
Remote: origin
Push URL: git@github.com:example/demo.git
$ git-veil whoami
Your principal: example@github.com
```

What happened. `.git-veil/` now holds `keyring`, `trust.json`,
`tracked.json` and, once you have run the step 1 recipe, `owner.verifying`,
the verifying key they all protect. Your X25519 private key lives in the
per-machine key store, never committed. The behaviour and options of
`init`, `import`, `repo-id` and `whoami` are in
[Commands](commands.md#setup).

You should add or edit a CODEOWNERS file that protects the `.git-veil/`
folder as owned by you. The suggestion above is the line to add. On a
platform that enforces CODEOWNERS with branch protection, a changed trust
anchor becomes a review-gated pull request instead of a silent push. The
file goes at the repository root, or under the platform directory
(`.github/CODEOWNERS` on GitHub).

## 3. Trust your own key (possession proof)

```sh
$ git-veil trust demo+example@github.com
trusted the repository owner key
pinned this repository owner key on this machine
warning: no CODEOWNERS file covers the .git-veil directory. Trust anchor changes are not review gated on the platform.
```

What happened. `trust` proved possession of your signing key and
pinned the owner fingerprint on this machine, outside the repository. The
fixed-derivation owner fingerprint was recorded in `.git-veil/trust.json`.
Commit that file alongside the verifying key. The mechanics of the proof
are in [Commands - trust](commands.md#trust).

Every gated command checks the keyring signature against this pin first and
fails closed without it. A fresh clone, even yours, has no pin until you
run `trust` there again. A machine without the signing seed cannot pin
directly at all. It imports a pin-file you export with `git-veil export-pin`.
See [joining.md](joining.md) for that flow.

## 4. Put yourself in the keyring

```sh
$ age-keygen -y my-age-identity.txt
age1xxxx
$ git-veil add-key example@github.com age1xxxx
added example@github.com to the keyring
note: the keyring has changed. To re-encrypt to the updated keyring, run the rotate command.
```

What happened. Your public key is the `age1xxxx` line `age-keygen`
printed when you created the identity in step 1; `age-keygen -y` prints it
again from the identity file any time you need it. `add-key` verified the
keyring against your pin and signed you in; the argument after the email is
the public key string. See [Commands - add-key](commands.md#add-key).

What happened. `hide` encrypts to every key in the signed keyring, so even
solo you must be in it. `add-key` verified the keyring against your pin and
signed you in; the argument after the email is the public key string that
`export` prints. See [Commands - add-key](commands.md#add-key).

The note stamps a ring-change pass as due on this machine. On a fresh
repository nothing is hidden yet, so the first `hide` of `.env` encrypts
to the current ring from the start, and you can leave the pass
undelivered. See [Commands - rotate](commands.md#rotate).

## 5. Track, hide, commit

```sh
$ printf 'API_KEY=hunter2\n' > .env
$ git-veil add-file .env
file not in .gitignore, adding: .env
added 1 files
$ git-veil hide .env
Encrypted: .env
Deleted plaintext: .env
files hidden
$ ls .env .env.secret
ls: .env: No such file or directory
.env.secret
```

What happened. `add-file` gitignored the plaintext name for you, as
git-secret does. It also recorded the path in the allowance store in your
key store: `add-file` implies `allow`, so the first `hide` runs without a
question. (The
question exists for paths someone else nominated; it is described in the
[two-collaborators guide](two-collaborators.md).) `hide` encrypted `.env`
to your key as `.env.secret` and deleted the plaintext. Pass
`--keep-plaintext` to keep it. `reveal` brings the plaintext back. That is
the only recovery.

Two guards watch the working tree: `hide` warns when a tracked plaintext is
not gitignored, and refuses when the ciphertext path itself is, because
either way the commit would carry the wrong bytes. The failure shapes are
in [Commands - hide](commands.md#hide). Commit the ciphertext and state,
not the plaintext:

```sh
git add .gitignore .git-veil .env.secret
git commit -m "Add encrypted secrets"
```

Gitignore the plaintext names, such as `.env`. Commit the `.secret` files and
`.git-veil/`. Never gitignore `*.secret`. That would defeat the fresh-clone
decryptability contract.

## 6. The daily cycle

Edit, check, hide, commit, reveal. Name the file you are working with:

```sh
$ git-veil reveal .env          # decrypt one file in place
Decrypted: .env
files revealed
... edit .env ...
$ git-veil changes              # report the diff
changed: .env
- API_KEY=hunter2
+ API_KEY=hunter4

1 files with changes
$ git-veil hide .env            # re-encrypt one file; plaintext deleted
Encrypted: .env
Deleted plaintext: .env
files hidden
$ git add .env.secret && git commit -m "Rotate API key"
$ git-veil reveal .env          # bring one file back
keyring signature verified
keys in keyring: 1
Decrypted: .env
files revealed
```

What happened. `reveal` decrypts ciphertext back to the plaintext
path and leaves the `.secret` files in place. `hide .env` re-encrypted one
file and left every other tracked file alone. `changes` decrypts each
ciphertext and diffs it against the plaintext beside it. Where there is no
diff to show, it prints `unchanged: …`, `no hidden version: …` or
`not present on disk (hidden): …`. To peek without disturbing anything,
`git-veil cat .env` writes the plaintext to stdout only. Neither the
plaintext nor the ciphertext on disk is touched.

Every `hide` and `reveal` names its file(s); there is no bare form. The
command acts on exactly the paths you give it, so keep the naming habit:
it is the habit that matters in a team, where a whole-manifest pass would
touch every ciphertext and the commit would look like you edited every
secret when you edited a few. See the
[two-collaborators guide](two-collaborators.md).

For the tightest solo posture, no plaintext lingers on disk. That is the
default. `hide` deletes the plaintext. Pass `--keep-plaintext` if you want
the plaintext left in place.

Install a pre-commit guard. The plaintext's only protection is the
`.gitignore` entry.

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

## 7. A build or deployment script reveals on its own key

The ciphertexts are committed, so a clone on a build box already carries
every secret. Give the box its own X25519 private key and its own pin:

- Import the box's private key: `git-veil import <key-file>`.
- Pin the owner key with `trust --import` and a pin-file you export with
  `git-veil export-pin`. That is the joining-user flow; see
  [joining.md](joining.md).
- Put the box's public key in the keyring with `git-veil add-key`, then
  deliver the ring-change pass with `git-veil rotate`: the box's
  ciphertexts carry a stanza for the box after one rotate. See
  [Commands - rotate](commands.md#rotate).

The script then reads what it needs straight from the committed
ciphertexts:

```sh
git-veil cat .env    # plaintext to stdout, no disk state touched
```

or restores the file in place before the step that needs it:

```sh
git-veil reveal .env
```

`cat` and `reveal` are never gated by the allowance check. Decryption
needs only keyring membership, so no `allow` step is needed on the box.

## 8. Health checks

```sh
git-veil verify-keys      # exit 0 only if the signature matches your pin
git-veil list-keys        # who can decrypt, after the same verification
git-veil list             # which files are tracked
git-veil error-codes      # every documented exit code, number and meaning
```

## Key store permissions

git-veil checks its key store the way gpg checks `~/.gnupg`: the store
directory and the private files must not be group- or world-accessible, and
a violation exits with code 30. The fix, the deliberate acknowledgment and
the one-command bypass are covered in
[Troubleshooting - key store permissions](troubleshooting.md#key-store-permissions-exit-30).
These checks apply to the key store only. Files inside your repository
working tree are yours to manage.
