# Solo developer setup

You keep secrets in a repository only you can read back. One key pair, one
keyring entry: yours.

Prerequisite: build the binary (`cargo build --release`; it lands at
`target/release/git-gpg`) and have `gpg` available. git-gpg does **not**
generate keys — make a key pair with any OpenPGP tool; these steps use gpg.
The examples use the remote `git@github.com:example/demo.git`; substitute
your own remote and emails throughout.

## 1. Create a key pair

The repository identity is derived from the remote push URL, and `trust`
later requires your key to carry the matching email (see step 5). For
`git@github.com:example/demo.git` that email is `example@github.com`.

```sh
gpg --batch --pinentry-mode loopback --passphrase '' \
  --quick-generate-key "Example Owner <example@github.com>" ed25519 sign never
gpg --batch --pinentry-mode loopback --passphrase '' \
  --quick-add-key "$(gpg --with-colons --list-keys example@github.com \
  | awk -F: '/^fpr:/{print $10; exit}')" cv25519 encr never
gpg --armor --export-secret-keys example@github.com > key.asc
gpg --armor --export example@github.com > me.pub
```

What just happened: a signing key with an encryption subkey exists in your
gpg keyring, exported as `key.asc` (PRIVATE — import this, then delete it)
and `me.pub` (public — what `trust` pins). git-gpg has **no** key
generation — every OpenPGP key starts life in an external tool like gpg.
For the public half, `gpg --armor --export` above is one way out; once
your key is imported (step 2), `git-gpg export example@github.com
--output me.pub` writes the same armoured public key from the local key
store, no gpg needed.

## 2. Initialize, import, identify

```sh
$ git-gpg init
✓ git-gpg initialized
$ git-gpg import key.asc
+ imported: example@github.com (E3C2934104874876A3866728BB1E91ED7BD2358A)
Summary: 1 imported, 0 skipped
$ git-gpg show-repo-id
Repository ID: demo+example@github.com
Remote: origin
Push URL: git@github.com:example/demo.git
$ git-gpg whoami
Your identity: example@github.com
Key store: /home/you/.git-gpg
```

What just happened: `.git-gpg/` now holds `keyring`, `trust.json` and
`tracked.json` (init never touches `.gitignore`); your private key lives in
the per-machine key store `$HOME/.git-gpg/secret-keys.pgp`, never committed
— `reveal`, `cat`, `unhide` and `changes` look their key up there.
`show-repo-id` prints the exact repo ID `trust` wants (it re-derives it
from the remote and refuses a mismatch); `whoami` shows which email
decrypting commands will use — from `git config user.email`, or `--email`.

## 3. Trust your own key

```sh
$ git-gpg trust demo+example@github.com me.pub
✓ Trusted key for demo+example@github.com (fingerprint: e3c29341…)
✓ Pinned e3c29341… for demo+example@github.com on this machine
```

What just happened: the key was verified (it must carry the repository
email and must not be expired, revoked or unsigned) and its fingerprint was
**pinned on this machine** in `$HOME/.git-gpg` — outside the repository,
never committed. Every gated command checks the keyring signature against
this pin first and fails closed without it. A fresh clone (even yours) has
no pin until you run `trust` there again.

## 4. Put yourself in the keyring

```sh
$ git-gpg tell example@github.com me.pub
✓ Added example@github.com to keyring
```

What just happened: `hide` encrypts to every key in the signed keyring, so
even solo you must be in it. The keyring at `.git-gpg/keyring` is signed by
your key and is committed.

## 5. Track, hide, commit

```sh
$ printf 'API_KEY=hunter2\n' > .env
$ echo .env >> .gitignore          # ignore the PLAINTEXT name
$ git-gpg add .env
Added 1 file(s)
$ git-gpg hide
✓ Keyring signature verified
Signed by fingerprint: e3c29341…
Repository ID: demo+example@github.com
Keys in keyring: 1
Encrypted: .env
✓ Files hidden
$ ls .env .env.secret
ls: cannot access '.env': No such file or directory
.env.secret
```

What just happened: `.env` was encrypted to your key and the plaintext
deleted; the ciphertext sits beside where the plaintext was. Commit the
ciphertext and state, not the plaintext:

```sh
git add .gitignore .git-gpg/keyring .git-gpg/tracked.json .git-gpg/trust.json .env.secret
git commit -m "Add encrypted secrets"
```

Gitignore the plaintext names (`.env`); commit the `.secret` files and
`.git-gpg/`. Never gitignore `*.secret` — that would defeat the
fresh-clone decryptability contract.

## 6. The daily cycle

Edit → check → hide → commit → reveal:

```sh
$ git-gpg unhide .env          # decrypt one file in place, delete its ciphertext
... edit .env ...
$ git-gpg changes .env         # data, not errors:
changed: .env
- API_KEY=hunter2
+ API_KEY=hunter3
1 file(s) with changes
$ git-gpg hide                 # re-encrypt, delete the plaintext
$ git add .env.secret && git commit -m "Rotate API key"
$ git-gpg reveal               # bring every tracked file back as plaintext
```

What just happened: `changes` decrypts each ciphertext and diffs it against
the plaintext beside it (`unchanged: …`, `no hidden version: …` and
`not present on disk (hidden): …` appear instead where applicable). To peek
without disturbing anything, `git-gpg cat .env` writes the plaintext to
stdout only — neither the plaintext nor the ciphertext on disk is touched.

## 7. Health checks

```sh
git-gpg verify-keyring   # exit 0 only if the signature matches your pin
git-gpg list-keys        # who can decrypt, after the same verification
git-gpg list             # which files are tracked
```

Passphrase-protected keys take the passphrase from `GITGPG_PASSPHRASE` or
`--passphrase-stdin` (exactly one line on stdin). `git-gpg help <command>`
shows the long-form workflow discussion for any command; rendered man pages
are in `docs/man/`.
