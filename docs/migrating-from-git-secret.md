# Migrating from git-secret to git-veil

git-veil is a git-secret work-alike: the mental model — tracked files
encrypted in place to a per-repository keyring of collaborator keys — maps
over almost one-to-one. What does NOT map is the material itself: git-veil
does not maintain compatibility with git-secret's cryptographic material
(see the [README's compatibility statement](../README.md#compatibility-with-git-secret)).

To be plain about it:

- The ciphertext differs. git-secret's `filename.secret` files are OpenPGP
  messages produced by whatever `gpg` binary it shells out to. git-veil's
  `.secret` files are age messages (age-encryption.org/v1) produced by the
  pure-Rust [`age` crate][age] in process. A git-veil user cannot reveal a
  git-secret-produced file and vice versa.
- The state directory differs: git-secret uses `.gitsecret/`, git-veil
  uses `.git-veil/`.
- The keyring machinery differs. git-secret stores a gpg keyring of public
  keys in `.gitsecret/keys/` and answers "who can read this repo" from it
  (`git secret whoknows`); decryption uses your personal `~/.gnupg`
  keyring. git-veil stores a keyring that is *signed* by the repository
  owner's Ed25519 key, keeps your age identity in a git-veil key store
  (`$HOME/.git-veil`), and verifies the keyring signature against a
  per-machine trust pin before every operation.

[age]: https://crates.io/crates/age

So there is no in-place upgrade: the path is *reveal everything, tear down
git-secret, re-key with git-veil, re-hide*. Everything stays plain files
in between, so the migration is low-drama — but plan a moment when nobody
else is pushing.

## What git-veil deliberately does differently

These are factual differences, not judgements — git-veil is inspired by
git-secret, and git-secret works fine for many teams. But they change
habits, so they are stated up front:

1. **No gpg binary, ever.** git-secret shells out to `gpg` for every
   operation, so keys live in (and move through) the GnuPG keychain:
   collaborators `gpg --import` each other's public keys, and git-secret
   finds them there when you run `tell`. git-veil has no gpg step at
   runtime: keys are age identities created with `age-keygen` (or
   `rage-keygen`) and moved as plain text files, with `import` (your own
   identity, per machine) and `export` (the recipient string, to hand to
   the owner). Your existing OpenPGP keys do NOT carry over — the
   migration includes creating fresh age keys.
2. **The keyring is signed and tamper-evident.** git-secret's
   `.gitsecret/keys/` keyring is an ordinary gpg keyring; nothing in
   git-secret detects it being edited in place. git-veil's keyring file
   (`.git-veil/keyring`) is signed by the repository owner's Ed25519 key,
   and the signature is verified against the pinned owner key before every
   encryption, decryption or keyring mutation. A tampered keyring fails
   closed.
3. **Trust is pinned per machine.** With git-secret, a fresh clone worked
   as soon as your `~/.gnupg` had a matching private key — the trust
   anchor was implicit in your keychain. In git-veil the trust anchor is
   an explicit pin of the owner's signing key, stored in your local key
   store and never committed. Every collaborator runs `git-veil trust` on
   every machine after cloning. This is the single biggest new habit.
4. **Keys are proven at the door.** `tell` test-encrypts an in-memory
   canary to a new collaborator's key before signing it into the ring — a
   key that cannot encrypt never enters the keyring — and `trust` parses
   the owner's Ed25519 verifying key before pinning it. (git-secret's
   `tell` warns about invalid keys since 0.3.2 but the keyring itself is
   not authenticated.)
5. **hide/reveal keep both sides by default.** `hide` encrypts and KEEPS
   the plaintext (deletion is opt-in with `--dangerously-delete-plaintext`,
   mirroring git-secret's `-d`), and `reveal` writes the plaintexts and
   LEAVES the `.secret` files in place — the same defaults git-secret has.
   git-veil additionally refuses `hide` outright when a `.secret` path is
   git-ignored (e.g. swallowed by a parent-directory rule), a silent-loss
   mode git-secret does not detect. See the cheat-sheet for the mapping.

## Step-by-step migration

Example throughout: repository `git@github.com:example/demo.git`, owner
`example@github.com`, collaborator `alice@example.com`, one secret file
`.env`. Substitute your own throughout.

### 1. In the git-secret repo: reveal and inventory

Run on a machine that has every secret's plaintext reachable:

```sh
$ git secret reveal          # writes .env next to .env.secret
$ git secret list            # the tracked list you must carry over
.env
$ cat .gitsecret/paths/mapping.cfg   # same list, in git-secret's own store
```

What just happened: every tracked file now exists as plaintext on disk.
git-secret's `list` reads its path mappings from
`.gitsecret/paths/mapping.cfg`; capture both outputs — this is the exact
file list you will `git-veil add` in step 4. Save the plaintexts somewhere
safe outside the repo until step 5's verification (do not commit them).

Note for teams whose workflow was `git secret hide -d`: if some tracked
files have *no* plaintext on disk right now, this is why — `hide -d`
deleted it and only ciphertext remains. `git secret reveal` brings them
back; make sure all tracked files decrypt before moving on (a stale
keyring or gpg version mismatch shows up here first).

### 2. Remove the git-secret machinery

git-secret has no built-in teardown command. The clean removal, after
step 1 has verified every file decrypts:

```sh
$ rm -rf .gitsecret
$ vi .gitignore      # remove the ".gitsecret/keys/random_seed" line
$ git add .gitignore
$ git commit -m "chore: remove git-secret state"
```

What just happened: `git secret init` created `.gitsecret/` (with `keys/`
and `paths/`) and added `.gitsecret/keys/random_seed` to `.gitignore`; all
other `.gitsecret/` contents were meant to be committed. Deleting the
directory and dropping that one `.gitignore` line is the full teardown.
The plaintext-name lines that `git secret add` appended to `.gitignore`
(`.env` etc.) **stay** — git-veil wants exactly the same rule: ignore the
plaintext names, commit the `.secret` ciphertexts. Keep those lines as
they are.

One warning: do NOT use `git secret clean` as a teardown shortcut. It
deletes every file ending in `.secret` in the repo — tracked or not —
which is fine here only because step 1 already put plaintexts on disk, but
it is a habit that destroys the only copy of a secret in normal use.

### 3. Re-key: create age keys, import, tell

git-veil never generates keys, and your existing OpenPGP keys do not carry
over: encryption is age (X25519) and keyring signing is raw Ed25519, so
this step creates fresh key material with `age-keygen` and `openssl`.
See [docs/solo.md](solo.md) step 1 for the details — and back the private
halves up.

The owner, in the repo:

```sh
$ cargo build --release          # binary: target/release/git-veil
$ git-veil init
✓ git-veil initialized
$ age-keygen -o my-age-identity.txt
$ git-veil import my-age-identity.txt
+ imported: age1… (…)
Summary: 1 imported, 0 skipped
$ umask 077
$ openssl genpkey -algorithm ED25519 -out "$HOME/.git-veil/ed25519.pem"
$ openssl pkey -in "$HOME/.git-veil/ed25519.pem" -outform DER \
  | tail -c 32 | xxd -p -c 32 > "$HOME/.git-veil/signing-keys.txt"
$ openssl pkey -in "$HOME/.git-veil/ed25519.pem" -pubout -outform DER \
  | tail -c 32 | xxd -p -c 32 > owner.verifying
$ git-veil show-repo-id
Repository ID: demo+example@github.com
Remote: origin
Push URL: git@github.com:example/demo.git
$ git-veil trust demo+example@github.com owner.verifying
✓ Trusted key for demo+example@github.com (fingerprint: …)
✓ Pinned … for demo+example@github.com on this machine
```

Each collaborator, on their machine, creates their own age identity and
sends the owner the printed recipient string:

```sh
$ age-keygen -o alice-age-identity.txt
# public key: age1...        # <- this line goes to the owner
$ git-veil import alice-age-identity.txt
```

The owner then adds each one (any file whose first line is the recipient
string works):

```sh
$ git-veil tell alice@example.com alice-age-identity.txt
✓ Added alice@example.com to keyring
```

What just happened: this is the git-secret `tell` split into two steps
(key hand-off, then ring membership). The reason is difference #1: there
is no shared gpg keychain for `tell` to look keys up in, so the recipient
string arrives as an explicit file, and the owner's `tell` signs it into
the keyring. Collaborators who want a head start can already `import`
their own identity (step 5 uses it).

### 4. Track the files and hide

Back to the file list captured in step 1:

```sh
$ git-veil add .env
$ git-veil hide
✓ Keyring signature verified
...
Encrypted: .env
✓ Files hidden
$ git add .gitignore .git-veil/keyring .git-veil/tracked.json .git-veil/trust.json .env.secret
$ git commit -m "feat: re-key secrets with git-veil"
$ git push
```

What just happened: `hide` encrypts every tracked file to the whole
current keyring and KEEPS the plaintext (git-secret's default too; pass
`--dangerously-delete-plaintext` for git-secret's `-d`). The committed
set matches git-secret's philosophy of "check in the state and the
ciphertext": `.git-veil/keyring` (signed), `tracked.json`, `trust.json`
and the `.env.secret` files. Repeat `add` + `hide` for every file from
your step-1 list, then spot-check `git-veil list` against it.

Note: your pre-push plaintexts from step 1 are still on disk and still
gitignored — exactly the state git-secret left them in. `hide` refuses
(exit code 40) if any `.secret` path is itself git-ignored, and warns
(exit code 41 in the message) if a plaintext is not gitignored.

### 5. Per-collaborator verification checklist

Each collaborator (and the owner, on any fresh clone) runs:

```sh
$ git clone git@github.com:example/demo.git && cd demo
$ git config user.email alice@example.com
$ git-veil import alice-age-identity.txt      # once per machine
$ git-veil show-repo-id                        # print the ID trust wants
Repository ID: demo+example@github.com
$ git-veil trust demo+example@github.com owner.verifying   # once per machine!
$ git-veil list-keys
✓ Keyring signature verified (signed by pinned trusted key)
Keys in keyring:
  example@github.com (…)
  alice@example.com (…)
Total: 2 keys
$ git-veil reveal
✓ Keyring signature verified
...
Decrypted: .env
✓ Files revealed
$ git-veil cat .env            # spot-check contents match pre-migration
$ sha256sum .env               # or compare bytes against your step-1 copy
```

Checklist:

- [ ] `trust` run on this machine — **this step is new for git-secret
      users**: your gpg keychain "just worked" before because the trust
      anchor was implicit in it; here each machine pins the owner key
      explicitly, and every gated command fails closed without the pin
- [ ] `list-keys` shows you in the ring and the signature verifying
- [ ] `reveal` succeeds and `cat` output matches the pre-migration
      plaintext (diff against the step-1 copy)
- [ ] Post-reveal state matches git-secret's: plaintexts on disk, the
      `.secret` files still in place and still tracked by git
- [ ] If someone was added to the old keyring but is missing here: the
      owner runs `git-veil tell` for them and re-hides (see
      [docs/joining.md](joining.md))
- [ ] Anyone leaving the team: `removeperson` + re-hide, and rotate the
      secrets they ever saw — the same forward-looking-revocation rules as
      git-secret apply (see [docs/departing.md](departing.md))

## Cheat-sheet: git-secret → git-veil

| git-secret                              | git-veil                        | Notes |
|-----------------------------------------|---------------------------------|-------|
| `git secret init`                       | `git-veil init` + `git-veil trust` | Setup splits in two: `init` creates `.git-veil/`, `trust` pins the owner's key per machine (git-secret had no pin step) |
| `git secret tell`                       | `git-veil import` + `git-veil tell` | Two steps, because there is no gpg keychain for `tell` to find keys in — recipient strings arrive as files; `import` is for *your own* age identity (per machine) |
| `git secret whoknows`                   | `git-veil list-keys`            | Prints keyring members after verifying the keyring signature |
| `git secret add`                        | `git-veil add`                  | Both append the plaintext name to `.gitignore` when not already ignored; git-veil additionally warns when the `.secret` path is itself git-ignored |
| `git secret rm`                         | `git-veil remove`               | Both untrack; git-veil leaves any ciphertext in place, like git-secret |
| `git secret hide`                       | `git-veil hide`                 | Same default: both keep the plaintext (git-veil deletes with `--dangerously-delete-plaintext`, git-secret with `-d`) |
| `git secret reveal`                     | `git-veil reveal`               | Same default: both leave the `.secret` ciphertext in place |
| `git secret cat`                        | `git-veil cat`                  | Both print one file to stdout without touching disk state |
| `git secret changes`                    | `git-veil changes`              | Both compare on-disk plaintext with the last hidden version |
| `git secret list`                       | `git-veil list`                 | git-secret reads `.gitsecret/paths/mapping.cfg`; git-veil reads `.git-veil/tracked.json` |
| `git secret removeperson`               | `git-veil removeperson`         | Both remove a member from the repo keyring; both are forward-looking only — see [docs/departing.md](departing.md) |
| `git secret killperson` (≤ 0.4.0)       | `git-veil removeperson`         | `killperson` was renamed to `removeperson` in git-secret 0.5.0; it always meant "delete from the repo's inner keyring", not from your gpg keyring |
| *(departing user's own key)*            | `git-veil removekey`            | git-secret has no equivalent: your private key lived in `~/.gnupg` and you managed it with `gpg` yourself. `removekey` is the local-store housekeeping step (local-only, destructive) |
| `git secret clean`                      | *(no bulk equivalent)*          | git-secret `clean` deletes all `*.secret` files repo-wide; git-veil deletes one file's ciphertext with `unhide <file>` — there is no repo-wide ciphertext deletion |
| `git secret usage`                      | `git-veil help`                 | Also `git-veil help <command>` for a workflow discussion, `git-veil <command> --help` for flags |
| *(none — verify-keyring)*               | `git-veil verify-keyring`       | No git-secret counterpart: git-secret's keyring is an unsigned gpg keyring, so there is nothing to verify. (git-secret has no `warnings` command — its invalid-key notices come from `tell`/`whoknows` output) |
| *(none)*                                | `git-veil trust`, `import`, `export`, `unhide`, `whoami`, `show-repo-id` | The rest of the machinery: per-machine trust pin, key hand-off without a gpg keychain, single-file reveal, identity/store introspection |

## Sources

git-secret behaviour and commands above are cited from the project's
documentation in the [sobolevn/git-secret repository][repo] (the
`man/man1` and `man/man7` pages: `git-secret.7`, `git-secret-add.1`,
`git-secret-cat.1`, `git-secret-changes.1`, `git-secret-clean.1`,
`git-secret-hide.1`, `git-secret-reveal.1`, `git-secret-tell.1`,
`git-secret-list.1`, `git-secret-remove.1`, `git-secret-removeperson.1`,
`git-secret-usage.1`, `git-secret-whoknows.1`, and the archived
`git-secret-killperson.1` at tag `v0.4.0`), plus the repository's
`CHANGELOG.md` for the 0.5.0 `killperson` → `removeperson` rename and the
0.3.2 invalid-key warnings in `tell`.

[repo]: https://github.com/sobolevn/git-secret
