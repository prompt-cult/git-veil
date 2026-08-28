# Departing: removing a collaborator

A collaborator (`bob@example.com`) leaves the team. The owner removes him
from the keyring with `removeperson`. Understand the semantics BEFORE you
rely on them:

- `removeperson` deletes bob's entry from the signed keyring and re-signs
  it. It is **forward-looking only**.
- Ciphertexts that already exist were encrypted TO bob's key. He can still
  decrypt every one of them he can obtain — with this tool, or with plain
  `gpg`, forever. Removing him changes nothing about the bytes already on
  disk or already in git history.
- Only a fresh `git-gpg hide` of every file produces new ciphertext
  without bob as a recipient — and even then, **git history still contains
  every old ciphertext**. Old commits stay decryptable by bob indefinitely.
- Therefore: if bob ever saw (or could have decrypted) a secret, treat that
  secret as compromised and **rotate it**. Revocation here is bookkeeping,
  not cryptography.

## 1. What the owner runs

Remove bob and re-hide (hide only encrypts plaintexts present on disk, so
reveal first if everything is currently hidden):

```sh
$ git-gpg removeperson bob@example.com
✓ Removed bob@example.com from keyring
$ git-gpg reveal
✓ Keyring signature verified
...
✓ Files revealed
$ git-gpg hide
✓ Keyring signature verified
...
Encrypted: .env
✓ Files hidden
$ git add .git-gpg/keyring .env.secret
$ git commit -m "Remove bob from keyring and re-hide"
$ git push
```

What just happened: the keyring signature was verified against the pinned
owner key before the change (removeperson fails closed on a tampered or
unsigned keyring, and on an email that is not in the ring); bob's entry
was dropped and the ring re-signed with the owner's key. From this hide
onward, new ciphertext does not include bob.

The re-hide replaces ciphertext only for files whose plaintext was on
disk. It does NOT scrub git history — every previous version of
`.env.secret` remains in old commits, encrypted to bob's key. If the
secrets must truly be gone from bob's reach, rotate them (see step 3) —
rewriting history with `git filter-repo` is an additional, separate
measure.

## 2. What the departing user (bob) should do

```sh
rm -rf ~/work/demo                 # wipe his clone (ciphertext + .git-gpg/)
```

And his local key store, `$HOME/.git-gpg/secret-keys.pgp`, holds his
PRIVATE key. **git-gpg has no command to remove a single key from the key
store** — he must edit the armoured blocks out of that file by hand, or
delete the file if it holds nothing else he needs. His normal gpg keyring
(gnupg) is separate: revoke or delete the key there if he wants it dead:

```sh
gpg --delete-secret-and-public-key bob@example.com
```

## 3. Verify the rotation actually happened

The honest sequencing: rotate the secret values themselves FIRST, then
remove + re-hide, so bob's last readable ciphertext contains an already
dead value. After the owner's push, verify from a remaining member's
chair (here: the owner, alice analogously):

```sh
$ git-gpg list-keys
✓ Keyring signature verified (signed by pinned trusted key)
Keys in keyring:
  example@github.com (5ea3e5f8…)
  alice@example.com (8ae022f3…)
Total: 2 keys
$ git-gpg reveal
✓ Keyring signature verified
...
Decrypted: .env
✓ Files revealed
$ cat .env            # confirm the NEW value, and rotate anything bob ever saw
```

What just happened: the ring is down to the owner and alice, the ring
signature still verifies against the unchanged owner pin, and a remaining
member can still decrypt the fresh ciphertext.

## 4. Demonstrating (to yourself) why revocation is forward-looking

This was verified against the real binary and gpg: a removed collaborator,
holding only what he already had (his private key plus an old ciphertext
copied out of git history), decrypts it with plain gpg:

```sh
$ git show 5833055:.env.secret > old.env.secret   # any pre-removal commit
$ gpg --decrypt old.env.secret
DB_PASSWORD=correct-horse
```

Meanwhile, bob pulling the updated repo finds the tool shuts him out:

```sh
$ git-gpg reveal
✓ Keyring signature verified
...
Error: user bob@example.com not found in keyring; check --email, or ask the owner to add you with git gpg tell
```

Both facts at once are the whole story: the tool refuses him on NEW
keyrings, but no software can un-ring old ciphertext in his possession.
(That error line also says `git gpg tell` — the binary is spelled
`git-gpg`.)

## Checklist

- [ ] Owner: `removeperson <email>` — fails if the email is not in the ring
- [ ] Owner: `reveal` then `hide`, commit `.git-gpg/keyring` + re-hidden `.secret` files, push
- [ ] Everyone: rotate every secret bob could ever decrypt, then commit the new values via hide
- [ ] Owner: `list-keys` shows bob gone; `reveal`/`cat` works for remaining members
- [ ] Departing user: wipe clone; hand-remove their key from `$HOME/.git-gpg/secret-keys.pgp`; revoke/delete the key in their gpg keyring
- [ ] Optional: rewrite history (`git filter-repo`) and force-push if the ciphertext bytes themselves must vanish
