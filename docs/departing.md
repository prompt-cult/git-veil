# Departing: removing a collaborator

A collaborator (`bob@example.com`) leaves the team. The owner removes him
from the keyring with `removeperson`. In the following, `age` refers to the
open source `age` encryption tooling, which may be installed separately to
securely create and maintain cryptographic keys outside of the git repo; the
`git-veil` software uses the Rust `rage` library to work with the keys.
Understand the semantics before you rely on them:

- `removeperson` deletes bob's entry from the signed keyring and re-signs
  it. It is forward-looking only.
- Ciphertexts that already exist were encrypted to bob's key. He can still
  decrypt every one of them he can obtain, with this tool or with the
  reference `age` CLI, forever. Removing him changes nothing about the bytes
  already on disk or already in git history.
- Only a fresh `git-veil hide` of every file produces new ciphertext
  that is not encrypted to bob's key. Even then, git history still contains
  every old ciphertext. Old commits stay decryptable by bob indefinitely.
- Therefore, if bob ever saw or could have decrypted a secret, treat that
  secret as compromised and rotate it. Revocation here is bookkeeping,
  not cryptography.

## 1. What the owner runs

Remove bob and re-hide (hide only encrypts plaintexts present on disk, so
reveal first if everything is currently hidden):

```sh
$ git-veil removeperson bob@example.com
removed bob@example.com from the keyring
$ git-veil reveal
keyring signature verified
keys in keyring: 2
Decrypted: .env
files revealed
$ git-veil hide
Encrypted: .env
Deleted plaintext: .env
files hidden
$ git add .git-veil/keyring .env.secret
$ git commit -m "Remove bob from keyring and re-hide"
$ git push
```

What happened. The keyring signature was verified against the pinned owner
key before the change. removeperson fails closed on a tampered or unsigned
keyring, and on an email that is not in the ring. Bob's entry was dropped
and the ring re-signed with the owner's key. From this hide onward, new
ciphertext does not include bob.

The re-hide replaces ciphertext only for files whose plaintext was on
disk. It does not scrub git history. Every previous version of
`.env.secret` remains in old commits, encrypted to bob's key. If the
secrets must truly be gone from bob's reach, rotate them. See step 3.
Rewriting history with `git filter-repo` is an additional, separate
measure.

## 2. What the departing user (bob) should do

```sh
rm -rf ~/work/demo                 # wipe his clone. Ciphertext and .git-veil go with it.
```

And his local key store, `$HOME/.git-veil`, holds his PRIVATE X25519 key.
He removes it from that store with `removekey`, selected by his exact
public key encoding. The private key is usually the only one in his
store, so `--yes` confirms its removal:

```sh
git-veil removekey age1... --yes
```

This is destructive and local-only. It does not touch any repository,
keyring or trust state, and it revokes nothing. If removekey refuses, the
fallback is the same as ever. A corrupt store is never deleted, and a
public key matching several store lines must be disambiguated. Edit the
matching line out of `identities.txt` and `recipients.txt` by hand, or
delete the file if it holds nothing else bob needs.

## 3. Verify the rotation actually happened

Rotate the secret values first. Then remove and re-hide, so bob's last
readable ciphertext contains an already dead value. After the owner's
push, verify from a remaining member's chair. Here that is the owner, and
alice is analogous:

```sh
$ git-veil list-keys
keyring signature verified and made by the pinned trusted key
Keys in keyring:
  example@github.com ad2468b2394c184e79f1f972f5a1f6939e1ba2187e9ccdb4154ec356f50550a8
  alice@example.com ea0ab7b15666042b7e0d000b04354e866d6806a79675456cfc68e06162819b80

Total: 2 keys
$ git-veil reveal
keyring signature verified
keys in keyring: 2
Decrypted: .env
files revealed
$ cat .env            # confirm the new value. Rotate anything bob ever saw.
```

What happened. The ring is down to the owner and alice, the ring
signature still verifies against the unchanged owner pin, and a remaining
member can still decrypt the fresh ciphertext.

## 4. Why revocation is forward-looking

A removed collaborator, holding only what he already had, can decrypt old
ciphertext with plain `age`. He needs only his X25519 private key and an
old ciphertext copied out of git history:

```sh
$ git show 5833055:.env.secret > old.env.secret   # any pre-removal commit
$ age -d -i bob-age-identity.txt old.env.secret
DB_PASSWORD=correct-horse
```

Meanwhile, bob pulling the updated repo finds the tool shuts him out:

```sh
$ git-veil reveal
keyring signature verified
keys in keyring: 2
error: user not found in the keyring. Check the principal, or ask the owner to add it
```

Together these are the whole story. The tool refuses bob on new
keyrings. No software can make the old ciphertext in his possession
unreadable.

## Checklist

- [ ] Owner: `removeperson <email>`. It fails if the email is not in the ring
- [ ] Owner: `reveal` then `hide`, commit `.git-veil/keyring` and the re-hidden `.secret` files, push
- [ ] Everyone: rotate every secret bob could ever decrypt, then commit the new values via hide
- [ ] Owner: `list-keys` shows bob gone; `reveal`/`cat` works for remaining members
- [ ] Departing user: wipe clone; `removekey` their key from the local key store; destroy or archive their backed-up X25519 private key
- [ ] Optional: rewrite history (`git filter-repo`) and force-push if the ciphertext bytes themselves must vanish
