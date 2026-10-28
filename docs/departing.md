# Departing a team repository

A collaborator (`bob@example.com`) leaves the team. The owner removes him
from the keyring with `remove-key`. In the following, `age` refers to the
open source `age` encryption tooling, which may be installed separately to
securely create and maintain cryptographic keys outside of the git repo; the
`git-veil` software uses the Rust `rage` library to work with the keys.
Understand the semantics before you rely on them:

- `remove-key` deletes bob's entry from the signed keyring and re-signs
  it. It is forward-looking only.
- Ciphertexts that already exist were encrypted to bob's key. He can still
  decrypt every one of them he can obtain, with this tool or with the
  reference `age` CLI, forever. Removing him changes nothing about the bytes
  already on disk or already in git history.
- Therefore, if bob ever saw or could have decrypted a secret, treat that
  secret as compromised and rotate it. Revocation here is bookkeeping,
  not cryptography.

## 1. What the owner runs

Remove bob, then deliver the ring-change pass:

```sh
$ git-veil remove-key bob@example.com
removed bob@example.com from the keyring
note: the keyring has changed. To re-encrypt to the updated keyring, run the rotate command.
$ git-veil rotate
Rotated: .env
files rotated
ring-change pass complete: every tracked ciphertext is re-encrypted to the current keyring
$ git add .git-veil/keyring .env.secret
$ git commit -m "Remove bob from keyring and re-encrypt"
$ git push
```

What happened. The keyring signature was verified against the pinned owner
key before the change. Bob's entry was dropped, the ring re-signed with the
owner's key, and the ring-change pass delivered: every tracked ciphertext
re-encrypted to the current ring. See
[Commands - remove-key](commands.md#remove-key) and
[Commands - rotate](commands.md#rotate).

The pass re-encrypts tracked ciphertexts. It does not scrub git history.
Every previous version of
`.env.secret` remains in old commits, encrypted to bob's key. If the
secrets must truly be gone from bob's reach, rotate them. See step 3.
Rewriting history with `git filter-repo` is an additional, separate
measure.

## 2. What the departing user (bob) should do

```sh
rm -rf ~/work/demo                 # wipe his clone. Ciphertext and .git-veil go with it.
```

And his local key store, `$HOME/.git-veil`, holds his PRIVATE X25519 key.
He removes it from that store with `forget`, selected by his exact
public key encoding. The private key is usually the only one in his
store, so `--yes` confirms its removal:

```sh
git-veil forget age1xxxx --yes
```

The command is destructive and local-only, and it revokes nothing; the
details are in [Commands - forget](commands.md#forget). If `forget` refuses,
the fallback is manual. Edit the matching line out of the key store files
by hand, or delete the file if it holds nothing else bob needs.

## 3. Verify the rotation actually happened

Rotate the secret values first. Then remove bob and deliver the
ring-change pass, so bob's last readable ciphertext contains an already
dead value. After the owner's
push, verify from a remaining member's chair. Here that is the owner, and
alice is analogous:

```sh
$ git-veil list-keys
keyring signature verified and made by the pinned trusted key
Keys in keyring:
  example@github.com ad2468b2394c184e79f1f972f5a1f6939e1ba2187e9ccdb4154ec356f50550a8
  alice@example.com ea0ab7b15666042b7e0d000b04354e866d6806a79675456cfc68e06162819b80

Total: 2 keys
$ git-veil reveal .env
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
$ git-veil reveal .env
keyring signature verified
keys in keyring: 2
error: user not found in the keyring. Check the principal, or ask the owner to add it
```

Together these are the whole story. The tool refuses bob on new
keyrings. No software can make the ciphertext already in his possession
unreadable.

## Checklist

- [ ] Owner: `remove-key <email>`. It fails if the email is not in the ring
- [ ] Owner: deliver the ring-change pass with `git-veil rotate`, commit `.git-veil/keyring` and the re-encrypted `.secret` files, push
- [ ] Everyone: rotate every secret bob could ever decrypt, then commit the new values via hide
- [ ] Owner: `list-keys` shows bob gone; `reveal`/`cat` works for remaining members
- [ ] Departing user: wipe clone; `forget` their key from the local key store; destroy or archive their backed-up X25519 private key
- [ ] Optional: rewrite history (`git filter-repo`) and force-push if the ciphertext bytes themselves must vanish
