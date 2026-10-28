# Team

One repository, several people, one keyring. The owner sets the
repository up once. After that every member hides and reveals on their
own key, and no member ever sees another member's private key.

What makes it safe to share:

- **A signed keyring.** `.git-veil/keyring` names who can decrypt and is
  signed with the owner's Ed25519 key. Every gated command verifies that
  signature against the local pin before it touches anything, so a
  keyring edited by a non-owner fails closed.
- **A pin per machine.** The owner key is pinned by a possession proof on
  machines holding the signing seed, and by an out-of-band pin-file
  everywhere else. The pin lives in the local key store and is never
  committed.
- **An allowance gate.** The tracking manifest is committed and unsigned,
  so anyone with write access can nominate a path in it. `hide` refuses to
  first-encrypt a path you never allowed on this machine (exit 72), and
  you answer with `git-veil allow`. See
  [Commands - allow](commands.md#allow).
- **A ring-change pass.** `add-key` and `remove-key` re-sign the keyring
  but change no ciphertext; `git-veil rotate` delivers the change. One pass
  consumes one change. See [Commands - rotate](commands.md#rotate).

## The flows

- **Setting up a shared repository** - the owner runs the solo steps, then
  exchanges public keys and pin-files with the first collaborator. The
  full walkthrough, including the exit-72 gate with real output, is in
  [Two collaborators](two-collaborators.md).
- **Someone joins** - the owner exports a pin-file, runs `add-key`, and
  delivers the ring-change pass before the newcomer can decrypt anything.
  The newcomer's own checklist is in
  [Joining a team repository](joining.md), including the failure shapes
  when an owner step has not happened yet.
- **Someone leaves** - `remove-key`, the ring-change pass, and rotation
  of every secret they could ever decrypt. Revocation is bookkeeping, not
  cryptography: the reasoning and the checklist are in
  [Departing](departing.md).

## Habits that keep a team repository sane

- **Name the files you touched.** `git-veil hide .env` churns one
  ciphertext. A whole-manifest pass rewrites every `.secret` in the
  commit, and reviewers cannot tell a one-file change from a repo-wide
  re-encryption without reading the command that made it.
- **Rotate before you revoke.** Remove the person, deliver the pass, and
  rotate every secret they ever saw. Old ciphertext in git history stays
  decryptable by their key forever.
- **Transfer pin-files out of band.** `export-pin` refuses an in-repo
  path. Send the file over ssh, and read the printed owner fingerprint to
  the importer so they can compare it with the committed
  `.git-veil/trust.json`.
- **Protect the trust anchor.** A CODEOWNERS file covering `.git-veil/`
  makes trust-anchor changes review
  gated on the platform. `init` and `trust` remind you.
