---
name: git-veil-everyday
description: The everyday git-veil routine for an agent working in a repository that is already initialized - the cat-first daily cycle (cat, changes, hide, commit, reveal), health checks, refusal handling, and the human ceremonies (initialize, add keys, transfer). Setup, solo, team, security and troubleshooting links all live in https://prompt-cult.github.io/git-veil/llms.txt. Use when a git repository carries a committed .git-veil/ directory, when tracked *.secret ciphertexts appear beside plaintext, or when git-veil commands/refusals (exit codes 10-73) come up.
---

# git-veil: the everyday routine

git-veil stores encrypted secrets in a git repository. The plaintext works
in your working tree; the ciphertext lives beside it as `<name>.secret`
and is committed. The keyring naming who can decrypt is Ed25519-signed,
and trust is pinned per machine.

The full map of the documentation, every use case, and the troubleshooting
chapters is one fetch away. READ THIS FIRST:

    https://prompt-cult.github.io/git-veil/llms.txt

## Recon before you act

```sh
git-veil list            # tracked files
git-veil list-keys       # who can decrypt, after signature verification
git-veil repo-id         # the identity this repo derives to
git-veil whoami          # the principal this machine acts as
```

## The daily cycle: cat first, then edit, then hide

Read a secret WITHOUT creating plaintext in the tree:

```sh
git-veil cat .env
```

Decrypt, edit, then give the secret back:

```sh
git-veil reveal .env      # plaintext back into the tree
# ... edit .env ...
git-veil changes .env     # diff vs the last hidden version, never echoes secrets
git-veil hide .env        # re-encrypt and DELETE the plaintext
git commit -m "chore: update .env secret"
```

`hide` deletes the plaintext on success; commit the `.secret` beside the
manifest change in the same commit. Working tree hygiene: never leave
plaintext lying around, never commit it, never circumvent `hide`.

## What the refusals mean

Every gated command checks the pinned trust, the keyring signature, and a
freshness baseline BEFORE touching anything. A refusal is the security
model working, not a bug. Never work around one:

- exit 10/11/12/13/14 - trust: no record here yet, no pin on this
  machine, pin/record disagreement, repo id mismatch, rollback.
- exit 20/21 - key store: no signing seed, no X25519 private key for you.
- exit 30 - key store permissions; fix the modes, do not skip the check.
- exit 62/63/70/71/73 - crypto and refusals, including: add-key REFUSES to
  replace a label already in the keyring (exit 73). A lost key is removed
  with remove-key and re-added, never replaced.

The complete contract is `git-veil error-codes`, and the explanations and
procedures for each failure shape live in the troubleshooting chapter of
https://prompt-cult.github.io/git-veil/llms.txt.

## Never do these

- Do not read, print, or commit plaintext secrets; `cat` and `changes`
  exist so you do not have to.
- Do not edit anything under `.git-veil/` by hand: those files are the
  trust anchor and are CODEOWNERS-gated, machine-signed, and verified.
- Do not try to make `add-key` overwrite an existing label: it refuses.
- Do not re-init over a repo that carries `.git-veil/`, on disk OR in the
  committed history. There is no automated patch path; the wipe-and-reset
  procedure (org transfer included) is a committed, human ceremony, see
  the troubleshooting chapter in llms.txt.

## Not your lane: the human ceremonies

Initialization, adding a collaborator key, pin transfer between machines,
and any trust-anchor change are possession-proofed human ceremonies. If
the repo has no `.git-veil/` yet, or someone must re-establish trust, an
agent NEVER fakes them: send the human to the setup chapters:

- New repository, one owner: the Solo guide.
- First install, channels (Homebrew first on macOS): the Installation page.
- Teams: two collaborators, joining, departing chapters.
- All of these are linked from https://prompt-cult.github.io/git-veil/llms.txt

The pin travels OUT of band (export-pin / trust --import), never inside
the repository, and only a machine holding the owner signing seed can
produce one. You cannot and must not synthesize one.
