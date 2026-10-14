# git-veil design specification

This document is the specification of git-veil's mechanisms: what the code
actually enforces, stated precisely enough to be re-verified. It is distinct
from the README (an overview) and the tutorials under `docs/` (how-to journeys);
when prose elsewhere disagrees with this document or with the code, this
document should be corrected first, then the prose. Each claim names the
enforcing function; the named function, not any line number, is the contract.

Mechanisms are specified as formal algorithms in a modified I/O automaton
notation, after Algorithm 1 of Michael et al 2017, "Recovering Shared Objects
without Stable Storage" (extended version): numbered lines; `upon` handlers for
command invocations; `function` blocks for helpers; `guards` that refuse; state
sections annotated with the invariant each variable carries. The algorithms
render here in LaTeX math blocks and on the project GitHub Pages site.

## Terminology: crypto terms in the core, ageisms at the boundary

git-veil's core and code speak RFC-standard cryptography only. The
vocabulary the `age` tool uses for these values is called **ageisms**. They
appear only at the
user surface, and only where the documentation advises the operator how to
do something in `age` (run an `age` command, interoperate with `age`/`rage`
tooling). Where both vocabularies must span, the form is the crypto term
followed by the ageism in brackets: "X25519 private key (`age` identity)".

In the following, `age` refers to the open source `age` encryption tooling,
which may be installed separately to securely create and maintain
cryptographic keys outside of the git repo; the `git-veil` software uses the
Rust `rage` library to work with the keys.

| Crypto term (git-veil core and code) | ageism (`age` vocabulary) |
|--------------------------------------|-----------------------------------|
| X25519 public key - bech32-encoded per the `age` spec encoding (`age1...`); X25519 per RFC 7748 | recipient |
| X25519 private key - bech32-encoded per the `age` spec encoding (`AGE-SECRET-KEY-1...`) | identity, identity file |
| principal - the keyring label (a collaborator's email) | - (`age` has no word for it) |
| Ed25519 verifying key - the public half of the keyring signing key | - (already standard vocabulary) |
| Ed25519 signing key - the private seed | - (already standard vocabulary) |

The law:

1. **Core and code** (src/, internals, comments, error messages, commit
   messages) use the crypto column only. An ageism in src/ outside a
   user-surface string literal is a defect; `tests/docs_drift.rs`
   (`test_no_ageisms_in_src_outside_string_literals`) greps for exactly
   that and fails the build.
2. **The user surface** (CLI help text, operator docs) uses the crypto
   column too, EXCEPT where the documentation advises the operator how to
   do something in `age`; only there may the ageism appear, in the bracketed
   spanning form.
3. **This table is the translation reference** for any reader spanning
   both vocabularies; AGENTS.md carries the same law verbatim.
4. **Two boundary tokens remain, named here as the contract**: the on-disk
   key store file names `identities.txt` (X25519 private keys) and
   `recipients.txt` (X25519 public keys) predate this rule and remain as
   format constants, and the upstream `age` crate's type names
   (`age::x25519::Identity`, `age::x25519::Recipient`) appear at the single
   import site in `src/age_crypto.rs`, where they are aliased to
   `X25519PrivateKey` / `X25519PublicKey`.

## Repository identity

Every repository is identified by a `repo_id` derived from its git remote push
URL (`parse_git_remote_url`, `derive_repo_id`, src/repo_identity.rs):

$$
\begin{array}{ll}
\multicolumn{2}{l}{\textbf{Algorithm 1} \quad \textsc{DeriveRepoId}(pushURL) \to \mathit{repoId}} \\
1: & \textbf{function } \textsc{DeriveRepoId}(pushURL) \\
2: & \quad \textbf{match } pushURL \text{ against } \text{user@host:owner/repo} \lor \text{scheme://[user[:pass]@]host[:port]/owner/repo},\\
   & \quad\quad scheme \in \{ssh, git, https\} \quad . \text{ no other scheme, no IPv6 literal, no extra path segments} \\
3: & \quad \textbf{if no shape matches then refuse } \text{fixed message, the URL never echoed} \\
4: & \quad \text{strip userinfo} \quad . \text{ credentials never enter the identity, never echoed} \\
5: & \quad \text{discard the port;} \text{ strip a trailing .git and a trailing slash} \\
6: & \quad \textbf{for all } c \in \{host, owner, repo\} \textbf{ do } c \leftarrow \text{lowercase}(c) \quad \textbf{end for} \\
7: & \quad \textbf{guard } @ \notin owner \land @ \notin repo \land @ \notin \text{scp user} \quad . \text{ credential-shaped input is rejected, not laundered} \\
8: & \quad \textbf{return } \langle repo \rangle + \langle owner \rangle @ \langle host \rangle \quad . \text{ e.g. git@github.com:example/demo.git} \to \text{demo+example@github.com} \\
9: & \textbf{end function}
\end{array}
$$

`show-repo-id` prints the derived id. `trust` re-derives it from the live
remote and refuses a provided `repo_id` that does not match the computed one
(`cmd_trust`, src/commands/trust.rs), so a typo cannot pin a key under the
wrong identity.

## The trust record (`trust.json`) and the per-machine pin

`trust.json` lives at `.git-veil/trust.json` and holds one JSON object with
two maps (`TrustStore`, src/trust_store.rs):

- `trusted_keys`: `{ "<repo_id>": "<fingerprint>" }` - the fingerprint of
  the owner key pinned for the repository under the single derivation (see
  "Fingerprints": the repository id is the label), compared against the
  local pin by every gated command;
- `owner_fingerprints`: `{ "<repo_id>": "<owner fingerprint>" }` - the same
  value: the fingerprint of the repository's committed owner verifying key
  (`owner.verifying`) under the single derivation, used by pin-file import
  and by humans verifying out of band.

Both fields default to absent when missing (pre-0.6 files parse cleanly);
the file is written pretty-printed and atomically
(`TrustStore::save_to_file`); a missing file reads as an empty store
(`TrustStore::load_from_file`).

Its role is **team visibility, not trust**. It is committed so every
collaborator can see which key the repository claims as its owner, and so a
changed claim is visible in git history. Because it is committed, it is
attacker-writable by anyone with write access to the repository - the docs
are explicit that it is never the anchor.

The actual anchor is the **per-machine pin**: a file at
`<key store>/trust-pins/<sanitized repo_id>` holding the fingerprint the user
chose on *this machine* (`TrustPinStore`, src/trust_store.rs). Pin filenames are
derived deterministically: bytes outside `[A-Za-z0-9._-]` are percent-encoded,
so the name can never escape the pin directory (`TrustPinStore::sanitize_repo_id`).
The pin is written only by the two pin-creation paths below; a
fresh clone has no pin, which is why trust must be re-established per machine.

### Pin creation (possession proof only)

A repository can never supply its own trust anchor: there is no keyfile
argument, no compatibility mode, no feature flag. Exactly two paths create a
pin. Algorithm 2 is the possession proof; Algorithm 3 is the export/import
pair; Algorithm 4 is the reconcile that keeps the committed store honest
after a move.

$$
\begin{array}{ll}
\multicolumn{2}{l}{\textbf{Algorithm 2} \quad \textsc{Trust} \text{ - the possession proof (} \texttt{cmd\_trust} \text{, src/commands/trust.rs)}} \\
\multicolumn{2}{l}{\textit{Permanent state: } T \text{ = committed } \texttt{.git-veil/trust.json} \text{ (} \mathit{trustedKeys}, \mathit{ownerFingerprints} \text{ maps);} \ S \text{ = the machine key store}} \\
\multicolumn{2}{l}{\textit{Machine state: } P \text{ = per-machine pins;} \ B \text{ = freshness baselines}} \\
1: & \textbf{upon } \textsc{Trust}(\mathit{providedId}) \\
2: & \quad \mathit{derivedId} \leftarrow \textsc{DeriveRepoId}(\text{pushURL(remote)}) \\
3: & \quad \textbf{guard } \mathit{providedId} = \mathit{derivedId} \quad \textbf{else refuse} \ . \ \text{exit 13} \\
4: & \quad \mathit{cand} \leftarrow \text{line 1 of the committed } \texttt{owner.verifying} \quad . \ \text{64-hex Ed25519 verifying key} \\
5: & \quad \textbf{if line 2 of } \texttt{owner.verifying} \text{ starts with the bech32 encoding then import it into } S \\
6: & \quad \textbf{function } \textsc{ProvePossession}(\mathit{cand}) \\
7: & \quad\quad seeds \leftarrow \text{lines of } \texttt{signing-keys.txt} \quad . \ \text{a present-but-garbage line is a parse refusal, exit 62} \\
8: & \quad\quad M \leftarrow \{ s \in seeds : \text{verifying}(s) = \mathit{cand} \} \\
9: & \quad\quad \textbf{if } |M| = 0 \textbf{ then refuse } \ . \ \text{exit 20} \\
10: & \quad\quad \textbf{if } |M| > 1 \textbf{ then refuse on ambiguity} \ . \ \text{exit 70; a degenerate duplicated store} \\
11: & \quad\quad \textbf{return} \ \text{the unique seed} \\
12: & \quad\quad \textbf{end function} \\
13: & \quad \textsc{ProvePossession}(\mathit{cand}) \\
14: & \quad \text{append } \mathit{cand} \text{ to } \texttt{verifying-keys.txt} \\
15: & \quad \mathit{fp} \leftarrow \textsc{Fingerprint}(\mathit{derivedId}, \mathit{cand}) \\
16: & \quad T.\mathit{trustedKeys}[\mathit{derivedId}] \leftarrow \mathit{fp} \quad . \ \text{trust.json written BEFORE the pin: a death between the writes fails closed} \\
17: & \quad T.\mathit{ownerFingerprints}[\mathit{derivedId}] \leftarrow \mathit{fp} \quad . \ \text{the owner commits the updated trust.json alongside owner.verifying} \\
18: & \quad \textsc{Reconcile}(T) \\
19: & \quad P[\mathit{derivedId}] \leftarrow \mathit{fp} \quad . \ \text{the machine pin, outside the repository} \\
20: & \quad B[\mathit{derivedId}] \leftarrow \bot \quad . \ \text{re-pinning is the recovery ceremony, so the baseline resets with it} \\
21: & \quad \textsc{CodeownersNotice} \quad . \ \text{non-blocking warning or suppression record; never alters an exit code} \\
22: & \textbf{end upon} \\[2mm]
\multicolumn{2}{l}{\textbf{function } \textsc{Reconcile}(T) \ . \ \text{issue \#43}} \\
a: & \quad live \leftarrow \{ \textsc{DeriveRepoId}(\text{pushURL}(r)) : r \in \text{configured remotes} \} \\
b: & \quad \textbf{for all } id \in \text{keys}(T.\mathit{trustedKeys}) \text{ with } id \notin live \textbf{ do} \\
c: & \quad\quad \text{delete } T.\mathit{trustedKeys}[id] \,; \text{ print the pruned } id \quad . \ \text{repository ids are public repository facts} \\
d: & \quad \textbf{end for} \\
e: & \textbf{end function}
\end{array}
$$

A repository move or rename leaves the old id in the committed store only
until the next possession proof: Algorithm 2's reconcile prunes every id no
configured remote derives and prints each removal, so a multi-remote
repository keeps exactly one entry per remote.

$$
\begin{array}{ll}
\multicolumn{2}{l}{\textbf{Algorithm 3} \quad \textsc{ExportPin} \text{ and } \textsc{ImportPin} \text{ (} \texttt{cmd\_export\_pin} \text{, } \texttt{cmd\_trust\_import} \text{)}} \\
\multicolumn{2}{l}{\textit{Pin-file format: two lines} \ \texttt{repo-id: <repo\_id>} \ \text{and} \ \texttt{verifying-key: <64-hex Ed25519 verifying key>}} \\
1: & \textbf{upon } \textsc{ExportPin}(\mathit{repoId}, out) \\
2: & \quad \text{run Algorithm 2's possession proof} \quad . \ \text{a machine without the matching seed cannot export, exit 20} \\
3: & \quad \textbf{guard } out \notin \text{repository worktree} \quad \textbf{else refuse} \ . \ \text{exit 71; the pin-file must travel out of band} \\
4: & \quad \text{write the two-line pin-file to } out \,; \text{ print } \textsc{Fingerprint}(\mathit{repoId}, \mathit{vk}) \ . \ \text{the human out-of-band token} \\
5: & \textbf{end upon} \\
6: & \textbf{upon } \textsc{ImportPin}(\mathit{path}) \\
7: & \quad \textbf{guard } \mathit{path} \notin \text{repository worktree} \quad \textbf{else refuse} \ . \ \text{exit 71; an attacker must not be able to ship the pin-file in the repo} \\
8: & \quad (\mathit{pinId}, \mathit{pinVK}) \leftarrow \text{parse the pin-file} \\
9: & \quad \mathit{derivedId} \leftarrow \textsc{DeriveRepoId}(\text{pushURL(remote)}) \\
10: & \quad \textbf{check (a): } \mathit{pinId} = \mathit{derivedId} \\
11: & \quad \textbf{check (b): } \mathit{pinVK} = \text{the committed } \texttt{owner.verifying} \\
12: & \quad \textbf{check (c): } \textsc{Fingerprint}(\mathit{pinId}, \mathit{pinVK}) = T.\mathit{ownerFingerprints}[\mathit{derivedId}] \\
   & \quad\quad . \ \text{an absent metadata field refuses: the owner must refresh it on a seed-holding machine} \\
13: & \quad \textbf{if any check fails then refuse} \ . \ \text{exit 70; one of the two channels is compromised} \\
14: & \quad \text{write the pin and reset the baseline as in Algorithm 2, without the reconcile} \\
15: & \textbf{end upon}
\end{array}
$$

The pin-file is the anchor; the repository's committed key and fingerprint
are the witnesses. Owner fingerprint derivation is fixed and documented
(`owner_key_fingerprint`, src/fingerprint.rs): the single derivation with the
repository id as the label and the canonical lowercase hex of the 32
verifying-key bytes as the public key encoding - never computed over the
seed, only the public half. See "Fingerprints" for the exact construction,
the stock-tool one-liners and the golden vectors.

Pin-files travel out of band, never through the repository. The path
gates in Algorithm 3 (exit 71) exist because an attacker with repo write
access could otherwise commit a bogus pin-file and have the victim import
it, and since without a pin the tool refuses all other operations, the pin
cannot travel through git-veil's own tracked-file mechanism either.
Pin-file integrity rides the transport - the same model as `known_hosts`
provisioning - and the printed owner fingerprint is the token for human
out-of-band verification (read it over the phone and compare with the
committed `owner_fingerprints` value).

Repo renames change the repo_id (it is derived from the remote push
URL), so a new pin is required. When the committed `trust.json` records
trust for a repo_id that differs from the one the current remote derives,
the gated commands refuse with a stated suspicion - Algorithm 4's
rename-suspicion refusals (exit code 10 on the verify path, 70 on the
import path) - naming the recorded and derived repo-ids as the clue and
nothing else. Error text is plain ASCII: no quoting marks, no
parentheses, no path echoes, nothing that trips a log parser or a terminal.
No remedy is printed: handing an operator a one-line fix for a trust-anchor
change is exactly what an attacker staging a repo move wants them to run
without thinking. The operator reads the docs, satisfies themselves the
rename is theirs, and fixes it with Algorithm 2 on a machine holding the
signing key; its reconcile prunes the old id, so the committed store
returns to naming exactly the ids the configured remotes derive.

## The gated-command chain

Every gated command verifies the keyring signature through
`verify_keyring_against_trust` (src/commands/verify_keyring.rs):

$$
\begin{array}{ll}
\multicolumn{2}{l}{\textbf{Algorithm 4} \quad \textsc{VerifyKeyring} \text{ - run by every gated command}} \\
1: & \textbf{upon any gated command} \\
2: & \quad \mathit{repoId} \leftarrow \textsc{DeriveRepoId}(\text{pushURL(remote)}) \,; \ T \leftarrow \text{load } \texttt{.git-veil/trust.json} \\
3: & \quad \textbf{if } \mathit{repoId} \notin \text{keys}(T.\mathit{trustedKeys}) \textbf{ then} \\
4: & \quad\quad \textbf{if } T.\mathit{trustedKeys} = \emptyset \textbf{ then refuse} \ . \ \text{exit 10: no trust record} \\
5: & \quad\quad \textbf{else refuse} \ . \ \text{exit 10: rename suspicion, naming the recorded and derived ids as the clue} \\
6: & \quad \mathit{claimed} \leftarrow T.\mathit{trustedKeys}[\mathit{repoId}] \\
7: & \quad \textbf{guard } \mathit{claimed} \text{ and the pin are not retired 16-hex values} \quad \textbf{else refuse} \ . \ \text{exit 70; hostile legacy format, nothing rewritten} \\
8: & \quad \mathit{pin} \leftarrow \text{read } P[\mathit{repoId}] \\
9: & \quad \textbf{if } \mathit{pin} = \bot \textbf{ then refuse} \ . \ \text{exit 11, naming } \mathit{repoId} \text{ and the remote it came from} \\
10: & \quad \textbf{guard } \mathit{pin} = \mathit{claimed} \text{ (case-insensitively)} \quad \textbf{else refuse} \ . \ \text{exit 12} \\
11: & \quad \mathit{vk} \leftarrow \text{the key store verifying key } k \text{ with } \textsc{Fingerprint}(\mathit{repoId}, \text{enc}(k)) = \mathit{claimed} \\
12: & \quad \mathit{ring} \leftarrow \text{parse } \texttt{.git-veil/keyring} \quad . \ \text{a legacy three-field entry refuses, exit 62} \\
13: & \quad \textbf{if the keyring carries a signature then verify it over the canonical content with } \mathit{vk} \\
   & \quad\quad \textbf{else if the keyring has entries then refuse} \ . \ \text{exit 63: an unsigned ring with entries launders trust} \\
14: & \quad \textsc{FreshnessGate}(\mathit{repoId}, \mathit{ring}) \quad . \ \text{Algorithm 5} \\
15: & \quad \textbf{return } (\mathit{repoId}, \mathit{claimed}, \mathit{ring}) \\
16: & \textbf{end upon}
\end{array}
$$

Every refusal in Algorithm 4 is a plain ASCII statement that prints no
command line; the remedy is this document, which the operator reads
deliberately. The message policy distinguishes secret material from public
repository facts: plaintext contents, key material and anything derivable
only by decryption are never printed, while facts readable in the committed
tree - tracked paths, committed ciphertext paths, principal labels,
repository identities - may be named, since refusing to name them buys no
security and costs the operator the ability to act.

So an attacker who rewrites `trust.json` - or commits a self-consistent
`owner.verifying`, signed keyring, metadata fingerprint and bogus pin-file -
achieves nothing on a machine that holds the real seed: the proof fails, and
an in-repo pin-file is refused by the path gate. Algorithm 2 writes
trust.json *before* the pin, so a death between the two writes leaves a
mismatch, never a silently accepted changed anchor. Re-pinning over a
different existing fingerprint prints a loud `replacing the previously
pinned fingerprint ...` notice.

## Fingerprints

Every fingerprint in git-veil is one derivation (`fingerprint_for_public_key`,
src/fingerprint.rs), stated exactly:

$$
FP(label, k) = \text{SHA-256}\big( \text{UTF8}(label) \, \| \, \text{":"} \, \| \, \text{UTF8}(enc(k)) \big)
$$

printed as 64 lowercase hex characters. The label is the principal label
for a keyring principal, or the repository id for the owner key. The
public key encoding $enc(k)$ is the bech32 X25519 public key (`age1...`) or
the 64 hex character Ed25519 verifying key. Both inputs are used verbatim -
no trimming, no case folding - so the construction is reproducible outside
the tool.

The derivation is a pure function over public values: no repository, no
key store, no pin, no network. A user on a clean host reproduces the exact
value with stock OS tools:

```sh
printf '%s:%s' 'alice@example.com' "$(age-keygen -y private-key.txt)" | sha256sum
printf '%s:%s' 'demo+example@github.com' "$(head -n 1 owner.verifying)" | sha256sum
```

Use `printf`, never `echo` (echo appends a newline and hashes different
bytes). Exactly one colon separates label and key. The digest is lowercase
hex. `owner.verifying` line 1 is the verifying key; `head -n 1` selects it
because the file may carry the owner's X25519 public key (`age` recipient)
on line 2.

Golden vectors. These (label, public key encoding, fingerprint)
triples are produced by the one-liners above and asserted against the Rust
implementation (tests/fingerprint.rs) - code equals coreutils for every
key type. The first public key is a real `age-keygen` X25519 public key; the
second is a real openssl-generated Ed25519 verifying key:

| label | public key encoding | fingerprint |
|-------|---------------------|-------------|
| `alice@example.com` | `age1ga9us2r837a445htpvmuvxnygc8mrxglvtzrfwk0kyy7q55r3ypqlt28nk` | `263e683748d60e61ea89a6470e209f697c5ec23452e8bc8f222e2aff48e0d36b` |
| `demo+example@github.com` | `92cf641b35021f2c38fa5016fe9c413d4a399bfdc67c6832b4f9fdd019ccebdb` | `b7480ed036c6ab15e0446b8caa694faeb2983959bb49e7920a94d14b6bb773d1` |

`git-veil fingerprint <LABEL> <PUBLIC_KEY>` prints the value and nothing
else.

Where fingerprints are used:

- the per-machine pin and the committed `trusted_keys` record carry the
  owner key fingerprint - the derivation with the repository id as the
  label (`owner_key_fingerprint`);
- `owner_fingerprints` carries the same value: the human out-of-band token
  (`export-pin` prints it) and the pin-file import witness;
- `list-keys` prints the binding fingerprint of each keyring principal -
  the derivation with the principal label - computed at print time; the
  keyring stores only the principal and the public key (format v2), never
  a fingerprint;
- key selection in `export`, `import`, `removekey` and `--signing-key` is
  by public key string only; no fingerprint-as-identifier mode remains.

**Legacy 16 hex character values are hostile.** The retired derivations
produced 16 hex character fingerprints. A pin or committed trust record in
that format is refused by every gated command with exit code 70, in a
message naming the derivation change; nothing is rewritten silently. The
recovery is re-establishing the pin as described in "Pin creation".

## Keyring format and freshness (rollback refusal)

The keyring file is an armored block:

```
-----BEGIN GIT-VEIL KEYRING-----
version:<n>
<email>:<X25519-public-key>
...
-----END GIT-VEIL KEYRING-----
-----BEGIN GIT-VEIL SIGNATURE-----
<base64 Ed25519 signature over everything above, markers included>
```

Keyring format v2: exactly two fields per entry - the
principal (email) and the bech32 X25519 public key - with the signature
over the pair.
Fingerprints are computed on demand (see "Fingerprints") and never stored;
a legacy three-field entry carrying a stored fingerprint is a parse
refusal (exit code 62), never a silent migration.

The `version:` line (Keyring, src/keyring.rs) is a **monotonic counter
carried inside the signed payload**: the signature covers it, so a version
number cannot be forged without the owner key. `tell` and `removeperson`
write `current + 1` (current = the keyring's own version, 0 when absent) -
the counter needs no state outside the keyring it is serialised into, and no
clock, so there is no drift to reason about.

The signature alone proves "the owner signed this at some point", not "this
is current": a plain `git revert` of a removeperson commit restores an old,
still-validly-signed keyring, silently returning a revoked collaborator to
the keyring. The defence is a per-machine **freshness baseline** - the
highest keyring version this machine has ever accepted for this repo id,
with the SHA-256 digest of the accepted signed content, stored outside the
repository next to the pin
(`<key store>/trust-pins/<sanitized repo id>.ring-version`,
TrustPinStore, src/trust_store.rs):

$$
\begin{array}{ll}
\multicolumn{2}{l}{\textbf{Algorithm 5} \quad \textsc{FreshnessGate}(\mathit{repoId}, \mathit{ring}) \ . \ \text{invoked from Algorithm 4, step 14}} \\
\multicolumn{2}{l}{\textit{Machine state: } B[\mathit{repoId}] = (\mathit{version}, \mathit{digest}) \ \text{or} \ \bot} \\
1: & v \leftarrow \mathit{ring}.\mathit{version} \quad . \ \text{a versionless ring counts as 0} \\
2: & \textbf{if } \mathit{ring} \text{ is unsigned with zero entries then} \\
3: & \quad \textbf{if } B = \bot \textbf{ then return} \ . \ \text{accepted as version 0; the fresh-init state is never recorded} \\
4: & \quad \textbf{refuse} \ . \ \text{exit 14: on a baselined machine an unsigned ring is a rollback to no collaborators} \\
5: & \textbf{if } B \ne \bot \textbf{ then} \\
6: & \quad \textbf{if } v < B.\mathit{version} \textbf{ then refuse} \ . \ \text{exit 14: rollback} \\
7: & \quad \textbf{if } v = B.\mathit{version} \land \text{digest}(\mathit{ring}) \ne B.\mathit{digest} \textbf{ then refuse} \ . \ \text{exit 14: fork, equal-version substitution} \\
8: & \textbf{if the ring is signed then } B \leftarrow (v, \text{digest}(\mathit{ring})) \quad . \ \text{only a signed ring moves the baseline} \\
\end{array}
$$

The fork rule (step 7) exists because two curating machines that do not
pull in between would otherwise produce two differently-populated
version-N keyrings, and the second would silently replace the first; a
legitimate bump to a higher version is accepted and advances both version
and digest. Baselines written before the digest existed carry no digest and
are upgraded in place on the next accepted signed ring. A fresh clone has
no baseline: the first gated command records the current signed keyring's
version - the same trust-on-first-use posture as the pin itself. The
baseline is machine-local state in the key store, which is exactly where it
must live: anything committed to the repo would be attacker-writable and
the refusal would be void.

**Recovery.** A legitimate rollback (the owner really does want an older
keyring state) is the same ceremony as a legitimate anchor change: re-run
Algorithm 2, which clears the freshness baseline along with re-pinning the
key. Old keyrings written before freshness existed are accepted until the
next `tell`/`removeperson` gives them a version; from then on their
rollback is refused.

## Key discovery and selection

git-veil **never generates key material**. A key the tool created is a key the
user never backed up; the tool's job on a missing key is to say so, teach the
creation recipe, and exit with a documented code - not to silently manufacture
credentials (`src/key_discovery.rs`).

$$
\begin{array}{ll}
\multicolumn{2}{l}{\textbf{Algorithm 6} \quad \textsc{DiscoverSigningKey}(S, \mathit{repoId}, \mathit{claimed}, \mathit{explicitVK}) \ . \ \text{used by tell and removeperson}} \\
\multicolumn{2}{l}{\textit{S = the key store;} \ \texttt{signing-keys.txt} \text{ holds one 64-hex seed per line, } \texttt{\#} \text{ comments and blank lines skipped}} \\
1: & \textbf{function } \textsc{DiscoverSigningKey} \\
2: & \quad keys \leftarrow \text{load signing keys} \quad . \ \text{a garbage line is a parse refusal, exit 62, never silently no keys} \\
3: & \quad \textbf{if } keys = \emptyset \textbf{ then refuse} \ . \ \text{exit 20 with the create-and-back-up recipe} \\
4: & \quad \textbf{if } \mathit{explicitVK} \ne \bot \textbf{ then} \\
5: & \quad\quad M \leftarrow \{ k \in keys : \text{hex}(\text{verifying}(k)) = \mathit{explicitVK} \} \quad . \ \text{the ONLY explicit form: the full 64-hex verifying key} \\
   & \quad\quad . \ \text{the 1-based index and the 64-hex seed forms are parse errors; a 16-hex fingerprint form is retired} \\
6: & \quad\quad \textbf{if } |M| = 0 \textbf{ then refuse} \ . \ \text{exit 20} \,; \ \textbf{if } |M| > 1 \textbf{ then refuse} \ . \ \text{exit 70} \\
7: & \quad\quad \textbf{return } \text{the unique } k \in M \\
8: & \quad M \leftarrow \{ k \in keys : \textsc{Fingerprint}(\mathit{repoId}, \text{enc}(\text{verifying}(k))) = \mathit{claimed} \} \\
9: & \quad \textbf{if } M = \emptyset \textbf{ then refuse} \ . \ \text{exit 20 with the recipe} \\
10: & \quad \textbf{return } \text{the unique match} \quad . \ \text{the pin, not list order, selects the key; deterministic, no menu} \\
11: & \textbf{end function}
\end{array}
$$

**X25519 private keys** (`discover_x25519_private_key`): decrypting commands
resolve their keyring entry by principal, then look up the matching X25519
private key in `<key store>/identities.txt`. No matching private key → exit
code 21 after printing the `age-keygen`/`rage-keygen` creation recipe for
the private key (an `age` identity), the `git-veil import` step, and the backup
instruction. A user whose principal is not in the signed keyring at all
fails earlier, with exit code 22.

## Key store permissions

The key store is checked at load time the way gpg checks `~/.gnupg`
(`src/permissions.rs`, Unix only):

$$
\begin{array}{ll}
\multicolumn{2}{l}{\textbf{Algorithm 7} \quad \textsc{PermissionsGate}(S) \ . \ \text{runs once in main, before any key material is read}} \\
\multicolumn{2}{l}{\textit{Permanent state: } A \text{ = acknowledged findings, } \texttt{permissions-ack.json} \text{ (mode 0600)}} \\
1: & \textbf{function } \textsc{PermissionsGate} \\
2: & \quad findings \leftarrow \{ S \} \cup \{ \texttt{identities.txt}, \texttt{signing-keys.txt} \} \text{ filtered to paths with group or world bits} \\
3: & \quad \textbf{for all } f \in findings \textbf{ do} \\
4: & \quad\quad \textbf{if } (f, mode(f)) \in A \textbf{ then continue} \quad . \ \text{exact (path, mode) pairs; any later change fails again} \\
5: & \quad\quad \textbf{refuse} \ . \ \text{exit 30, listing each path with its observed mode and the fix} \\
6: & \quad \textbf{end for} \\
7: & \textbf{end function}
\end{array}
$$

git-veil **never chmods a file it did not create**. The acknowledgment
model follows git's dubious-ownership pattern:
`git-veil trust-permissions` records the current findings as exact
`(path, mode)` pairs in `<key store>/permissions-ack.json` (created mode
0600 via `write_atomic_mode`); a later check passes only if every finding
matches an acknowledged pair exactly - permissions that later change to
anything else fail again. The check is bypassed entirely by the global
`--dangerously-skip-permissions-check` flag or a truthy
`GIT_VEIL_SKIP_PERMISSIONS` environment variable.

Files git-veil itself creates that hold private key material -
`identities.txt` (via `import` and `import_x25519_private_key_to_store`) and the
acknowledgment file - are created mode 0600 at write time
(`write_atomic_mode`, src/fs_atomic.rs), independent of the process umask.
Repo working-tree files (revealed plaintext, `.secret` ciphertext) are
deliberately not permission-policed: they are ordinary repository content.

## Crash safety and durability

**Atomic writes.** Every durable state file goes through `write_atomic`
(src/fs_atomic.rs): write to a temp file `<name>.tmp-<pid>` in the same
directory (same volume, so the rename can never degrade into a copy), fsync the
file, rename it over the target, then best-effort fsync the parent directory
(directory-fsync errors are ignored - not portable). On any failure the temp
file is removed and the target is untouched. The target is therefore always
either the old content or the new content, never a mix. `write_atomic_mode` is
the same sequence with an explicit creation mode for private key material.
Covered writes: the keyring (`cmd_init`, `cmd_tell`, `cmd_removeperson`),
tracked.json (`TrackedFiles::save`), trust.json and pins (`TrustStore`,
`TrustPinStore`), the private-key/public-key/verifying-key stores
(`cmd_import`, `import_x25519_private_key_to_store`,
`import_x25519_public_key_to_store`, `cmd_trust`), ciphertext (`cmd_hide`),
restored plaintext (`cmd_reveal`,
`cmd_unhide`), export output (`cmd_export`), the removekey rewrite
(`cmd_removekey`), and the permissions acknowledgment
(`cmd_trust_permissions`). Key-store appends are implemented as read-existing
plus `write_atomic` of the whole accumulated content - an accepted O(n) trade
so a torn private-key store (which would brick all decryption) is impossible.

$$
\begin{array}{ll}
\multicolumn{2}{l}{\textbf{Algorithm 8} \quad \textsc{TwoPhase} \text{ - the hide/reveal/unhide commit discipline}} \\
1: & \textbf{phase 1 (in memory): } \text{read and validate every target;} \text{ compute all outputs} \\
   & \quad \text{any failure aborts with nothing changed on disk} \\
2: & \textbf{phase 2 (commit): } \text{write each output atomically;} \text{ a part-way failure is reported with written/total counts, exit non-zero} \\
3: & \textbf{hide (default): } \text{delete each plaintext after its ciphertext is durably on disk} \ . \ \texttt{--keep-plaintext} \text{ opts out} \\
4: & \textbf{invariant: at worst both copies exist, never neither}
\end{array}
$$

**Plaintext lifecycle.** Deleting by default is a deliberate posture: the
plaintext's only protection in the worktree is a `.gitignore` line, so the
normal loop is `reveal` → edit → `hide`, with the plaintext existing only
while it is being edited. Consequences, stated honestly:

- **Skip-and-report, not error.** A tracked path whose plaintext is absent
  and whose ciphertext exists (on disk or committed) is skipped and reported
  as "already hidden" - re-running `hide` on a hidden repo does nothing and
  succeeds. A tracked path with neither plaintext nor ciphertext is skipped
  and reported as never-hidden. Neither state is an error: absence of
  plaintext is the steady state of this lifecycle.
- **Rotation requires the plaintext.** `removeperson` + `hide` alone cannot
  re-encrypt ciphertexts whose plaintexts are gone - the correct rotation is
  `reveal` (restores plaintexts), `removeperson`, `hide` (re-encrypts to the
  new ring, deletes plaintexts again). Documented here because it is the one
  workflow that changed shape with this default.
- The intent gate (exit 72) and the code-41 plaintext-leak warning only
  apply to paths that have a plaintext to encrypt; a path with no plaintext
  has nothing to exfiltrate and nothing to warn about.

**Crash windows that remain.** Death between a phase-2 write and its paired
delete (the default path) leaves both copies on disk. This is stated
honestly: it is a redundancy window, not a data-loss window, and the
plaintext is gitignored. The next command resolves it: re-running `hide`
re-encrypts the still-present plaintexts to the current keyring and atomically
overwrites the ciphertexts. Death during `trust` between the trust.json write
and the pin write fails closed on the next gated command (Algorithm 2's
ordering invariant).

## Ignore safety

Ciphertext lives beside its plaintext as `<name>.secret` and is meant to be
committed; plaintext is meant to be gitignored. The gates below run inside
Algorithm 9 (`src/commands/add.rs`, `src/commands/hide.rs`):

1. **Add-time gitignore gate** (`ensure_gitignored`): like git-secret, `add`
   runs `git check-ignore` on the plaintext path and appends it to
   `.gitignore` when not already ignored.
2. **Ciphertext-ignored refusal**: a `.secret` path can be silently swallowed
   by an unrelated broad rule (e.g. a parent directory like `.tmp/` in
   `.gitignore`) - `add` would succeed and the ciphertext would never reach
   the repository. `add` therefore warns (exit stays 0) when the future
   `.secret` path is git-ignored, and `hide` **refuses outright** with exit
   code 40 before encrypting anything, listing every offending path.
3. **Plaintext-leak warning**: if a tracked plaintext exists on disk but is
   not gitignored (typically after a rename or a `.gitignore` edit), `hide`
   prints a warning citing exit code 41 and proceeds - the condition is a
   risk, not a tool failure. The tutorials show an optional pre-commit hook
   that turns it into a hard stop.
4. **Reveal-side tracked-plaintext refusal**: the inverse case is not a
   warning but a hard refusal in the decryption-write commands. A plaintext
   that is tracked in git is ordinary repository content, not a secret
   (git-veil plaintexts are gitignored by construction; a tracked plaintext
   is exactly the state the code-41 warning flags). If `reveal` or `unhide`
   refused nothing there, a repo writer could nominate a source file - say
    `ci/deploy.sh` - in the unsigned `tracked.json` and commit a payload
    ciphertext encrypted to the ring's public keys (no signing key
    needed, the keyring is untouched); the victim's `reveal` would overwrite
   the source file and the CI would execute it. `reveal` and `unhide`
   therefore refuse with exit code 43 (PlaintextTracked) when the target
   plaintext path is tracked in the git index, naming the path and the
   `git rm --cached` remedy. `cat` is not gated: it never writes. The gate
   is `ensure_not_tracked_in_git` (src/commands/reveal.rs, unhide.rs) over
   `is_tracked_in_git` (src/commands/add.rs), whose index match is
   case-insensitive as a fallback: on the macOS and Windows default
   filesystems a case-variant spelling (`BUILD.SH` vs `Build.sh`) resolves
   to the same file, so an exact-match miss must still refuse when any
   case-variant of the path is in the index. On case-sensitive filesystems
   the fallback can in principle false-positive two genuinely distinct
   case-variant files - for a secrets tool refusing beats overwriting.

## Orphaned ciphertext (a committed `.secret` that is not tracked)

`hide` re-encrypts only tracked paths. That makes the tracked manifest the
de-facto revocation boundary: if a path is removed from `tracked.json`, the
old ciphertext is never re-encrypted, so after a `removeperson` rotation the
stale `.secret` stays decryptable by the removed collaborator - silently,
with `hide` reporting success. Since `tracked.json` is committed and unsigned
repo content, any repo writer can cause this by deleting manifest entries.

Two mitigations close the hole:

1. **`remove` deletes the sibling ciphertext by default.** Untracking a file
   deletes `<name>.secret` from the working tree in the same step
   (`--keep-ciphertext` preserves the old leave-in-place behaviour). The
   ciphertext is committed content, so deletion is recoverable from git
   history; the honest way to keep an untracked ciphertext around is now an
   explicit flag, not a default.
2. **`hide` refuses orphaned ciphertext (exit 42).** Algorithm 9's step 2
   enumerates ciphertext paths committed to the git index and refuses when
   any of them does not correspond to a tracked path, naming each one. The
   gate runs even when `tracked.json` is empty - that is exactly the
   de-tracking-then-rotate attack shape. The index is read verbatim
   (`git -c core.quotePath=false ls-files -z`) so unicode/space names map
   back to their tracked paths; a committed file named exactly `.secret`
   (no plaintext stem - it cannot correspond to any tracked path) is warned
   about and ignored rather than fatal, so one junk file cannot brick hide.

Scope, stated honestly: the gate reads the git **index**, so it catches
committed (staged) ciphertexts - the exfiltration channel. An uncommitted
on-disk `.secret` left behind by `remove --keep-ciphertext` is not detected
until staged; a blind `git add -A` could sweep it into a commit. This is the
same risk class as the code-41 plaintext-leak warning and is documented as
such, not hidden.

## Encryption intent (refusing nominated paths)

`tracked.json` is committed and unsigned: any repo writer can add a path to
it. The victim's next `hide` would then encrypt a file the victim never
added - typically a gitignored secret - to every keyring member, including
the attacker's, and the ciphertext is committed in the ordinary flow. The
plaintext being gitignored suppresses even the code-41 warning, so the
exfiltration is silent. The manifest cannot distinguish "user intends to
track this" from "attacker nominated it" - the manifest IS the attack
surface - so intent is bound to the **victim's own action** instead:
`add` records intent on the machine that ran it, appending the resolved
repo-relative path to a machine-local intent log,
`<key store>/local-adds/<sanitized repo id>` (one path per line;
`LocalAdds`, src/intent.rs). The key store is outside the repository and
permission-checked, so repo writers cannot write or poison it, and a
`pull` cannot alter it. Algorithm 9 defines what `hide` then demands:

$$
\begin{array}{ll}
\multicolumn{2}{l}{\textbf{Algorithm 9} \quad \textsc{Hide} \text{ - the gate sequence before any encryption (} \texttt{cmd\_hide} \text{)}} \\
\multicolumn{2}{l}{\textit{Machine state: } I \text{ = intent log;} \ C[\mathit{digest}] \text{ = the happen-before baseline cache}} \\
1: & \textbf{upon } \textsc{Hide} \\
2: & \quad \textsc{VerifyKeyring} \quad . \ \text{Algorithm 4} \\
3: & \quad \text{gates 40 and 41: refuse git-ignored future ciphertext paths (exit 40); warn on non-gitignored tracked plaintexts (exit stays 0)} \\
4: & \quad index \leftarrow \text{ciphertext paths in the git index} \quad . \ \text{read verbatim, core.quotePath=false, -z} \\
5: & \quad orphans \leftarrow \{ c \in index : \text{plaintext}(c) \notin tracked \} \\
6: & \quad \textbf{if } orphans \ne \emptyset \textbf{ then refuse} \ . \ \text{exit 42, naming each orphan; a committed file named exactly .secret is warned and skipped} \\
7: & \quad digest \leftarrow \text{SHA-256 of } \texttt{tracked.json} \,; \ cache \leftarrow C[\mathit{digest}] \\
8: & \quad \textbf{for all } p \in tracked \text{ with } \text{plaintext}(p) \text{ on disk and a committed ciphertext } c(p) \textbf{ do} \\
9: & \quad\quad \textbf{if } p \in cache \textbf{ then } \mathit{established}(p) \quad . \ \text{the fast path} \\
10: & \quad\quad \textbf{else if } \textsc{HappenBefore}(p, c(p)) \textbf{ then } cache \leftarrow cache \cup \{p\} \,; \mathit{established}(p) \\
11: & \quad\quad \textbf{else if } p \notin I \textbf{ then refuse} \ . \ \text{exit 72, naming the paths; the remedy is this document} \\
12: & \quad \text{encrypt phase 1 to the full ring in memory, then commit per Algorithm 8} \\
13: & \textbf{end upon} \\[2mm]
\multicolumn{2}{l}{\textbf{function } \textsc{HappenBefore}(p, c) \ . \ \text{issue \#19; a committed ciphertext is established only when it predates the manifest entry}} \\
a: & \quad \textbf{for all } k \in \text{commits touching } \texttt{tracked.json} \text{, newest first} \textbf{ do} \\
b: & \quad\quad \textbf{if entry}(p) \in \text{manifest}@k \ \land \ \text{entry}(p) \notin \text{manifest}@{\text{parent}(k)} \textbf{ then} \\
c: & \quad\quad\quad \textbf{return } c \in \text{tree}(\text{parent}(k)) \\
d: & \quad \textbf{end for} \\
e: & \quad \textbf{return false} \\
f: & \textbf{end function}
\end{array}
$$

The happen-before result is cached per manifest version: the key store
either holds a baseline for that manifest hash or it does not - there is no
clone-versus-update distinction anywhere in the logic. Any manifest change
(add, remove, reorder) changes the hash, which selects a fresh cache entry,
so a remove-and-readd is re-checked against the re-add commit with no
invalidation logic and no garbage collection. A path that fails the check
is never cached: every `hide` re-runs the check and refuses again.

Honest residual. The happen-before check raises the
attacker's cost from one visible change to a crafted history: a dummy
ciphertext committed BEFORE the nomination still predates the manifest
entry and passes the check. The intent log remains the real anchor -
every machine that wants to first-encrypt a path must have run `add`
for it - and the check only removes the free ride a same-commit dummy
otherwise gets. A stricter rule (for example binding the manifest hash
into the signed keyring payload) is the follow-up direction.

Stated honestly, the remaining trade-offs: the intent log is machine-local,
so an owner who re-hides from a machine whose key store was restored must
re-run `add` for any path without an established ciphertext; and a
malicious collaborator can still make `hide` refuse (availability) by
nominating junk paths - that is fail-closed by design, the same posture as
the code-40 gate, and each refusal names the offending paths.

## CODEOWNERS coverage for the trust-critical paths (suggested, never required)

CODEOWNERS is a platform feature, not a git feature: plain git ignores the
file. Where the platform enforces it (with branch protection), a
write-access attacker's rekey of the trust anchor becomes a review-gated
change instead of a silent push. The tool suggests and warns; it never
requires, and it works unchanged on plain-git hosting. On platforms with
no CODEOWNERS support the file simply sits there ignored, which is
harmless.

- **Locations, in platform precedence order**: the repository root,
  then `.github/`, `docs/`, `.gitlab/`, `.gitea/`, `.forgejo/` and
  `.bitbucket/`. The first file found in that order is the one evaluated
  (src/codeowners.rs).
- **Matching reuses the gitignore matcher** (gix-ignore, the gitoxide
  matcher): CODEOWNERS patterns are a subset of gitignore (no negation, no
  character ranges, no escape handling), so the matcher answers whether a
  pattern covers `owner.verifying` and the `.git-veil/` directory,
  last-match-wins. Owner strings are not validated - only the question
  does any pattern match these paths is answered. Gitea and Forgejo use a
  different pattern language; the gitignore matcher may produce false
  negatives there, and the warning is non-blocking, so a false negative
  only costs an unnecessary reminder.
- **`git-veil init` suggests, once, in plain text.** After initializing
  `.git-veil/`, a non-quiet `init` prints a suggestion naming the
  trust-critical paths and the lines to add, with no prompt, no stdin and
  no file creation. `git-veil init -q` prints nothing. The tool never
  creates a CODEOWNERS file.
- **`git-veil trust` warns when the trust anchor is not review-gated.**
  Algorithm 2's final step: after a successful pin (proof or import), a
  non-blocking warning is printed when no CODEOWNERS file covers the
  trust-critical paths. The warning never refuses and never alters the
  exit code.
- **Suppression is deliberate and bound to the pin.** A user who does not
  want CODEOWNERS and does not want the reminder suppresses it per pinned
  repository: `git-veil trust --suppress-codeowners` records the
  repository id in the key store (`codeowners-suppression`, outside the
  repository and attacker-proof) at the same moment the possession proof
  or import pins the anchor. Only the pin-creation command can write the
  entry, so creating a suppression requires holding the machine that
  proved possession of the signing key - the possession proof is the
  signature on the suppression. Suppressed repositories print no
  CODEOWNERS warning.

## Path safety

Tracked paths are repo-relative strings in `.git-veil/tracked.json`. Four
layers guard them:

$$
\begin{array}{ll}
\multicolumn{2}{l}{\textbf{Algorithm 10} \quad \textsc{AcceptTrackedPath} \text{ - and the decryption-write gate}} \\
1: & \textbf{function } \textsc{AcceptTrackedPath}(\mathit{input}) \\
2: & \quad \textbf{guard } \mathit{input} \text{ is non-empty and relative, every component Normal} \quad \textbf{else refuse} \ . \ \text{exit 71 (} \texttt{validate\_tracked\_path} \text{)} \\
3: & \quad \textbf{guard } \text{canonicalise}(\mathit{input}, \text{symlinks resolved, } \texttt{..} \text{ collapsed}) \subseteq \text{repository root} \\
   & \quad\quad \textbf{else refuse} \ . \ \text{exit 71; a link to } \text{/home/victim/.ssh/id\_rsa} \text{ fails here at add time} \\
4: & \quad \textbf{guard } \text{lstat}(\mathit{path}) \text{ is a regular file or absent} \quad \textbf{else refuse} \ . \ \text{exit 71; a committed symlink is refused on every use} \\
5: & \quad \textbf{guard } \text{ciphertext path} = \langle \text{plaintext}.secret \rangle \text{ inside the repository root} \quad \textbf{else refuse} \ . \ \text{exit 71} \\
6: & \textbf{end function} \\[2mm]
\multicolumn{2}{l}{\textbf{upon } \textsc{Reveal} / \textsc{Unhide} \text{ (the decryption-write gate)}} \\
a: & \quad \textbf{guard } \text{the target plaintext is not tracked in the git index, case-insensitively} \\
   & \quad\quad \textbf{else refuse} \ . \ \text{exit 43, naming the path; cat is not gated, it never writes} \\
b: & \textbf{end upon}
\end{array}
$$

Layer 1 is `validate_tracked_path`, layer 2 the add-time
canonicalise-and-reject (`resolve_repo_relative_input` with
`PathResolveMode::CanonicaliseRequireExists`), layer 3 the read-time
regular-file gate (`ensure_regular_file`, lstat; a *missing* path is
accepted - the plaintext is normally absent while hidden), layer 4
`ensure_ciphertext_beside_plaintext`. Layers 1 to 4 fire on every use of a
tracked path in hide, reveal, unhide, cat and changes. *Threats countered:*
a malicious committed tracked.json making git-veil read or write outside
the repository; tracking a symlink whose target is read into committed
ciphertext (hide) or printed (cat/changes) or written through
(reveal/unhide); any future drift in the ciphertext-path math reintroducing
an escape. The case-insensitive fallback in the decryption-write gate
exists because on the macOS and Windows default filesystems a case-variant
spelling (`BUILD.SH` vs `Build.sh`) resolves to the same file, so an
exact-match miss must still refuse when any case-variant of the path is in
the index; on case-sensitive filesystems the fallback can in principle
false-positive two genuinely distinct case-variant files - for a secrets
tool refusing beats overwriting. Which path-resolution contract each
command uses is pinned down per caller in `PathResolveMode`
(src/tracked_files.rs).

## Exit codes

Every deliberate failure exits with a documented code (`ExitCode`,
src/exit_codes.rs); errors without a specific code exit 1, and clap usage
errors exit 2. `git-veil error-codes` prints this table; it is public API -
codes are never renumbered, only appended.

| Code | Name                        | Meaning |
|-----:|------------------------------|---------|
| 1    | GeneralError                 | Failure without a more specific code |
| 2    | Usage                        | Command-line usage error |
| 10   | NoTrustRecord                | Committed trust.json has no entry for this repository; run `git-veil trust` |
| 11   | NoTrustPin                   | No local trust pin on this machine; run `git-veil trust` |
| 12   | TrustMismatch                | Committed trust.json disagrees with this machine's pin; re-pin if intended |
| 13   | TrustRepoIdMismatch          | repo_id argument does not match the one derived from the remote |
| 14   | KeyringRollback              | Keyring version is below this machine's freshness baseline; re-`trust` if the rollback is intended |
| 20   | NoSigningKey                 | No Ed25519 signing key in the key store; create one and back it up |
| 21   | NoX25519PrivateKey           | No X25519 private key in the key store matching your keyring entry; create and import one |
| 22   | PrincipalNotInKeyring        | Your principal is not in the signed keyring; ask the owner to `tell` you |
| 30   | UnsafeKeyStorePermissions    | Key store directory or private key file is group/world accessible |
| 40   | CiphertextIgnored            | A `.secret` ciphertext path is git-ignored (fatal in `hide`; warning in `add`) |
| 41   | PlaintextNotIgnored          | Tracked plaintext on disk is not git-ignored (warning; exit stays 0) |
| 42   | OrphanedCiphertext           | A committed `.secret` ciphertext path is not tracked; `hide` refuses (see "Orphaned ciphertext") |
| 43   | PlaintextTracked             | The plaintext is tracked in git (fatal in `reveal`/`unhide`; see "Ignore safety" gate 4) |
| 60   | DecryptionFailed             | Ciphertext could not be decrypted with the local private key |
| 61   | EncryptionFailed             | Encryption failed |
| 62   | KeyParseFailure              | A key, keyring or signature could not be parsed |
| 63   | SignatureVerificationFailed  | Keyring signature missing or invalid |
| 70   | Refused                      | Policy refusal (e.g. `init` over established trust, `clean` without `--yes`) |
| 71   | UnsafePath                   | Path-safety refusal (symlink, outside repository, unsafe tracked path) |
| 72   | UnintendedEncryption         | `hide` refuses to encrypt a file the user never added on this machine (see "Encryption intent") |
