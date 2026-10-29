# Trust And Pinning Model

This section has diagrams that explain the **trust** section of the `git-veil` command reference. 

The repo owner commits the public part of their signing key into the repo. An attacker could replace the real public key with their own. We require the user to assert trust in the owner's signing-key fingerprint only once. 

## Trust Anchors And PINs 

We pin the fingerprint to the git service, organisation, and repo, which we call the `repo-id`:

```mermaid
flowchart TD
  A["Machine wants to trust repo"] --> B{"Possession proof available?"}
  B -- "yes: signing seed in local key store" --> C["git-veil trust &lt;repo_id&gt;"]
  B -- "no: consumer machine" --> D["Obtain pin-file out of band"]
  C --> E["Read committed .git-veil/owner.verifying"]
  E --> F{"Matches verifying key derived from a seed in signing-keys.txt?"}
  F -- "exact match" --> G["Pin written to key store"]
  F -- "no match" --> X1["Refuse — exit 20"]
  D --> H["git-veil trust --import &lt;pin-file&gt;"]
  H --> I{"3 consistency checks"}
  I -- "all pass" --> G
  I -- "any mismatch" --> X2["Refuse — exit 70"]
  H -- "pin-file inside the worktree" --> X3["Refuse — exit 71"]
```

## How the pinned trust anchor is used

Every command that touches secrets runs this check first. No pin, or a bad signature, means nothing is touched.

```mermaid
flowchart TD
  A["Gated command (add-key, hide, reveal, rotate, ...)"] --> B["Verify keyring signature against pinned trusted key"]
  B --> C{"Committed trust record?"}
  C -- "missing" --> E10["exit 10"]
  C -- "present" --> D{"Local pin on this machine?"}
  D -- "missing" --> E11["exit 11"]
  D -- "present" --> E{"Record agrees with pin?"}
  E -- "disagrees" --> E12["exit 12"]
  E -- "agrees" --> F{"Keyring rollback below freshness baseline?"}
  F -- "yes" --> E14["exit 14"]
  F -- "no" --> G{"Signature valid?"}
  G -- "valid" --> OK["Proceed — secrets may be touched"]
```

## The export-pin → import ceremony

The pin-file always travels out of band (scp, USB, read aloud), never through the repository - the `known_hosts` provisioning model.

## Trust commands and exit codes

| Command | Purpose | Notable exit codes |
| --- | --- | --- |
| `trust <repo_id>` | Possession proof; pin from committed `.git-veil/owner.verifying` | 13, 20, 70, 71, 30 |
| `trust --import <pin-file>` | Pin from an exported pin-file, out of band | 13, 20, 70, 71, 30 |
| `export-pin` | Write pin-file for machines without the signing key | 20, 71, 30 |
| `fingerprint <label> <public_key>` | Pure `SHA-256(label:encoding)` derivation, no state | usage errors (2) |
| `verify-keys` | Cheap health check of the gate above | 10, 11, 12, 14, 63, 70, 30 |
| `trust-permissions` | Acknowledge key-store permission state (exit 30) | 30 |

**Refused as hostile:** a pin or trust record in the old 16-hex-character fingerprint format is refused until trust is re-established (exit 70).

**Typical order:** `init` → `trust` → `add-key` → `rotate`. 
