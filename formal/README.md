# git-veil formal security model

This Lean 4 project specifies selected security contracts from the complete
design and command documentation at release **v0.17.5** (`c42f799`). The
checkout used for the review was clean on `main`, two commits behind that tag.
The two intervening commits changed release/build files and installation
documentation; the design page, command page, and modeled source files were
identical. The model targets the release tag without checking out or changing
the shared branch.

## Verify

With elan installed, from this directory run:

```sh
lake build
```

The project pins Lean in `lean-toolchain`. `lake build` elaborates the model
and checks every theorem with Lean's kernel; no git-veil runtime tests are
part of this formal project.

## What the model states

[`GitVeil/SecurityModel.lean`](GitVeil/SecurityModel.lean) has explicit state
for the tracked manifest, Git index, worktree ciphertexts, plaintexts,
ignore facts, per-machine allowance, path-safety facts, local membership and
private-key facts, trust pin and committed trust record, signed keyring,
freshness baseline, ring-change stamp, and key-store permission gate.
Commands are state predicates/transitions, not axioms asserting the desired
conclusion.

Kernel-checked model results cover:

- A trusted command requires a local pin matching the committed record; an
  unsigned populated keyring, a backwards version, or an equal-version
  signed-content fork is rejected.
- First encryption of a plaintext requires either local allowance or a
  ciphertext for that logical path in the index. A denied hide transition
  preserves the modeled state. A non-ignored plaintext is a warning fact,
  not a hide refusal, matching the documented exit-41 behavior.
- Reveal requires a valid trust/permission gate, membership and the matching
  local private key, and refuses to overwrite a plaintext path in the Git
  index. Allowance is not a reveal precondition.
- Rotation requires a matching stamp and no indexed orphan paths.
- A per-file atomic replacement yields an old or new complete file value.

The theorems prove these statements only for this Lean model. The predicates
`signatureValid`, `safePaths`, ignore results, index membership, key
possession, and file presence are supplied state facts. Lean does not prove
Ed25519, X25519, SHA-256, Git's pathspec/ignore behavior, Rust path resolution,
filesystem race freedom, or correspondence between Rust execution and these
transitions.

## Countermodels and implementation review

The file contains kernel-checked countermodels, derived from the v0.17.5
source. They are evidence that the stronger property is not a theorem of the
implementation-shaped model:

1. **Rotation can consume its stamp while an old indexed ciphertext remains.**
   `cmd_rotate` checks indexed paths for *untracked* orphans, then selects
   only tracked ciphertexts for which `Path::exists()` succeeds in the
   worktree. An indexed ciphertext missing from the worktree passes the orphan
   check, is skipped, and the successful pass clears the stamp. The model
   witness leaves the index ciphertext at ring version 1 after a version-2
   pass reports completion. This is a confirmed security deviation from the
   requirement that every committed ciphertext be re-encrypted.
2. **Unsigned empty-ring freshness differs from Design Algorithm 5.** The
   design says an unsigned empty ring is accepted only when no baseline
   exists, and otherwise refused. `verify_keyring_against_trust` checks the
   observed version and only compares a digest when the presented ring is
   signed. Therefore an unsigned empty version-0 ring passes with a stored
   version-0 baseline. More generally, an unsigned empty ring carrying a
   version at least as high as the baseline can pass without advancing that
   baseline. The theorem exhibits the version-0 case. Establishing whether
   such a baseline is reachable in ordinary command history is a separate
   correspondence question; the invariant as stated is not enforced for all
   representable states.
3. **The documented allowance residual is real.** A repo writer can place a
   dummy ciphertext path in the index before the plaintext is nominated.
   `hide` treats that path as established and permits encryption with no local
   allowance. This is explicitly acknowledged in the design as the two-commit
   ambush residual; the model records it as a counterexample, not a security
   guarantee.
4. **Atomic file replacement is not a multi-file transaction.** `hide`,
   `reveal`, and `rotate` prepare outputs before phase 2, but then replace
   files one by one. Their loops can have successful writes and a later write
   error, leaving a mixed batch. The design describes this partial-write
   outcome and reports counts; any blanket reading of “all-or-nothing” must
   be limited to validation/encryption failures before phase 2. The model
   distinguishes per-file atomicity from batch atomicity.
5. **Ignore-rule mutation has unmodeled failure and pattern semantics.**
   `add_file::ensure_gitignored` appends the raw filename as a Git ignore
   pattern, so pattern metacharacters are not escaped. It also treats every
   `read_to_string(.gitignore)` error as an empty file, then uses
   `fs::write`; a read or interrupted write can therefore lose existing
   ignore rules. Hide's ciphertext-ignore check is a guard only if Git's
   check result is interpreted correctly. This model takes ignore facts as
   explicit inputs and does not claim that the Rust code safely maintains
   `.gitignore`.

## Correspondence boundary

The implementation paths reviewed are:

- `src/commands/verify_keys.rs`, `src/trust_store.rs`, `src/keyring.rs` for
  trust, signature, freshness, and ring-pass state;
- `src/commands/hide.rs`, `src/commands/reveal.rs`, `src/commands/rotate.rs`
  for command transitions and index/worktree behavior;
- `src/commands/add_file.rs`, `src/commands/allow.rs`, `src/allowance.rs`
  for first-encrypt consent and ignore handling;
- `src/tracked_files.rs`, `src/fs_atomic.rs`, and `src/permissions.rs` for
  path, file replacement, and key-store gates.

To claim implementation correctness, a separate refinement proof or
systematic executable correspondence argument must show that each Rust
operation preserves the model's state relation, including Git-index parsing,
error paths, concurrent filesystem changes, and multi-file write failures.
Nothing in this Lean project makes that claim.
