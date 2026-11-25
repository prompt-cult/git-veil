import Std

/-!
# git-veil security transition model

This is an explicit, finite-state abstraction of the security-relevant
contracts in `docs/src/design.md` and `docs/src/commands.md`, checked against
release v0.17.5. It is a model of the documented state transitions, not a
proof that Rust, Git, age/rage, the filesystem, or the operating system
implements those transitions. Countermodels below record concrete gaps found
by reading the tagged implementation.

`Ciphertext.path` is the logical tracked plaintext path whose sibling
`<path>.secret` is represented by the ciphertext. `indexCiphertexts` models
the Git index (including staged and committed entries); `worktreeCiphertexts`
models files currently present on disk. A keyring digest and version are
abstract natural numbers. Cryptographic collision resistance and signature
unforgeability are assumptions outside this model; `signatureValid` is an
explicit state fact, not a cryptographic proof.
-/

namespace GitVeil.SecurityModel

abbrev Path := String

structure Ciphertext where
  path : Path
  ringVersion : Nat
  deriving Repr, DecidableEq

structure Ring where
  version : Nat
  digest : Nat
  signed : Bool
  signatureValid : Bool
  entries : List String
  deriving Repr, DecidableEq

structure State where
  repoId : String
  tracked : List Path
  indexCiphertexts : List Ciphertext
  worktreeCiphertexts : List Ciphertext
  plaintextOnDisk : List Path
  plaintextInIndex : List Path
  ignoredPlaintext : List Path
  ignoredCiphertext : List Path
  allowedHere : List Path
  safePaths : List Path
  memberPrincipals : List String
  localPrivatePrincipals : List String
  pin : Option String
  committedTrustRecord : Option String
  ring : Ring
  baseline : Option (Nat × Nat)
  ringPassStamp : Option (Nat × Nat)
  keyStorePermissionsSafe : Bool
  permissionBypass : Bool
  deriving Repr, DecidableEq

def hasPath (xs : List Path) (p : Path) : Bool := xs.contains p

def hasCiphertext (xs : List Ciphertext) (p : Path) : Bool :=
  xs.any (fun c => c.path == p)

def hasCurrentCiphertext (xs : List Ciphertext) (p : Path) (v : Nat) : Bool :=
  xs.any (fun c => c.path == p && c.ringVersion == v)

def permissionGate (s : State) : Bool :=
  s.keyStorePermissionsSafe || s.permissionBypass

def signatureGate (r : Ring) : Bool :=
  if r.signed then r.signatureValid else r.entries.isEmpty

/-!
The implementation comparison is the branch in
`verify_keyring_against_trust` (v0.17.5). It compares the observed version
to the baseline and compares digests only when both rings are signed. An
unsigned empty ring does not advance the baseline, but with an existing
baseline it can still pass if its observed version is not lower.
-/
def implementationFreshnessGate (r : Ring) (baseline : Option (Nat × Nat)) : Bool :=
  match baseline with
  | none => true
  | some (baseVersion, baseDigest) =>
      if baseVersion > r.version then false
      else if baseVersion == r.version && r.signed && baseDigest != r.digest then false
      else true

/-!
The design's stronger unsigned-empty rule in Algorithm 5: unsigned empty
is accepted only before any baseline exists. A signed ring must not roll
back, and at equal version must retain the accepted digest.
-/
def designFreshnessGate (r : Ring) (baseline : Option (Nat × Nat)) : Bool :=
  if !r.signed && r.entries.isEmpty then baseline.isNone
  else
    match baseline with
    | none => true
    | some (baseVersion, baseDigest) =>
        if baseVersion > r.version then false
        else if baseVersion == r.version && baseDigest != r.digest then false
        else true

def trustedState (s : State) : Bool :=
  s.pin.isSome && s.pin == s.committedTrustRecord &&
    signatureGate s.ring && implementationFreshnessGate s.ring s.baseline

def securityGate (s : State) : Bool :=
  trustedState s && permissionGate s

/-! ## Hide and reveal -/

def hideAdmissible (s : State) (p : Path) : Bool :=
  securityGate s && hasPath s.tracked p && hasPath s.safePaths p &&
    !(hasPath s.ignoredCiphertext p) &&
    (!(hasPath s.plaintextOnDisk p) || hasPath s.allowedHere p ||
      hasCiphertext s.indexCiphertexts p)

def hideWarnsPlaintextLeak (s : State) (p : Path) : Bool :=
  hasPath s.plaintextOnDisk p && !hasPath s.ignoredPlaintext p

def hideStep (s : State) (p : Path) : State :=
  if hideAdmissible s p then
    { s with
      worktreeCiphertexts :=
        ({ path := p, ringVersion := s.ring.version } : Ciphertext) ::
          s.worktreeCiphertexts
      plaintextOnDisk := s.plaintextOnDisk.filter (fun q => q != p) }
  else s

def revealAdmissible (s : State) (principal : String) (p : Path) : Bool :=
  securityGate s && hasPath s.tracked p && hasPath s.safePaths p &&
    hasPath s.memberPrincipals principal && hasPath s.localPrivatePrincipals principal &&
    !hasPath s.plaintextInIndex p && hasCiphertext s.worktreeCiphertexts p

/-! ## Rotation -/

def noIndexedOrphans (s : State) : Bool :=
  s.indexCiphertexts.all (fun c => hasPath s.tracked c.path)

def stampMatchesRing (s : State) : Bool :=
  s.ringPassStamp == some (s.ring.version, s.ring.digest)

def rotateAdmissible (s : State) : Bool :=
  securityGate s && !s.ring.entries.isEmpty && stampMatchesRing s &&
    noIndexedOrphans s

/-!
The release implementation selects only tracked paths whose ciphertext is
present in the worktree. A tracked ciphertext absent from disk is skipped,
even if its old ciphertext remains in the index. The index itself is not
rewritten by rotate. -/
def rotateStep (s : State) : State :=
  if rotateAdmissible s then
    { s with
      worktreeCiphertexts := s.worktreeCiphertexts.map (fun c =>
        if hasPath s.tracked c.path then { c with ringVersion := s.ring.version } else c)
      ringPassStamp := none }
  else s

/-! ## Executable examples and model theorems -/

theorem trust_gate_requires_matching_pin (s : State) (h : trustedState s = true) :
    s.pin.isSome = true ∧ s.pin = s.committedTrustRecord := by
  simp [trustedState] at h
  rcases h with ⟨⟨⟨hp, hm⟩, _⟩, _⟩
  exact ⟨hp, hm⟩

theorem populated_unsigned_ring_is_rejected (s : State)
    (h : s.ring.signed = false) (hn : s.ring.entries.isEmpty = false) :
    trustedState s = false := by
  simp [trustedState, signatureGate, h, hn]

theorem backwards_ring_version_is_rejected (s : State) (v d : Nat)
    (hbase : s.baseline = some (v, d)) (hback : v > s.ring.version) :
    implementationFreshnessGate s.ring s.baseline = false := by
  simp [implementationFreshnessGate, hbase, hback]

theorem equal_version_signed_fork_is_rejected (r : Ring) (v d : Nat)
    (hs : r.signed = true) (hv : v = r.version) (hd : d != r.digest) :
    implementationFreshnessGate r (some (v, d)) = false := by
  simp [implementationFreshnessGate, hs, hv, hd]

theorem refused_hide_is_state_preserving (s : State) (p : Path)
    (h : hideAdmissible s p = false) : hideStep s p = s := by
  simp [hideStep, h]

theorem hide_first_encrypt_requires_allowance_or_index (s : State) (p : Path)
    (h : hideAdmissible s p = true) (hp : hasPath s.plaintextOnDisk p = true) :
    hasPath s.allowedHere p = true ∨ hasCiphertext s.indexCiphertexts p = true := by
  simp [hideAdmissible, hp] at h
  simp_all

theorem reveal_rejects_indexed_plaintext (s : State) (principal : String) (p : Path)
    (h : hasPath s.plaintextInIndex p = true) :
    revealAdmissible s principal p = false := by
  simp [revealAdmissible, h]

theorem rotate_requires_matching_stamp_and_no_orphans (s : State)
    (h : rotateAdmissible s = true) :
    stampMatchesRing s = true ∧ noIndexedOrphans s = true := by
  simp [rotateAdmissible] at h
  rcases h with ⟨⟨⟨_, _⟩, hs⟩, ho⟩
  exact ⟨hs, ho⟩

/-!
Countermodel: the implementation accepts an unsigned empty version-0 ring
on a machine with an existing version-0 baseline. The design says any
existing baseline makes that state a rollback. This state is unusual in
ordinary command history, but it is reachable as a model state (for example
legacy baseline data); implementation correspondence must establish whether
it can be excluded by stronger invariants.
-/
def unsignedBaselineCounterexample : Ring :=
  { version := 0, digest := 0, signed := false, signatureValid := false, entries := [] }

theorem unsigned_empty_existing_baseline_deviation :
    implementationFreshnessGate unsignedBaselineCounterexample (some (0, 17)) = true ∧
    designFreshnessGate unsignedBaselineCounterexample (some (0, 17)) = false := by
  decide

/-!
Countermodel from `cmd_rotate`: a ciphertext exists in the index but is
missing from the worktree. It is tracked, so the orphan gate passes. The
pass skips it and clears the matching stamp, leaving the indexed old
ciphertext decryptable to its former key recipients.
-/
def skippedIndexedCiphertext : State :=
  { repoId := "repo"
    tracked := ["secret.env"]
    indexCiphertexts := [{ path := "secret.env", ringVersion := 1 }]
    worktreeCiphertexts := []
    plaintextOnDisk := []
    plaintextInIndex := []
    ignoredPlaintext := []
    ignoredCiphertext := []
    allowedHere := []
    safePaths := ["secret.env"]
    memberPrincipals := ["owner"]
    localPrivatePrincipals := ["owner"]
    pin := some "owner-fp"
    committedTrustRecord := some "owner-fp"
    ring := { version := 2, digest := 20, signed := true, signatureValid := true,
              entries := ["owner"] }
    baseline := none
    ringPassStamp := some (2, 20)
    keyStorePermissionsSafe := true
    permissionBypass := false }

theorem rotate_accepts_missing_worktree_ciphertext :
    rotateAdmissible skippedIndexedCiphertext = true := by
  decide

theorem rotate_clears_stamp_but_leaves_old_index_ciphertext :
    (rotateStep skippedIndexedCiphertext).ringPassStamp = none ∧
    hasCurrentCiphertext (rotateStep skippedIndexedCiphertext).indexCiphertexts
      "secret.env" 1 = true ∧
    hasCurrentCiphertext (rotateStep skippedIndexedCiphertext).indexCiphertexts
      "secret.env" 2 = false := by
  decide

/-!
Countermodel explicitly documented under Allowance: a repo writer can put
a dummy ciphertext path in the index before nominating the path. Since the
allowance decision is based on index membership, first encryption proceeds
without local consent. This is an acknowledged residual limitation, not a
proved protection.
-/
def indexedDummyBypassesAllowance : State :=
  { skippedIndexedCiphertext with
    tracked := ["attack.env"]
    indexCiphertexts := [{ path := "attack.env", ringVersion := 1 }]
    worktreeCiphertexts := []
    plaintextOnDisk := ["attack.env"]
    allowedHere := []
    safePaths := ["attack.env"]
    ignoredCiphertext := [] }

theorem committed_dummy_is_treated_as_established :
    hideAdmissible indexedDummyBypassesAllowance "attack.env" = true := by
  decide

/-!
Per-file atomic rename is modeled as a choice between the previous complete
file and its replacement. It does not give a multi-file transaction: a
failure after one successful rename can leave a mixed batch. This outcome is
permitted by the sequential phase-2 loops in hide, reveal, and rotate.
-/
inductive AtomicFileValue (α : Type) where
  | oldValue : α → AtomicFileValue α
  | newValue : α → AtomicFileValue α
  deriving Repr, DecidableEq

theorem one_atomic_file_is_old_or_new (x : AtomicFileValue α) :
    (∃ a, x = .oldValue a) ∨ (∃ a, x = .newValue a) := by
  cases x with
  | oldValue a => exact Or.inl ⟨a, rfl⟩
  | newValue a => exact Or.inr ⟨a, rfl⟩

def twoFileBatchAfterFirstWrite (oldSecond newFirst : Nat) : Nat × Nat :=
  (newFirst, oldSecond)

theorem sequential_batch_can_be_mixed (oldSecond newFirst : Nat) :
    (twoFileBatchAfterFirstWrite oldSecond newFirst).1 = newFirst ∧
    (twoFileBatchAfterFirstWrite oldSecond newFirst).2 = oldSecond := by
  constructor <;> rfl

end GitVeil.SecurityModel
