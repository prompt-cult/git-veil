import GitVeil.SecurityModel

/-!
# Post-fix gates — exhaustive truth-table verification (v0.18.x)

This file checks the gates as at commit `7cbfc71` (post tag v0.18.1,
in-progress v0.18.2 bump), the release line carrying the fixes for the
v0.17.5 countermodels recorded in `GitVeil.SecurityModel`.

Method: every security gate in the Rust code reads a small, enumerable
set of features before it branches. Each gate is re-encoded here as a
pure function of those boolean (and three-way comparison) features, the
complete input space is enumerated, and kernel-checked `decide` proofs
exhaustively assert (a) the v0.18.x gate equals the documented design
gate on every reachable input, and (b) the v0.17.5 gate diverges from
the design on exactly the input class of each recorded countermodel and
nowhere else. Completeness argument: the enumerated features are
precisely the variables read by the corresponding Rust branches; no
branch in the implementation reads anything else.

Corresponding cell functions exist in Rust in `src/gates.rs`; the Rust commands
(`verify_keyring_against_trust`, `cmd_rotate`) construct these cells from
observed repository state and dispatch on the pure verdicts. The definitions are maintained separately; Lean does not check the Rust implementation.

The rotate and hide fixes are additionally tied back to the full `State`
transition model from `GitVeil.SecurityModel`: the v0.17.5 countermodel
states are shown to be rejected by the v0.18.x gates and state-preserving
under refusal.
-/

namespace GitVeil.SecurityModel

/-! ## Keyring freshness gate (`verify_keyring_against_trust`) -/

/-- The v0.18.x freshness gate (`src/commands/verify_keys.rs`,
`gates::freshness_verdict`), lifted to the `SecurityModel` types. The
unsigned-empty ring is refused whenever any baseline exists; version
regression is refused; equal-version digest mismatch is refused for
signed rings. -/
def implementationFreshnessGateV18 (r : Ring) (baseline : Option (Nat × Nat)) : Bool :=
  if !r.signed && r.entries.isEmpty then baseline.isNone
  else
    match baseline with
    | none => true
    | some (baseVersion, baseDigest) =>
        if baseVersion > r.version then false
        else if baseVersion == r.version && r.signed && baseDigest != r.digest then false
        else true

/-- The single difference between the v0.18.x gate and the design gate is
the `r.signed` guard on the equal-version digest check. Rings that would
expose the difference (unsigned with entries) are refused by the signature
gate before freshness runs, so on every state the freshness logic can
observe, the implementation equals the design. -/
theorem v18_freshness_matches_design_on_gated_rings (r : Ring) (b : Option (Nat × Nat))
    (h : r.signed = true ∨ r.entries.isEmpty = true) :
    implementationFreshnessGateV18 r b = designFreshnessGate r b := by
  unfold implementationFreshnessGateV18 designFreshnessGate
  rcases h with hs | he
  · cases b with
    | none => simp [hs]
    | some p =>
        obtain ⟨bv, bd⟩ := p
        simp [hs]
  · by_cases hs : r.signed = true
    · cases b with
      | none => simp [hs]
      | some p =>
          obtain ⟨bv, bd⟩ := p
          simp [hs]
    · simp [hs, he]

/-- The v0.17.5 countermodel state is now rejected by the implementation
gate itself, not only by the design. -/
theorem unsigned_empty_countermodel_now_rejected_by_implementation :
    implementationFreshnessGateV18 unsignedBaselineCounterexample (some (0, 17)) = false := by
  decide

/-- Three-way comparison of a baseline version against an observed one. -/
inductive Rel3 where
  | below  -- baseline version is lower than the observed version
  | equal  -- equal versions
  | above  -- baseline version is greater (a rollback attempt)
  deriving BEq, DecidableEq, Repr

/-- One cell of the freshness input space: every feature a freshness
branch reads, and nothing else. Rust: `gates::FreshnessCell`. -/
structure FreshnessCell where
  signed : Bool       -- the ring carries a signature that verified
  empty : Bool        -- the ring has zero entries
  hasBaseline : Bool  -- this machine has accepted a ring before
  rel : Rel3          -- baseline version vs observed version
  digestDiff : Bool   -- at equal version, digests differ
  deriving DecidableEq, Repr

/-- Rings with entries but no valid signature never reach the freshness
branches: the signature gate refuses them first. -/
def freshnessReachable (c : FreshnessCell) : Bool := c.signed || c.empty

/-- The distinct results returned by the Rust freshness gate. -/
inductive FreshnessVerdict where
  | accept | unsignedEmptyRollback | versionRollback | equalVersionFork
  deriving BEq, DecidableEq, Repr

def freshnessVerdictV18 (c : FreshnessCell) : FreshnessVerdict :=
  match c.signed, c.empty, c.hasBaseline, c.rel, c.digestDiff with
  | false, true, false, _, _ => .accept
  | false, true, true, _, _ => .unsignedEmptyRollback
  | _, _, false, _, _ => .accept
  | _, _, true, .above, _ => .versionRollback
  | true, _, true, .equal, true => .equalVersionFork
  | _, _, true, .equal, _ => .accept
  | _, _, true, .below, _ => .accept

/-- The acceptance projection used in the design-gate theorems. -/
def cellFreshnessV18 (c : FreshnessCell) : Bool :=
  freshnessVerdictV18 c == .accept

/-- The design freshness gate as a cell function (Algorithm 5). -/
def cellFreshnessDesign (c : FreshnessCell) : Bool :=
  if !c.signed && c.empty then !c.hasBaseline
  else if !c.hasBaseline then true
  else match c.rel with
    | .above => false
    | .equal => !c.digestDiff
    | .below => true

/-- The v0.17.5 freshness gate as a cell function: the unsigned-empty
ring sails through every baseline check. -/
def cellFreshnessV175 (c : FreshnessCell) : Bool :=
  if !c.hasBaseline then true
  else match c.rel with
    | .above => false
    | .equal => !(c.signed && c.digestDiff)
    | .below => true

def allBools : List Bool := [false, true]

def allRels : List Rel3 := [.below, .equal, .above]

/-- The complete freshness input space: 2 × 2 × 2 × 3 × 2 = 48 cells. -/
def allFreshnessCells : List FreshnessCell :=
  allBools.flatMap fun signed =>
  allBools.flatMap fun empty =>
  allBools.flatMap fun hasBaseline =>
  allRels.flatMap fun rel =>
  allBools.map fun digestDiff =>
    { signed, empty, hasBaseline, rel, digestDiff }

/-- Exhaustive: on every reachable input the v0.18.x gate is the design
gate. -/
theorem exhaustive_v18_freshness_is_design :
    allFreshnessCells.all (fun c =>
      if freshnessReachable c then cellFreshnessV18 c == cellFreshnessDesign c else true) = true := by
  decide

/-- Exhaustive: among reachable inputs the v0.17.5 gate diverges from the
design exactly on unsigned-empty-with-a-baseline — the recorded
countermodel class — excluding version rollbacks both versions refuse,
and nowhere else. -/
theorem exhaustive_v175_divergence_is_exactly_the_countermodel :
    allFreshnessCells.all (fun c =>
      (freshnessReachable c && (cellFreshnessV175 c != cellFreshnessDesign c))
        == (!c.signed && c.empty && c.hasBaseline && c.rel != .above)) = true := by
  decide

/-! ## Ring-change pass gate (`cmd_rotate`) -/

/-- A tracked path whose ciphertext is committed but absent from the
worktree (the v0.17.5 countermodel condition). -/
def hasIndexOnlyCiphertext (s : State) : Bool :=
  s.tracked.any (fun p =>
    hasCiphertext s.indexCiphertexts p && !hasCiphertext s.worktreeCiphertexts p)

/-- The v0.18.x rotate gate: the v0.17.5 gate plus the index-only
refusal, mirroring the gate in `src/commands/rotate.rs` and
`gates::rotate_gate`. -/
def rotateAdmissibleV18 (s : State) : Bool :=
  rotateAdmissible s && !hasIndexOnlyCiphertext s

/-- The v0.18.x rotate step refuses (state-preserving) when the gate
fails. -/
def rotateStepV18 (s : State) : State :=
  if rotateAdmissibleV18 s then rotateStep s else s

/-- The v0.17.5 countermodel state is refused by the v0.18.x gate. -/
theorem countermodel_state_now_refused :
    rotateAdmissibleV18 skippedIndexedCiphertext = false := by
  decide

/-- Refusal is state-preserving: the countermodel state keeps its stamp,
so a later, honest pass is still armed. -/
theorem countermodel_refusal_preserves_state_and_stamp :
    rotateStepV18 skippedIndexedCiphertext = skippedIndexedCiphertext ∧
    (rotateStepV18 skippedIndexedCiphertext).ringPassStamp = some (2, 20) := by
  decide

/-- One cell of the rotate admissibility input space. Rust:
`gates::RotateCell`. -/
structure RotateCell where
  securityOk : Bool    -- trust and permission gates pass
  nonEmptyRing : Bool  -- the keyring has entries
  stampMatch : Bool    -- the stamp matches the committed ring
  noOrphans : Bool     -- every committed ciphertext is tracked
  indexOnly : Bool     -- a tracked ciphertext is committed but off-disk
  deriving DecidableEq, Repr

/-- The complete rotate input space: 2⁵ = 32 cells. -/
def allRotateCells : List RotateCell :=
  allBools.flatMap fun securityOk =>
  allBools.flatMap fun nonEmptyRing =>
  allBools.flatMap fun stampMatch =>
  allBools.flatMap fun noOrphans =>
  allBools.map fun indexOnly =>
    { securityOk, nonEmptyRing, stampMatch, noOrphans, indexOnly }

/-- The v0.17.5 rotate gate: no index-only check. -/
def rotateGateV175 (c : RotateCell) : Bool :=
  c.securityOk && c.nonEmptyRing && c.stampMatch && c.noOrphans

/-- The design gate: the documented ceremony additionally accounts for
every committed ciphertext, so an index-only ciphertext refuses the
pass. -/
def rotateGateDesign (c : RotateCell) : Bool :=
  rotateGateV175 c && !c.indexOnly

/-- The v0.18.x rotate gate. Rust: `gates::rotate_gate`. -/
def rotateGateV18 (c : RotateCell) : Bool :=
  match c.securityOk, c.nonEmptyRing, c.stampMatch, c.noOrphans, c.indexOnly with
  | true, true, true, true, false => true
  | _, _, _, _, _ => false

/-- Exhaustive: on all 32 inputs the v0.18.x gate is the design gate.
-/
theorem exhaustive_v18_rotate_is_design :
    allRotateCells.all (fun c => rotateGateV18 c == rotateGateDesign c) = true := by
  decide

/-- Exhaustive: the v0.17.5 gate diverges from the design exactly when
every other gate passes and an index-only ciphertext exists — the
countermodel class — and nowhere else. -/
theorem exhaustive_v175_rotate_divergence_is_exactly_the_countermodel :
    allRotateCells.all (fun c =>
      (rotateGateV175 c != rotateGateDesign c)
        == (c.securityOk && c.nonEmptyRing && c.stampMatch && c.noOrphans && c.indexOnly)) = true := by
  decide

/-! ## Security-gate composition

Every mutating gated command first computes the same trust and permission
conjunction. Exhaustively: whenever the security gate fails, hide, reveal
and rotate all refuse, whatever their command-specific checks say. Rust:
`gates::security_gate`. -/

/-- One cell of the security-gate input space: pin present, pin matches
the committed record, signature gate, freshness gate, key-store
permissions safe, permission bypass set. Rust: `gates::SecurityCell`. -/
structure SecurityCell where
  pinPresent : Bool
  pinMatch : Bool
  sigOk : Bool
  freshOk : Bool
  permsSafe : Bool
  bypass : Bool
  deriving DecidableEq, Repr

/-- The complete security-gate input space: 2⁶ = 64 cells. -/
def allSecurityCells : List SecurityCell :=
  allBools.flatMap fun pinPresent =>
  allBools.flatMap fun pinMatch =>
  allBools.flatMap fun sigOk =>
  allBools.flatMap fun freshOk =>
  allBools.flatMap fun permsSafe =>
  allBools.map fun bypass =>
    { pinPresent, pinMatch, sigOk, freshOk, permsSafe, bypass }

/-- The trust conjunction. Rust: `gates::trusted`. -/
def cellTrusted (c : SecurityCell) : Bool :=
  c.pinPresent && c.pinMatch && c.sigOk && c.freshOk

/-- The shared security gate. Rust: `gates::security_gate`. -/
def cellSecurity (c : SecurityCell) : Bool :=
  match c.pinPresent, c.pinMatch, c.sigOk, c.freshOk, c.permsSafe, c.bypass with
  | true, true, true, true, true, _ => true
  | true, true, true, true, false, true => true
  | _, _, _, _, _, _ => false

/-- A command is admissible only when the security gate passes and its
own checks do. Rust: `gates::tests::cell_admissible`. -/
def cellAdmissible (c : SecurityCell) (ownChecks : Bool) : Bool :=
  cellSecurity c && ownChecks

/-- Exhaustive: no command-specific check set can admit a command when
the security gate fails. Rust mirror:
`gates::tests::security_gate_dominates_on_all_64_cells`. -/
theorem exhaustive_security_gate_dominates :
    allSecurityCells.all (fun c =>
      if cellSecurity c then true
      else cellAdmissible c true == false && cellAdmissible c false == false) = true := by
  decide

/-- Exhaustive: the bypass bit is the only override of unsafe key-store
permissions, and it never overrides a trust failure. Rust mirror:
`gates::tests::bypass_scope_is_permissions_only_on_all_64_cells`. -/
theorem exhaustive_bypass_scope_is_permissions_only :
    allSecurityCells.all (fun c =>
      (cellSecurity c && !c.permsSafe) == (cellTrusted c && c.bypass && !c.permsSafe)) = true := by
  decide

end GitVeil.SecurityModel
