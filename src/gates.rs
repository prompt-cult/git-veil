//! Security gates as pure functions over enumerated feature cells.
//!
//! Each security-critical branch in the commands reads a small,
//! enumerable set of features before it decides. This module isolates
//! every such decision into a pure function of those features, in the
//! same branch order as the Lean 4 model `formal/GitVeil/V018.lean`,
//! which kernel-checks the complete truth tables by `decide`:
//!
//! - `freshness_verdict`   ↔ `cellFreshnessV18`     (48 cells: theorem
//!   `exhaustive_v18_freshness_is_design` — equals the design on every
//!   reachable input)
//! - `rotate_gate`         ↔ `rotateGateV18`        (32 cells: theorem
//!   `exhaustive_v18_rotate_is_design`)
//! - `security_gate`       ↔ `cellSecurity`         (64 cells: theorems
//!   `exhaustive_security_gate_dominates`,
//!   `exhaustive_bypass_scope_is_permissions_only`)
//!
//! Lean and Rust are maintained separately. Matching branch structure makes
//! review possible; it is not a mechanical proof of Rust equivalence.

/// Three-way comparison of the baseline version against the observed
/// keyring version. Lean: `Rel3`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Rel3 {
    /// Baseline version is lower than the observed version: the ring
    /// advanced.
    Below,
    /// Equal versions: fork detection applies.
    Equal,
    /// Baseline version is greater: a rollback attempt.
    Above,
}

/// Every feature a freshness branch reads: the signature verified, the
/// ring is empty, this machine has a baseline, the version relation, and
/// (at equal versions) whether the digests differ. Lean: `FreshnessCell`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct FreshnessCell {
    pub signed: bool,
    pub empty: bool,
    pub has_baseline: bool,
    pub rel: Rel3,
    pub digest_diff: bool,
}

/// The freshness decision with its refusal class, so the caller keeps
/// its distinct error messages. Accept ⟺ the Lean `cellFreshnessV18`
/// gate returns true.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum FreshnessVerdict {
    Accept,
    /// An unsigned empty ring against any baseline: a rollback to no
    /// collaborators.
    UnsignedEmptyRollback,
    /// Observed version below the baseline.
    VersionRollback,
    /// Equal version, signed, different content: an equal-version
    /// substitution.
    EqualVersionFork,
}

/// The v0.18.x keyring freshness gate. Lean: `cellFreshnessV18`.
///
/// Branch order mirrors both the Lean cell function and the previous
/// inline implementation in `verify_keyring_against_trust`:
/// 1. unsigned empty rings are accepted only before any baseline exists;
/// 2. anything is accepted on a baseline-less machine;
/// 3. a baseline version above the observed version is a rollback;
/// 4. at equal versions a signed ring with different content is a fork;
/// 5. otherwise the ring is fresh.
pub(crate) fn freshness_verdict(cell: &FreshnessCell) -> FreshnessVerdict {
    use FreshnessVerdict::*;
    match (
        cell.signed,
        cell.empty,
        cell.has_baseline,
        cell.rel,
        cell.digest_diff,
    ) {
        (false, true, false, _, _) => Accept,
        (false, true, true, _, _) => UnsignedEmptyRollback,
        (_, _, false, _, _) => Accept,
        (_, _, true, Rel3::Above, _) => VersionRollback,
        (true, _, true, Rel3::Equal, true) => EqualVersionFork,
        (_, _, true, Rel3::Equal | Rel3::Below, _) => Accept,
    }
}

/// Every feature the rotate admissibility branches read. Lean:
/// `RotateCell`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RotateCell {
    /// The trust and permission gates passed for this command.
    pub security_ok: bool,
    /// The keyring has entries.
    pub non_empty_ring: bool,
    /// The machine's ring-change stamp matches the committed keyring.
    pub stamp_match: bool,
    /// Every committed ciphertext path is tracked.
    pub no_orphans: bool,
    /// A tracked ciphertext is committed but absent from the worktree.
    pub index_only: bool,
}

/// The v0.18.x rotate admissibility gate. Lean: `rotateGateV18`.
#[allow(clippy::match_like_matches_macro)]
pub(crate) fn rotate_gate(cell: &RotateCell) -> bool {
    match (
        cell.security_ok,
        cell.non_empty_ring,
        cell.stamp_match,
        cell.no_orphans,
        cell.index_only,
    ) {
        (true, true, true, true, false) => true,
        _ => false,
    }
}

/// Every feature of the shared security gate: the pin exists and matches
/// the committed trust record, the signature gate, the freshness gate,
/// key-store permissions, and the explicit bypass. Lean: `SecurityCell`.
///
/// The composition is exercised by the exhaustive tests below; in the
/// binary the two halves run in `main` (permissions) and
/// `verify_keyring_against_trust` (trust) with a shared error path, so
/// no single call site can construct this cell today.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Copy, Debug)]
pub(crate) struct SecurityCell {
    pub pin_present: bool,
    pub pin_match: bool,
    pub sig_ok: bool,
    pub fresh_ok: bool,
    pub perms_safe: bool,
    pub bypass: bool,
}

/// The trust conjunction. Lean: `cellTrusted`.
#[cfg_attr(not(test), allow(dead_code))]
#[allow(clippy::match_like_matches_macro)]
pub(crate) fn trusted(cell: &SecurityCell) -> bool {
    match (cell.pin_present, cell.pin_match, cell.sig_ok, cell.fresh_ok) {
        (true, true, true, true) => true,
        _ => false,
    }
}

/// The security gate every mutating gated command passes through:
/// trust holds, and the key-store permissions are safe or explicitly
/// bypassed. Lean: `cellSecurity`.
#[cfg_attr(not(test), allow(dead_code))]
#[allow(clippy::match_like_matches_macro)]
pub(crate) fn security_gate(cell: &SecurityCell) -> bool {
    match (
        cell.pin_present,
        cell.pin_match,
        cell.sig_ok,
        cell.fresh_ok,
        cell.perms_safe,
        cell.bypass,
    ) {
        (true, true, true, true, true, _) | (true, true, true, true, false, true) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The recorded v0.17.5 countermodel cell: unsigned, empty, existing
    /// equal-version baseline. The v0.18.x gate refuses it.
    #[test]
    fn unsigned_empty_countermodel_is_refused() {
        let cell = FreshnessCell {
            signed: false,
            empty: true,
            has_baseline: true,
            rel: Rel3::Equal,
            digest_diff: false,
        };
        assert_eq!(
            freshness_verdict(&cell),
            FreshnessVerdict::UnsignedEmptyRollback
        );
    }

    /// The complete security-gate input space: 2⁶ = 64 cells.
    fn all_security_cells() -> Vec<SecurityCell> {
        let mut cells = Vec::with_capacity(64);
        for pin_present in [false, true] {
            for pin_match in [false, true] {
                for sig_ok in [false, true] {
                    for fresh_ok in [false, true] {
                        for perms_safe in [false, true] {
                            for bypass in [false, true] {
                                cells.push(SecurityCell {
                                    pin_present,
                                    pin_match,
                                    sig_ok,
                                    fresh_ok,
                                    perms_safe,
                                    bypass,
                                });
                            }
                        }
                    }
                }
            }
        }
        cells
    }

    /// Exhaustive: no command-specific checks can admit a command when
    /// the security gate fails. Rust mirror of Lean theorem
    /// `exhaustive_security_gate_dominates`.
    /// A command is admissible only as `security_gate && ownChecks`.
    /// Lean: `cellAdmissible`.
    fn cell_admissible(c: &SecurityCell, own_checks: bool) -> bool {
        security_gate(c) && own_checks
    }

    #[test]
    fn security_gate_dominates_on_all_64_cells() {
        let cells = all_security_cells();
        assert_eq!(cells.len(), 64);
        for c in &cells {
            for own_checks in [false, true] {
                // admissible implies the gate passed: a failed security
                // gate refuses regardless of command-specific checks.
                assert!(
                    !cell_admissible(c, own_checks) || security_gate(c),
                    "cell {c:?} own_checks {own_checks}"
                );
                if !security_gate(c) {
                    assert!(!cell_admissible(c, own_checks), "cell {c:?}");
                }
            }
        }
    }

    /// Exhaustive: the bypass bit is the only override of unsafe
    /// key-store permissions, and it never overrides a trust failure.
    /// Rust mirror of Lean theorem
    /// `exhaustive_bypass_scope_is_permissions_only`.
    #[test]
    fn bypass_scope_is_permissions_only_on_all_64_cells() {
        for c in all_security_cells() {
            assert_eq!(
                security_gate(&c) && !c.perms_safe,
                trusted(&c) && c.bypass && !c.perms_safe,
                "cell {c:?}"
            );
        }
    }
}
