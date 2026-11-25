#![cfg(not(windows))]

//! Compare every Rust gate result with freshly evaluated Lean model output.
//! Requires the Lean toolchain pinned in formal/lean-toolchain.

#[path = "../src/gates.rs"]
mod gates;

use gates::{FreshnessCell, FreshnessVerdict, Rel3, RotateCell, SecurityCell};
use std::collections::BTreeMap;
use std::process::Command;

fn bit(value: bool) -> u8 {
    u8::from(value)
}

#[test]
fn every_gate_result_matches_lean() {
    let formal = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("formal");
    let build = Command::new("lake")
        .arg("build")
        .current_dir(&formal)
        .output()
        .expect("lake is required for the Lean correspondence test");
    assert!(
        build.status.success(),
        "lake build failed:\n{}\n{}",
        String::from_utf8_lossy(&build.stdout),
        String::from_utf8_lossy(&build.stderr)
    );
    let output = Command::new("lake")
        .args(["env", "lean", "--run", "GateTable.lean"])
        .current_dir(&formal)
        .output()
        .expect("could not evaluate Lean gate table");
    assert!(
        output.status.success(),
        "Lean gate table failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let table = String::from_utf8(output.stdout).expect("Lean output must be UTF-8");
    let mut lean = BTreeMap::new();
    for line in table.lines() {
        let (cell, result) = line.rsplit_once(' ').expect("malformed Lean table row");
        assert!(
            lean.insert(cell.to_owned(), result.to_owned()).is_none(),
            "duplicate Lean cell: {cell}"
        );
    }

    let mut rust = BTreeMap::new();
    for signed in [false, true] {
        for empty in [false, true] {
            for has_baseline in [false, true] {
                for (rel, name) in [
                    (Rel3::Below, "below"),
                    (Rel3::Equal, "equal"),
                    (Rel3::Above, "above"),
                ] {
                    for digest_diff in [false, true] {
                        let c = FreshnessCell {
                            signed,
                            empty,
                            has_baseline,
                            rel,
                            digest_diff,
                        };
                        let result = match gates::freshness_verdict(&c) {
                            FreshnessVerdict::Accept => "accept",
                            FreshnessVerdict::UnsignedEmptyRollback => "unsigned-empty-rollback",
                            FreshnessVerdict::VersionRollback => "version-rollback",
                            FreshnessVerdict::EqualVersionFork => "equal-version-fork",
                        };
                        rust.insert(
                            format!(
                                "freshness {} {} {} {name} {}",
                                bit(signed),
                                bit(empty),
                                bit(has_baseline),
                                bit(digest_diff)
                            ),
                            result.to_owned(),
                        );
                    }
                }
            }
        }
    }
    assert_eq!(rust.len(), 48);
    for security_ok in [false, true] {
        for non_empty_ring in [false, true] {
            for stamp_match in [false, true] {
                for no_orphans in [false, true] {
                    for index_only in [false, true] {
                        let c = RotateCell {
                            security_ok,
                            non_empty_ring,
                            stamp_match,
                            no_orphans,
                            index_only,
                        };
                        rust.insert(
                            format!(
                                "rotate {} {} {} {} {}",
                                bit(security_ok),
                                bit(non_empty_ring),
                                bit(stamp_match),
                                bit(no_orphans),
                                bit(index_only)
                            ),
                            bit(gates::rotate_gate(&c)).to_string(),
                        );
                    }
                }
            }
        }
    }
    assert_eq!(rust.len(), 80);
    for pin_present in [false, true] {
        for pin_match in [false, true] {
            for sig_ok in [false, true] {
                for fresh_ok in [false, true] {
                    for perms_safe in [false, true] {
                        for bypass in [false, true] {
                            let c = SecurityCell {
                                pin_present,
                                pin_match,
                                sig_ok,
                                fresh_ok,
                                perms_safe,
                                bypass,
                            };
                            rust.insert(
                                format!(
                                    "security {} {} {} {} {} {}",
                                    bit(pin_present),
                                    bit(pin_match),
                                    bit(sig_ok),
                                    bit(fresh_ok),
                                    bit(perms_safe),
                                    bit(bypass)
                                ),
                                bit(gates::security_gate(&c)).to_string(),
                            );
                        }
                    }
                }
            }
        }
    }
    assert_eq!(rust.len(), 144);
    assert_eq!(lean, rust, "Lean and Rust gate tables differ");
}
