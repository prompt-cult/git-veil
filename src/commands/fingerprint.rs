//! `git-veil fingerprint <LABEL> <PUBLIC_KEY>` prints the binding
//! fingerprint of a labelled public key.
//!
//! A pure function of its two arguments: no repository, no key store,
//! no pin, no network. The printed value is the single derivation
//! every git-veil fingerprint uses, reproducible with stock OS tools.
//! See docs/src/design.md, "Fingerprints".

use crate::fingerprint::fingerprint_for_public_key;

/// Prints the 64 lowercase hex character fingerprint and nothing else.
pub fn cmd_fingerprint(label: &str, public_key: &str) {
    println!("{}", fingerprint_for_public_key(label, public_key));
}
