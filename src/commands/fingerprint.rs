//! `git-veil fingerprint <LABEL> <PUBLIC_KEY>`: print the binding
//! fingerprint of a labelled public key.
//!
//! A pure function of its two arguments: no repository, no key store, no
//! pin, no network. The printed value is the single derivation every
//! git-veil fingerprint uses (issue #41), reproducible with stock OS
//! tools - see docs/design.md, "Fingerprints".

use crate::fingerprint::fingerprint_for_public_key;

/// Prints the 64 lowercase hex character fingerprint and nothing else.
pub fn cmd_fingerprint(label: &str, public_key: &str) {
    println!("{}", fingerprint_for_public_key(label, public_key));
}
