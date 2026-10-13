//! `git-veil export-pin <repo_id> --output <pin-file>`: emit the pin-file
//! that a machine WITHOUT the signing key imports with
//! `git-veil trust --import`.
//!
//! Export requires the SAME possession proof as `trust`: an exact match
//! between the repository's committed `owner.verifying` and the verifying
//! key derived from a seed in the signing key store. A machine without the
//! matching seed cannot export at all — pins originate only from machines
//! holding the signing key; store-less machines are consumers, never
//! producers. The output path must be outside the repository worktree.

use anyhow::Result;
use std::path::Path;

use crate::commands::trust::{ensure_path_outside_repo, prove_possession, read_owner_verifying};
use crate::pin_file::{derive_and_check_repo_id, write_pin_file, PinFile};

pub fn cmd_export_pin(
    repo_root: &Path,
    repo_id: &str,
    output: &Path,
    remote_name: &str,
    key_store: &Path,
) -> Result<()> {
    derive_and_check_repo_id(repo_root, remote_name, repo_id)?;

    // Same possession proof as trust: no matching seed, no export.
    let (verifying_key, _hex, _recipient) = read_owner_verifying(repo_root)?;
    prove_possession(key_store, &verifying_key)?;

    // The pin-file must not land inside the repository: it would be
    // committed, and a committed pin is exactly the self-supplied anchor
    // the pin model exists to prevent.
    ensure_path_outside_repo(repo_root, output)?;

    let pin_file = PinFile {
        repo_id: repo_id.to_string(),
        verifying_key,
    };
    write_pin_file(output, &pin_file)?;

    // The owner key fingerprint (the single derivation with the repository
    // id as the label) is the human out-of-band verification token: read
    // it to the importing machine's operator and have them compare it
    // against the repository's committed metadata.
    println!("pin-file written to {}", output.display());
    println!("owner key fingerprint: {}", pin_file.owner_fingerprint());
    println!(
        "import it on the target machine with: git-veil trust --import {}",
        output.display()
    );
    Ok(())
}
