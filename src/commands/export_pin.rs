//! `git-veil export-pin <repo_id>` prints the pin to stdout (the pin
//! artifact alone) so it can be piped straight to the machine that will
//! run `git-veil trust --import`; `--output <pin-file>` writes it to a
//! file instead.
//!
//! Export requires the same possession proof as `trust`: an exact
//! match between the repository's committed `owner.verifying` and the
//! verifying key derived from a seed in the signing key store. A
//! machine without the matching seed cannot export at all. Pins
//! originate only from machines holding the signing key. Store-less
//! machines are consumers, never producers. An `--output` path must be
//! outside the repository worktree.

use anyhow::Result;
use std::path::Path;

use crate::commands::trust::{ensure_path_outside_repo, prove_possession, read_owner_verifying};
use crate::pin_file::{derive_and_check_repo_id, write_pin_file, PinFile};

pub fn cmd_export_pin(
    repo_root: &Path,
    repo_id: &str,
    output: Option<&Path>,
    remote_name: &str,
    key_store: &Path,
) -> Result<()> {
    derive_and_check_repo_id(repo_root, remote_name, repo_id)?;

    // Same possession proof as trust: no matching seed, no export.
    let (verifying_key, _hex, _public_key) = read_owner_verifying(repo_root)?;
    prove_possession(key_store, &verifying_key)?;

    let pin_file = PinFile {
        repo_id: repo_id.to_string(),
        verifying_key,
    };

    // The owner key fingerprint (the single derivation with the repository
    // id as the label) is the human out-of-band verification token: read
    // it to the importing machine's operator and have them compare it
    // against the repository's committed metadata. Chatter lives on
    // stderr so a redirected stdout captures the pin artifact alone.
    //
    // With --output the artifact goes to the file. The destination must
    // not land inside the repository: it would be committed, and a
    // committed pin is exactly the self-supplied anchor the pin model
    // exists to prevent. A redirected stdout owes the same discipline to
    // the operator; the import refusal of in-repo pin files is the gate
    // that cannot be overridden.
    match output {
        Some(path) => {
            ensure_path_outside_repo(repo_root, path)?;
            write_pin_file(path, &pin_file)?;
            println!("pin-file written to {}", path.display());
            eprintln!("owner key fingerprint: {}", pin_file.owner_fingerprint());
            eprintln!(
                "import it on the target machine with: git-veil trust --import {}",
                path.display()
            );
            eprintln!("keep pin-files out of the repository worktree");
        }
        None => {
            print!("{}", pin_file.serialize());
            eprintln!("owner key fingerprint: {}", pin_file.owner_fingerprint());
            eprintln!("import it on the target machine with: git-veil trust --import <pin-file>");
            eprintln!("keep stdout's pin out of the repository worktree");
        }
    }
    Ok(())
}
