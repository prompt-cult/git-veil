//! CLI definition shared by the binary and the docs-generation subcommands.
//!
//! Keeping `Cli`/`Commands` in the library lets the `completions` and
//! `manpages` subcommands regenerate their output from the real clap
//! definition (`Cli::command()`) with zero duplication — no build.rs
//! copy of the parser is needed.

use clap::{Parser, Subcommand, CommandFactory};
use std::path::PathBuf;
use anyhow::{Context as _, Result};

#[derive(Debug, Parser)]
#[command(name = "git-gpg")]
#[command(about = "Git secret management using pure Rust OpenPGP")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Initialize git-gpg in the current repository
    Init,

    /// Import your private key(s) into the git-gpg key store
    Import {
        /// File(s) containing armoured private key blocks
        #[arg(required = true)]
        files: Vec<String>,
        /// Key store directory (default: $HOME/.git-gpg)
        #[arg(long)]
        gpg_home: Option<PathBuf>,
    },

    /// Establish trust for a repository by verifying the owner's signing key
    Trust {
        /// Repository ID (e.g., fara+simbo1905@github.com)
        repo_id: String,
        /// Path to owner's public key file
        signing_key: String,
        /// Git remote name
        #[arg(long, default_value = "origin")]
        remote: String,
        /// Key store directory (default: $HOME/.git-gpg)
        #[arg(long)]
        gpg_home: Option<PathBuf>,
    },

    /// Add a collaborator's public key to the keyring
    Tell {
        /// Collaborator's email
        email: String,
        /// Path to collaborator's public key file
        public_key: String,
        /// Git remote name
        #[arg(long, default_value = "origin")]
        remote: String,
        /// Key store directory (default: $HOME/.git-gpg)
        #[arg(long)]
        gpg_home: Option<PathBuf>,
        /// Read the passphrase for a passphrase-protected private key from
        /// stdin (exactly one line). Wins over the GITGPG_PASSPHRASE
        /// environment variable; never pass a passphrase as a CLI argument.
        #[arg(long)]
        passphrase_stdin: bool,
    },

    /// Remove a collaborator from the keyring
    #[command(name = "removeperson")]
    RemovePerson {
        /// Email of the collaborator to remove
        email: String,
        /// Git remote name
        #[arg(long, default_value = "origin")]
        remote: String,
        /// Key store directory (default: $HOME/.git-gpg)
        #[arg(long)]
        gpg_home: Option<PathBuf>,
        /// Read the passphrase for a passphrase-protected private key from
        /// stdin (exactly one line). Wins over the GITGPG_PASSPHRASE
        /// environment variable; never pass a passphrase as a CLI argument.
        #[arg(long)]
        passphrase_stdin: bool,
    },

    /// Add a file to be encrypted
    Add {
        /// File(s) to add
        #[arg(required = true)]
        files: Vec<String>,
    },

    /// Remove a file from encryption tracking
    Remove {
        /// File(s) to remove
        #[arg(required = true)]
        files: Vec<String>,
    },

    /// List all tracked files
    List,

    /// Hide - encrypt all tracked files
    Hide {
        /// Git remote name
        #[arg(long, default_value = "origin")]
        remote: String,
        /// Key store directory (default: $HOME/.git-gpg)
        #[arg(long)]
        gpg_home: Option<PathBuf>,
    },

    /// Reveal - decrypt all tracked files
    Reveal {
        /// Your email address
        #[arg(long)]
        email: Option<String>,
        /// Git remote name
        #[arg(long, default_value = "origin")]
        remote: String,
        /// Key store directory (default: $HOME/.git-gpg)
        #[arg(long)]
        gpg_home: Option<PathBuf>,
        /// Read the passphrase for a passphrase-protected private key from
        /// stdin (exactly one line). Wins over the GITGPG_PASSPHRASE
        /// environment variable; never pass a passphrase as a CLI argument.
        #[arg(long)]
        passphrase_stdin: bool,
    },

    /// Cat - decrypt a single tracked file to stdout
    Cat {
        /// File to decrypt
        file: String,
        /// Your email address
        #[arg(long)]
        email: Option<String>,
        /// Git remote name
        #[arg(long, default_value = "origin")]
        remote: String,
        /// Key store directory (default: $HOME/.git-gpg)
        #[arg(long)]
        gpg_home: Option<PathBuf>,
        /// Read the passphrase for a passphrase-protected private key from
        /// stdin (exactly one line). Wins over the GITGPG_PASSPHRASE
        /// environment variable; never pass a passphrase as a CLI argument.
        #[arg(long)]
        passphrase_stdin: bool,
    },

    /// Unhide - decrypt a single tracked file back to plaintext and delete its ciphertext
    Unhide {
        /// File to unhide
        file: String,
        /// Your email address
        #[arg(long)]
        email: Option<String>,
        /// Git remote name
        #[arg(long, default_value = "origin")]
        remote: String,
        /// Key store directory (default: $HOME/.git-gpg)
        #[arg(long)]
        gpg_home: Option<PathBuf>,
        /// Read the passphrase for a passphrase-protected private key from
        /// stdin (exactly one line). Wins over the GITGPG_PASSPHRASE
        /// environment variable; never pass a passphrase as a CLI argument.
        #[arg(long)]
        passphrase_stdin: bool,
    },

    /// Changes - report where plaintext differs from the last hidden version
    Changes {
        /// File(s) to check (default: all tracked files)
        files: Vec<String>,
        /// Your email address
        #[arg(long)]
        email: Option<String>,
        /// Git remote name
        #[arg(long, default_value = "origin")]
        remote: String,
        /// Key store directory (default: $HOME/.git-gpg)
        #[arg(long)]
        gpg_home: Option<PathBuf>,
        /// Read the passphrase for a passphrase-protected private key from
        /// stdin (exactly one line). Wins over the GITGPG_PASSPHRASE
        /// environment variable; never pass a passphrase as a CLI argument.
        #[arg(long)]
        passphrase_stdin: bool,
    },

    /// Show the repository ID
    #[command(name = "show-repo-id")]
    ShowRepoId {
        /// Git remote name
        #[arg(long, default_value = "origin")]
        remote: String,
    },

    /// Show your identity
    Whoami {
        /// Email override
        #[arg(long)]
        email: Option<String>,
        /// Key store directory (default: $HOME/.git-gpg)
        #[arg(long)]
        gpg_home: Option<PathBuf>,
    },

    /// Verify the keyring signature
    #[command(name = "verify-keyring")]
    VerifyKeyring {
        /// Git remote name
        #[arg(long, default_value = "origin")]
        remote: String,
        /// Key store directory (default: $HOME/.git-gpg)
        #[arg(long)]
        gpg_home: Option<PathBuf>,
    },

    /// List all keys in the keyring (requires a verified keyring signature)
    #[command(name = "list-keys")]
    ListKeys {
        /// Git remote name
        #[arg(long, default_value = "origin")]
        remote: String,
        /// Key store directory (default: $HOME/.git-gpg)
        #[arg(long)]
        gpg_home: Option<PathBuf>,
    },

    /// Clean - remove all git-gpg metadata
    Clean {
        /// Confirm destruction of tracked state and any ciphertext. Required
        /// when the clean would destroy tracked files or their in-place
        /// `<name>.secret` ciphertext (which may be the only remaining copy).
        #[arg(long)]
        yes: bool,
    },

    /// Emit a shell completion script for the given shell to stdout
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },

    /// Write roff man pages (git-gpg.1 plus one per subcommand) to a directory
    Manpages {
        /// Directory to write the .1 files into (default: ./man)
        output_dir: Option<PathBuf>,
    },
}

/// Handler for `git-gpg completions <shell>`: writes the completion script
/// for the real clap definition to stdout.
pub fn run_completions(shell: clap_complete::Shell) {
    let mut cmd = Cli::command();
    clap_complete::generate(shell, &mut cmd, "git-gpg", &mut std::io::stdout());
}

/// Handler for `git-gpg manpages [OUTPUT_DIR]`: writes `git-gpg.1` plus one
/// `git-gpg-<sub>.1` per subcommand, all generated from the real clap
/// definition. Defaults to `./man` relative to the current directory.
pub fn run_manpages(output_dir: &std::path::Path) -> Result<()> {
    let root = Cli::command();
    let bin_name = root.get_name().to_string();

    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("failed to create output directory {}", output_dir.display()))?;

    let root_page = output_dir.join(format!("{}.1", bin_name));
    let man = clap_mangen::Man::new(root.clone());
    man.render(&mut std::fs::File::create(&root_page).with_context(|| {
        format!("failed to create {}", root_page.display())
    })?)
    .with_context(|| format!("failed to render {}", root_page.display()))?;

    for sub in root.get_subcommands() {
        let full_name = format!("{}-{}", bin_name, sub.get_name());
        let page = output_dir.join(format!("{}.1", full_name));
        let usage_bin_name = format!("{} {}", bin_name, sub.get_name());
        let man = clap_mangen::Man::new(
            sub.clone()
                .name(full_name)
                .bin_name(usage_bin_name),
        );
        man.render(&mut std::fs::File::create(&page)
            .with_context(|| format!("failed to create {}", page.display()))?)
        .with_context(|| format!("failed to render {}", page.display()))?;
    }

    Ok(())
}
