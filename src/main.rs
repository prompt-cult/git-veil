use clap::{Parser, Subcommand};
use std::path::PathBuf;
use anyhow::{Context as _, Result};

use git_gpg::{
    cmd_init, cmd_import, cmd_trust, cmd_tell, cmd_removeperson, cmd_add, cmd_remove, cmd_list,
    cmd_hide, cmd_reveal, cmd_unhide, cmd_cat, cmd_changes, cmd_clean, cmd_show_repo_id,
    cmd_whoami, cmd_verify_keyring, cmd_list_keys, default_gpg_home, get_git_config_email,
};

#[derive(Debug, clap::Parser)]
#[command(name = "git-gpg")]
#[command(about = "Git secret management using pure Rust OpenPGP")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Initialize git-gpg in the current repository
    Init,

    /// Import your private key(s) into the git-gpg key store
    Import {
        /// File(s) containing armoured private key blocks
        #[arg(required = true)]
        files: Vec<String>,
        /// GPG home directory
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
        /// GPG home directory
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
        /// GPG home directory
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
        /// GPG home directory
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
        /// GPG home directory
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
        /// GPG home directory
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
        /// GPG home directory
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
        /// GPG home directory
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
        /// GPG home directory
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
        /// GPG home directory
        #[arg(long)]
        gpg_home: Option<PathBuf>,
    },

    /// Verify the keyring signature
    #[command(name = "verify-keyring")]
    VerifyKeyring {
        /// Git remote name
        #[arg(long, default_value = "origin")]
        remote: String,
        /// GPG home directory
        #[arg(long)]
        gpg_home: Option<PathBuf>,
    },

    /// List all keys in the keyring (requires a verified keyring signature)
    #[command(name = "list-keys")]
    ListKeys {
        /// Git remote name
        #[arg(long, default_value = "origin")]
        remote: String,
        /// GPG home directory
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
}

/// Resolves the email for commands that accept --email: an explicit,
/// non-empty value wins; otherwise fall back to `git config user.email`.
fn resolve_email(repo_root: &std::path::Path, email: Option<String>) -> Result<String> {
    match email {
        Some(e) if !e.trim().is_empty() => Ok(e),
        Some(_) => anyhow::bail!("--email must not be empty"),
        None => get_git_config_email(repo_root),
    }
}

/// Resolves the key store location for commands that consume a gpg_home:
/// an explicit `--gpg-home` wins; otherwise fall back to `$HOME/.gnupg`.
/// Resolved lazily so HOME-free subcommands (init/add/remove/list/clean/
/// show-repo-id) never fail on an unset HOME. list-keys is no longer in this
/// set: it verifies the keyring signature against the pinned key, so it
/// consumes a gpg_home like every other gated command.
fn resolve_gpg_home(gpg_home: Option<PathBuf>) -> Result<PathBuf> {
    gpg_home.map(Ok).unwrap_or_else(default_gpg_home)
}

/// Resolves the passphrase for private-key use, mirroring resolve_email/
/// resolve_gpg_home: `--passphrase-stdin` wins over the `GITGPG_PASSPHRASE`
/// environment variable; when both are absent, None is returned and the key
/// is unlocked with an empty passphrase (back-compat with unprotected keys).
/// Interactive tty prompting is deliberately deferred. The passphrase is
/// never passed as a CLI argument (process-listing leak) and is never logged.
fn resolve_passphrase(passphrase_stdin: bool) -> Result<Option<String>> {
    if passphrase_stdin {
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .context("Failed to read passphrase from stdin")?;
        if line.ends_with("\r\n") {
            line.truncate(line.len() - 2);
        } else if line.ends_with('\n') {
            line.truncate(line.len() - 1);
        }
        return Ok(Some(line));
    }
    match std::env::var("GITGPG_PASSPHRASE") {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            // Never propagate the value into the error message.
            anyhow::bail!("GITGPG_PASSPHRASE is not valid UTF-8")
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let repo_root = std::env::current_dir()?;

    match cli.command {
        Commands::Init => cmd_init(&repo_root)?,
        Commands::Import { files, gpg_home: opt } => {
            cmd_import(&repo_root, &files, &resolve_gpg_home(opt)?)?;
        }
        Commands::Trust { repo_id, signing_key, remote, gpg_home: opt } => {
            cmd_trust(&repo_root, &repo_id, &signing_key, &remote, &resolve_gpg_home(opt)?)?;
        }
        Commands::Tell { email, public_key, remote, gpg_home: opt, passphrase_stdin } => {
            let passphrase = resolve_passphrase(passphrase_stdin)?;
            cmd_tell(&repo_root, &email, &public_key, &remote, &resolve_gpg_home(opt)?, passphrase.as_deref())?;
        }
        Commands::RemovePerson { email, remote, gpg_home: opt, passphrase_stdin } => {
            let passphrase = resolve_passphrase(passphrase_stdin)?;
            cmd_removeperson(&repo_root, &email, &remote, &resolve_gpg_home(opt)?, passphrase.as_deref())?;
        }
        Commands::Add { files } => cmd_add(&repo_root, files)?,
        Commands::Remove { files } => cmd_remove(&repo_root, files)?,
        Commands::List => cmd_list(&repo_root)?,
        Commands::Hide { remote, gpg_home: opt } => {
            cmd_hide(&repo_root, &remote, &resolve_gpg_home(opt)?)?;
        }
        Commands::Reveal { email, remote, gpg_home: opt, passphrase_stdin } => {
            let email = resolve_email(&repo_root, email)?;
            let passphrase = resolve_passphrase(passphrase_stdin)?;
            cmd_reveal(&repo_root, &email, &remote, &resolve_gpg_home(opt)?, passphrase.as_deref())?;
        }
        Commands::Cat { file, email, remote, gpg_home: opt, passphrase_stdin } => {
            let email = resolve_email(&repo_root, email)?;
            let passphrase = resolve_passphrase(passphrase_stdin)?;
            cmd_cat(&repo_root, &file, &email, &remote, &resolve_gpg_home(opt)?, passphrase.as_deref())?;
        }
        Commands::Unhide { file, email, remote, gpg_home: opt, passphrase_stdin } => {
            let email = resolve_email(&repo_root, email)?;
            let passphrase = resolve_passphrase(passphrase_stdin)?;
            cmd_unhide(&repo_root, &file, &email, &remote, &resolve_gpg_home(opt)?, passphrase.as_deref())?;
        }
        Commands::Changes { files, email, remote, gpg_home: opt, passphrase_stdin } => {
            let email = resolve_email(&repo_root, email)?;
            let passphrase = resolve_passphrase(passphrase_stdin)?;
            cmd_changes(&repo_root, files, &email, &remote, &resolve_gpg_home(opt)?, passphrase.as_deref())?;
        }
        Commands::ShowRepoId { remote } => cmd_show_repo_id(&repo_root, &remote)?,
        Commands::Whoami { email, gpg_home: opt } => {
            cmd_whoami(&repo_root, email.as_deref(), &resolve_gpg_home(opt)?)?;
        }
        Commands::VerifyKeyring { remote, gpg_home: opt } => {
            cmd_verify_keyring(&repo_root, &remote, &resolve_gpg_home(opt)?)?;
        }
        Commands::ListKeys { remote, gpg_home: opt } => {
            cmd_list_keys(&repo_root, &remote, &resolve_gpg_home(opt)?)?;
        }
        Commands::Clean { yes } => cmd_clean(&repo_root, yes)?,
    }

    Ok(())
}
