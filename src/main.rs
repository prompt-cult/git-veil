//! git-gpg - A Rust-based Git secret management tool using pure Rust OpenPGP
//!
//! This tool provides a bash-free, zero-C-dependency alternative to git-secret.
//! It uses the `pgp` crate which implements RFC 4880 / RFC 9580 (OpenPGP) with pure Rust.

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use anyhow::Result;

use git_gpg::{
    cmd_init, cmd_import, cmd_trust, cmd_tell, cmd_add, cmd_remove, cmd_list,
    cmd_hide, cmd_reveal, cmd_clean, cmd_show_repo_id, cmd_whoami,
    cmd_verify_keyring, cmd_list_keys, default_gpg_home,
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

    /// List all keys in the keyring
    #[command(name = "list-keys")]
    ListKeys,

    /// Clean - remove all git-gpg metadata
    Clean,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let gpg_home = default_gpg_home();

    match cli.command {
        Commands::Init => cmd_init()?,
        Commands::Import { files, gpg_home: opt } => {
            cmd_import(&files, &opt.unwrap_or(gpg_home))?;
        }
        Commands::Trust { repo_id, signing_key, remote, gpg_home: opt } => {
            cmd_trust(&repo_id, &signing_key, &remote, &opt.unwrap_or(gpg_home))?;
        }
        Commands::Tell { email, public_key, remote, gpg_home: opt } => {
            cmd_tell(&email, &public_key, &remote, &opt.unwrap_or(gpg_home))?;
        }
        Commands::Add { files } => cmd_add(files)?,
        Commands::Remove { files } => cmd_remove(files)?,
        Commands::List => cmd_list()?,
        Commands::Hide { remote, gpg_home: opt } => {
            cmd_hide(&remote, &opt.unwrap_or(gpg_home))?;
        }
        Commands::Reveal { email, remote, gpg_home: opt } => {
            let email = email.unwrap_or_else(|| "default@example.com".to_string());
            cmd_reveal(&email, &remote, &opt.unwrap_or(gpg_home))?;
        }
        Commands::ShowRepoId { remote } => cmd_show_repo_id(&remote)?,
        Commands::Whoami { email, gpg_home: opt } => {
            cmd_whoami(email.as_deref(), &opt.unwrap_or(gpg_home))?;
        }
        Commands::VerifyKeyring { remote, gpg_home: opt } => {
            cmd_verify_keyring(&remote, &opt.unwrap_or(gpg_home))?;
        }
        Commands::ListKeys => cmd_list_keys()?,
        Commands::Clean => cmd_clean()?,
    }

    Ok(())
}
