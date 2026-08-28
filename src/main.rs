use clap::Parser as _;
use std::path::PathBuf;
use anyhow::{Context as _, Result};

use git_gpg::{
    cli::{Cli, Commands},
    cmd_init, cmd_import, cmd_trust, cmd_tell, cmd_removeperson, cmd_add, cmd_remove, cmd_list,
    cmd_hide, cmd_reveal, cmd_unhide, cmd_cat, cmd_changes, cmd_clean, cmd_show_repo_id,
    cmd_whoami, cmd_verify_keyring, cmd_list_keys, default_gpg_home, get_git_config_email,
};

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
/// an explicit `--gpg-home` wins; otherwise fall back to `$HOME/.git-gpg`.
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
        Commands::Completions { shell } => git_gpg::cli::run_completions(shell),
        Commands::Manpages { output_dir } => {
            let dir = output_dir.unwrap_or_else(|| PathBuf::from("man"));
            git_gpg::cli::run_manpages(&dir)?;
        }
    }

    Ok(())
}
