use anyhow::Result;
use clap::{CommandFactory as _, Parser as _};
use std::path::PathBuf;
use std::process::ExitCode as StdExitCode;

use git_veil::{
    check_key_store_permissions,
    cli::{Cli, Commands},
    cmd_add, cmd_cat, cmd_changes, cmd_clean, cmd_export, cmd_hide, cmd_import, cmd_init, cmd_list,
    cmd_list_keys, cmd_remove, cmd_removekey, cmd_removeperson, cmd_reveal, cmd_show_repo_id,
    cmd_tell, cmd_trust, cmd_trust_permissions, cmd_unhide, cmd_verify_keyring, cmd_whoami,
    default_key_store, exit_code_of, get_git_config_email, permissions_check_bypassed_from_env,
    ExitCode,
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

/// Resolves the key store location for commands that consume a key_store:
/// an explicit `--key-store` wins; then `$GIT_VEIL_HOME`; then `$HOME/.git-veil`.
/// Resolved lazily so HOME-free subcommands (init/add/remove/list/clean/
/// show-repo-id/error-codes) never fail on an unset HOME. list-keys is no
/// longer in this set: it verifies the keyring signature against the pinned
/// key, so it consumes a key_store like every other gated command.
///
/// Every resolved key store passes the permission gate BEFORE any key
/// material is read (gpg checks ~/.gnupg the same way). Bypassed by the
/// global --dangerously-skip-permissions-check flag or a truthy
/// GIT_VEIL_SKIP_PERMISSIONS.
fn resolve_key_store(key_store: Option<PathBuf>, skip_permissions_check: bool) -> Result<PathBuf> {
    let store = key_store.map(Ok).unwrap_or_else(default_key_store)?;
    check_key_store_permissions(&store, skip_permissions_check)?;
    Ok(store)
}

/// Intercepts `git-veil help [cmd]` so that per the UX spec the command's
/// discussion + EXAMPLES (its after_long_help content) render FIRST and the
/// usage/options block renders LAST. `git-veil <cmd> --help` keeps clap's
/// native order (options before after_long_help), matching the man pages.
fn handle_help_subcommand(rest: &[String]) -> Result<()> {
    let mut root = Cli::command();
    match rest.first() {
        None => {
            print!("{}", root.render_long_help());
        }
        Some(name) => {
            let Some(sub) = root.find_subcommand(name.as_str()) else {
                eprintln!("error: unrecognized subcommand '{name}'");
                std::process::exit(2);
            };
            let mut sub = sub.clone();
            if let Some(after) = sub.get_after_long_help() {
                println!("{after}");
            }
            print!("{}", sub.render_help());
        }
    }
    Ok(())
}

fn main() -> StdExitCode {
    let code = match run() {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("error: {:#}", err);
            exit_code_of(&err)
        }
    };
    StdExitCode::from(code as u8)
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 2 && args[1] == "help" {
        return handle_help_subcommand(&args[2..]);
    }

    let cli = Cli::parse();
    let skip_permissions_check =
        cli.dangerously_skip_permissions_check || permissions_check_bypassed_from_env();
    let repo_root = std::env::current_dir()?;

    match cli.command {
        Commands::Init => cmd_init(&repo_root)?,
        Commands::Import {
            files,
            key_store: opt,
        } => {
            cmd_import(
                &repo_root,
                &files,
                &resolve_key_store(opt, skip_permissions_check)?,
            )?;
        }
        Commands::Export {
            identifier,
            output,
            key_store: opt,
        } => {
            cmd_export(
                &resolve_key_store(opt, skip_permissions_check)?,
                &identifier,
                output.as_deref(),
            )?;
        }
        Commands::RemoveKey {
            identifier,
            yes,
            key_store: opt,
        } => {
            cmd_removekey(
                &resolve_key_store(opt, skip_permissions_check)?,
                &identifier,
                yes,
            )?;
        }
        Commands::Trust {
            repo_id,
            verifying_key,
            remote,
            key_store: opt,
        } => {
            cmd_trust(
                &repo_root,
                &repo_id,
                &verifying_key,
                &remote,
                &resolve_key_store(opt, skip_permissions_check)?,
            )?;
        }
        Commands::Tell {
            email,
            public_key,
            remote,
            signing_key,
            key_store: opt,
        } => {
            cmd_tell(
                &repo_root,
                &email,
                &public_key,
                &remote,
                &resolve_key_store(opt, skip_permissions_check)?,
                signing_key.as_deref(),
            )?;
        }
        Commands::RemovePerson {
            email,
            remote,
            signing_key,
            key_store: opt,
        } => {
            cmd_removeperson(
                &repo_root,
                &email,
                &remote,
                &resolve_key_store(opt, skip_permissions_check)?,
                signing_key.as_deref(),
            )?;
        }
        Commands::Add { files } => cmd_add(&repo_root, files)?,
        Commands::Remove { files } => cmd_remove(&repo_root, files)?,
        Commands::List => cmd_list(&repo_root)?,
        Commands::Hide {
            remote,
            key_store: opt,
            dangerously_delete_plaintext,
        } => {
            cmd_hide(
                &repo_root,
                &remote,
                &resolve_key_store(opt, skip_permissions_check)?,
                dangerously_delete_plaintext,
            )?;
        }
        Commands::Reveal {
            email,
            remote,
            key_store: opt,
        } => {
            let email = resolve_email(&repo_root, email)?;
            cmd_reveal(
                &repo_root,
                &email,
                &remote,
                &resolve_key_store(opt, skip_permissions_check)?,
            )?;
        }
        Commands::Cat {
            file,
            email,
            remote,
            key_store: opt,
        } => {
            let email = resolve_email(&repo_root, email)?;
            cmd_cat(
                &repo_root,
                &file,
                &email,
                &remote,
                &resolve_key_store(opt, skip_permissions_check)?,
            )?;
        }
        Commands::Unhide {
            file,
            email,
            remote,
            key_store: opt,
        } => {
            let email = resolve_email(&repo_root, email)?;
            cmd_unhide(
                &repo_root,
                &file,
                &email,
                &remote,
                &resolve_key_store(opt, skip_permissions_check)?,
            )?;
        }
        Commands::Changes {
            files,
            email,
            remote,
            key_store: opt,
        } => {
            let email = resolve_email(&repo_root, email)?;
            cmd_changes(
                &repo_root,
                files,
                &email,
                &remote,
                &resolve_key_store(opt, skip_permissions_check)?,
            )?;
        }
        Commands::ShowRepoId { remote } => cmd_show_repo_id(&repo_root, &remote)?,
        Commands::Whoami {
            email,
            key_store: opt,
        } => {
            cmd_whoami(
                &repo_root,
                email.as_deref(),
                &resolve_key_store(opt, skip_permissions_check)?,
            )?;
        }
        Commands::VerifyKeyring {
            remote,
            key_store: opt,
        } => {
            cmd_verify_keyring(
                &repo_root,
                &remote,
                &resolve_key_store(opt, skip_permissions_check)?,
            )?;
        }
        Commands::ListKeys {
            remote,
            key_store: opt,
        } => {
            cmd_list_keys(
                &repo_root,
                &remote,
                &resolve_key_store(opt, skip_permissions_check)?,
            )?;
        }
        Commands::TrustPermissions { key_store: opt } => {
            // Deliberately resolved WITHOUT the permission gate: this is the
            // command that records the acknowledgment, so it cannot be
            // blocked by the very findings it acknowledges.
            let store = opt.map(Ok).unwrap_or_else(default_key_store)?;
            cmd_trust_permissions(&store)?;
        }
        Commands::ErrorCodes => {
            for code in ExitCode::ALL {
                println!(
                    "{:>3}  {:<30} {}",
                    *code as u8,
                    code.name(),
                    code.description()
                );
            }
        }
        Commands::Clean { yes } => cmd_clean(&repo_root, yes)?,
        Commands::Completions { shell } => git_veil::cli::run_completions(shell),
        Commands::Manpages { output_dir } => {
            let dir = output_dir.unwrap_or_else(|| PathBuf::from("man"));
            git_veil::cli::run_manpages(&dir)?;
        }
    }

    Ok(())
}
