use anyhow::Result;
use clap::{CommandFactory as _, Parser as _};
use std::path::PathBuf;
use std::process::ExitCode as StdExitCode;

use git_veil::{
    check_key_store_permissions,
    cli::{Cli, Commands},
    cmd_add_file, cmd_add_key, cmd_allow, cmd_cat, cmd_changes, cmd_clean, cmd_export,
    cmd_export_pin, cmd_fingerprint, cmd_forget, cmd_hide, cmd_import, cmd_init, cmd_list,
    cmd_list_keys, cmd_remove_file, cmd_remove_key, cmd_repo_id, cmd_reveal, cmd_rotate, cmd_trust,
    cmd_trust_permissions, cmd_verify_keys, cmd_whoami, default_key_store, exit_code_of,
    get_git_config_email, permissions_check_bypassed_from_env, ExitCode,
};

/// Resolves the email for commands that accept --email: an explicit,
/// non-empty value wins. Otherwise fall back to `git config user.email`.
fn resolve_email(repo_root: &std::path::Path, email: Option<String>) -> Result<String> {
    match email {
        Some(e) if !e.trim().is_empty() => Ok(e),
        Some(_) => anyhow::bail!("--email must not be empty"),
        None => get_git_config_email(repo_root),
    }
}

/// Resolves the key store location for commands that consume a key_store.
/// An explicit `--key-store` wins, then `$GIT_VEIL_HOME`, then
/// `$HOME/.git-veil`. Resolved lazily so HOME-free subcommands
/// (remove-file/list/clean/repo-id/error-codes) never fail on an unset
/// HOME. add-file, allow and list-keys are not in that set: add-file and
/// allow record the machine-local allowance store in the key store (see
/// "Allowance" in docs/src/design.md), and list-keys verifies the keyring
/// signature against the pinned key, so all three consume a key_store
/// like every other gated command.
///
/// Every resolved key store passes the permission gate before any key
/// material is read (gpg checks ~/.gnupg the same way). Bypassed by the
/// global --dangerously-skip-permissions-check flag or a truthy
/// GIT_VEIL_SKIP_PERMISSIONS.
fn resolve_key_store(key_store: Option<PathBuf>, skip_permissions_check: bool) -> Result<PathBuf> {
    let store = key_store.map(Ok).unwrap_or_else(default_key_store)?;
    check_key_store_permissions(&store, skip_permissions_check)?;
    Ok(store)
}

/// Intercepts `git-veil help [cmd]`. Per the UX spec, the command's
/// discussion + EXAMPLES (its after_long_help content) render first and the
/// usage/options block renders last. `git-veil <cmd> --help` keeps clap's
/// native order (options before after_long_help), matching the man pages.
fn handle_help_subcommand(rest: &[String]) -> Result<()> {
    let mut root = Cli::command();
    match rest.first() {
        None => {
            print!("{}", root.render_long_help());
        }
        Some(name) => {
            let Some(sub) = root.find_subcommand(name.as_str()) else {
                eprintln!("error: unrecognized subcommand");
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
        Commands::Init {
            verifying_key,
            remote,
            quiet,
            suppress_codeowners,
            key_store: opt,
        } => {
            cmd_init(
                &repo_root,
                &verifying_key,
                &remote,
                &resolve_key_store(opt, skip_permissions_check)?,
                quiet,
                suppress_codeowners,
            )?;
        }
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
        Commands::Forget {
            identifier,
            yes,
            key_store: opt,
        } => {
            cmd_forget(
                &resolve_key_store(opt, skip_permissions_check)?,
                &identifier,
                yes,
            )?;
        }
        Commands::Trust {
            import,
            remote,
            suppress_codeowners,
            key_store: opt,
        } => {
            let key_store = resolve_key_store(opt, skip_permissions_check)?;
            cmd_trust(
                &repo_root,
                &import,
                &remote,
                &key_store,
                suppress_codeowners,
            )?;
        }
        Commands::ExportPin {
            repo_id,
            output,
            remote,
            key_store: opt,
        } => {
            cmd_export_pin(
                &repo_root,
                &repo_id,
                output.as_deref(),
                &remote,
                &resolve_key_store(opt, skip_permissions_check)?,
            )?;
        }
        Commands::Fingerprint { label, public_key } => {
            cmd_fingerprint(&label, &public_key);
        }
        Commands::AddKey {
            email,
            public_key,
            remote,
            signing_key,
            key_store: opt,
        } => {
            cmd_add_key(
                &repo_root,
                &email,
                &public_key,
                &remote,
                &resolve_key_store(opt, skip_permissions_check)?,
                signing_key.as_deref(),
            )?;
        }
        Commands::RemoveKey {
            email,
            remote,
            signing_key,
            key_store: opt,
        } => {
            cmd_remove_key(
                &repo_root,
                &email,
                &remote,
                &resolve_key_store(opt, skip_permissions_check)?,
                signing_key.as_deref(),
            )?;
        }
        Commands::AddFile { files, remote } => cmd_add_file(
            &repo_root,
            files,
            &remote,
            &resolve_key_store(None, skip_permissions_check)?,
        )?,
        Commands::Allow { files, remote } => cmd_allow(
            &repo_root,
            files,
            &remote,
            &resolve_key_store(None, skip_permissions_check)?,
        )?,
        Commands::RemoveFile {
            files,
            keep_ciphertext,
        } => cmd_remove_file(&repo_root, files, keep_ciphertext)?,
        Commands::List => cmd_list(&repo_root)?,
        Commands::Hide {
            remote,
            key_store: opt,
            keep_plaintext,
            files,
        } => {
            let key_store = resolve_key_store(opt, skip_permissions_check)?;
            cmd_hide(&repo_root, &remote, &key_store, keep_plaintext, files)?;
        }
        Commands::Rotate {
            remote,
            key_store: opt,
        } => {
            let key_store = resolve_key_store(opt, skip_permissions_check)?;
            cmd_rotate(&repo_root, &remote, &key_store)?;
        }
        Commands::Reveal {
            email,
            remote,
            key_store: opt,
            files,
        } => {
            let email = resolve_email(&repo_root, email)?;
            cmd_reveal(
                &repo_root,
                &email,
                &remote,
                &resolve_key_store(opt, skip_permissions_check)?,
                files,
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
        Commands::RepoId { remote } => cmd_repo_id(&repo_root, &remote)?,
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
        Commands::VerifyKeys {
            remote,
            key_store: opt,
        } => {
            cmd_verify_keys(
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
            // Deliberately resolved without the permission gate. This
            // command records the acknowledgment, so the gate must not
            // block it with its own findings.
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
