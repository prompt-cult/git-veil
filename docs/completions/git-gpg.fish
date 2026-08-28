# Print an optspec for argparse to handle cmd's options that are independent of any subcommand.
function __fish_git_gpg_global_optspecs
    string join \n h/help V/version
end

function __fish_git_gpg_needs_command
    # Figure out if the current invocation already has a command.
    set -l cmd (commandline -opc)
    set -e cmd[1]
    argparse -s (__fish_git_gpg_global_optspecs) -- $cmd 2>/dev/null
    or return
    if set -q argv[1]
        # Also print the command, so this can be used to figure out what it is.
        echo $argv[1]
        return 1
    end
    return 0
end

function __fish_git_gpg_using_subcommand
    set -l cmd (__fish_git_gpg_needs_command)
    test -z "$cmd"
    and return 1
    contains -- $cmd[1] $argv
end

complete -c git-gpg -n "__fish_git_gpg_needs_command" -s h -l help -d 'Print help'
complete -c git-gpg -n "__fish_git_gpg_needs_command" -s V -l version -d 'Print version'
complete -c git-gpg -n "__fish_git_gpg_needs_command" -f -a "init" -d 'Initialize git-gpg in the current repository'
complete -c git-gpg -n "__fish_git_gpg_needs_command" -f -a "import" -d 'Import your private key(s) into the git-gpg key store'
complete -c git-gpg -n "__fish_git_gpg_needs_command" -f -a "trust" -d 'Establish trust for a repository by verifying the owner\'s signing key'
complete -c git-gpg -n "__fish_git_gpg_needs_command" -f -a "tell" -d 'Add a collaborator\'s public key to the keyring'
complete -c git-gpg -n "__fish_git_gpg_needs_command" -f -a "removeperson" -d 'Remove a collaborator from the keyring'
complete -c git-gpg -n "__fish_git_gpg_needs_command" -f -a "add" -d 'Add a file to be encrypted'
complete -c git-gpg -n "__fish_git_gpg_needs_command" -f -a "remove" -d 'Remove a file from encryption tracking'
complete -c git-gpg -n "__fish_git_gpg_needs_command" -f -a "list" -d 'List all tracked files'
complete -c git-gpg -n "__fish_git_gpg_needs_command" -f -a "hide" -d 'Hide - encrypt all tracked files'
complete -c git-gpg -n "__fish_git_gpg_needs_command" -f -a "reveal" -d 'Reveal - decrypt all tracked files'
complete -c git-gpg -n "__fish_git_gpg_needs_command" -f -a "cat" -d 'Cat - decrypt a single tracked file to stdout'
complete -c git-gpg -n "__fish_git_gpg_needs_command" -f -a "unhide" -d 'Unhide - decrypt a single tracked file back to plaintext and delete its ciphertext'
complete -c git-gpg -n "__fish_git_gpg_needs_command" -f -a "changes" -d 'Changes - report where plaintext differs from the last hidden version'
complete -c git-gpg -n "__fish_git_gpg_needs_command" -f -a "show-repo-id" -d 'Show the repository ID'
complete -c git-gpg -n "__fish_git_gpg_needs_command" -f -a "whoami" -d 'Show your identity'
complete -c git-gpg -n "__fish_git_gpg_needs_command" -f -a "verify-keyring" -d 'Verify the keyring signature'
complete -c git-gpg -n "__fish_git_gpg_needs_command" -f -a "list-keys" -d 'List all keys in the keyring (requires a verified keyring signature)'
complete -c git-gpg -n "__fish_git_gpg_needs_command" -f -a "clean" -d 'Clean - remove all git-gpg metadata'
complete -c git-gpg -n "__fish_git_gpg_needs_command" -f -a "completions" -d 'Emit a shell completion script for the given shell to stdout'
complete -c git-gpg -n "__fish_git_gpg_needs_command" -f -a "manpages" -d 'Write roff man pages (git-gpg.1 plus one per subcommand) to a directory'
complete -c git-gpg -n "__fish_git_gpg_needs_command" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c git-gpg -n "__fish_git_gpg_using_subcommand init" -s h -l help -d 'Print help'
complete -c git-gpg -n "__fish_git_gpg_using_subcommand import" -l gpg-home -d 'Key store directory (default: $HOME/.git-gpg)' -r -F
complete -c git-gpg -n "__fish_git_gpg_using_subcommand import" -s h -l help -d 'Print help'
complete -c git-gpg -n "__fish_git_gpg_using_subcommand trust" -l remote -d 'Git remote name' -r
complete -c git-gpg -n "__fish_git_gpg_using_subcommand trust" -l gpg-home -d 'Key store directory (default: $HOME/.git-gpg)' -r -F
complete -c git-gpg -n "__fish_git_gpg_using_subcommand trust" -s h -l help -d 'Print help'
complete -c git-gpg -n "__fish_git_gpg_using_subcommand tell" -l remote -d 'Git remote name' -r
complete -c git-gpg -n "__fish_git_gpg_using_subcommand tell" -l gpg-home -d 'Key store directory (default: $HOME/.git-gpg)' -r -F
complete -c git-gpg -n "__fish_git_gpg_using_subcommand tell" -l passphrase-stdin -d 'Read the passphrase for a passphrase-protected private key from stdin (exactly one line). Wins over the GITGPG_PASSPHRASE environment variable; never pass a passphrase as a CLI argument'
complete -c git-gpg -n "__fish_git_gpg_using_subcommand tell" -s h -l help -d 'Print help'
complete -c git-gpg -n "__fish_git_gpg_using_subcommand removeperson" -l remote -d 'Git remote name' -r
complete -c git-gpg -n "__fish_git_gpg_using_subcommand removeperson" -l gpg-home -d 'Key store directory (default: $HOME/.git-gpg)' -r -F
complete -c git-gpg -n "__fish_git_gpg_using_subcommand removeperson" -l passphrase-stdin -d 'Read the passphrase for a passphrase-protected private key from stdin (exactly one line). Wins over the GITGPG_PASSPHRASE environment variable; never pass a passphrase as a CLI argument'
complete -c git-gpg -n "__fish_git_gpg_using_subcommand removeperson" -s h -l help -d 'Print help'
complete -c git-gpg -n "__fish_git_gpg_using_subcommand add" -s h -l help -d 'Print help'
complete -c git-gpg -n "__fish_git_gpg_using_subcommand remove" -s h -l help -d 'Print help'
complete -c git-gpg -n "__fish_git_gpg_using_subcommand list" -s h -l help -d 'Print help'
complete -c git-gpg -n "__fish_git_gpg_using_subcommand hide" -l remote -d 'Git remote name' -r
complete -c git-gpg -n "__fish_git_gpg_using_subcommand hide" -l gpg-home -d 'Key store directory (default: $HOME/.git-gpg)' -r -F
complete -c git-gpg -n "__fish_git_gpg_using_subcommand hide" -s h -l help -d 'Print help'
complete -c git-gpg -n "__fish_git_gpg_using_subcommand reveal" -l email -d 'Your email address' -r
complete -c git-gpg -n "__fish_git_gpg_using_subcommand reveal" -l remote -d 'Git remote name' -r
complete -c git-gpg -n "__fish_git_gpg_using_subcommand reveal" -l gpg-home -d 'Key store directory (default: $HOME/.git-gpg)' -r -F
complete -c git-gpg -n "__fish_git_gpg_using_subcommand reveal" -l passphrase-stdin -d 'Read the passphrase for a passphrase-protected private key from stdin (exactly one line). Wins over the GITGPG_PASSPHRASE environment variable; never pass a passphrase as a CLI argument'
complete -c git-gpg -n "__fish_git_gpg_using_subcommand reveal" -s h -l help -d 'Print help'
complete -c git-gpg -n "__fish_git_gpg_using_subcommand cat" -l email -d 'Your email address' -r
complete -c git-gpg -n "__fish_git_gpg_using_subcommand cat" -l remote -d 'Git remote name' -r
complete -c git-gpg -n "__fish_git_gpg_using_subcommand cat" -l gpg-home -d 'Key store directory (default: $HOME/.git-gpg)' -r -F
complete -c git-gpg -n "__fish_git_gpg_using_subcommand cat" -l passphrase-stdin -d 'Read the passphrase for a passphrase-protected private key from stdin (exactly one line). Wins over the GITGPG_PASSPHRASE environment variable; never pass a passphrase as a CLI argument'
complete -c git-gpg -n "__fish_git_gpg_using_subcommand cat" -s h -l help -d 'Print help'
complete -c git-gpg -n "__fish_git_gpg_using_subcommand unhide" -l email -d 'Your email address' -r
complete -c git-gpg -n "__fish_git_gpg_using_subcommand unhide" -l remote -d 'Git remote name' -r
complete -c git-gpg -n "__fish_git_gpg_using_subcommand unhide" -l gpg-home -d 'Key store directory (default: $HOME/.git-gpg)' -r -F
complete -c git-gpg -n "__fish_git_gpg_using_subcommand unhide" -l passphrase-stdin -d 'Read the passphrase for a passphrase-protected private key from stdin (exactly one line). Wins over the GITGPG_PASSPHRASE environment variable; never pass a passphrase as a CLI argument'
complete -c git-gpg -n "__fish_git_gpg_using_subcommand unhide" -s h -l help -d 'Print help'
complete -c git-gpg -n "__fish_git_gpg_using_subcommand changes" -l email -d 'Your email address' -r
complete -c git-gpg -n "__fish_git_gpg_using_subcommand changes" -l remote -d 'Git remote name' -r
complete -c git-gpg -n "__fish_git_gpg_using_subcommand changes" -l gpg-home -d 'Key store directory (default: $HOME/.git-gpg)' -r -F
complete -c git-gpg -n "__fish_git_gpg_using_subcommand changes" -l passphrase-stdin -d 'Read the passphrase for a passphrase-protected private key from stdin (exactly one line). Wins over the GITGPG_PASSPHRASE environment variable; never pass a passphrase as a CLI argument'
complete -c git-gpg -n "__fish_git_gpg_using_subcommand changes" -s h -l help -d 'Print help'
complete -c git-gpg -n "__fish_git_gpg_using_subcommand show-repo-id" -l remote -d 'Git remote name' -r
complete -c git-gpg -n "__fish_git_gpg_using_subcommand show-repo-id" -s h -l help -d 'Print help'
complete -c git-gpg -n "__fish_git_gpg_using_subcommand whoami" -l email -d 'Email override' -r
complete -c git-gpg -n "__fish_git_gpg_using_subcommand whoami" -l gpg-home -d 'Key store directory (default: $HOME/.git-gpg)' -r -F
complete -c git-gpg -n "__fish_git_gpg_using_subcommand whoami" -s h -l help -d 'Print help'
complete -c git-gpg -n "__fish_git_gpg_using_subcommand verify-keyring" -l remote -d 'Git remote name' -r
complete -c git-gpg -n "__fish_git_gpg_using_subcommand verify-keyring" -l gpg-home -d 'Key store directory (default: $HOME/.git-gpg)' -r -F
complete -c git-gpg -n "__fish_git_gpg_using_subcommand verify-keyring" -s h -l help -d 'Print help'
complete -c git-gpg -n "__fish_git_gpg_using_subcommand list-keys" -l remote -d 'Git remote name' -r
complete -c git-gpg -n "__fish_git_gpg_using_subcommand list-keys" -l gpg-home -d 'Key store directory (default: $HOME/.git-gpg)' -r -F
complete -c git-gpg -n "__fish_git_gpg_using_subcommand list-keys" -s h -l help -d 'Print help'
complete -c git-gpg -n "__fish_git_gpg_using_subcommand clean" -l yes -d 'Confirm destruction of tracked state and any ciphertext. Required when the clean would destroy tracked files or their in-place `<name>.secret` ciphertext (which may be the only remaining copy)'
complete -c git-gpg -n "__fish_git_gpg_using_subcommand clean" -s h -l help -d 'Print help'
complete -c git-gpg -n "__fish_git_gpg_using_subcommand completions" -s h -l help -d 'Print help'
complete -c git-gpg -n "__fish_git_gpg_using_subcommand manpages" -s h -l help -d 'Print help'
complete -c git-gpg -n "__fish_git_gpg_using_subcommand help; and not __fish_seen_subcommand_from init import trust tell removeperson add remove list hide reveal cat unhide changes show-repo-id whoami verify-keyring list-keys clean completions manpages help" -f -a "init" -d 'Initialize git-gpg in the current repository'
complete -c git-gpg -n "__fish_git_gpg_using_subcommand help; and not __fish_seen_subcommand_from init import trust tell removeperson add remove list hide reveal cat unhide changes show-repo-id whoami verify-keyring list-keys clean completions manpages help" -f -a "import" -d 'Import your private key(s) into the git-gpg key store'
complete -c git-gpg -n "__fish_git_gpg_using_subcommand help; and not __fish_seen_subcommand_from init import trust tell removeperson add remove list hide reveal cat unhide changes show-repo-id whoami verify-keyring list-keys clean completions manpages help" -f -a "trust" -d 'Establish trust for a repository by verifying the owner\'s signing key'
complete -c git-gpg -n "__fish_git_gpg_using_subcommand help; and not __fish_seen_subcommand_from init import trust tell removeperson add remove list hide reveal cat unhide changes show-repo-id whoami verify-keyring list-keys clean completions manpages help" -f -a "tell" -d 'Add a collaborator\'s public key to the keyring'
complete -c git-gpg -n "__fish_git_gpg_using_subcommand help; and not __fish_seen_subcommand_from init import trust tell removeperson add remove list hide reveal cat unhide changes show-repo-id whoami verify-keyring list-keys clean completions manpages help" -f -a "removeperson" -d 'Remove a collaborator from the keyring'
complete -c git-gpg -n "__fish_git_gpg_using_subcommand help; and not __fish_seen_subcommand_from init import trust tell removeperson add remove list hide reveal cat unhide changes show-repo-id whoami verify-keyring list-keys clean completions manpages help" -f -a "add" -d 'Add a file to be encrypted'
complete -c git-gpg -n "__fish_git_gpg_using_subcommand help; and not __fish_seen_subcommand_from init import trust tell removeperson add remove list hide reveal cat unhide changes show-repo-id whoami verify-keyring list-keys clean completions manpages help" -f -a "remove" -d 'Remove a file from encryption tracking'
complete -c git-gpg -n "__fish_git_gpg_using_subcommand help; and not __fish_seen_subcommand_from init import trust tell removeperson add remove list hide reveal cat unhide changes show-repo-id whoami verify-keyring list-keys clean completions manpages help" -f -a "list" -d 'List all tracked files'
complete -c git-gpg -n "__fish_git_gpg_using_subcommand help; and not __fish_seen_subcommand_from init import trust tell removeperson add remove list hide reveal cat unhide changes show-repo-id whoami verify-keyring list-keys clean completions manpages help" -f -a "hide" -d 'Hide - encrypt all tracked files'
complete -c git-gpg -n "__fish_git_gpg_using_subcommand help; and not __fish_seen_subcommand_from init import trust tell removeperson add remove list hide reveal cat unhide changes show-repo-id whoami verify-keyring list-keys clean completions manpages help" -f -a "reveal" -d 'Reveal - decrypt all tracked files'
complete -c git-gpg -n "__fish_git_gpg_using_subcommand help; and not __fish_seen_subcommand_from init import trust tell removeperson add remove list hide reveal cat unhide changes show-repo-id whoami verify-keyring list-keys clean completions manpages help" -f -a "cat" -d 'Cat - decrypt a single tracked file to stdout'
complete -c git-gpg -n "__fish_git_gpg_using_subcommand help; and not __fish_seen_subcommand_from init import trust tell removeperson add remove list hide reveal cat unhide changes show-repo-id whoami verify-keyring list-keys clean completions manpages help" -f -a "unhide" -d 'Unhide - decrypt a single tracked file back to plaintext and delete its ciphertext'
complete -c git-gpg -n "__fish_git_gpg_using_subcommand help; and not __fish_seen_subcommand_from init import trust tell removeperson add remove list hide reveal cat unhide changes show-repo-id whoami verify-keyring list-keys clean completions manpages help" -f -a "changes" -d 'Changes - report where plaintext differs from the last hidden version'
complete -c git-gpg -n "__fish_git_gpg_using_subcommand help; and not __fish_seen_subcommand_from init import trust tell removeperson add remove list hide reveal cat unhide changes show-repo-id whoami verify-keyring list-keys clean completions manpages help" -f -a "show-repo-id" -d 'Show the repository ID'
complete -c git-gpg -n "__fish_git_gpg_using_subcommand help; and not __fish_seen_subcommand_from init import trust tell removeperson add remove list hide reveal cat unhide changes show-repo-id whoami verify-keyring list-keys clean completions manpages help" -f -a "whoami" -d 'Show your identity'
complete -c git-gpg -n "__fish_git_gpg_using_subcommand help; and not __fish_seen_subcommand_from init import trust tell removeperson add remove list hide reveal cat unhide changes show-repo-id whoami verify-keyring list-keys clean completions manpages help" -f -a "verify-keyring" -d 'Verify the keyring signature'
complete -c git-gpg -n "__fish_git_gpg_using_subcommand help; and not __fish_seen_subcommand_from init import trust tell removeperson add remove list hide reveal cat unhide changes show-repo-id whoami verify-keyring list-keys clean completions manpages help" -f -a "list-keys" -d 'List all keys in the keyring (requires a verified keyring signature)'
complete -c git-gpg -n "__fish_git_gpg_using_subcommand help; and not __fish_seen_subcommand_from init import trust tell removeperson add remove list hide reveal cat unhide changes show-repo-id whoami verify-keyring list-keys clean completions manpages help" -f -a "clean" -d 'Clean - remove all git-gpg metadata'
complete -c git-gpg -n "__fish_git_gpg_using_subcommand help; and not __fish_seen_subcommand_from init import trust tell removeperson add remove list hide reveal cat unhide changes show-repo-id whoami verify-keyring list-keys clean completions manpages help" -f -a "completions" -d 'Emit a shell completion script for the given shell to stdout'
complete -c git-gpg -n "__fish_git_gpg_using_subcommand help; and not __fish_seen_subcommand_from init import trust tell removeperson add remove list hide reveal cat unhide changes show-repo-id whoami verify-keyring list-keys clean completions manpages help" -f -a "manpages" -d 'Write roff man pages (git-gpg.1 plus one per subcommand) to a directory'
complete -c git-gpg -n "__fish_git_gpg_using_subcommand help; and not __fish_seen_subcommand_from init import trust tell removeperson add remove list hide reveal cat unhide changes show-repo-id whoami verify-keyring list-keys clean completions manpages help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
