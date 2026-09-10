# Print an optspec for argparse to handle cmd's options that are independent of any subcommand.
function __fish_git_veil_global_optspecs
    string join \n dangerously-skip-permissions-check h/help V/version
end

function __fish_git_veil_needs_command
    # Figure out if the current invocation already has a command.
    set -l cmd (commandline -opc)
    set -e cmd[1]
    argparse -s (__fish_git_veil_global_optspecs) -- $cmd 2>/dev/null
    or return
    if set -q argv[1]
        # Also print the command, so this can be used to figure out what it is.
        echo $argv[1]
        return 1
    end
    return 0
end

function __fish_git_veil_using_subcommand
    set -l cmd (__fish_git_veil_needs_command)
    test -z "$cmd"
    and return 1
    contains -- $cmd[1] $argv
end

complete -c git-veil -n "__fish_git_veil_needs_command" -l dangerously-skip-permissions-check -d 'Bypass the key store permission checks (also: GIT_VEIL_SKIP_PERMISSIONS=1)'
complete -c git-veil -n "__fish_git_veil_needs_command" -s h -l help -d 'Print help'
complete -c git-veil -n "__fish_git_veil_needs_command" -s V -l version -d 'Print version'
complete -c git-veil -n "__fish_git_veil_needs_command" -f -a "init" -d 'Initialize git-veil state (.git-veil/) in the current repository'
complete -c git-veil -n "__fish_git_veil_needs_command" -f -a "import" -d 'Import your age identity (private key) into the git-veil key store'
complete -c git-veil -n "__fish_git_veil_needs_command" -f -a "export" -d 'Export a public key (recipient string) from the local key store'
complete -c git-veil -n "__fish_git_veil_needs_command" -f -a "removekey" -d 'Remove an age identity from the local key store (destructive, local-only)'
complete -c git-veil -n "__fish_git_veil_needs_command" -f -a "trust" -d 'Verify and pin the repository owner\'s Ed25519 verifying key (per machine)'
complete -c git-veil -n "__fish_git_veil_needs_command" -f -a "tell" -d 'Add a collaborator\'s age recipient key to the keyring and re-sign it'
complete -c git-veil -n "__fish_git_veil_needs_command" -f -a "removeperson" -d 'Remove a collaborator from the keyring and re-sign it'
complete -c git-veil -n "__fish_git_veil_needs_command" -f -a "add" -d 'Track files for encryption'
complete -c git-veil -n "__fish_git_veil_needs_command" -f -a "remove" -d 'Untrack files (leaves any ciphertext in place)'
complete -c git-veil -n "__fish_git_veil_needs_command" -f -a "list" -d 'List all tracked files'
complete -c git-veil -n "__fish_git_veil_needs_command" -f -a "hide" -d 'Encrypt all tracked files to the keyring'
complete -c git-veil -n "__fish_git_veil_needs_command" -f -a "reveal" -d 'Decrypt all tracked files back to plaintext'
complete -c git-veil -n "__fish_git_veil_needs_command" -f -a "cat" -d 'Decrypt a single tracked file to stdout'
complete -c git-veil -n "__fish_git_veil_needs_command" -f -a "unhide" -d 'Decrypt one tracked file back to plaintext'
complete -c git-veil -n "__fish_git_veil_needs_command" -f -a "changes" -d 'Report where plaintext differs from the last hidden version'
complete -c git-veil -n "__fish_git_veil_needs_command" -f -a "show-repo-id" -d 'Show the repository ID derived from the git remote push URL'
complete -c git-veil -n "__fish_git_veil_needs_command" -f -a "whoami" -d 'Show the identity and key store git-veil will use'
complete -c git-veil -n "__fish_git_veil_needs_command" -f -a "verify-keyring" -d 'Verify the keyring signature against the pinned trusted key'
complete -c git-veil -n "__fish_git_veil_needs_command" -f -a "list-keys" -d 'List keyring keys after verifying the keyring signature'
complete -c git-veil -n "__fish_git_veil_needs_command" -f -a "trust-permissions" -d 'Acknowledge the key store\'s current permissions as trusted'
complete -c git-veil -n "__fish_git_veil_needs_command" -f -a "error-codes" -d 'List every documented exit code with its name and meaning'
complete -c git-veil -n "__fish_git_veil_needs_command" -f -a "clean" -d 'Remove the .git-veil state directory (--yes required when data would be lost)'
complete -c git-veil -n "__fish_git_veil_needs_command" -f -a "completions" -d 'Emit a shell completion script for the given shell to stdout'
complete -c git-veil -n "__fish_git_veil_needs_command" -f -a "manpages" -d 'Write roff man pages (git-veil.1 plus one per subcommand) to a directory'
complete -c git-veil -n "__fish_git_veil_needs_command" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c git-veil -n "__fish_git_veil_using_subcommand init" -l dangerously-skip-permissions-check -d 'Bypass the key store permission checks (also: GIT_VEIL_SKIP_PERMISSIONS=1)'
complete -c git-veil -n "__fish_git_veil_using_subcommand init" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c git-veil -n "__fish_git_veil_using_subcommand import" -l key-store -d 'Key store directory (default: $GIT_VEIL_HOME or $HOME/.git-veil)' -r -F
complete -c git-veil -n "__fish_git_veil_using_subcommand import" -l dangerously-skip-permissions-check -d 'Bypass the key store permission checks (also: GIT_VEIL_SKIP_PERMISSIONS=1)'
complete -c git-veil -n "__fish_git_veil_using_subcommand import" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c git-veil -n "__fish_git_veil_using_subcommand export" -l output -d 'Write the recipient string to this file instead of stdout' -r -F
complete -c git-veil -n "__fish_git_veil_using_subcommand export" -l key-store -d 'Key store directory (default: $GIT_VEIL_HOME or $HOME/.git-veil)' -r -F
complete -c git-veil -n "__fish_git_veil_using_subcommand export" -l dangerously-skip-permissions-check -d 'Bypass the key store permission checks (also: GIT_VEIL_SKIP_PERMISSIONS=1)'
complete -c git-veil -n "__fish_git_veil_using_subcommand export" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c git-veil -n "__fish_git_veil_using_subcommand removekey" -l key-store -d 'Key store directory (default: $GIT_VEIL_HOME or $HOME/.git-veil)' -r -F
complete -c git-veil -n "__fish_git_veil_using_subcommand removekey" -l yes -d 'Confirm destructive removals: required when the target is the only private key in the store, and to remove ALL keys when the email matches several'
complete -c git-veil -n "__fish_git_veil_using_subcommand removekey" -l dangerously-skip-permissions-check -d 'Bypass the key store permission checks (also: GIT_VEIL_SKIP_PERMISSIONS=1)'
complete -c git-veil -n "__fish_git_veil_using_subcommand removekey" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c git-veil -n "__fish_git_veil_using_subcommand trust" -l remote -d 'Git remote name' -r
complete -c git-veil -n "__fish_git_veil_using_subcommand trust" -l key-store -d 'Key store directory (default: $GIT_VEIL_HOME or $HOME/.git-veil). The store and its pins are the trust boundary for every repository that uses it' -r -F
complete -c git-veil -n "__fish_git_veil_using_subcommand trust" -l dangerously-skip-permissions-check -d 'Bypass the key store permission checks (also: GIT_VEIL_SKIP_PERMISSIONS=1)'
complete -c git-veil -n "__fish_git_veil_using_subcommand trust" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c git-veil -n "__fish_git_veil_using_subcommand tell" -l remote -d 'Git remote name' -r
complete -c git-veil -n "__fish_git_veil_using_subcommand tell" -l signing-key -d 'Which signing key to use: 1-based index into signing-keys.txt, or a 64-hex-character seed (default: the key matching the pinned fingerprint)' -r
complete -c git-veil -n "__fish_git_veil_using_subcommand tell" -l key-store -d 'Key store directory (default: $GIT_VEIL_HOME or $HOME/.git-veil)' -r -F
complete -c git-veil -n "__fish_git_veil_using_subcommand tell" -l dangerously-skip-permissions-check -d 'Bypass the key store permission checks (also: GIT_VEIL_SKIP_PERMISSIONS=1)'
complete -c git-veil -n "__fish_git_veil_using_subcommand tell" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c git-veil -n "__fish_git_veil_using_subcommand removeperson" -l remote -d 'Git remote name' -r
complete -c git-veil -n "__fish_git_veil_using_subcommand removeperson" -l signing-key -d 'Which signing key to use: 1-based index into signing-keys.txt, or a 64-hex-character seed (default: the key matching the pinned fingerprint)' -r
complete -c git-veil -n "__fish_git_veil_using_subcommand removeperson" -l key-store -d 'Key store directory (default: $GIT_VEIL_HOME or $HOME/.git-veil)' -r -F
complete -c git-veil -n "__fish_git_veil_using_subcommand removeperson" -l dangerously-skip-permissions-check -d 'Bypass the key store permission checks (also: GIT_VEIL_SKIP_PERMISSIONS=1)'
complete -c git-veil -n "__fish_git_veil_using_subcommand removeperson" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c git-veil -n "__fish_git_veil_using_subcommand add" -l dangerously-skip-permissions-check -d 'Bypass the key store permission checks (also: GIT_VEIL_SKIP_PERMISSIONS=1)'
complete -c git-veil -n "__fish_git_veil_using_subcommand add" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c git-veil -n "__fish_git_veil_using_subcommand remove" -l dangerously-skip-permissions-check -d 'Bypass the key store permission checks (also: GIT_VEIL_SKIP_PERMISSIONS=1)'
complete -c git-veil -n "__fish_git_veil_using_subcommand remove" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c git-veil -n "__fish_git_veil_using_subcommand list" -l dangerously-skip-permissions-check -d 'Bypass the key store permission checks (also: GIT_VEIL_SKIP_PERMISSIONS=1)'
complete -c git-veil -n "__fish_git_veil_using_subcommand list" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c git-veil -n "__fish_git_veil_using_subcommand hide" -l remote -d 'Git remote name' -r
complete -c git-veil -n "__fish_git_veil_using_subcommand hide" -l key-store -d 'Key store directory (default: $GIT_VEIL_HOME or $HOME/.git-veil)' -r -F
complete -c git-veil -n "__fish_git_veil_using_subcommand hide" -l dangerously-delete-plaintext -d 'Delete plaintext files after successful encryption'
complete -c git-veil -n "__fish_git_veil_using_subcommand hide" -l dangerously-skip-permissions-check -d 'Bypass the key store permission checks (also: GIT_VEIL_SKIP_PERMISSIONS=1)'
complete -c git-veil -n "__fish_git_veil_using_subcommand hide" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c git-veil -n "__fish_git_veil_using_subcommand reveal" -l email -d 'Your email address' -r
complete -c git-veil -n "__fish_git_veil_using_subcommand reveal" -l remote -d 'Git remote name' -r
complete -c git-veil -n "__fish_git_veil_using_subcommand reveal" -l key-store -d 'Key store directory (default: $GIT_VEIL_HOME or $HOME/.git-veil)' -r -F
complete -c git-veil -n "__fish_git_veil_using_subcommand reveal" -l dangerously-skip-permissions-check -d 'Bypass the key store permission checks (also: GIT_VEIL_SKIP_PERMISSIONS=1)'
complete -c git-veil -n "__fish_git_veil_using_subcommand reveal" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c git-veil -n "__fish_git_veil_using_subcommand cat" -l email -d 'Your email address' -r
complete -c git-veil -n "__fish_git_veil_using_subcommand cat" -l remote -d 'Git remote name' -r
complete -c git-veil -n "__fish_git_veil_using_subcommand cat" -l key-store -d 'Key store directory (default: $GIT_VEIL_HOME or $HOME/.git-veil)' -r -F
complete -c git-veil -n "__fish_git_veil_using_subcommand cat" -l dangerously-skip-permissions-check -d 'Bypass the key store permission checks (also: GIT_VEIL_SKIP_PERMISSIONS=1)'
complete -c git-veil -n "__fish_git_veil_using_subcommand cat" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c git-veil -n "__fish_git_veil_using_subcommand unhide" -l email -d 'Your email address' -r
complete -c git-veil -n "__fish_git_veil_using_subcommand unhide" -l remote -d 'Git remote name' -r
complete -c git-veil -n "__fish_git_veil_using_subcommand unhide" -l key-store -d 'Key store directory (default: $GIT_VEIL_HOME or $HOME/.git-veil)' -r -F
complete -c git-veil -n "__fish_git_veil_using_subcommand unhide" -l dangerously-skip-permissions-check -d 'Bypass the key store permission checks (also: GIT_VEIL_SKIP_PERMISSIONS=1)'
complete -c git-veil -n "__fish_git_veil_using_subcommand unhide" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c git-veil -n "__fish_git_veil_using_subcommand changes" -l email -d 'Your email address' -r
complete -c git-veil -n "__fish_git_veil_using_subcommand changes" -l remote -d 'Git remote name' -r
complete -c git-veil -n "__fish_git_veil_using_subcommand changes" -l key-store -d 'Key store directory (default: $GIT_VEIL_HOME or $HOME/.git-veil)' -r -F
complete -c git-veil -n "__fish_git_veil_using_subcommand changes" -l dangerously-skip-permissions-check -d 'Bypass the key store permission checks (also: GIT_VEIL_SKIP_PERMISSIONS=1)'
complete -c git-veil -n "__fish_git_veil_using_subcommand changes" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c git-veil -n "__fish_git_veil_using_subcommand show-repo-id" -l remote -d 'Git remote name' -r
complete -c git-veil -n "__fish_git_veil_using_subcommand show-repo-id" -l dangerously-skip-permissions-check -d 'Bypass the key store permission checks (also: GIT_VEIL_SKIP_PERMISSIONS=1)'
complete -c git-veil -n "__fish_git_veil_using_subcommand show-repo-id" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c git-veil -n "__fish_git_veil_using_subcommand whoami" -l email -d 'Email override' -r
complete -c git-veil -n "__fish_git_veil_using_subcommand whoami" -l key-store -d 'Key store directory (default: $GIT_VEIL_HOME or $HOME/.git-veil)' -r -F
complete -c git-veil -n "__fish_git_veil_using_subcommand whoami" -l dangerously-skip-permissions-check -d 'Bypass the key store permission checks (also: GIT_VEIL_SKIP_PERMISSIONS=1)'
complete -c git-veil -n "__fish_git_veil_using_subcommand whoami" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c git-veil -n "__fish_git_veil_using_subcommand verify-keyring" -l remote -d 'Git remote name' -r
complete -c git-veil -n "__fish_git_veil_using_subcommand verify-keyring" -l key-store -d 'Key store directory (default: $GIT_VEIL_HOME or $HOME/.git-veil)' -r -F
complete -c git-veil -n "__fish_git_veil_using_subcommand verify-keyring" -l dangerously-skip-permissions-check -d 'Bypass the key store permission checks (also: GIT_VEIL_SKIP_PERMISSIONS=1)'
complete -c git-veil -n "__fish_git_veil_using_subcommand verify-keyring" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c git-veil -n "__fish_git_veil_using_subcommand list-keys" -l remote -d 'Git remote name' -r
complete -c git-veil -n "__fish_git_veil_using_subcommand list-keys" -l key-store -d 'Key store directory (default: $GIT_VEIL_HOME or $HOME/.git-veil)' -r -F
complete -c git-veil -n "__fish_git_veil_using_subcommand list-keys" -l dangerously-skip-permissions-check -d 'Bypass the key store permission checks (also: GIT_VEIL_SKIP_PERMISSIONS=1)'
complete -c git-veil -n "__fish_git_veil_using_subcommand list-keys" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c git-veil -n "__fish_git_veil_using_subcommand trust-permissions" -l key-store -d 'Key store directory (default: $GIT_VEIL_HOME or $HOME/.git-veil)' -r -F
complete -c git-veil -n "__fish_git_veil_using_subcommand trust-permissions" -l dangerously-skip-permissions-check -d 'Bypass the key store permission checks (also: GIT_VEIL_SKIP_PERMISSIONS=1)'
complete -c git-veil -n "__fish_git_veil_using_subcommand trust-permissions" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c git-veil -n "__fish_git_veil_using_subcommand error-codes" -l dangerously-skip-permissions-check -d 'Bypass the key store permission checks (also: GIT_VEIL_SKIP_PERMISSIONS=1)'
complete -c git-veil -n "__fish_git_veil_using_subcommand error-codes" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c git-veil -n "__fish_git_veil_using_subcommand clean" -l yes -d 'Confirm destruction of tracked state and any ciphertext. Required when the clean would destroy tracked files or their in-place `<name>.secret` ciphertext (which may be the only remaining copy)'
complete -c git-veil -n "__fish_git_veil_using_subcommand clean" -l dangerously-skip-permissions-check -d 'Bypass the key store permission checks (also: GIT_VEIL_SKIP_PERMISSIONS=1)'
complete -c git-veil -n "__fish_git_veil_using_subcommand clean" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c git-veil -n "__fish_git_veil_using_subcommand completions" -l dangerously-skip-permissions-check -d 'Bypass the key store permission checks (also: GIT_VEIL_SKIP_PERMISSIONS=1)'
complete -c git-veil -n "__fish_git_veil_using_subcommand completions" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c git-veil -n "__fish_git_veil_using_subcommand manpages" -l dangerously-skip-permissions-check -d 'Bypass the key store permission checks (also: GIT_VEIL_SKIP_PERMISSIONS=1)'
complete -c git-veil -n "__fish_git_veil_using_subcommand manpages" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c git-veil -n "__fish_git_veil_using_subcommand help; and not __fish_seen_subcommand_from init import export removekey trust tell removeperson add remove list hide reveal cat unhide changes show-repo-id whoami verify-keyring list-keys trust-permissions error-codes clean completions manpages help" -f -a "init" -d 'Initialize git-veil state (.git-veil/) in the current repository'
complete -c git-veil -n "__fish_git_veil_using_subcommand help; and not __fish_seen_subcommand_from init import export removekey trust tell removeperson add remove list hide reveal cat unhide changes show-repo-id whoami verify-keyring list-keys trust-permissions error-codes clean completions manpages help" -f -a "import" -d 'Import your age identity (private key) into the git-veil key store'
complete -c git-veil -n "__fish_git_veil_using_subcommand help; and not __fish_seen_subcommand_from init import export removekey trust tell removeperson add remove list hide reveal cat unhide changes show-repo-id whoami verify-keyring list-keys trust-permissions error-codes clean completions manpages help" -f -a "export" -d 'Export a public key (recipient string) from the local key store'
complete -c git-veil -n "__fish_git_veil_using_subcommand help; and not __fish_seen_subcommand_from init import export removekey trust tell removeperson add remove list hide reveal cat unhide changes show-repo-id whoami verify-keyring list-keys trust-permissions error-codes clean completions manpages help" -f -a "removekey" -d 'Remove an age identity from the local key store (destructive, local-only)'
complete -c git-veil -n "__fish_git_veil_using_subcommand help; and not __fish_seen_subcommand_from init import export removekey trust tell removeperson add remove list hide reveal cat unhide changes show-repo-id whoami verify-keyring list-keys trust-permissions error-codes clean completions manpages help" -f -a "trust" -d 'Verify and pin the repository owner\'s Ed25519 verifying key (per machine)'
complete -c git-veil -n "__fish_git_veil_using_subcommand help; and not __fish_seen_subcommand_from init import export removekey trust tell removeperson add remove list hide reveal cat unhide changes show-repo-id whoami verify-keyring list-keys trust-permissions error-codes clean completions manpages help" -f -a "tell" -d 'Add a collaborator\'s age recipient key to the keyring and re-sign it'
complete -c git-veil -n "__fish_git_veil_using_subcommand help; and not __fish_seen_subcommand_from init import export removekey trust tell removeperson add remove list hide reveal cat unhide changes show-repo-id whoami verify-keyring list-keys trust-permissions error-codes clean completions manpages help" -f -a "removeperson" -d 'Remove a collaborator from the keyring and re-sign it'
complete -c git-veil -n "__fish_git_veil_using_subcommand help; and not __fish_seen_subcommand_from init import export removekey trust tell removeperson add remove list hide reveal cat unhide changes show-repo-id whoami verify-keyring list-keys trust-permissions error-codes clean completions manpages help" -f -a "add" -d 'Track files for encryption'
complete -c git-veil -n "__fish_git_veil_using_subcommand help; and not __fish_seen_subcommand_from init import export removekey trust tell removeperson add remove list hide reveal cat unhide changes show-repo-id whoami verify-keyring list-keys trust-permissions error-codes clean completions manpages help" -f -a "remove" -d 'Untrack files (leaves any ciphertext in place)'
complete -c git-veil -n "__fish_git_veil_using_subcommand help; and not __fish_seen_subcommand_from init import export removekey trust tell removeperson add remove list hide reveal cat unhide changes show-repo-id whoami verify-keyring list-keys trust-permissions error-codes clean completions manpages help" -f -a "list" -d 'List all tracked files'
complete -c git-veil -n "__fish_git_veil_using_subcommand help; and not __fish_seen_subcommand_from init import export removekey trust tell removeperson add remove list hide reveal cat unhide changes show-repo-id whoami verify-keyring list-keys trust-permissions error-codes clean completions manpages help" -f -a "hide" -d 'Encrypt all tracked files to the keyring'
complete -c git-veil -n "__fish_git_veil_using_subcommand help; and not __fish_seen_subcommand_from init import export removekey trust tell removeperson add remove list hide reveal cat unhide changes show-repo-id whoami verify-keyring list-keys trust-permissions error-codes clean completions manpages help" -f -a "reveal" -d 'Decrypt all tracked files back to plaintext'
complete -c git-veil -n "__fish_git_veil_using_subcommand help; and not __fish_seen_subcommand_from init import export removekey trust tell removeperson add remove list hide reveal cat unhide changes show-repo-id whoami verify-keyring list-keys trust-permissions error-codes clean completions manpages help" -f -a "cat" -d 'Decrypt a single tracked file to stdout'
complete -c git-veil -n "__fish_git_veil_using_subcommand help; and not __fish_seen_subcommand_from init import export removekey trust tell removeperson add remove list hide reveal cat unhide changes show-repo-id whoami verify-keyring list-keys trust-permissions error-codes clean completions manpages help" -f -a "unhide" -d 'Decrypt one tracked file back to plaintext'
complete -c git-veil -n "__fish_git_veil_using_subcommand help; and not __fish_seen_subcommand_from init import export removekey trust tell removeperson add remove list hide reveal cat unhide changes show-repo-id whoami verify-keyring list-keys trust-permissions error-codes clean completions manpages help" -f -a "changes" -d 'Report where plaintext differs from the last hidden version'
complete -c git-veil -n "__fish_git_veil_using_subcommand help; and not __fish_seen_subcommand_from init import export removekey trust tell removeperson add remove list hide reveal cat unhide changes show-repo-id whoami verify-keyring list-keys trust-permissions error-codes clean completions manpages help" -f -a "show-repo-id" -d 'Show the repository ID derived from the git remote push URL'
complete -c git-veil -n "__fish_git_veil_using_subcommand help; and not __fish_seen_subcommand_from init import export removekey trust tell removeperson add remove list hide reveal cat unhide changes show-repo-id whoami verify-keyring list-keys trust-permissions error-codes clean completions manpages help" -f -a "whoami" -d 'Show the identity and key store git-veil will use'
complete -c git-veil -n "__fish_git_veil_using_subcommand help; and not __fish_seen_subcommand_from init import export removekey trust tell removeperson add remove list hide reveal cat unhide changes show-repo-id whoami verify-keyring list-keys trust-permissions error-codes clean completions manpages help" -f -a "verify-keyring" -d 'Verify the keyring signature against the pinned trusted key'
complete -c git-veil -n "__fish_git_veil_using_subcommand help; and not __fish_seen_subcommand_from init import export removekey trust tell removeperson add remove list hide reveal cat unhide changes show-repo-id whoami verify-keyring list-keys trust-permissions error-codes clean completions manpages help" -f -a "list-keys" -d 'List keyring keys after verifying the keyring signature'
complete -c git-veil -n "__fish_git_veil_using_subcommand help; and not __fish_seen_subcommand_from init import export removekey trust tell removeperson add remove list hide reveal cat unhide changes show-repo-id whoami verify-keyring list-keys trust-permissions error-codes clean completions manpages help" -f -a "trust-permissions" -d 'Acknowledge the key store\'s current permissions as trusted'
complete -c git-veil -n "__fish_git_veil_using_subcommand help; and not __fish_seen_subcommand_from init import export removekey trust tell removeperson add remove list hide reveal cat unhide changes show-repo-id whoami verify-keyring list-keys trust-permissions error-codes clean completions manpages help" -f -a "error-codes" -d 'List every documented exit code with its name and meaning'
complete -c git-veil -n "__fish_git_veil_using_subcommand help; and not __fish_seen_subcommand_from init import export removekey trust tell removeperson add remove list hide reveal cat unhide changes show-repo-id whoami verify-keyring list-keys trust-permissions error-codes clean completions manpages help" -f -a "clean" -d 'Remove the .git-veil state directory (--yes required when data would be lost)'
complete -c git-veil -n "__fish_git_veil_using_subcommand help; and not __fish_seen_subcommand_from init import export removekey trust tell removeperson add remove list hide reveal cat unhide changes show-repo-id whoami verify-keyring list-keys trust-permissions error-codes clean completions manpages help" -f -a "completions" -d 'Emit a shell completion script for the given shell to stdout'
complete -c git-veil -n "__fish_git_veil_using_subcommand help; and not __fish_seen_subcommand_from init import export removekey trust tell removeperson add remove list hide reveal cat unhide changes show-repo-id whoami verify-keyring list-keys trust-permissions error-codes clean completions manpages help" -f -a "manpages" -d 'Write roff man pages (git-veil.1 plus one per subcommand) to a directory'
complete -c git-veil -n "__fish_git_veil_using_subcommand help; and not __fish_seen_subcommand_from init import export removekey trust tell removeperson add remove list hide reveal cat unhide changes show-repo-id whoami verify-keyring list-keys trust-permissions error-codes clean completions manpages help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
