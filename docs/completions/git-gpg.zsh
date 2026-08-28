#compdef git-gpg

autoload -U is-at-least

_git-gpg() {
    typeset -A opt_args
    typeset -a _arguments_options
    local ret=1

    if is-at-least 5.2; then
        _arguments_options=(-s -S -C)
    else
        _arguments_options=(-s -C)
    fi

    local context curcontext="$curcontext" state line
    _arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
'--help[Print help]' \
'-V[Print version]' \
'--version[Print version]' \
":: :_git-gpg_commands" \
"*::: :->git-gpg" \
&& ret=0
    case $state in
    (git-gpg)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:git-gpg-command-$line[1]:"
        case $line[1] in
            (init)
_arguments "${_arguments_options[@]}" : \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(import)
_arguments "${_arguments_options[@]}" : \
'--gpg-home=[Key store directory (default\: \$HOME/.git-gpg)]:GPG_HOME:_files' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
'*::files -- File(s) containing armoured private key blocks:_default' \
&& ret=0
;;
(export)
_arguments "${_arguments_options[@]}" : \
'--output=[Write the armoured public key to this file instead of stdout]:OUTPUT:_files' \
'--gpg-home=[Key store directory (default\: \$HOME/.git-gpg)]:GPG_HOME:_files' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':identifier -- Email or fingerprint of the key to export:_default' \
&& ret=0
;;
(removekey)
_arguments "${_arguments_options[@]}" : \
'--gpg-home=[Key store directory (default\: \$HOME/.git-gpg)]:GPG_HOME:_files' \
'--yes[Confirm destructive removals\: required when the target is the only private key in the store, and to remove ALL keys when the email matches several]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':identifier -- Fingerprint or exact case-insensitive email of the key(s) to remove:_default' \
&& ret=0
;;
(trust)
_arguments "${_arguments_options[@]}" : \
'--remote=[Git remote name]:REMOTE:_default' \
'--gpg-home=[Key store directory (default\: \$HOME/.git-gpg)]:GPG_HOME:_files' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':repo_id -- Repository ID (e.g., fara+simbo1905@github.com):_default' \
':signing_key -- Path to owner'\''s public key file:_default' \
&& ret=0
;;
(tell)
_arguments "${_arguments_options[@]}" : \
'--remote=[Git remote name]:REMOTE:_default' \
'--gpg-home=[Key store directory (default\: \$HOME/.git-gpg)]:GPG_HOME:_files' \
'--passphrase-stdin[Read the passphrase for a passphrase-protected private key from stdin (exactly one line). Wins over the GITGPG_PASSPHRASE environment variable; never pass a passphrase as a CLI argument]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':email -- Collaborator'\''s email:_default' \
':public_key -- Path to collaborator'\''s public key file:_default' \
&& ret=0
;;
(removeperson)
_arguments "${_arguments_options[@]}" : \
'--remote=[Git remote name]:REMOTE:_default' \
'--gpg-home=[Key store directory (default\: \$HOME/.git-gpg)]:GPG_HOME:_files' \
'--passphrase-stdin[Read the passphrase for a passphrase-protected private key from stdin (exactly one line). Wins over the GITGPG_PASSPHRASE environment variable; never pass a passphrase as a CLI argument]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':email -- Email of the collaborator to remove:_default' \
&& ret=0
;;
(add)
_arguments "${_arguments_options[@]}" : \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
'*::files -- File(s) to add:_default' \
&& ret=0
;;
(remove)
_arguments "${_arguments_options[@]}" : \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
'*::files -- File(s) to remove:_default' \
&& ret=0
;;
(list)
_arguments "${_arguments_options[@]}" : \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(hide)
_arguments "${_arguments_options[@]}" : \
'--remote=[Git remote name]:REMOTE:_default' \
'--gpg-home=[Key store directory (default\: \$HOME/.git-gpg)]:GPG_HOME:_files' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(reveal)
_arguments "${_arguments_options[@]}" : \
'--email=[Your email address]:EMAIL:_default' \
'--remote=[Git remote name]:REMOTE:_default' \
'--gpg-home=[Key store directory (default\: \$HOME/.git-gpg)]:GPG_HOME:_files' \
'--passphrase-stdin[Read the passphrase for a passphrase-protected private key from stdin (exactly one line). Wins over the GITGPG_PASSPHRASE environment variable; never pass a passphrase as a CLI argument]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(cat)
_arguments "${_arguments_options[@]}" : \
'--email=[Your email address]:EMAIL:_default' \
'--remote=[Git remote name]:REMOTE:_default' \
'--gpg-home=[Key store directory (default\: \$HOME/.git-gpg)]:GPG_HOME:_files' \
'--passphrase-stdin[Read the passphrase for a passphrase-protected private key from stdin (exactly one line). Wins over the GITGPG_PASSPHRASE environment variable; never pass a passphrase as a CLI argument]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':file -- File to decrypt:_default' \
&& ret=0
;;
(unhide)
_arguments "${_arguments_options[@]}" : \
'--email=[Your email address]:EMAIL:_default' \
'--remote=[Git remote name]:REMOTE:_default' \
'--gpg-home=[Key store directory (default\: \$HOME/.git-gpg)]:GPG_HOME:_files' \
'--passphrase-stdin[Read the passphrase for a passphrase-protected private key from stdin (exactly one line). Wins over the GITGPG_PASSPHRASE environment variable; never pass a passphrase as a CLI argument]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':file -- File to unhide:_default' \
&& ret=0
;;
(changes)
_arguments "${_arguments_options[@]}" : \
'--email=[Your email address]:EMAIL:_default' \
'--remote=[Git remote name]:REMOTE:_default' \
'--gpg-home=[Key store directory (default\: \$HOME/.git-gpg)]:GPG_HOME:_files' \
'--passphrase-stdin[Read the passphrase for a passphrase-protected private key from stdin (exactly one line). Wins over the GITGPG_PASSPHRASE environment variable; never pass a passphrase as a CLI argument]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
'*::files -- File(s) to check (default\: all tracked files):_default' \
&& ret=0
;;
(show-repo-id)
_arguments "${_arguments_options[@]}" : \
'--remote=[Git remote name]:REMOTE:_default' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(whoami)
_arguments "${_arguments_options[@]}" : \
'--email=[Email override]:EMAIL:_default' \
'--gpg-home=[Key store directory (default\: \$HOME/.git-gpg)]:GPG_HOME:_files' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(verify-keyring)
_arguments "${_arguments_options[@]}" : \
'--remote=[Git remote name]:REMOTE:_default' \
'--gpg-home=[Key store directory (default\: \$HOME/.git-gpg)]:GPG_HOME:_files' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(list-keys)
_arguments "${_arguments_options[@]}" : \
'--remote=[Git remote name]:REMOTE:_default' \
'--gpg-home=[Key store directory (default\: \$HOME/.git-gpg)]:GPG_HOME:_files' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(clean)
_arguments "${_arguments_options[@]}" : \
'--yes[Confirm destruction of tracked state and any ciphertext. Required when the clean would destroy tracked files or their in-place \`<name>.secret\` ciphertext (which may be the only remaining copy)]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(completions)
_arguments "${_arguments_options[@]}" : \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':shell -- Shell to generate completions for:(bash elvish fish powershell zsh)' \
&& ret=0
;;
(manpages)
_arguments "${_arguments_options[@]}" : \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
'::output_dir -- Directory to write the .1 files into (default\: ./man):_files' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_git-gpg__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:git-gpg-help-command-$line[1]:"
        case $line[1] in
            (init)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(import)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(export)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(removekey)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(trust)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(tell)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(removeperson)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(add)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(remove)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(list)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(hide)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(reveal)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(cat)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(unhide)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(changes)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(show-repo-id)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(whoami)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(verify-keyring)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(list-keys)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(clean)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(completions)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(manpages)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
}

(( $+functions[_git-gpg_commands] )) ||
_git-gpg_commands() {
    local commands; commands=(
'init:Initialize git-gpg state (.git-gpg/) in the current repository' \
'import:Import your private key(s) into the git-gpg key store' \
'export:Export an armoured public key from the local key store' \
'removekey:Remove a key from the local key store (destructive, local-only)' \
'trust:Verify and pin the repository owner'\''s signing key (per machine)' \
'tell:Add a collaborator'\''s public key to the keyring and re-sign it' \
'removeperson:Remove a collaborator from the keyring and re-sign it' \
'add:Track files for encryption' \
'remove:Untrack files (leaves any ciphertext in place)' \
'list:List all tracked files' \
'hide:Encrypt all tracked files to the keyring and delete the plaintexts' \
'reveal:Decrypt all tracked files back to plaintext' \
'cat:Decrypt a single tracked file to stdout' \
'unhide:Decrypt one tracked file back to plaintext and delete its ciphertext' \
'changes:Report where plaintext differs from the last hidden version' \
'show-repo-id:Show the repository ID derived from the git remote push URL' \
'whoami:Show the identity and key store git-gpg will use' \
'verify-keyring:Verify the keyring signature against the pinned trusted key' \
'list-keys:List keyring keys after verifying the keyring signature' \
'clean:Remove the .git-gpg state directory (--yes required when data would be lost)' \
'completions:Emit a shell completion script for the given shell to stdout' \
'manpages:Write roff man pages (git-gpg.1 plus one per subcommand) to a directory' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'git-gpg commands' commands "$@"
}
(( $+functions[_git-gpg__subcmd__add_commands] )) ||
_git-gpg__subcmd__add_commands() {
    local commands; commands=()
    _describe -t commands 'git-gpg add commands' commands "$@"
}
(( $+functions[_git-gpg__subcmd__cat_commands] )) ||
_git-gpg__subcmd__cat_commands() {
    local commands; commands=()
    _describe -t commands 'git-gpg cat commands' commands "$@"
}
(( $+functions[_git-gpg__subcmd__changes_commands] )) ||
_git-gpg__subcmd__changes_commands() {
    local commands; commands=()
    _describe -t commands 'git-gpg changes commands' commands "$@"
}
(( $+functions[_git-gpg__subcmd__clean_commands] )) ||
_git-gpg__subcmd__clean_commands() {
    local commands; commands=()
    _describe -t commands 'git-gpg clean commands' commands "$@"
}
(( $+functions[_git-gpg__subcmd__completions_commands] )) ||
_git-gpg__subcmd__completions_commands() {
    local commands; commands=()
    _describe -t commands 'git-gpg completions commands' commands "$@"
}
(( $+functions[_git-gpg__subcmd__export_commands] )) ||
_git-gpg__subcmd__export_commands() {
    local commands; commands=()
    _describe -t commands 'git-gpg export commands' commands "$@"
}
(( $+functions[_git-gpg__subcmd__help_commands] )) ||
_git-gpg__subcmd__help_commands() {
    local commands; commands=(
'init:Initialize git-gpg state (.git-gpg/) in the current repository' \
'import:Import your private key(s) into the git-gpg key store' \
'export:Export an armoured public key from the local key store' \
'removekey:Remove a key from the local key store (destructive, local-only)' \
'trust:Verify and pin the repository owner'\''s signing key (per machine)' \
'tell:Add a collaborator'\''s public key to the keyring and re-sign it' \
'removeperson:Remove a collaborator from the keyring and re-sign it' \
'add:Track files for encryption' \
'remove:Untrack files (leaves any ciphertext in place)' \
'list:List all tracked files' \
'hide:Encrypt all tracked files to the keyring and delete the plaintexts' \
'reveal:Decrypt all tracked files back to plaintext' \
'cat:Decrypt a single tracked file to stdout' \
'unhide:Decrypt one tracked file back to plaintext and delete its ciphertext' \
'changes:Report where plaintext differs from the last hidden version' \
'show-repo-id:Show the repository ID derived from the git remote push URL' \
'whoami:Show the identity and key store git-gpg will use' \
'verify-keyring:Verify the keyring signature against the pinned trusted key' \
'list-keys:List keyring keys after verifying the keyring signature' \
'clean:Remove the .git-gpg state directory (--yes required when data would be lost)' \
'completions:Emit a shell completion script for the given shell to stdout' \
'manpages:Write roff man pages (git-gpg.1 plus one per subcommand) to a directory' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'git-gpg help commands' commands "$@"
}
(( $+functions[_git-gpg__subcmd__help__subcmd__add_commands] )) ||
_git-gpg__subcmd__help__subcmd__add_commands() {
    local commands; commands=()
    _describe -t commands 'git-gpg help add commands' commands "$@"
}
(( $+functions[_git-gpg__subcmd__help__subcmd__cat_commands] )) ||
_git-gpg__subcmd__help__subcmd__cat_commands() {
    local commands; commands=()
    _describe -t commands 'git-gpg help cat commands' commands "$@"
}
(( $+functions[_git-gpg__subcmd__help__subcmd__changes_commands] )) ||
_git-gpg__subcmd__help__subcmd__changes_commands() {
    local commands; commands=()
    _describe -t commands 'git-gpg help changes commands' commands "$@"
}
(( $+functions[_git-gpg__subcmd__help__subcmd__clean_commands] )) ||
_git-gpg__subcmd__help__subcmd__clean_commands() {
    local commands; commands=()
    _describe -t commands 'git-gpg help clean commands' commands "$@"
}
(( $+functions[_git-gpg__subcmd__help__subcmd__completions_commands] )) ||
_git-gpg__subcmd__help__subcmd__completions_commands() {
    local commands; commands=()
    _describe -t commands 'git-gpg help completions commands' commands "$@"
}
(( $+functions[_git-gpg__subcmd__help__subcmd__export_commands] )) ||
_git-gpg__subcmd__help__subcmd__export_commands() {
    local commands; commands=()
    _describe -t commands 'git-gpg help export commands' commands "$@"
}
(( $+functions[_git-gpg__subcmd__help__subcmd__help_commands] )) ||
_git-gpg__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'git-gpg help help commands' commands "$@"
}
(( $+functions[_git-gpg__subcmd__help__subcmd__hide_commands] )) ||
_git-gpg__subcmd__help__subcmd__hide_commands() {
    local commands; commands=()
    _describe -t commands 'git-gpg help hide commands' commands "$@"
}
(( $+functions[_git-gpg__subcmd__help__subcmd__import_commands] )) ||
_git-gpg__subcmd__help__subcmd__import_commands() {
    local commands; commands=()
    _describe -t commands 'git-gpg help import commands' commands "$@"
}
(( $+functions[_git-gpg__subcmd__help__subcmd__init_commands] )) ||
_git-gpg__subcmd__help__subcmd__init_commands() {
    local commands; commands=()
    _describe -t commands 'git-gpg help init commands' commands "$@"
}
(( $+functions[_git-gpg__subcmd__help__subcmd__list_commands] )) ||
_git-gpg__subcmd__help__subcmd__list_commands() {
    local commands; commands=()
    _describe -t commands 'git-gpg help list commands' commands "$@"
}
(( $+functions[_git-gpg__subcmd__help__subcmd__list-keys_commands] )) ||
_git-gpg__subcmd__help__subcmd__list-keys_commands() {
    local commands; commands=()
    _describe -t commands 'git-gpg help list-keys commands' commands "$@"
}
(( $+functions[_git-gpg__subcmd__help__subcmd__manpages_commands] )) ||
_git-gpg__subcmd__help__subcmd__manpages_commands() {
    local commands; commands=()
    _describe -t commands 'git-gpg help manpages commands' commands "$@"
}
(( $+functions[_git-gpg__subcmd__help__subcmd__remove_commands] )) ||
_git-gpg__subcmd__help__subcmd__remove_commands() {
    local commands; commands=()
    _describe -t commands 'git-gpg help remove commands' commands "$@"
}
(( $+functions[_git-gpg__subcmd__help__subcmd__removekey_commands] )) ||
_git-gpg__subcmd__help__subcmd__removekey_commands() {
    local commands; commands=()
    _describe -t commands 'git-gpg help removekey commands' commands "$@"
}
(( $+functions[_git-gpg__subcmd__help__subcmd__removeperson_commands] )) ||
_git-gpg__subcmd__help__subcmd__removeperson_commands() {
    local commands; commands=()
    _describe -t commands 'git-gpg help removeperson commands' commands "$@"
}
(( $+functions[_git-gpg__subcmd__help__subcmd__reveal_commands] )) ||
_git-gpg__subcmd__help__subcmd__reveal_commands() {
    local commands; commands=()
    _describe -t commands 'git-gpg help reveal commands' commands "$@"
}
(( $+functions[_git-gpg__subcmd__help__subcmd__show-repo-id_commands] )) ||
_git-gpg__subcmd__help__subcmd__show-repo-id_commands() {
    local commands; commands=()
    _describe -t commands 'git-gpg help show-repo-id commands' commands "$@"
}
(( $+functions[_git-gpg__subcmd__help__subcmd__tell_commands] )) ||
_git-gpg__subcmd__help__subcmd__tell_commands() {
    local commands; commands=()
    _describe -t commands 'git-gpg help tell commands' commands "$@"
}
(( $+functions[_git-gpg__subcmd__help__subcmd__trust_commands] )) ||
_git-gpg__subcmd__help__subcmd__trust_commands() {
    local commands; commands=()
    _describe -t commands 'git-gpg help trust commands' commands "$@"
}
(( $+functions[_git-gpg__subcmd__help__subcmd__unhide_commands] )) ||
_git-gpg__subcmd__help__subcmd__unhide_commands() {
    local commands; commands=()
    _describe -t commands 'git-gpg help unhide commands' commands "$@"
}
(( $+functions[_git-gpg__subcmd__help__subcmd__verify-keyring_commands] )) ||
_git-gpg__subcmd__help__subcmd__verify-keyring_commands() {
    local commands; commands=()
    _describe -t commands 'git-gpg help verify-keyring commands' commands "$@"
}
(( $+functions[_git-gpg__subcmd__help__subcmd__whoami_commands] )) ||
_git-gpg__subcmd__help__subcmd__whoami_commands() {
    local commands; commands=()
    _describe -t commands 'git-gpg help whoami commands' commands "$@"
}
(( $+functions[_git-gpg__subcmd__hide_commands] )) ||
_git-gpg__subcmd__hide_commands() {
    local commands; commands=()
    _describe -t commands 'git-gpg hide commands' commands "$@"
}
(( $+functions[_git-gpg__subcmd__import_commands] )) ||
_git-gpg__subcmd__import_commands() {
    local commands; commands=()
    _describe -t commands 'git-gpg import commands' commands "$@"
}
(( $+functions[_git-gpg__subcmd__init_commands] )) ||
_git-gpg__subcmd__init_commands() {
    local commands; commands=()
    _describe -t commands 'git-gpg init commands' commands "$@"
}
(( $+functions[_git-gpg__subcmd__list_commands] )) ||
_git-gpg__subcmd__list_commands() {
    local commands; commands=()
    _describe -t commands 'git-gpg list commands' commands "$@"
}
(( $+functions[_git-gpg__subcmd__list-keys_commands] )) ||
_git-gpg__subcmd__list-keys_commands() {
    local commands; commands=()
    _describe -t commands 'git-gpg list-keys commands' commands "$@"
}
(( $+functions[_git-gpg__subcmd__manpages_commands] )) ||
_git-gpg__subcmd__manpages_commands() {
    local commands; commands=()
    _describe -t commands 'git-gpg manpages commands' commands "$@"
}
(( $+functions[_git-gpg__subcmd__remove_commands] )) ||
_git-gpg__subcmd__remove_commands() {
    local commands; commands=()
    _describe -t commands 'git-gpg remove commands' commands "$@"
}
(( $+functions[_git-gpg__subcmd__removekey_commands] )) ||
_git-gpg__subcmd__removekey_commands() {
    local commands; commands=()
    _describe -t commands 'git-gpg removekey commands' commands "$@"
}
(( $+functions[_git-gpg__subcmd__removeperson_commands] )) ||
_git-gpg__subcmd__removeperson_commands() {
    local commands; commands=()
    _describe -t commands 'git-gpg removeperson commands' commands "$@"
}
(( $+functions[_git-gpg__subcmd__reveal_commands] )) ||
_git-gpg__subcmd__reveal_commands() {
    local commands; commands=()
    _describe -t commands 'git-gpg reveal commands' commands "$@"
}
(( $+functions[_git-gpg__subcmd__show-repo-id_commands] )) ||
_git-gpg__subcmd__show-repo-id_commands() {
    local commands; commands=()
    _describe -t commands 'git-gpg show-repo-id commands' commands "$@"
}
(( $+functions[_git-gpg__subcmd__tell_commands] )) ||
_git-gpg__subcmd__tell_commands() {
    local commands; commands=()
    _describe -t commands 'git-gpg tell commands' commands "$@"
}
(( $+functions[_git-gpg__subcmd__trust_commands] )) ||
_git-gpg__subcmd__trust_commands() {
    local commands; commands=()
    _describe -t commands 'git-gpg trust commands' commands "$@"
}
(( $+functions[_git-gpg__subcmd__unhide_commands] )) ||
_git-gpg__subcmd__unhide_commands() {
    local commands; commands=()
    _describe -t commands 'git-gpg unhide commands' commands "$@"
}
(( $+functions[_git-gpg__subcmd__verify-keyring_commands] )) ||
_git-gpg__subcmd__verify-keyring_commands() {
    local commands; commands=()
    _describe -t commands 'git-gpg verify-keyring commands' commands "$@"
}
(( $+functions[_git-gpg__subcmd__whoami_commands] )) ||
_git-gpg__subcmd__whoami_commands() {
    local commands; commands=()
    _describe -t commands 'git-gpg whoami commands' commands "$@"
}

if [ "$funcstack[1]" = "_git-gpg" ]; then
    _git-gpg "$@"
else
    compdef _git-gpg git-gpg
fi
