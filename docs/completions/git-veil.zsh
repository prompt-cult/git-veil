#compdef git-veil

autoload -U is-at-least

_git-veil() {
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
'--dangerously-skip-permissions-check[Bypass the key store permission checks (also\: GIT_VEIL_SKIP_PERMISSIONS=1)]' \
'-h[Print help]' \
'--help[Print help]' \
'-V[Print version]' \
'--version[Print version]' \
":: :_git-veil_commands" \
"*::: :->git-veil" \
&& ret=0
    case $state in
    (git-veil)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:git-veil-command-$line[1]:"
        case $line[1] in
            (init)
_arguments "${_arguments_options[@]}" : \
'--dangerously-skip-permissions-check[Bypass the key store permission checks (also\: GIT_VEIL_SKIP_PERMISSIONS=1)]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(import)
_arguments "${_arguments_options[@]}" : \
'--key-store=[Key store directory (default\: \$GIT_VEIL_HOME or \$HOME/.git-veil)]:KEY_STORE:_files' \
'--dangerously-skip-permissions-check[Bypass the key store permission checks (also\: GIT_VEIL_SKIP_PERMISSIONS=1)]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
'*::files -- File(s) containing AGE-SECRET-KEY-1... lines (age-keygen output works as-is):_default' \
&& ret=0
;;
(export)
_arguments "${_arguments_options[@]}" : \
'--output=[Write the recipient string to this file instead of stdout]:OUTPUT:_files' \
'--key-store=[Key store directory (default\: \$GIT_VEIL_HOME or \$HOME/.git-veil)]:KEY_STORE:_files' \
'--dangerously-skip-permissions-check[Bypass the key store permission checks (also\: GIT_VEIL_SKIP_PERMISSIONS=1)]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':identifier -- Recipient string (age1...) or fingerprint of the key to export:_default' \
&& ret=0
;;
(removekey)
_arguments "${_arguments_options[@]}" : \
'--key-store=[Key store directory (default\: \$GIT_VEIL_HOME or \$HOME/.git-veil)]:KEY_STORE:_files' \
'--yes[Confirm destructive removals\: required when the target is the only private key in the store, and to remove ALL keys when the email matches several]' \
'--dangerously-skip-permissions-check[Bypass the key store permission checks (also\: GIT_VEIL_SKIP_PERMISSIONS=1)]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':identifier -- Fingerprint or exact recipient string of the identity to remove:_default' \
&& ret=0
;;
(trust)
_arguments "${_arguments_options[@]}" : \
'--remote=[Git remote name]:REMOTE:_default' \
'--key-store=[Key store directory (default\: \$GIT_VEIL_HOME or \$HOME/.git-veil). The store and its pins are the trust boundary for every repository that uses it]:KEY_STORE:_files' \
'--dangerously-skip-permissions-check[Bypass the key store permission checks (also\: GIT_VEIL_SKIP_PERMISSIONS=1)]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':repo_id -- Repository ID (e.g., fara+simbo1905@github.com):_default' \
':verifying_key -- Path to the owner'\''s Ed25519 verifying key file (64 hex chars):_default' \
&& ret=0
;;
(tell)
_arguments "${_arguments_options[@]}" : \
'--remote=[Git remote name]:REMOTE:_default' \
'--signing-key=[Which signing key to use\: 1-based index into signing-keys.txt, or a 64-hex-character seed (default\: the key matching the pinned fingerprint)]:SELECTION:_default' \
'--key-store=[Key store directory (default\: \$GIT_VEIL_HOME or \$HOME/.git-veil)]:KEY_STORE:_files' \
'--dangerously-skip-permissions-check[Bypass the key store permission checks (also\: GIT_VEIL_SKIP_PERMISSIONS=1)]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':email -- Collaborator'\''s email:_default' \
':public_key -- Path to file containing the collaborator'\''s age recipient string (age1...):_default' \
&& ret=0
;;
(removeperson)
_arguments "${_arguments_options[@]}" : \
'--remote=[Git remote name]:REMOTE:_default' \
'--signing-key=[Which signing key to use\: 1-based index into signing-keys.txt, or a 64-hex-character seed (default\: the key matching the pinned fingerprint)]:SELECTION:_default' \
'--key-store=[Key store directory (default\: \$GIT_VEIL_HOME or \$HOME/.git-veil)]:KEY_STORE:_files' \
'--dangerously-skip-permissions-check[Bypass the key store permission checks (also\: GIT_VEIL_SKIP_PERMISSIONS=1)]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':email -- Email of the collaborator to remove:_default' \
&& ret=0
;;
(add)
_arguments "${_arguments_options[@]}" : \
'--dangerously-skip-permissions-check[Bypass the key store permission checks (also\: GIT_VEIL_SKIP_PERMISSIONS=1)]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
'*::files -- File(s) to add:_default' \
&& ret=0
;;
(remove)
_arguments "${_arguments_options[@]}" : \
'--dangerously-skip-permissions-check[Bypass the key store permission checks (also\: GIT_VEIL_SKIP_PERMISSIONS=1)]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
'*::files -- File(s) to remove:_default' \
&& ret=0
;;
(list)
_arguments "${_arguments_options[@]}" : \
'--dangerously-skip-permissions-check[Bypass the key store permission checks (also\: GIT_VEIL_SKIP_PERMISSIONS=1)]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(hide)
_arguments "${_arguments_options[@]}" : \
'--remote=[Git remote name]:REMOTE:_default' \
'--key-store=[Key store directory (default\: \$GIT_VEIL_HOME or \$HOME/.git-veil)]:KEY_STORE:_files' \
'--dangerously-delete-plaintext[Delete plaintext files after successful encryption]' \
'--dangerously-skip-permissions-check[Bypass the key store permission checks (also\: GIT_VEIL_SKIP_PERMISSIONS=1)]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(reveal)
_arguments "${_arguments_options[@]}" : \
'--email=[Your email address]:EMAIL:_default' \
'--remote=[Git remote name]:REMOTE:_default' \
'--key-store=[Key store directory (default\: \$GIT_VEIL_HOME or \$HOME/.git-veil)]:KEY_STORE:_files' \
'--dangerously-skip-permissions-check[Bypass the key store permission checks (also\: GIT_VEIL_SKIP_PERMISSIONS=1)]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(cat)
_arguments "${_arguments_options[@]}" : \
'--email=[Your email address]:EMAIL:_default' \
'--remote=[Git remote name]:REMOTE:_default' \
'--key-store=[Key store directory (default\: \$GIT_VEIL_HOME or \$HOME/.git-veil)]:KEY_STORE:_files' \
'--dangerously-skip-permissions-check[Bypass the key store permission checks (also\: GIT_VEIL_SKIP_PERMISSIONS=1)]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':file -- File to decrypt:_default' \
&& ret=0
;;
(unhide)
_arguments "${_arguments_options[@]}" : \
'--email=[Your email address]:EMAIL:_default' \
'--remote=[Git remote name]:REMOTE:_default' \
'--key-store=[Key store directory (default\: \$GIT_VEIL_HOME or \$HOME/.git-veil)]:KEY_STORE:_files' \
'--dangerously-skip-permissions-check[Bypass the key store permission checks (also\: GIT_VEIL_SKIP_PERMISSIONS=1)]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':file -- File to unhide:_default' \
&& ret=0
;;
(changes)
_arguments "${_arguments_options[@]}" : \
'--email=[Your email address]:EMAIL:_default' \
'--remote=[Git remote name]:REMOTE:_default' \
'--key-store=[Key store directory (default\: \$GIT_VEIL_HOME or \$HOME/.git-veil)]:KEY_STORE:_files' \
'--dangerously-skip-permissions-check[Bypass the key store permission checks (also\: GIT_VEIL_SKIP_PERMISSIONS=1)]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
'*::files -- File(s) to check (default\: all tracked files):_default' \
&& ret=0
;;
(show-repo-id)
_arguments "${_arguments_options[@]}" : \
'--remote=[Git remote name]:REMOTE:_default' \
'--dangerously-skip-permissions-check[Bypass the key store permission checks (also\: GIT_VEIL_SKIP_PERMISSIONS=1)]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(whoami)
_arguments "${_arguments_options[@]}" : \
'--email=[Email override]:EMAIL:_default' \
'--key-store=[Key store directory (default\: \$GIT_VEIL_HOME or \$HOME/.git-veil)]:KEY_STORE:_files' \
'--dangerously-skip-permissions-check[Bypass the key store permission checks (also\: GIT_VEIL_SKIP_PERMISSIONS=1)]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(verify-keyring)
_arguments "${_arguments_options[@]}" : \
'--remote=[Git remote name]:REMOTE:_default' \
'--key-store=[Key store directory (default\: \$GIT_VEIL_HOME or \$HOME/.git-veil)]:KEY_STORE:_files' \
'--dangerously-skip-permissions-check[Bypass the key store permission checks (also\: GIT_VEIL_SKIP_PERMISSIONS=1)]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(list-keys)
_arguments "${_arguments_options[@]}" : \
'--remote=[Git remote name]:REMOTE:_default' \
'--key-store=[Key store directory (default\: \$GIT_VEIL_HOME or \$HOME/.git-veil)]:KEY_STORE:_files' \
'--dangerously-skip-permissions-check[Bypass the key store permission checks (also\: GIT_VEIL_SKIP_PERMISSIONS=1)]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(trust-permissions)
_arguments "${_arguments_options[@]}" : \
'--key-store=[Key store directory (default\: \$GIT_VEIL_HOME or \$HOME/.git-veil)]:KEY_STORE:_files' \
'--dangerously-skip-permissions-check[Bypass the key store permission checks (also\: GIT_VEIL_SKIP_PERMISSIONS=1)]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(error-codes)
_arguments "${_arguments_options[@]}" : \
'--dangerously-skip-permissions-check[Bypass the key store permission checks (also\: GIT_VEIL_SKIP_PERMISSIONS=1)]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(clean)
_arguments "${_arguments_options[@]}" : \
'--yes[Confirm destruction of tracked state and any ciphertext. Required when the clean would destroy tracked files or their in-place \`<name>.secret\` ciphertext (which may be the only remaining copy)]' \
'--dangerously-skip-permissions-check[Bypass the key store permission checks (also\: GIT_VEIL_SKIP_PERMISSIONS=1)]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(completions)
_arguments "${_arguments_options[@]}" : \
'--dangerously-skip-permissions-check[Bypass the key store permission checks (also\: GIT_VEIL_SKIP_PERMISSIONS=1)]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':shell -- Shell to generate completions for:(bash elvish fish powershell zsh)' \
&& ret=0
;;
(manpages)
_arguments "${_arguments_options[@]}" : \
'--dangerously-skip-permissions-check[Bypass the key store permission checks (also\: GIT_VEIL_SKIP_PERMISSIONS=1)]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
'::output_dir -- Directory to write the .1 files into (default\: ./man):_files' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_git-veil__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:git-veil-help-command-$line[1]:"
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
(trust-permissions)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(error-codes)
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

(( $+functions[_git-veil_commands] )) ||
_git-veil_commands() {
    local commands; commands=(
'init:Initialize git-veil state (.git-veil/) in the current repository' \
'import:Import your age identity (private key) into the git-veil key store' \
'export:Export a public key (recipient string) from the local key store' \
'removekey:Remove an age identity from the local key store (destructive, local-only)' \
'trust:Verify and pin the repository owner'\''s Ed25519 verifying key (per machine)' \
'tell:Add a collaborator'\''s age recipient key to the keyring and re-sign it' \
'removeperson:Remove a collaborator from the keyring and re-sign it' \
'add:Track files for encryption' \
'remove:Untrack files (leaves any ciphertext in place)' \
'list:List all tracked files' \
'hide:Encrypt all tracked files to the keyring' \
'reveal:Decrypt all tracked files back to plaintext' \
'cat:Decrypt a single tracked file to stdout' \
'unhide:Decrypt one tracked file back to plaintext' \
'changes:Report where plaintext differs from the last hidden version' \
'show-repo-id:Show the repository ID derived from the git remote push URL' \
'whoami:Show the identity and key store git-veil will use' \
'verify-keyring:Verify the keyring signature against the pinned trusted key' \
'list-keys:List keyring keys after verifying the keyring signature' \
'trust-permissions:Acknowledge the key store'\''s current permissions as trusted' \
'error-codes:List every documented exit code with its name and meaning' \
'clean:Remove the .git-veil state directory (--yes required when data would be lost)' \
'completions:Emit a shell completion script for the given shell to stdout' \
'manpages:Write roff man pages (git-veil.1 plus one per subcommand) to a directory' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'git-veil commands' commands "$@"
}
(( $+functions[_git-veil__subcmd__add_commands] )) ||
_git-veil__subcmd__add_commands() {
    local commands; commands=()
    _describe -t commands 'git-veil add commands' commands "$@"
}
(( $+functions[_git-veil__subcmd__cat_commands] )) ||
_git-veil__subcmd__cat_commands() {
    local commands; commands=()
    _describe -t commands 'git-veil cat commands' commands "$@"
}
(( $+functions[_git-veil__subcmd__changes_commands] )) ||
_git-veil__subcmd__changes_commands() {
    local commands; commands=()
    _describe -t commands 'git-veil changes commands' commands "$@"
}
(( $+functions[_git-veil__subcmd__clean_commands] )) ||
_git-veil__subcmd__clean_commands() {
    local commands; commands=()
    _describe -t commands 'git-veil clean commands' commands "$@"
}
(( $+functions[_git-veil__subcmd__completions_commands] )) ||
_git-veil__subcmd__completions_commands() {
    local commands; commands=()
    _describe -t commands 'git-veil completions commands' commands "$@"
}
(( $+functions[_git-veil__subcmd__error-codes_commands] )) ||
_git-veil__subcmd__error-codes_commands() {
    local commands; commands=()
    _describe -t commands 'git-veil error-codes commands' commands "$@"
}
(( $+functions[_git-veil__subcmd__export_commands] )) ||
_git-veil__subcmd__export_commands() {
    local commands; commands=()
    _describe -t commands 'git-veil export commands' commands "$@"
}
(( $+functions[_git-veil__subcmd__help_commands] )) ||
_git-veil__subcmd__help_commands() {
    local commands; commands=(
'init:Initialize git-veil state (.git-veil/) in the current repository' \
'import:Import your age identity (private key) into the git-veil key store' \
'export:Export a public key (recipient string) from the local key store' \
'removekey:Remove an age identity from the local key store (destructive, local-only)' \
'trust:Verify and pin the repository owner'\''s Ed25519 verifying key (per machine)' \
'tell:Add a collaborator'\''s age recipient key to the keyring and re-sign it' \
'removeperson:Remove a collaborator from the keyring and re-sign it' \
'add:Track files for encryption' \
'remove:Untrack files (leaves any ciphertext in place)' \
'list:List all tracked files' \
'hide:Encrypt all tracked files to the keyring' \
'reveal:Decrypt all tracked files back to plaintext' \
'cat:Decrypt a single tracked file to stdout' \
'unhide:Decrypt one tracked file back to plaintext' \
'changes:Report where plaintext differs from the last hidden version' \
'show-repo-id:Show the repository ID derived from the git remote push URL' \
'whoami:Show the identity and key store git-veil will use' \
'verify-keyring:Verify the keyring signature against the pinned trusted key' \
'list-keys:List keyring keys after verifying the keyring signature' \
'trust-permissions:Acknowledge the key store'\''s current permissions as trusted' \
'error-codes:List every documented exit code with its name and meaning' \
'clean:Remove the .git-veil state directory (--yes required when data would be lost)' \
'completions:Emit a shell completion script for the given shell to stdout' \
'manpages:Write roff man pages (git-veil.1 plus one per subcommand) to a directory' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'git-veil help commands' commands "$@"
}
(( $+functions[_git-veil__subcmd__help__subcmd__add_commands] )) ||
_git-veil__subcmd__help__subcmd__add_commands() {
    local commands; commands=()
    _describe -t commands 'git-veil help add commands' commands "$@"
}
(( $+functions[_git-veil__subcmd__help__subcmd__cat_commands] )) ||
_git-veil__subcmd__help__subcmd__cat_commands() {
    local commands; commands=()
    _describe -t commands 'git-veil help cat commands' commands "$@"
}
(( $+functions[_git-veil__subcmd__help__subcmd__changes_commands] )) ||
_git-veil__subcmd__help__subcmd__changes_commands() {
    local commands; commands=()
    _describe -t commands 'git-veil help changes commands' commands "$@"
}
(( $+functions[_git-veil__subcmd__help__subcmd__clean_commands] )) ||
_git-veil__subcmd__help__subcmd__clean_commands() {
    local commands; commands=()
    _describe -t commands 'git-veil help clean commands' commands "$@"
}
(( $+functions[_git-veil__subcmd__help__subcmd__completions_commands] )) ||
_git-veil__subcmd__help__subcmd__completions_commands() {
    local commands; commands=()
    _describe -t commands 'git-veil help completions commands' commands "$@"
}
(( $+functions[_git-veil__subcmd__help__subcmd__error-codes_commands] )) ||
_git-veil__subcmd__help__subcmd__error-codes_commands() {
    local commands; commands=()
    _describe -t commands 'git-veil help error-codes commands' commands "$@"
}
(( $+functions[_git-veil__subcmd__help__subcmd__export_commands] )) ||
_git-veil__subcmd__help__subcmd__export_commands() {
    local commands; commands=()
    _describe -t commands 'git-veil help export commands' commands "$@"
}
(( $+functions[_git-veil__subcmd__help__subcmd__help_commands] )) ||
_git-veil__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'git-veil help help commands' commands "$@"
}
(( $+functions[_git-veil__subcmd__help__subcmd__hide_commands] )) ||
_git-veil__subcmd__help__subcmd__hide_commands() {
    local commands; commands=()
    _describe -t commands 'git-veil help hide commands' commands "$@"
}
(( $+functions[_git-veil__subcmd__help__subcmd__import_commands] )) ||
_git-veil__subcmd__help__subcmd__import_commands() {
    local commands; commands=()
    _describe -t commands 'git-veil help import commands' commands "$@"
}
(( $+functions[_git-veil__subcmd__help__subcmd__init_commands] )) ||
_git-veil__subcmd__help__subcmd__init_commands() {
    local commands; commands=()
    _describe -t commands 'git-veil help init commands' commands "$@"
}
(( $+functions[_git-veil__subcmd__help__subcmd__list_commands] )) ||
_git-veil__subcmd__help__subcmd__list_commands() {
    local commands; commands=()
    _describe -t commands 'git-veil help list commands' commands "$@"
}
(( $+functions[_git-veil__subcmd__help__subcmd__list-keys_commands] )) ||
_git-veil__subcmd__help__subcmd__list-keys_commands() {
    local commands; commands=()
    _describe -t commands 'git-veil help list-keys commands' commands "$@"
}
(( $+functions[_git-veil__subcmd__help__subcmd__manpages_commands] )) ||
_git-veil__subcmd__help__subcmd__manpages_commands() {
    local commands; commands=()
    _describe -t commands 'git-veil help manpages commands' commands "$@"
}
(( $+functions[_git-veil__subcmd__help__subcmd__remove_commands] )) ||
_git-veil__subcmd__help__subcmd__remove_commands() {
    local commands; commands=()
    _describe -t commands 'git-veil help remove commands' commands "$@"
}
(( $+functions[_git-veil__subcmd__help__subcmd__removekey_commands] )) ||
_git-veil__subcmd__help__subcmd__removekey_commands() {
    local commands; commands=()
    _describe -t commands 'git-veil help removekey commands' commands "$@"
}
(( $+functions[_git-veil__subcmd__help__subcmd__removeperson_commands] )) ||
_git-veil__subcmd__help__subcmd__removeperson_commands() {
    local commands; commands=()
    _describe -t commands 'git-veil help removeperson commands' commands "$@"
}
(( $+functions[_git-veil__subcmd__help__subcmd__reveal_commands] )) ||
_git-veil__subcmd__help__subcmd__reveal_commands() {
    local commands; commands=()
    _describe -t commands 'git-veil help reveal commands' commands "$@"
}
(( $+functions[_git-veil__subcmd__help__subcmd__show-repo-id_commands] )) ||
_git-veil__subcmd__help__subcmd__show-repo-id_commands() {
    local commands; commands=()
    _describe -t commands 'git-veil help show-repo-id commands' commands "$@"
}
(( $+functions[_git-veil__subcmd__help__subcmd__tell_commands] )) ||
_git-veil__subcmd__help__subcmd__tell_commands() {
    local commands; commands=()
    _describe -t commands 'git-veil help tell commands' commands "$@"
}
(( $+functions[_git-veil__subcmd__help__subcmd__trust_commands] )) ||
_git-veil__subcmd__help__subcmd__trust_commands() {
    local commands; commands=()
    _describe -t commands 'git-veil help trust commands' commands "$@"
}
(( $+functions[_git-veil__subcmd__help__subcmd__trust-permissions_commands] )) ||
_git-veil__subcmd__help__subcmd__trust-permissions_commands() {
    local commands; commands=()
    _describe -t commands 'git-veil help trust-permissions commands' commands "$@"
}
(( $+functions[_git-veil__subcmd__help__subcmd__unhide_commands] )) ||
_git-veil__subcmd__help__subcmd__unhide_commands() {
    local commands; commands=()
    _describe -t commands 'git-veil help unhide commands' commands "$@"
}
(( $+functions[_git-veil__subcmd__help__subcmd__verify-keyring_commands] )) ||
_git-veil__subcmd__help__subcmd__verify-keyring_commands() {
    local commands; commands=()
    _describe -t commands 'git-veil help verify-keyring commands' commands "$@"
}
(( $+functions[_git-veil__subcmd__help__subcmd__whoami_commands] )) ||
_git-veil__subcmd__help__subcmd__whoami_commands() {
    local commands; commands=()
    _describe -t commands 'git-veil help whoami commands' commands "$@"
}
(( $+functions[_git-veil__subcmd__hide_commands] )) ||
_git-veil__subcmd__hide_commands() {
    local commands; commands=()
    _describe -t commands 'git-veil hide commands' commands "$@"
}
(( $+functions[_git-veil__subcmd__import_commands] )) ||
_git-veil__subcmd__import_commands() {
    local commands; commands=()
    _describe -t commands 'git-veil import commands' commands "$@"
}
(( $+functions[_git-veil__subcmd__init_commands] )) ||
_git-veil__subcmd__init_commands() {
    local commands; commands=()
    _describe -t commands 'git-veil init commands' commands "$@"
}
(( $+functions[_git-veil__subcmd__list_commands] )) ||
_git-veil__subcmd__list_commands() {
    local commands; commands=()
    _describe -t commands 'git-veil list commands' commands "$@"
}
(( $+functions[_git-veil__subcmd__list-keys_commands] )) ||
_git-veil__subcmd__list-keys_commands() {
    local commands; commands=()
    _describe -t commands 'git-veil list-keys commands' commands "$@"
}
(( $+functions[_git-veil__subcmd__manpages_commands] )) ||
_git-veil__subcmd__manpages_commands() {
    local commands; commands=()
    _describe -t commands 'git-veil manpages commands' commands "$@"
}
(( $+functions[_git-veil__subcmd__remove_commands] )) ||
_git-veil__subcmd__remove_commands() {
    local commands; commands=()
    _describe -t commands 'git-veil remove commands' commands "$@"
}
(( $+functions[_git-veil__subcmd__removekey_commands] )) ||
_git-veil__subcmd__removekey_commands() {
    local commands; commands=()
    _describe -t commands 'git-veil removekey commands' commands "$@"
}
(( $+functions[_git-veil__subcmd__removeperson_commands] )) ||
_git-veil__subcmd__removeperson_commands() {
    local commands; commands=()
    _describe -t commands 'git-veil removeperson commands' commands "$@"
}
(( $+functions[_git-veil__subcmd__reveal_commands] )) ||
_git-veil__subcmd__reveal_commands() {
    local commands; commands=()
    _describe -t commands 'git-veil reveal commands' commands "$@"
}
(( $+functions[_git-veil__subcmd__show-repo-id_commands] )) ||
_git-veil__subcmd__show-repo-id_commands() {
    local commands; commands=()
    _describe -t commands 'git-veil show-repo-id commands' commands "$@"
}
(( $+functions[_git-veil__subcmd__tell_commands] )) ||
_git-veil__subcmd__tell_commands() {
    local commands; commands=()
    _describe -t commands 'git-veil tell commands' commands "$@"
}
(( $+functions[_git-veil__subcmd__trust_commands] )) ||
_git-veil__subcmd__trust_commands() {
    local commands; commands=()
    _describe -t commands 'git-veil trust commands' commands "$@"
}
(( $+functions[_git-veil__subcmd__trust-permissions_commands] )) ||
_git-veil__subcmd__trust-permissions_commands() {
    local commands; commands=()
    _describe -t commands 'git-veil trust-permissions commands' commands "$@"
}
(( $+functions[_git-veil__subcmd__unhide_commands] )) ||
_git-veil__subcmd__unhide_commands() {
    local commands; commands=()
    _describe -t commands 'git-veil unhide commands' commands "$@"
}
(( $+functions[_git-veil__subcmd__verify-keyring_commands] )) ||
_git-veil__subcmd__verify-keyring_commands() {
    local commands; commands=()
    _describe -t commands 'git-veil verify-keyring commands' commands "$@"
}
(( $+functions[_git-veil__subcmd__whoami_commands] )) ||
_git-veil__subcmd__whoami_commands() {
    local commands; commands=()
    _describe -t commands 'git-veil whoami commands' commands "$@"
}

if [ "$funcstack[1]" = "_git-veil" ]; then
    _git-veil "$@"
else
    compdef _git-veil git-veil
fi
