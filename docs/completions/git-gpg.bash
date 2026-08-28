_git__gpg() {
    local i cur prev opts cmd
    COMPREPLY=()
    if [[ "${BASH_VERSINFO[0]}" -ge 4 ]]; then
        cur="$2"
    else
        cur="${COMP_WORDS[COMP_CWORD]}"
    fi
    prev="$3"
    cmd=""
    opts=""

    for i in "${COMP_WORDS[@]:0:COMP_CWORD}"
    do
        case "${cmd},${i}" in
            ",$1")
                cmd="git__gpg"
                ;;
            git__gpg,add)
                cmd="git__gpg__subcmd__add"
                ;;
            git__gpg,cat)
                cmd="git__gpg__subcmd__cat"
                ;;
            git__gpg,changes)
                cmd="git__gpg__subcmd__changes"
                ;;
            git__gpg,clean)
                cmd="git__gpg__subcmd__clean"
                ;;
            git__gpg,completions)
                cmd="git__gpg__subcmd__completions"
                ;;
            git__gpg,export)
                cmd="git__gpg__subcmd__export"
                ;;
            git__gpg,help)
                cmd="git__gpg__subcmd__help"
                ;;
            git__gpg,hide)
                cmd="git__gpg__subcmd__hide"
                ;;
            git__gpg,import)
                cmd="git__gpg__subcmd__import"
                ;;
            git__gpg,init)
                cmd="git__gpg__subcmd__init"
                ;;
            git__gpg,list)
                cmd="git__gpg__subcmd__list"
                ;;
            git__gpg,list-keys)
                cmd="git__gpg__subcmd__list__subcmd__keys"
                ;;
            git__gpg,manpages)
                cmd="git__gpg__subcmd__manpages"
                ;;
            git__gpg,remove)
                cmd="git__gpg__subcmd__remove"
                ;;
            git__gpg,removekey)
                cmd="git__gpg__subcmd__removekey"
                ;;
            git__gpg,removeperson)
                cmd="git__gpg__subcmd__removeperson"
                ;;
            git__gpg,reveal)
                cmd="git__gpg__subcmd__reveal"
                ;;
            git__gpg,show-repo-id)
                cmd="git__gpg__subcmd__show__subcmd__repo__subcmd__id"
                ;;
            git__gpg,tell)
                cmd="git__gpg__subcmd__tell"
                ;;
            git__gpg,trust)
                cmd="git__gpg__subcmd__trust"
                ;;
            git__gpg,unhide)
                cmd="git__gpg__subcmd__unhide"
                ;;
            git__gpg,verify-keyring)
                cmd="git__gpg__subcmd__verify__subcmd__keyring"
                ;;
            git__gpg,whoami)
                cmd="git__gpg__subcmd__whoami"
                ;;
            git__gpg__subcmd__help,add)
                cmd="git__gpg__subcmd__help__subcmd__add"
                ;;
            git__gpg__subcmd__help,cat)
                cmd="git__gpg__subcmd__help__subcmd__cat"
                ;;
            git__gpg__subcmd__help,changes)
                cmd="git__gpg__subcmd__help__subcmd__changes"
                ;;
            git__gpg__subcmd__help,clean)
                cmd="git__gpg__subcmd__help__subcmd__clean"
                ;;
            git__gpg__subcmd__help,completions)
                cmd="git__gpg__subcmd__help__subcmd__completions"
                ;;
            git__gpg__subcmd__help,export)
                cmd="git__gpg__subcmd__help__subcmd__export"
                ;;
            git__gpg__subcmd__help,help)
                cmd="git__gpg__subcmd__help__subcmd__help"
                ;;
            git__gpg__subcmd__help,hide)
                cmd="git__gpg__subcmd__help__subcmd__hide"
                ;;
            git__gpg__subcmd__help,import)
                cmd="git__gpg__subcmd__help__subcmd__import"
                ;;
            git__gpg__subcmd__help,init)
                cmd="git__gpg__subcmd__help__subcmd__init"
                ;;
            git__gpg__subcmd__help,list)
                cmd="git__gpg__subcmd__help__subcmd__list"
                ;;
            git__gpg__subcmd__help,list-keys)
                cmd="git__gpg__subcmd__help__subcmd__list__subcmd__keys"
                ;;
            git__gpg__subcmd__help,manpages)
                cmd="git__gpg__subcmd__help__subcmd__manpages"
                ;;
            git__gpg__subcmd__help,remove)
                cmd="git__gpg__subcmd__help__subcmd__remove"
                ;;
            git__gpg__subcmd__help,removekey)
                cmd="git__gpg__subcmd__help__subcmd__removekey"
                ;;
            git__gpg__subcmd__help,removeperson)
                cmd="git__gpg__subcmd__help__subcmd__removeperson"
                ;;
            git__gpg__subcmd__help,reveal)
                cmd="git__gpg__subcmd__help__subcmd__reveal"
                ;;
            git__gpg__subcmd__help,show-repo-id)
                cmd="git__gpg__subcmd__help__subcmd__show__subcmd__repo__subcmd__id"
                ;;
            git__gpg__subcmd__help,tell)
                cmd="git__gpg__subcmd__help__subcmd__tell"
                ;;
            git__gpg__subcmd__help,trust)
                cmd="git__gpg__subcmd__help__subcmd__trust"
                ;;
            git__gpg__subcmd__help,unhide)
                cmd="git__gpg__subcmd__help__subcmd__unhide"
                ;;
            git__gpg__subcmd__help,verify-keyring)
                cmd="git__gpg__subcmd__help__subcmd__verify__subcmd__keyring"
                ;;
            git__gpg__subcmd__help,whoami)
                cmd="git__gpg__subcmd__help__subcmd__whoami"
                ;;
            *)
                ;;
        esac
    done

    case "${cmd}" in
        git__gpg)
            opts="-h -V --help --version init import export removekey trust tell removeperson add remove list hide reveal cat unhide changes show-repo-id whoami verify-keyring list-keys clean completions manpages help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 1 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        git__subcmd__gpg__subcmd__add)
            opts="-h --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        git__subcmd__gpg__subcmd__cat)
            opts="-h --email --remote --gpg-home --passphrase-stdin --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --remote)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --gpg-home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        git__subcmd__gpg__subcmd__changes)
            opts="-h --email --remote --gpg-home --passphrase-stdin --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --remote)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --gpg-home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        git__subcmd__gpg__subcmd__clean)
            opts="-h --yes --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        git__subcmd__gpg__subcmd__completions)
            opts="-h --help bash elvish fish powershell zsh"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        git__subcmd__gpg__subcmd__export)
            opts="-h --output --gpg-home --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --gpg-home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        git__subcmd__gpg__subcmd__help)
            opts="init import export removekey trust tell removeperson add remove list hide reveal cat unhide changes show-repo-id whoami verify-keyring list-keys clean completions manpages help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        git__subcmd__gpg__subcmd__help__subcmd__add)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        git__subcmd__gpg__subcmd__help__subcmd__cat)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        git__subcmd__gpg__subcmd__help__subcmd__changes)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        git__subcmd__gpg__subcmd__help__subcmd__clean)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        git__subcmd__gpg__subcmd__help__subcmd__completions)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        git__subcmd__gpg__subcmd__help__subcmd__export)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        git__subcmd__gpg__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        git__subcmd__gpg__subcmd__help__subcmd__hide)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        git__subcmd__gpg__subcmd__help__subcmd__import)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        git__subcmd__gpg__subcmd__help__subcmd__init)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        git__subcmd__gpg__subcmd__help__subcmd__list)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        git__subcmd__gpg__subcmd__help__subcmd__list__subcmd__keys)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        git__subcmd__gpg__subcmd__help__subcmd__manpages)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        git__subcmd__gpg__subcmd__help__subcmd__remove)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        git__subcmd__gpg__subcmd__help__subcmd__removekey)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        git__subcmd__gpg__subcmd__help__subcmd__removeperson)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        git__subcmd__gpg__subcmd__help__subcmd__reveal)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        git__subcmd__gpg__subcmd__help__subcmd__show__subcmd__repo__subcmd__id)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        git__subcmd__gpg__subcmd__help__subcmd__tell)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        git__subcmd__gpg__subcmd__help__subcmd__trust)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        git__subcmd__gpg__subcmd__help__subcmd__unhide)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        git__subcmd__gpg__subcmd__help__subcmd__verify__subcmd__keyring)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        git__subcmd__gpg__subcmd__help__subcmd__whoami)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        git__subcmd__gpg__subcmd__hide)
            opts="-h --remote --gpg-home --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --remote)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --gpg-home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        git__subcmd__gpg__subcmd__import)
            opts="-h --gpg-home --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --gpg-home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        git__subcmd__gpg__subcmd__init)
            opts="-h --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        git__subcmd__gpg__subcmd__list)
            opts="-h --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        git__subcmd__gpg__subcmd__list__subcmd__keys)
            opts="-h --remote --gpg-home --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --remote)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --gpg-home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        git__subcmd__gpg__subcmd__manpages)
            opts="-h --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        git__subcmd__gpg__subcmd__remove)
            opts="-h --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        git__subcmd__gpg__subcmd__removekey)
            opts="-h --yes --gpg-home --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --gpg-home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        git__subcmd__gpg__subcmd__removeperson)
            opts="-h --remote --gpg-home --passphrase-stdin --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --remote)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --gpg-home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        git__subcmd__gpg__subcmd__reveal)
            opts="-h --email --remote --gpg-home --passphrase-stdin --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --remote)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --gpg-home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        git__subcmd__gpg__subcmd__show__subcmd__repo__subcmd__id)
            opts="-h --remote --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --remote)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        git__subcmd__gpg__subcmd__tell)
            opts="-h --remote --gpg-home --passphrase-stdin --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --remote)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --gpg-home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        git__subcmd__gpg__subcmd__trust)
            opts="-h --remote --gpg-home --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --remote)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --gpg-home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        git__subcmd__gpg__subcmd__unhide)
            opts="-h --email --remote --gpg-home --passphrase-stdin --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --remote)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --gpg-home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        git__subcmd__gpg__subcmd__verify__subcmd__keyring)
            opts="-h --remote --gpg-home --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --remote)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --gpg-home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        git__subcmd__gpg__subcmd__whoami)
            opts="-h --email --gpg-home --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --gpg-home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
    esac
}

if [[ "${BASH_VERSINFO[0]}" -eq 4 && "${BASH_VERSINFO[1]}" -ge 4 || "${BASH_VERSINFO[0]}" -gt 4 ]]; then
    complete -F _git__gpg -o nosort -o bashdefault -o default git-gpg
else
    complete -F _git__gpg -o bashdefault -o default git-gpg
fi
