#!/usr/bin/env bash
# Autocompletado bash para Lobera
# Instalación:
#   source tools/completions/lobera_completion.bash
# O permanente:
#   echo 'source /ruta/lobera/tools/completions/lobera_completion.bash' >> ~/.bashrc

_lobera_modules() {
    echo "smb rpc ldap kerberos winrm ssh ftp mssql ssl http https db report"
}

_lobera_scripts() {
    local module="$1"
    local lobera_dir
    lobera_dir="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/../.."
    local script_dir="${lobera_dir}/scripts/${module}"

    if [[ -d "$script_dir" ]]; then
        find "$script_dir" -name "*.py" ! -name "__init__.py" ! -name "scan_params.py" ! -name "shell_params.py" \
             -printf "%f\n" 2>/dev/null | sed 's/\.py$//' | sed 's/_/-/g'
    fi
}

_lobera_completions() {
    local cur prev words cword
    _init_completion || return

    local modules
    modules="$(_lobera_modules)"

    # Primer argumento: módulo
    if [[ $cword -eq 1 ]]; then
        COMPREPLY=($(compgen -W "$modules" -- "$cur"))
        return
    fi

    local module="${words[1]}"

    case "$prev" in
        --script|-s)
            local scripts
            scripts="$(_lobera_scripts "$module")"
            COMPREPLY=($(compgen -W "$scripts" -- "$cur"))
            return
            ;;
        -t|--target)
            # Completar con IPs del historial si están disponibles
            COMPREPLY=()
            return
            ;;
        -u|--user)
            COMPREPLY=()
            return
            ;;
        -p|--password)
            COMPREPLY=()
            return
            ;;
        -H|--hash)
            COMPREPLY=()
            return
            ;;
        -d|--domain)
            COMPREPLY=()
            return
            ;;
        --ccache|--kirbi)
            COMPREPLY=($(compgen -f -- "$cur"))
            return
            ;;
        --format)
            COMPREPLY=($(compgen -W "html md" -- "$cur"))
            return
            ;;
        -o|--output)
            COMPREPLY=($(compgen -f -- "$cur"))
            return
            ;;
        --workers)
            COMPREPLY=($(compgen -W "1 2 4 8 16" -- "$cur"))
            return
            ;;
        --delay)
            COMPREPLY=($(compgen -W "0 0.5 1 2 5 10 30 60" -- "$cur"))
            return
            ;;
        --jitter)
            COMPREPLY=($(compgen -W "0 0.5 1 2 5" -- "$cur"))
            return
            ;;
        --port)
            case "$module" in
                smb)    COMPREPLY=($(compgen -W "445 139" -- "$cur")) ;;
                ldap)   COMPREPLY=($(compgen -W "389 636" -- "$cur")) ;;
                winrm)  COMPREPLY=($(compgen -W "5985 5986" -- "$cur")) ;;
                ssh)    COMPREPLY=($(compgen -W "22" -- "$cur")) ;;
                ftp)    COMPREPLY=($(compgen -W "21" -- "$cur")) ;;
                mssql)  COMPREPLY=($(compgen -W "1433" -- "$cur")) ;;
                http)   COMPREPLY=($(compgen -W "80 8080 8000 8443" -- "$cur")) ;;
                https)  COMPREPLY=($(compgen -W "443 8443" -- "$cur")) ;;
                *)      COMPREPLY=() ;;
            esac
            return
            ;;
    esac

    # Flags disponibles para todos los módulos
    local common_flags="-t --target -u --user -p --password -H --hash -d --domain
                        --port --timeout --script --scanner --ldaps --dry-run
                        --ccache --workers --delay --jitter --continue-on-lockout"

    # Flags específicos por módulo
    local module_flags=""
    case "$module" in
        kerberos)
            module_flags="--kirbi --krbtgt-hash --service-hash --aes"
            ;;
        report)
            module_flags="--format -o --output"
            ;;
        http|https)
            module_flags="--path --method --data --headers"
            ;;
    esac

    if [[ "$cur" == -* ]]; then
        COMPREPLY=($(compgen -W "$common_flags $module_flags" -- "$cur"))
    fi
}

complete -F _lobera_completions lobera.py
complete -F _lobera_completions lobera
