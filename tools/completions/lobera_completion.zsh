#compdef lobera.py lobera
# Autocompletado zsh para Lobera
# Instalación:
#   cp tools/completions/lobera_completion.zsh /usr/local/share/zsh/site-functions/_lobera
#   autoload -Uz compinit && compinit
# O simplemente en ~/.zshrc:
#   source /ruta/lobera/tools/completions/lobera_completion.zsh

_lobera() {
    local -a modules scripts flags
    local module context state state_descr line
    typeset -A opt_args

    modules=(
        'smb:Operaciones sobre SMB/CIFS'
        'rpc:Llamadas RPC y MSRPC'
        'ldap:Consultas y ataques LDAP/AD'
        'kerberos:Ataques Kerberos (ticket, roast, deleg...)'
        'winrm:Windows Remote Management'
        'ssh:Secure Shell'
        'ftp:FTP'
        'mssql:Microsoft SQL Server'
        'ssl:Inspección SSL/TLS'
        'http:HTTP'
        'https:HTTPS'
        'db:Gestión de la base de datos de sesión'
        'report:Generar informe HTML/Markdown'
    )

    _arguments -C \
        '1:módulo:->module' \
        '*:: :->args' \
    && return

    case $state in
        module)
            _describe 'módulo' modules
            ;;
        args)
            module="${words[1]}"
            local lobera_dir script_dir scripts_list
            lobera_dir="$(dirname "$(readlink -f "${(%):-%x}")")/../.."
            script_dir="${lobera_dir}/scripts/${module}"

            scripts_list=()
            if [[ -d "$script_dir" ]]; then
                for f in "$script_dir"/**/*.py(N); do
                    local base="${f:t:r}"
                    [[ "$base" == "__init__" || "$base" == "scan_params" || "$base" == "shell_params" ]] && continue
                    scripts_list+=("${base//_/-}")
                done
            fi

            flags=(
                '(-t --target)'{-t,--target}'[IP, CIDR, rango o @fichero]:objetivo'
                '(-u --user)'{-u,--user}'[Usuario]:usuario'
                '(-p --password)'{-p,--password}'[Contraseña]:contraseña'
                '(-H --hash)'{-H,--hash}'[Hash NT para pass-the-hash]:hash'
                '(-d --domain)'{-d,--domain}'[Dominio AD]:dominio'
                '--port[Puerto]:puerto'
                '--timeout[Timeout en segundos]:segundos'
                '--ccache[Fichero .ccache Kerberos]:fichero:_files'
                '--workers[Hilos en modo batch]:número'
                '--delay[Delay entre intentos de spray]:segundos'
                '--jitter[Jitter aleatorio al delay]:segundos'
                '--dry-run[Simular sin ejecutar nada]'
                '--continue-on-lockout[Continuar spray aunque haya lockout]'
                '--ldaps[Usar LDAPS en lugar de LDAP]'
                '--scanner[Ejecutar escáner en lugar de scripts]'
            )

            if [[ ${#scripts_list[@]} -gt 0 ]]; then
                flags+=('--script[Script a ejecutar]:script:('"${scripts_list[*]}"')')
            else
                flags+=('--script[Script a ejecutar]:script')
            fi

            case "$module" in
                kerberos)
                    flags+=(
                        '--kirbi[Fichero .kirbi de Windows]:fichero:_files'
                        '--krbtgt-hash[Hash del KRBTGT para golden ticket]:hash'
                        '--service-hash[Hash del servicio para silver ticket]:hash'
                    )
                    ;;
                report)
                    flags+=(
                        '--format[Formato de salida]:formato:(html md)'
                        '(-o --output)'{-o,--output}'[Fichero de salida]:fichero:_files'
                    )
                    ;;
            esac

            _arguments $flags
            ;;
    esac
}

_lobera "$@"
