#!/usr/bin/env python3
# lobera.py — CLI principal de Lobera
# Autor: mitr0kerb

import sys
from pathlib import Path

_ROOT = Path(__file__).parent

from core.output import console
from core.session_db import init_db

# ── Banner ────────────────────────────────────────────────────────────────────

def show_banner():
    import pyfiglet
    art = pyfiglet.figlet_format("LOBERA", font="slant")
    console.print(f"[bold cyan]{art}[/bold cyan]")
    console.print("[dim]  AD enumeration & attack toolkit — SMB · RPC · Kerberos · LDAP · WinRM · SSH · SSL · HTTP · HTTPS · FTP · MSSQL[/dim]")
    console.print("[dim]  v1.0 — by [/dim][bold cyan]mitr0kerb[/bold cyan]\n")

# ── Tablas de shells / scanners ───────────────────────────────────────────────

_PROTO_COLORS = {
    "smb":      "green",
    "kerberos": "magenta",
    "rpc":      "blue",
    "ldap":     "yellow",
    "winrm":    "cyan",
    "ssh":      "turquoise2",
    "ssl":      "gold1",
    "http":     "bright_cyan",
    "https":    "deep_sky_blue1",
    "ftp":      "orange1",
    "mssql":    "bright_red",
}

_SHELL_CLASSES = {
    "smb":      ("modules.smb_script_shell",      "SMBScriptShell"),
    "kerberos": ("modules.kerberos_script_shell",  "KerberosScriptShell"),
    "rpc":      ("modules.rpc_script_shell",       "RPCScriptShell"),
    "ldap":     ("modules.ldap_script_shell",      "LDAPScriptShell"),
    "winrm":    ("modules.winrm_script_shell",     "WinRMScriptShell"),
    "ssh":      ("modules.ssh_script_shell",       "SSHScriptShell"),
    "ssl":      ("modules.ssl_script_shell",       "SSLScriptShell"),
    "http":     ("modules.http_script_shell",      "HTTPScriptShell"),
    "https":    ("modules.https_script_shell",     "HTTPSScriptShell"),
    "ftp":      ("modules.ftp_script_shell",       "FTPScriptShell"),
    "mssql":    ("modules.mssql_script_shell",     "MSSQLScriptShell"),
}

_SCANNER_FUNCS = {
    "smb":      ("scripts.smb.scanner",       "run_smb_scanner"),
    "kerberos": ("scripts.kerberos.scanner",  "run_kerberos_scanner"),
    "rpc":      ("scripts.rpc.scanner",       "run_rpc_scanner"),
    "ldap":     ("scripts.ldap.scanner",      "run_ldap_scanner"),
    "winrm":    ("scripts.winrm.scanner",     "run_winrm_scanner"),
    "ssh":      ("scripts.ssh.scanner",       "run_ssh_scanner"),
    "ssl":      ("scripts.ssl.scanner",       "run_ssl_scanner"),
    "http":     ("scripts.http.scanner",      "run_http_scanner"),
    "https":    ("scripts.https.scanner",     "run_https_scanner"),
    "ftp":      ("scripts.ftp.scanner",       "run_ftp_scanner"),
    "mssql":    ("scripts.mssql.scanner",     "run_mssql_scanner"),
}

# ── Dispatcher genérico ───────────────────────────────────────────────────────

def _run_proto(protocol, args):
    root  = _ROOT
    color = _PROTO_COLORS.get(protocol, "white")

    scanner     = getattr(args, "scanner",           False)
    inter_shell = getattr(args, "interactive_shell", False)
    script      = getattr(args, "script",            None)
    script_fam  = getattr(args, "script_fam",        None)

    if scanner:
        mod_name, func_name = _SCANNER_FUNCS[protocol]
        mod  = __import__(mod_name, fromlist=[func_name])
        func = getattr(mod, func_name)
        func(args)
        return

    if inter_shell:
        mod_name, cls_name = _SHELL_CLASSES[protocol]
        mod = __import__(mod_name, fromlist=[cls_name])
        cls = getattr(mod, cls_name)
        cls(root).run()
        return

    from modules.classic import list_scripts, run_script, run_script_family

    if script:
        # Modo clásico: muestra params si faltan, ejecuta si están todos
        run_script(protocol, script, root, color, args)
        return

    if script_fam:
        run_script_family(protocol, script_fam, root, color, args)
        return

    # Sin flags: listar scripts
    list_scripts(protocol, root, color)


# ── Funciones por protocolo ───────────────────────────────────────────────────

def run_smb(args):      _run_proto("smb",      args)
def run_kerberos(args): _run_proto("kerberos", args)
def run_rpc(args):      _run_proto("rpc",      args)
def run_ldap(args):     _run_proto("ldap",     args)
def run_winrm(args):    _run_proto("winrm",    args)
def run_ssh(args):      _run_proto("ssh",      args)
def run_ssl(args):      _run_proto("ssl",      args)
def run_http(args):     _run_proto("http",     args)
def run_https(args):    _run_proto("https",    args)
def run_ftp(args):      _run_proto("ftp",      args)
def run_mssql(args):    _run_proto("mssql",    args)

# ── db ────────────────────────────────────────────────────────────────────────

def run_db(args):
    from core.session_db import (get_targets, get_findings,
                                  get_credentials, delete_target)
    from core.output import print_table

    action = getattr(args, "db_action", None)

    if action == "targets":
        targets = get_targets()
        if not targets:
            console.print("[yellow]No hay ningún objetivo guardado.[/yellow]")
            return
        rows = [(t["ip"], t["domain"] or "-", t["hostname"] or "-", t["first_seen"])
                for t in targets]
        print_table("Objetivos vistos", ["IP", "Dominio", "Hostname", "Primera vez"], rows)

    elif action == "findings":
        if not args.target:
            console.print("[red]Falta -t/--target.[/red]"); return
        findings = get_findings(args.target)
        if getattr(args, "protocol", None):
            findings = [f for f in findings if f["protocol"] == args.protocol]
        if not findings:
            console.print(f"[yellow]Sin hallazgos para {args.target}.[/yellow]"); return
        rows = [(f["protocol"], f["finding_type"], f["detail"], f["timestamp"])
                for f in findings]
        print_table(f"Hallazgos para {args.target}",
                    ["Protocolo", "Tipo", "Detalle", "Timestamp"], rows)

    elif action == "creds":
        if not args.target:
            console.print("[red]Falta -t/--target.[/red]"); return
        creds = get_credentials(args.target, only_valid=not getattr(args, "all", False))
        if not creds:
            console.print(f"[yellow]Sin credenciales para {args.target}.[/yellow]"); return
        show_secret = getattr(args, "show_secret", False)
        rows = []
        for c in creds:
            secret = c["secret"] if show_secret else ("*" * 8 if c["secret"] else "")
            rows.append((c["user"] or "(vacío)", secret, c["secret_type"],
                         "Sí" if c["valid"] else "No", c["source"], c["timestamp"]))
        print_table(f"Credenciales para {args.target}",
                    ["Usuario", "Secreto", "Tipo", "Válida", "Origen", "Timestamp"], rows)
        if not show_secret:
            console.print("[dim]Secretos ocultos. Usa --show-secret para verlos.[/dim]")

    elif action == "delete":
        if not args.target:
            console.print("[red]Falta -t/--target.[/red]"); return
        findings = get_findings(args.target)
        creds    = get_credentials(args.target, only_valid=False)
        targets  = [t for t in get_targets() if t["ip"] == args.target]
        if not targets and not findings and not creds:
            console.print(f"[yellow]Nada guardado para {args.target}.[/yellow]"); return
        console.print(f"[bold red]Vas a borrar TODO para {args.target}:[/bold red]")
        console.print(f"  • {len(targets)} target(s)")
        console.print(f"  • {len(creds)} credencial(es)")
        console.print(f"  • {len(findings)} finding(s)")
        console.print("[bold red]Irreversible.[/bold red]\n")
        if not getattr(args, "yes", False):
            answer = console.input("¿Estás seguro? Escribe [bold]sí[/bold]: ").strip().lower()
            if answer not in ("si", "sí", "s", "yes", "y"):
                console.print("[yellow]Cancelado.[/yellow]"); return
        counts = delete_target(args.target)
        console.print(f"[green]Borrado: {sum(counts.values())} fila(s) eliminadas.[/green]")

    else:
        console.print("[yellow]Acciones disponibles: targets, findings, creds, delete[/yellow]")
        console.print("[dim]lobera.py db <acción> -h[/dim]")

# ── Parser ────────────────────────────────────────────────────────────────────

def _add_proto_flags(p):
    """
    Flags de modo (cómo lanzar el módulo) + todos los parámetros posibles
    de todos los scripts, para que el modo clásico los pueda recibir por CLI.
    """
    # ── modos ────────────────────────────────────────────────────────────────
    p.add_argument("--scanner",           action="store_true",
                   help="Autopwn scanner interactivo")
    p.add_argument("--interactive-shell", action="store_true",
                   dest="interactive_shell",
                   help="Consola interactiva de scripts")
    p.add_argument("--script",     default=None, metavar="NOMBRE",
                   help="Ejecuta un script por nombre")
    p.add_argument("--script-fam", default=None, metavar="FAMILIA",
                   dest="script_fam",
                   help="Ejecuta toda una familia de scripts")

    # ── credenciales / target base (comunes a casi todos los scripts) ─────────
    p.add_argument("-t", "--target",   default=None,   help="IP/hostname del objetivo")
    p.add_argument("-u", "--user",     default=None,   help="Usuario")
    p.add_argument("-p", "--password", default=None,   help="Contraseña")
    p.add_argument("-H", "--hash",     default=None,   help="Hash NT (pass-the-hash)")
    p.add_argument("-d", "--domain",   default=None,   help="Dominio FQDN")
    p.add_argument("--timeout",        default=None, type=int, help="Timeout (segundos)")

    # ── red / servicio ────────────────────────────────────────────────────────
    p.add_argument("--port",           default=None, type=int, help="Puerto del servicio")
    p.add_argument("--instance",       default=None,   help="Nombre de instancia (MSSQL)")
    p.add_argument("--ldaps",          action="store_true", default=False, help="Usar LDAPS")
    p.add_argument("--ssl",            action="store_true", default=False, help="Usar SSL")
    p.add_argument("--sni",            default=None,   help="Server Name Indication (HTTPS)")
    p.add_argument("--http-port",      default=None, type=int, dest="http_port",
                   help="Puerto HTTP (para TLS stripping)")

    # ── ficheros / listas ─────────────────────────────────────────────────────
    p.add_argument("--userlist",       default=None,   help="Wordlist de usuarios")
    p.add_argument("--passlist",       default=None,   help="Wordlist de passwords")
    p.add_argument("--wordlist",       default=None,   help="Wordlist genérica (dir brute, etc.)")

    # ── SMB específico ────────────────────────────────────────────────────────
    p.add_argument("--share",          default=None,   help="Share SMB concreto")
    p.add_argument("--ext",            default=None,   help="Extensiones a buscar (ej: .txt,.kdbx)")
    p.add_argument("--keywords",       default=None,   help="Palabras clave en nombres de fichero")
    p.add_argument("--depth",          default=None, type=int, help="Profundidad de recursión")

    # ── Kerberos específico ───────────────────────────────────────────────────
    p.add_argument("--spn",            default=None,   help="SPN objetivo (ej: cifs/DC01.CORP.LOCAL)")
    p.add_argument("--ccache",         default=None,   help="Ruta al fichero .ccache")
    p.add_argument("--kirbi",          default=None,   help="Ruta al fichero .kirbi")
    p.add_argument("--krbtgt-hash",    default=None, dest="krbtgt_hash",
                   help="Hash NT del krbtgt")
    p.add_argument("--service-hash",   default=None, dest="service_hash",
                   help="Hash NT de la cuenta de servicio")
    p.add_argument("--domain-sid",     default=None, dest="domain_sid",
                   help="SID del dominio (S-1-5-21-...)")
    p.add_argument("--user-id",        default=None, type=int, dest="user_id",
                   help="RID del usuario a impersonar (default: 500)")
    p.add_argument("--groups",         default=None,
                   help="RIDs de grupos separados por coma")
    p.add_argument("--target-user",    default=None, dest="target_user",
                   help="Usuario objetivo a impersonar")
    p.add_argument("--target-computer",default=None, dest="target_computer",
                   help="Nombre del equipo objetivo")
    p.add_argument("--attacker-account",default=None, dest="attacker_account",
                   help="Cuenta controlada por el atacante")
    p.add_argument("--cert",           default=None,   help="Ruta al certificado .pem")
    p.add_argument("--pfx",            default=None,   help="Ruta al certificado .pfx")
    p.add_argument("--template",       default=None,   help="Plantilla ADCS")
    p.add_argument("--ca",             default=None,   help="CA authority (ej: CORP-CA)")
    p.add_argument("--alt-name",       default=None, dest="alt_name",
                   help="Nombre alternativo para el certificado")
    p.add_argument("--dc-name",        default=None, dest="dc_name",
                   help="Nombre del DC (para noPac)")
    p.add_argument("--user-sid",       default=None, dest="user_sid",
                   help="SID del usuario (para ms14-068)")
    p.add_argument("--vector",         default=None,
                   help="Vector de ataque (kerber-loss)")
    p.add_argument("--new-password",   default=None, dest="new_password",
                   help="Nueva contraseña a establecer")

    # ── LDAP específico ───────────────────────────────────────────────────────
    p.add_argument("--target-dn",      default=None, dest="target_dn",
                   help="DN del objeto LDAP objetivo")
    p.add_argument("--target-obj",     default=None, dest="target_obj",
                   help="DN/sAMAccountName objetivo (acl-abuse)")
    p.add_argument("--out-dir",        default=None, dest="out_dir",
                   help="Directorio de salida (bloodhound)")
    p.add_argument("--save-list",      default=None, dest="save_list",
                   help="Ruta para guardar lista resultante")
    p.add_argument("--filter-flag",    default=None, dest="filter_flag",
                   help="Filtro por flag UAC")
    p.add_argument("--enabled-only",   action="store_true", default=False,
                   dest="enabled_only", help="Solo cuentas habilitadas")
    p.add_argument("--privileged-only",action="store_true", default=False,
                   dest="privileged_only", help="Solo grupos privilegiados")
    p.add_argument("--os-filter",      default=None, dest="os_filter",
                   help="Filtro por sistema operativo")
    p.add_argument("--undeleg",        action="store_true", default=False,
                   help="Solo equipos con delegación sin restricciones")
    p.add_argument("--action",         default=None,
                   help="Acción ACL (detect/reset-password/add-member/...)")
    p.add_argument("--source-user",    default=None, dest="source_user",
                   help="Usuario origen del ACE")
    p.add_argument("--save-key",       default=None, dest="save_key",
                   help="Ruta para guardar clave privada (shadow-creds)")
    p.add_argument("--mode",           default=None,
                   help="Modo relay (add-da/rbcd/dump/shadow-creds)")
    p.add_argument("--relay-target-user", default=None, dest="relay_target_user",
                   help="Usuario objetivo del relay")
    p.add_argument("--continue-on-lockout", action="store_true", default=False,
                   dest="continue_on_lockout",
                   help="Continuar aunque se detecte lockout")

    # ── MSSQL específico ──────────────────────────────────────────────────────
    p.add_argument("--command",        default=None,
                   help="Comando OS a ejecutar (xp_cmdshell)")
    p.add_argument("--query",          default=None,
                   help="Query SQL arbitraria")
    p.add_argument("--attacker-ip",    default=None, dest="attacker_ip",
                   help="IP del atacante (NTLM steal)")

    # ── FTP específico ────────────────────────────────────────────────────────
    p.add_argument("--delay",          default=None, type=float,
                   help="Delay entre intentos (segundos)")

    # ── HTTP/HTTPS específico ─────────────────────────────────────────────────
    p.add_argument("--path",           default=None,
                   help="Ruta HTTP inicial (default: /)")
    p.add_argument("--param",          default=None,
                   help="Parámetro a inyectar (sqli, xss, lfi, ssrf)")
    p.add_argument("--listener",       default=None,
                   help="Dominio OOB para log4shell")
    p.add_argument("--client-id",      default=None, dest="client_id",
                   help="Client ID OAuth (oauth-misconfig)")
    p.add_argument("--max-depth",      default=None, type=int, dest="max_depth",
                   help="Profundidad máxima de crawling")
    p.add_argument("--max-pages",      default=None, type=int, dest="max_pages",
                   help="Páginas máximas de crawling")


def build_parser():
    import argparse
    parser = argparse.ArgumentParser(
        prog="lobera",
        description="Lobera — AD enumeration & attack toolkit",
    )
    subs = parser.add_subparsers(dest="module", metavar="módulo")

    # ── Protocolos ──────────────────────────────────────────────────────────
    proto_help = {
        "smb":      "Scripts SMB",
        "kerberos": "Scripts Kerberos",
        "rpc":      "Scripts RPC",
        "ldap":     "Scripts LDAP",
        "winrm":    "Scripts WinRM",
        "ssh":      "Scripts SSH",
        "ssl":      "Scripts SSL",
        "http":     "Scripts HTTP",
        "https":    "Scripts HTTPS",
        "ftp":      "Scripts FTP",
        "mssql":    "Scripts MSSQL",
    }
    for proto, help_text in proto_help.items():
        p = subs.add_parser(proto, help=help_text)
        _add_proto_flags(p)

    # ── db ──────────────────────────────────────────────────────────────────
    db_p = subs.add_parser("db", help="Base de datos de sesión")
    db_s = db_p.add_subparsers(dest="db_action", metavar="acción")

    db_s.add_parser("targets", help="Lista objetivos")

    db_findings = db_s.add_parser("findings", help="Lista hallazgos de un objetivo")
    db_findings.add_argument("-t", "--target",  default=None)
    db_findings.add_argument("--protocol",      default=None)

    db_creds = db_s.add_parser("creds", help="Lista credenciales de un objetivo")
    db_creds.add_argument("-t", "--target",     default=None)
    db_creds.add_argument("--all",              action="store_true")
    db_creds.add_argument("--show-secret",      action="store_true", dest="show_secret")

    db_delete = db_s.add_parser("delete", help="Borra todo lo de un objetivo")
    db_delete.add_argument("-t", "--target",    default=None)
    db_delete.add_argument("--yes",             action="store_true")

    return parser

# ── main ──────────────────────────────────────────────────────────────────────

def main():
    root_str = str(_ROOT)
    if root_str not in sys.path:
        sys.path.insert(0, root_str)

    init_db()

    from core.auth import login
    if not login():
        sys.exit(1)

    parser = build_parser()
    args   = parser.parse_args()

    if args.module is None:
        show_banner()
        console.print("[yellow]No se ha especificado ningún módulo.[/yellow]")
        console.print(
            "Módulos disponibles: "
            "[bold green]smb[/bold green] · "
            "[bold magenta]kerberos[/bold magenta] · "
            "[bold blue]rpc[/bold blue] · "
            "[bold yellow]ldap[/bold yellow] · "
            "[bold cyan]winrm[/bold cyan] · "
            "[bold turquoise2]ssh[/bold turquoise2] · "
            "[bold gold1]ssl[/bold gold1] · "
            "[bold bright_cyan]http[/bold bright_cyan] · "
            "[bold deep_sky_blue1]https[/bold deep_sky_blue1] · "
            "[bold orange1]ftp[/bold orange1] · "
            "[bold bright_red]mssql[/bold bright_red] · "
            "[bold white]db[/bold white]"
        )
        console.print("[dim]lobera.py <módulo>                    → árbol de scripts disponibles[/dim]")
        console.print("[dim]lobera.py <módulo> --script=<nombre>  → ver parámetros / ejecutar[/dim]")
        console.print("[dim]lobera.py <módulo> --scanner          → autopwn scanner[/dim]")
        console.print("[dim]lobera.py <módulo> --interactive-shell → consola interactiva[/dim]\n")
        return

    dispatch = {
        "smb":      run_smb,
        "kerberos": run_kerberos,
        "rpc":      run_rpc,
        "ldap":     run_ldap,
        "winrm":    run_winrm,
        "ssh":      run_ssh,
        "ssl":      run_ssl,
        "http":     run_http,
        "https":    run_https,
        "ftp":      run_ftp,
        "mssql":    run_mssql,
        "db":       run_db,
    }
    runner = dispatch.get(args.module)
    if runner:
        runner(args)
    else:
        console.print(f"[red]Módulo desconocido: {args.module}[/red]")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[dim]Interrumpido.[/dim]")
        sys.exit(130)
