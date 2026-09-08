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
    from core.i18n import T
    art = pyfiglet.figlet_format("LOBERA", font="slant")
    console.print(f"[bold cyan]{art}[/bold cyan]")
    console.print(f"[dim]  {T('banner_subtitle')} — SMB · RPC · Kerberos · LDAP · WinRM · SSH · SSL · HTTP · HTTPS · FTP · MSSQL[/dim]")
    console.print(f"[dim]  v1.0 — by [/dim][bold cyan]mitr0kerb[/bold cyan]\n")

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
    from core.i18n import T
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
        run_script(protocol, script, root, color, args)
        return

    if script_fam:
        run_script_family(protocol, script_fam, root, color, args)
        return

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
    from core.i18n import T
    from core.session_db import (get_targets, get_findings,
                                  get_credentials, delete_target)
    from core.output import print_table

    action = getattr(args, "db_action", None)

    if action == "targets":
        targets = get_targets()
        if not targets:
            console.print(f"[yellow]{T('db_no_targets')}[/yellow]")
            return
        rows = [(t["ip"], t["domain"] or "-", t["hostname"] or "-", t["first_seen"])
                for t in targets]
        print_table(T("db_targets_header"),
                    [T("col_ip"), T("col_domain"), T("col_hostname"), T("col_first_seen")],
                    rows)

    elif action == "findings":
        if not args.target:
            console.print(f"[red]{T('err_no_target')}[/red]"); return
        findings = get_findings(args.target)
        if getattr(args, "protocol", None):
            findings = [f for f in findings if f["protocol"] == args.protocol]
        if not findings:
            console.print(f"[yellow]{T('db_no_findings')} {args.target}.[/yellow]"); return
        rows = [(f["protocol"], f["finding_type"], f["detail"], f["timestamp"])
                for f in findings]
        print_table(f"{T('db_findings_header')} {args.target}",
                    [T("col_protocol"), T("col_type"), T("col_detail"), T("col_timestamp")],
                    rows)

    elif action == "creds":
        if not args.target:
            console.print(f"[red]{T('err_no_target')}[/red]"); return
        creds = get_credentials(args.target, only_valid=not getattr(args, "all", False))
        if not creds:
            console.print(f"[yellow]{T('db_no_creds')} {args.target}.[/yellow]"); return
        show_secret = getattr(args, "show_secret", False)
        rows = []
        for c in creds:
            secret = c["secret"] if show_secret else ("*" * 8 if c["secret"] else "")
            valid  = T("col_yes") if c["valid"] else T("col_no")
            rows.append((c["user"] or "(vacío)", secret, c["secret_type"],
                         valid, c["source"], c["timestamp"]))
        print_table(f"{T('db_creds_header')} {args.target}",
                    [T("col_user"), T("col_secret"), "Tipo", T("col_valid"),
                     T("col_origin"), T("col_timestamp")],
                    rows)
        if not show_secret:
            console.print(f"[dim]{T('db_secrets_hidden')}[/dim]")

    elif action == "delete":
        if not args.target:
            console.print(f"[red]{T('err_no_target')}[/red]"); return
        findings = get_findings(args.target)
        creds    = get_credentials(args.target, only_valid=False)
        targets  = [t for t in get_targets() if t["ip"] == args.target]
        if not targets and not findings and not creds:
            console.print(f"[yellow]{T('db_nothing_saved')} {args.target}.[/yellow]"); return
        console.print(f"[bold red]{T('db_delete_title')} {args.target}:[/bold red]")
        console.print(f"  • {len(targets)} target(s)")
        console.print(f"  • {len(creds)} credencial(es)")
        console.print(f"  • {len(findings)} finding(s)")
        console.print(f"[bold red]{T('db_delete_irreversible')}[/bold red]\n")
        if not getattr(args, "yes", False):
            answer = console.input(T("db_delete_confirm")).strip().lower()
            if answer not in ("si", "sí", "s", "yes", "y"):
                console.print(f"[yellow]{T('db_cancelled')}[/yellow]"); return
        counts = delete_target(args.target)
        total  = sum(counts.values())
        console.print(f"[green]{T('db_deleted')} {total} {T('db_rows_deleted')}[/green]")

    else:
        console.print(f"[yellow]{T('db_actions')}: targets, findings, creds, delete[/yellow]")
        console.print("[dim]lobera.py db <acción> -h[/dim]")

# ── Parser ────────────────────────────────────────────────────────────────────

def _add_proto_flags(p):
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

    # target / credenciales
    p.add_argument("-t", "--target",   default=None)
    p.add_argument("-u", "--user",     default=None)
    p.add_argument("-p", "--password", default=None)
    p.add_argument("-H", "--hash",     default=None)
    p.add_argument("-d", "--domain",   default=None)
    p.add_argument("--timeout",        default=None, type=int)

    # red / servicio
    p.add_argument("--port",           default=None, type=int)
    p.add_argument("--instance",       default=None)
    p.add_argument("--ldaps",          action="store_true", default=False)
    p.add_argument("--ssl",            action="store_true", default=False)
    p.add_argument("--sni",            default=None)
    p.add_argument("--http-port",      default=None, type=int, dest="http_port")

    # listas
    p.add_argument("--userlist",       default=None)
    p.add_argument("--passlist",       default=None)
    p.add_argument("--wordlist",       default=None)

    # SMB
    p.add_argument("--share",          default=None)
    p.add_argument("--ext",            default=None)
    p.add_argument("--keywords",       default=None)
    p.add_argument("--depth",          default=None, type=int)

    # Kerberos
    p.add_argument("--spn",            default=None)
    p.add_argument("--ccache",         default=None)
    p.add_argument("--kirbi",          default=None)
    p.add_argument("--krbtgt-hash",    default=None, dest="krbtgt_hash")
    p.add_argument("--service-hash",   default=None, dest="service_hash")
    p.add_argument("--domain-sid",     default=None, dest="domain_sid")
    p.add_argument("--user-id",        default=None, type=int, dest="user_id")
    p.add_argument("--groups",         default=None)
    p.add_argument("--target-user",    default=None, dest="target_user")
    p.add_argument("--target-computer",default=None, dest="target_computer")
    p.add_argument("--attacker-account",default=None, dest="attacker_account")
    p.add_argument("--cert",           default=None)
    p.add_argument("--pfx",            default=None)
    p.add_argument("--template",       default=None)
    p.add_argument("--ca",             default=None)
    p.add_argument("--alt-name",       default=None, dest="alt_name")
    p.add_argument("--dc-name",        default=None, dest="dc_name")
    p.add_argument("--user-sid",       default=None, dest="user_sid")
    p.add_argument("--vector",         default=None)
    p.add_argument("--new-password",   default=None, dest="new_password")

    # LDAP
    p.add_argument("--target-dn",      default=None, dest="target_dn")
    p.add_argument("--target-obj",     default=None, dest="target_obj")
    p.add_argument("--out-dir",        default=None, dest="out_dir")
    p.add_argument("--save-list",      default=None, dest="save_list")
    p.add_argument("--filter-flag",    default=None, dest="filter_flag")
    p.add_argument("--enabled-only",   action="store_true", default=False, dest="enabled_only")
    p.add_argument("--privileged-only",action="store_true", default=False, dest="privileged_only")
    p.add_argument("--os-filter",      default=None, dest="os_filter")
    p.add_argument("--undeleg",        action="store_true", default=False)
    p.add_argument("--action",         default=None)
    p.add_argument("--source-user",    default=None, dest="source_user")
    p.add_argument("--save-key",       default=None, dest="save_key")
    p.add_argument("--mode",           default=None)
    p.add_argument("--relay-target-user", default=None, dest="relay_target_user")
    p.add_argument("--continue-on-lockout", action="store_true", default=False,
                   dest="continue_on_lockout")

    # MSSQL
    p.add_argument("--command",        default=None)
    p.add_argument("--query",          default=None)
    p.add_argument("--attacker-ip",    default=None, dest="attacker_ip")

    # FTP / delay
    p.add_argument("--delay",          default=None, type=float)

    # HTTP/HTTPS
    p.add_argument("--path",           default=None)
    p.add_argument("--param",          default=None)
    p.add_argument("--listener",       default=None)
    p.add_argument("--client-id",      default=None, dest="client_id")
    p.add_argument("--max-depth",      default=None, type=int, dest="max_depth")
    p.add_argument("--max-pages",      default=None, type=int, dest="max_pages")


def build_parser():
    import argparse
    parser = argparse.ArgumentParser(
        prog="lobera",
        description="Lobera — AD enumeration & attack toolkit",
    )
    # Flag global de idioma (procesado antes de parse_args)
    parser.add_argument("--lang", default=None, metavar="LANG",
                        help="Cambia el idioma: es | en")

    subs = parser.add_subparsers(dest="module", metavar="módulo")

    proto_help = {
        "smb": "Scripts SMB", "kerberos": "Scripts Kerberos",
        "rpc": "Scripts RPC", "ldap": "Scripts LDAP",
        "winrm": "Scripts WinRM", "ssh": "Scripts SSH",
        "ssl": "Scripts SSL", "http": "Scripts HTTP",
        "https": "Scripts HTTPS", "ftp": "Scripts FTP",
        "mssql": "Scripts MSSQL",
    }
    for proto, help_text in proto_help.items():
        p = subs.add_parser(proto, help=help_text)
        _add_proto_flags(p)

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

    # ── 1. Inicializar DB ─────────────────────────────────────────────────
    first_run = init_db()

    # ── 2. Idioma ─────────────────────────────────────────────────────────
    from core.i18n import set_lang, get_lang
    from core.lang_selector import (
        select_language_interactive,
        apply_lang_from_db,
        cmd_change_lang,
    )
    from core.session_db import get_setting, save_setting

    # Detectar --lang en argv antes de parsear (para que afecte al banner)
    lang_override = None
    for i, arg in enumerate(sys.argv[1:]):
        if arg.startswith("--lang="):
            lang_override = arg.split("=", 1)[1].strip().lower()
            break
        if arg == "--lang" and i + 1 < len(sys.argv) - 1:
            lang_override = sys.argv[i + 2].strip().lower()
            break

    if lang_override:
        if cmd_change_lang(lang_override):
            save_setting("lang", get_lang())
        # Si el único argumento era --lang, salir tras confirmar el cambio
        non_lang_args = [a for a in sys.argv[1:]
                         if not a.startswith("--lang") and a != lang_override]
        if not non_lang_args:
            return
    elif first_run:
        # Primera ejecución: preguntar idioma antes del banner
        chosen = select_language_interactive()
        save_setting("lang", chosen)
    else:
        # Cargar preferencia guardada
        saved_lang = get_setting("lang", "es")
        apply_lang_from_db(saved_lang)

    # ── 3. Auth ───────────────────────────────────────────────────────────
    from core.auth import login
    if not login():
        sys.exit(1)

    # ── 4. Banner ─────────────────────────────────────────────────────────
    show_banner()

    # ── 5. Parsear args (filtrando --lang para que argparse no se queje) ──
    filtered_argv = []
    skip_next = False
    for arg in sys.argv[1:]:
        if skip_next:
            skip_next = False
            continue
        if arg.startswith("--lang="):
            continue
        if arg == "--lang":
            skip_next = True
            continue
        filtered_argv.append(arg)

    parser = build_parser()
    args   = parser.parse_args(filtered_argv)

    # ── 6. Dispatch ───────────────────────────────────────────────────────
    from core.i18n import T

    if args.module is None:
        console.print(f"[yellow]{T('no_module')}[/yellow]")
        console.print(
            f"{T('modules_available')}: "
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
        console.print(f"[dim]lobera.py <módulo>                    → {T('usage_list')}[/dim]")
        console.print(f"[dim]lobera.py <módulo> --script=<nombre>  → {T('usage_script')}[/dim]")
        console.print(f"[dim]lobera.py <módulo> --scanner          → {T('usage_scanner')}[/dim]")
        console.print(f"[dim]lobera.py <módulo> --interactive-shell → {T('usage_shell')}[/dim]")
        console.print(f"[dim]lobera.py --lang=en                   → cambiar idioma[/dim]\n")
        return

    dispatch = {
        "smb": run_smb, "kerberos": run_kerberos, "rpc": run_rpc,
        "ldap": run_ldap, "winrm": run_winrm, "ssh": run_ssh,
        "ssl": run_ssl, "http": run_http, "https": run_https,
        "ftp": run_ftp, "mssql": run_mssql, "db": run_db,
    }
    runner = dispatch.get(args.module)
    if runner:
        runner(args)
    else:
        console.print(f"[red]{T('err_unknown_module')}: {args.module}[/red]")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[dim]Interrumpido.[/dim]")
        sys.exit(130)
