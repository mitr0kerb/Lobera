#!/usr/bin/env python3
# lobera.py

import argparse
import ast
import sys
import importlib
import pathlib

from core.session_db import (
    init_db, get_targets, get_findings, get_credentials, delete_target,
)
from core.target import Target
from core.credentials import Creds
from core.output import console, print_table
from utils.banner import show_banner
from rich.table import Table
from rich.tree import Tree


# ============================================================
# Configuración por módulo
# ============================================================

VERSION = "1.0"

MODULE_CONFIG = {
    "smb":      {"color": "green",   "label": "Sscripts", "proto": "SMB"},
    "kerberos": {"color": "magenta", "label": "Kscripts", "proto": "KRB"},
    "rpc":      {"color": "blue",    "label": "Rscripts", "proto": "RPC"},
    "ldap":     {"color": "yellow",  "label": "Lscripts", "proto": "LDAP"},
    "winrm":    {"color": "cyan",    "label": "Wscripts", "proto": "WINRM"},
}

NO_TARGET_SCRIPTS = {
    "kerberos": {"golden-ticket", "silver-ticket", "pass-the-ticket"},
}

# Ruta raíz del proyecto (donde vive lobera.py)
_ROOT = pathlib.Path(__file__).parent


# ============================================================
# Banner de módulo
# ============================================================

def _print_module_banner(module):
    import pyfiglet
    cfg   = MODULE_CONFIG.get(module, {"color": "white", "label": module.upper()})
    color = cfg["color"]
    label = cfg["label"]
    art   = pyfiglet.figlet_format(label, font="slant")
    console.print(f"[bold {color}]{art}[/bold {color}]")
    console.print(
        f"[dim]  módulo [bold {color}]{module.upper()}[/bold {color}] — "
        f"lobera.py {module} --script=<nombre> -t <ip>[/dim]\n"
    )


# ============================================================
# Helpers comunes
# ============================================================

def add_common_args(parser):
    parser.add_argument("-t", "--target",   default=None, help="IP o hostname del objetivo")
    parser.add_argument("-u", "--user",     default="",   help="Usuario")
    parser.add_argument("-p", "--password", default="",   help="Contraseña")
    parser.add_argument("-H", "--hash",     default=None, help="Hash NT (o LM:NT)")
    parser.add_argument("-d", "--domain",   default="",   help="Dominio FQDN")
    parser.add_argument("-k", "--kerberos", action="store_true", dest="use_kerberos",
                        help="Autenticar con ticket Kerberos (KRB5CCNAME del entorno)")
    parser.add_argument("--ccache",  default=None, metavar="FILE",
                        help="Ruta al fichero .ccache")
    parser.add_argument("--timeout", type=int, default=5,
                        help="Timeout de conexión en segundos (default: 5)")


def require_target(args, script_name=None, module=None):
    exempt = NO_TARGET_SCRIPTS.get(module or "", set())
    if script_name and script_name in exempt:
        return True
    if not args.target:
        console.print("[red]Falta -t/--target (obligatorio para este script).[/red]")
        return False
    return True


def make_target(args):
    return Target(ip=args.target or "", domain=args.domain, timeout=args.timeout)


def make_creds(args):
    ccache = None
    if getattr(args, "use_kerberos", False):
        import os
        ccache = getattr(args, "ccache", None) or os.environ.get("KRB5CCNAME")
    return Creds(
        user=args.user,
        password=args.password,
        domain=args.domain,
        hash=args.hash,
        ccache=ccache,
    )


def detect_hash_format(secret, secret_type):
    if secret_type == "null":     return "null session"
    if secret_type == "password": return "texto claro"
    if secret_type == "hash":
        if secret and ":" in secret:
            _, nt = secret.split(":", 1)
            return "LM:NTLM" if len(nt) == 32 else "LM:NT"
        if secret and len(secret) == 32:
            return "NTLM (32 hex)"
        return "hash (desconocido)"
    return secret_type or "desconocido"


# ============================================================
# Script loader — dos capas:
#   1. _script_metadata()  → AST, sin importar, para el árbol
#   2. _import_script_cls() → import real, solo al ejecutar
# ============================================================

class _ScriptMeta:
    """
    Objeto ligero con los metadatos de un script extraídos por AST.
    Se usa en el árbol de scripts (lobera.py smb) sin importar el módulo.
    """
    __slots__ = ("name", "description", "category", "path")

    def __init__(self, name, description, category, path):
        self.name        = name
        self.description = description
        self.category    = category
        self.path        = path          # pathlib.Path al fichero .py

def _script_metadata(py_path):
    """
    Extrae name, description, category de un script leyendo el AST
    sin importarlo. Funciona con cualquier nombre de clase que herede
    de BaseScript (SharesScript, UserEnumScript, Script, etc.).
    """
    try:
        source = py_path.read_text(encoding="utf-8", errors="replace")
        tree   = ast.parse(source, filename=str(py_path))
    except Exception:
        return None

    meta = {"name": None, "description": None, "category": None}

    for node in ast.walk(tree):
        # Cualquier clase que herede de algo (tiene al menos una base)
        if isinstance(node, ast.ClassDef) and node.bases:
            for item in node.body:
                if isinstance(item, ast.Assign):
                    for target in item.targets:
                        if (isinstance(target, ast.Name)
                                and target.id in meta
                                and isinstance(item.value, ast.Constant)):
                            meta[target.id] = item.value.value
            # Primera clase con bases que tenga name definido
            if meta["name"] is not None:
                break

    if meta["name"] is None:
        meta["name"] = py_path.stem

    return _ScriptMeta(
        name        = meta["name"],
        description = meta["description"] or "",
        category    = meta["category"] or py_path.parent.name,
        path        = py_path,
    )


def _import_script_cls(py_path):
    """
    Importa el fichero .py y devuelve la clase Script.
    Se llama SOLO cuando el usuario ejecuta un script, no para el árbol.
    Añade _ROOT al sys.path si es necesario.
    """
    root_str = str(_ROOT)
    if root_str not in sys.path:
        sys.path.insert(0, root_str)

    rel      = py_path.relative_to(_ROOT)
    mod_path = str(rel).replace("/", ".").replace("\\", ".")[:-3]  # quitar .py

    try:
        mod = importlib.import_module(mod_path)
        return getattr(mod, "Script", None)
    except Exception as exc:
        console.print(f"[red]Error importando {mod_path}: {exc}[/red]")
        return None


# ============================================================
# Funciones de descubrimiento de scripts
# ============================================================

def _get_tree_meta(module):
    """
    Devuelve dict {family_name: [_ScriptMeta, ...]} para todos los scripts
    del módulo, usando AST (sin importar nada).
    """
    scripts_root = _ROOT / "scripts" / module
    result = {}
    if not scripts_root.is_dir():
        return result

    for family_dir in sorted(scripts_root.iterdir()):
        if not family_dir.is_dir() or family_dir.name.startswith("_"):
            continue
        metas = []
        for py in sorted(family_dir.glob("*.py")):
            if py.name == "__init__.py":
                continue
            meta = _script_metadata(py)
            if meta:
                metas.append(meta)
        if metas:
            result[family_dir.name] = metas
    return result


def _find_script_path(module, name):
    """
    Busca el fichero .py cuyo campo name == <name> o cuyo stem == <name>
    dentro de scripts/<module>/**/*.py, usando AST.
    Devuelve pathlib.Path o None.
    """
    scripts_root = _ROOT / "scripts" / module
    if not scripts_root.is_dir():
        return None

    for py in scripts_root.rglob("*.py"):
        if py.name == "__init__.py":
            continue
        if py.stem == name:
            return py
        # Comprobar el campo name= dentro del fichero
        meta = _script_metadata(py)
        if meta and meta.name == name:
            return py
    return None


def _get_family_paths(module, family):
    """
    Devuelve lista de pathlib.Path de scripts en scripts/<module>/<family>/.
    """
    family_dir = _ROOT / "scripts" / module / family
    if not family_dir.is_dir():
        return []
    return [py for py in sorted(family_dir.glob("*.py"))
            if py.name != "__init__.py"]


# ============================================================
# Árbol visual
# ============================================================
def _print_module_tree(module):
    _print_module_banner(module)

    cfg       = MODULE_CONFIG.get(module, {"color": "white"})
    color     = cfg["color"]
    tree_data = _get_tree_meta(module)

    if not tree_data:
        console.print(f"[yellow]No hay scripts disponibles para el módulo '{module}'.[/yellow]")
        console.print(f"[dim]  (buscando en: {_ROOT / 'scripts' / module})[/dim]")
        return

    from rich.text import Text
    tree = Tree(f"[bold {color}]{module.upper()}[/bold {color}]")
    for family, metas in tree_data.items():
        branch = tree.add(f"[bold {color}]{family}[/bold {color}]")
        for m in metas:
            label = Text()
            label.append(m.name, style="bold white")
            label.append("  ")
            label.append(m.description, style="dim")
            branch.add(label)
    console.print(tree, overflow="fold")
    console.print(f"\n[dim]lobera.py {module} --script=<nombre> -t <ip> [opciones][/dim]")
# ============================================================
# Ejecución
# ============================================================

def _run_script_cls(cls, target, creds, **kwargs):
    try:
        script = cls(target, creds)
        script.run(**kwargs)
    except KeyboardInterrupt:
        console.print("\n[dim]Script interrumpido.[/dim]")
    except Exception as exc:
        name = getattr(cls, "name", cls.__name__)
        console.print(f"[red]Error ejecutando {name}: {exc}[/red]")


def _show_script_examples(cls):
    examples    = getattr(cls, "EXAMPLES", [])
    script_name = getattr(cls, "name", "?")
    if not examples:
        console.print(f"[yellow]No hay ejemplos para '{script_name}'.[/yellow]")
        return
    t = Table(title=f"Ejemplos — {script_name}")
    t.add_column("Parámetro", style="cyan")
    t.add_column("Qué hace")
    t.add_column("[green]Buen uso[/green]")
    t.add_column("[red]Mal uso[/red]")
    for ex in examples:
        t.add_row(ex.get("flag",""), ex.get("desc",""),
                  ex.get("good",""), ex.get("bad",""))
    console.print(t)


def run_module_generic(module_name, args):
    script_name  = getattr(args, "script",     None)
    script_fam   = getattr(args, "script_fam", None)
    show_example = getattr(args, "example",    False)

    if not script_name and not script_fam:
        _print_module_tree(module_name)
        return

    target = make_target(args)
    creds  = make_creds(args)
    extra  = _build_extra_kwargs(args)

    if script_name:
        py_path = _find_script_path(module_name, script_name)
        if py_path is None:
            console.print(f"[red]Script '{script_name}' no encontrado en '{module_name}'.[/red]")
            return
        cls = _import_script_cls(py_path)
        if cls is None:
            return
        if show_example:
            _show_script_examples(cls)
            return
        if not require_target(args, script_name, module_name):
            return
        _run_script_cls(cls, target, creds, **extra)

    elif script_fam:
        for fam in script_fam.split("/"):
            fam   = fam.strip()
            paths = _get_family_paths(module_name, fam)
            if not paths:
                console.print(f"[yellow]Familia '{fam}' no encontrada en '{module_name}'.[/yellow]")
                continue
            for py_path in paths:
                meta = _script_metadata(py_path)
                sname = meta.name if meta else py_path.stem
                if not require_target(args, sname, module_name):
                    continue
                cls = _import_script_cls(py_path)
                if cls:
                    _run_script_cls(cls, target, creds, **extra)


# ============================================================
# kwargs extra
# ============================================================

def _build_extra_kwargs(args):
    _skip = {"module", "db_action", "script", "script_fam", "example",
             "target", "user", "password", "hash", "domain", "timeout",
             "use_kerberos"}
    extra = {k: v for k, v in vars(args).items() if k not in _skip}
    extra["use_kerberos"] = getattr(args, "use_kerberos", False)
    return extra


# ============================================================
# Parsers
# ============================================================

def _add_script_args(p):
    p.add_argument("--script",     default=None, metavar="NOMBRE",
                   help="Script a ejecutar")
    p.add_argument("--script-fam", default=None, dest="script_fam",
                   metavar="FAMILIA[/FAMILIA2]",
                   help="Ejecuta todos los scripts de una familia")
    p.add_argument("--example",    action="store_true",
                   help="Muestra ejemplos del script indicado en --script")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="lobera",
        description=f"Lobera {VERSION} — pentest AD modular",
    )
    subs = parser.add_subparsers(dest="module", metavar="módulo")

        # ---- SMB ----
    smb = subs.add_parser(
        "smb",
        help="Consola interactiva de scripts SMB",
    )
    smb.add_argument(
        "--scanner", action="store_true",
        help="Modo autopwn interactivo SMB",
    )

    
        # ---- Kerberos ----
    krb = subs.add_parser("kerberos", help="Consola interactiva de scripts Kerberos")
    krb.add_argument("--scanner", action="store_true",
                     help="Modo autopwn interactivo Kerberos")

    # ---- RPC ----
    rpc = subs.add_parser("rpc", help="Scripts RPC (SAMR, LSA, SCM, WINREG…)")
    add_common_args(rpc); _add_script_args(rpc)
    rpc.add_argument("--shell",            action="store_true",
                     help="Abre la consola interactiva RPC")
    rpc.add_argument("--local-admins",     action="store_true", dest="local_admins")
    rpc.add_argument("--running-only",     action="store_true", dest="running_only")
    rpc.add_argument("--interesting-only", action="store_true", dest="interesting_only")
    rpc.add_argument("--open-files",       action="store_true", dest="open_files")
    rpc.add_argument("--priv",             default=None)
    rpc.add_argument("--hive",             default="HKLM")
    rpc.add_argument("--key",              default=None)
    rpc.add_argument("--value",            default=None)
    rpc.add_argument("--action",           default=None)
    rpc.add_argument("--command",          default=None)
    rpc.add_argument("--svc-name",         default="LobSvc", dest="svc_name")
    rpc.add_argument("--wait",             type=int, default=3)
    rpc.add_argument("--dll-path",         default=None, dest="dll_path")
    rpc.add_argument("--listener",         default=None)
    rpc.add_argument("--pipe",             default="lsarpc",
                     choices=["lsarpc","efsrpc","samr","lsass","netlogon"])
    rpc.add_argument("--rid-start",        type=int, default=500, dest="rid_start")
    rpc.add_argument("--rid-end",          type=int, default=10000, dest="rid_end")
    rpc.add_argument("--out-dir",          default=None, dest="out_dir")

    # ---- LDAP ----
    ldap = subs.add_parser("ldap", help="Consola interactiva de scripts LDAP")
    ldap.add_argument("--scanner", action="store_true",
                      help="Modo autopwn interactivo LDAP")

    # ---- WinRM ----
    winrm = subs.add_parser("winrm", help="Scripts WinRM / PowerShell remoto")
    add_common_args(winrm); _add_script_args(winrm)
    winrm.add_argument("--shell",    action="store_true",
                       help="Abre consola interactiva WinRM/PS")
    winrm.add_argument("--ssl",      action="store_true",
                       help="Usar HTTPS (puerto 5986)")
    winrm.add_argument("--port",     type=int, default=None)
    winrm.add_argument("--command",  default=None)
    winrm.add_argument("--script-ps",default=None, dest="script_ps", metavar="FILE")
    winrm.add_argument("--out-dir",  default=None, dest="out_dir")
    winrm.add_argument("--userlist", default=None, metavar="FILE")
    winrm.add_argument("--action",   default=None)
    winrm.add_argument("--listener", default=None)
    winrm.add_argument("--lport",    type=int, default=4444)
    winrm.add_argument("--url",      default=None)

    # ---- DB ----
    db      = subs.add_parser("db", help="Base de datos de sesión")
    db_subs = db.add_subparsers(dest="db_action", metavar="acción")

    dbt = db_subs.add_parser("targets")
    dbt.add_argument("--example", action="store_true")

    dbf = db_subs.add_parser("findings")
    dbf.add_argument("-t","--target", default=None)
    dbf.add_argument("--protocol",   default=None)
    dbf.add_argument("--example",    action="store_true")

    dbc = db_subs.add_parser("creds")
    dbc.add_argument("-t","--target",  default=None)
    dbc.add_argument("--all",          action="store_true")
    dbc.add_argument("--show-secret",  action="store_true", dest="show_secret")
    dbc.add_argument("--example",      action="store_true")

    dbd = db_subs.add_parser("delete")
    dbd.add_argument("-t","--target", default=None)
    dbd.add_argument("--yes",         action="store_true")
    dbd.add_argument("--example",     action="store_true")

    return parser


# ============================================================
# Runners
# ============================================================

def run_smb(args):
    if getattr(args, "scanner", False):
        from scripts.smb.scanner import run_smb_scanner
        run_smb_scanner(args)
        return
    from modules.smb_script_shell import SMBScriptShell
    SMBScriptShell(_ROOT).run()

def run_kerberos(args):
    if getattr(args, "scanner", False):
        from scripts.kerberos.scanner import run_kerberos_scanner
        run_kerberos_scanner(args)
        return
    from modules.kerberos_script_shell import KerberosScriptShell
    KerberosScriptShell(_ROOT).run()


def run_rpc(args):
    if getattr(args, "shell", False):
        from modules.rpc_shell import RPCShell
        RPCShell(make_target(args), make_creds(args)).run()
        return
    run_module_generic("rpc", args)


def run_ldap(args):
    if getattr(args, "scanner", False):
        from scripts.ldap.scanner import run_ldap_scanner
        run_ldap_scanner(args)
        return
    from modules.ldap_script_shell import LDAPScriptShell
    LDAPScriptShell(_ROOT).run()


def run_winrm(args):
    if getattr(args, "shell", False):
        from modules.winrm_shell import WinRMShell
        WinRMShell(make_target(args), make_creds(args),
                   use_ssl=getattr(args,"ssl",False),
                   port=getattr(args,"port",None)).run()
        return
    run_module_generic("winrm", args)


# ============================================================
# Runner DB
# ============================================================

def run_db(args):
    action = getattr(args, "db_action", None)
    if action is None:
        console.print("[yellow]Acciones disponibles: targets, findings, creds, delete[/yellow]")
        console.print("[dim]lobera.py db <acción> -h[/dim]")
        return
    if getattr(args, "example", False):
        _show_db_examples(action); return
    if action == "targets":    _run_db_targets()
    elif action == "findings": _run_db_findings(args)
    elif action == "creds":    _run_db_creds(args)
    elif action == "delete":   _run_db_delete(args)


def _run_db_targets():
    targets = get_targets()
    if not targets:
        console.print("[yellow]No hay objetivos guardados aún.[/yellow]"); return
    print_table("Objetivos", ["IP","Dominio","Hostname","Primera vez"],
                [(t["ip"], t["domain"] or "-", t["hostname"] or "-", t["first_seen"])
                 for t in targets])


def _run_db_findings(args):
    if not args.target:
        console.print("[red]Falta -t/--target.[/red]"); return
    findings = get_findings(args.target)
    if getattr(args,"protocol",None):
        findings = [f for f in findings if f["protocol"] == args.protocol]
    if not findings:
        console.print(f"[yellow]No hay hallazgos para {args.target}.[/yellow]"); return
    print_table(f"Hallazgos — {args.target}",
                ["Protocolo","Tipo","Detalle","Timestamp"],
                [(f["protocol"],f["finding_type"],f["detail"],f["timestamp"])
                 for f in findings])


def _run_db_creds(args):
    if not args.target:
        console.print("[red]Falta -t/--target.[/red]"); return
    creds = get_credentials(args.target, only_valid=not getattr(args,"all",False))
    if not creds:
        console.print(f"[yellow]No hay credenciales para {args.target}.[/yellow]"); return
    show_secret = getattr(args,"show_secret",False)
    rows = []
    for c in creds:
        secret = c["secret"] if show_secret else ("*"*8 if c["secret"] else "")
        rows.append((c["user"] or "(vacío)", secret,
                     detect_hash_format(c["secret"],c["secret_type"]),
                     "Sí" if c["valid"] else "No",
                     c["source"], c["timestamp"]))
    print_table(f"Credenciales — {args.target}",
                ["Usuario","Secreto","Formato","Válida","Origen","Timestamp"], rows)
    if not show_secret and creds:
        console.print("[dim]Usa --show-secret para ver los secretos en claro.[/dim]")


def _run_db_delete(args):
    if not args.target:
        console.print("[red]Falta -t/--target.[/red]"); return
    findings = get_findings(args.target)
    creds    = get_credentials(args.target, only_valid=False)
    targets  = [t for t in get_targets() if t["ip"] == args.target]
    if not targets and not findings and not creds:
        console.print(f"[yellow]No hay nada guardado para {args.target}.[/yellow]"); return
    console.print(f"[bold red]Borrar TODO para {args.target}:[/bold red]")
    console.print(f"  • {len(targets)} target(s) · {len(creds)} credencial(es) · {len(findings)} finding(s)")
    console.print("[bold red]Irreversible.[/bold red]\n")
    if not getattr(args,"yes",False):
        ans = console.input("¿Confirmar? Escribe [bold]sí[/bold]: ").strip().lower()
        if ans not in ("si","sí","s","yes","y"):
            console.print("[yellow]Cancelado.[/yellow]"); return
    counts = delete_target(args.target)
    console.print(f"[green]Borrado: {sum(counts.values())} fila(s).[/green]")


def _show_db_examples(action):
    examples = {
        "targets":  [{"flag":"(sin flags)","desc":"Lista todos","good":"lobera.py db targets","bad":"db targets -t IP"}],
        "findings": [{"flag":"-t","desc":"Objetivo","good":"db findings -t 10.129.1.5","bad":"db findings (sin -t)"}],
        "creds":    [{"flag":"--show-secret","desc":"Ver secretos","good":"db creds -t IP --show-secret","bad":"en sesión grabada"}],
        "delete":   [{"flag":"-t","desc":"Borra todo","good":"db delete -t IP","bad":"db delete -t IP --yes sin revisar"}],
    }
    for ex in examples.get(action,[]):
        t = Table(title=f"Ejemplos — db {action}")
        t.add_column("Parámetro",style="cyan"); t.add_column("Qué hace")
        t.add_column("[green]Buen uso[/green]"); t.add_column("[red]Mal uso[/red]")
        t.add_row(ex["flag"],ex["desc"],ex["good"],ex["bad"])
        console.print(t)


# ============================================================
# Entry point
# ============================================================
def main():
    root_str = str(_ROOT)
    if root_str not in sys.path:
        sys.path.insert(0, root_str)
    
    show_banner()
    init_db()

    from core.auth import login
    if not login():
        sys.exit(1)

    parser = build_parser()
    args   = parser.parse_args()

    if args.module is None:
        console.print("[yellow]No se ha especificado ningún módulo.[/yellow]")
        console.print(
            "Módulos disponibles: "
            "[bold green]smb[/bold green] · "
            "[bold magenta]kerberos[/bold magenta] · "
            "[bold blue]rpc[/bold blue] · "
            "[bold yellow]ldap[/bold yellow] · "
            "[bold cyan]winrm[/bold cyan] · "
            "[bold white]db[/bold white]"
        )
        console.print("[dim]lobera.py <módulo> -h     →  opciones del módulo[/dim]")
        console.print("[dim]lobera.py <módulo>         →  árbol de scripts disponibles[/dim]\n")
        return

    dispatch = {
        "smb":      run_smb,
        "kerberos": run_kerberos,
        "rpc":      run_rpc,
        "ldap":     run_ldap,
        "winrm":    run_winrm,
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
