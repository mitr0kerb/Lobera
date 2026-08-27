#!/usr/bin/env python3
# lobera.py

import argparse
import sys

from core.session_db import init_db, get_targets, get_findings, get_credentials, delete_target
from core.target import Target
from core.credentials import Creds
from core.output import console, print_table
from core import auth
from modules.smb import SMBModule
from modules.smb_shell import SMBShell
from utils.banner import show_banner
from rich.table import Table


# ============================================================
# Helpers comunes
# ============================================================

def add_common_target_args(parser):
    """Argumentos comunes a toda acción de módulos de ataque (target, credenciales).
    -t no es 'required' a nivel de argparse para permitir '--example' sin target;
    se valida a mano en cada acción real con require_target()."""
    parser.add_argument("-t", "--target", default=None, help="IP o hostname del objetivo (obligatorio salvo con --example)")
    parser.add_argument("-u", "--user", default="", help="Usuario")
    parser.add_argument("-p", "--password", default="", help="Contraseña")
    parser.add_argument("-H", "--hash", default=None, help="Hash NT (o LM:NT) para pass-the-hash")
    parser.add_argument("-d", "--domain", default="", help="Dominio")
    parser.add_argument("--timeout", type=int, default=5, help="Timeout de conexión en segundos (default: 5)")


def require_target(args):
    """Valida que se haya dado -t cuando la acción va a ejecutarse de verdad."""
    if not args.target:
        console.print("[red]Falta -t/--target (obligatorio salvo con --example).[/red]")
        return False
    return True


def parse_csv(raw):
    if raw is None:
        return None
    if raw == "":
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]


def detect_hash_format(secret, secret_type):
    """Clasifica el formato de un secreto guardado para mostrarlo de forma legible."""
    if secret_type == "null":
        return "null session"
    if secret_type == "password":
        return "texto claro"
    if secret_type == "hash":
        if ":" in secret:
            lm, nt = secret.split(":", 1)
            if len(nt) == 32:
                return "LM:NTLM (NT hash 32 hex)"
            return "LM:NT (formato no estándar)"
        if len(secret) == 32:
            return "NTLM (NT hash, 32 hex)"
        return f"hash ({len(secret)} caracteres, formato no reconocido)"
    return secret_type


# ============================================================
# Parser
# ============================================================

def build_parser():
    parser = argparse.ArgumentParser(
        prog="lobera",
        description="Lobera - herramienta modular de enumeración y ataques AD"
    )
    subparsers = parser.add_subparsers(dest="module", metavar="módulo")

    # ============================================================
    # Módulo: smb
    # ============================================================
    smb_parser = subparsers.add_parser("smb", help="Enumeración y ataques SMB")
    smb_subparsers = smb_parser.add_subparsers(dest="smb_action", metavar="acción")

    # --- smb enum ---
    enum_parser = smb_subparsers.add_parser("enum", help="Enumeración: shares, signing, null session")
    add_common_target_args(enum_parser)
    enum_parser.add_argument("--example", action="store_true", help="Muestra ejemplos de uso y sale")
    enum_parser.add_argument("--smb-version", choices=["v1", "v2", "v2.1", "v3"], default=None,
                              help="Fuerza una versión de SMB (por defecto: negociación automática)")
    enum_parser.add_argument("--shares", action="store_true", help="Lista los shares disponibles")
    enum_parser.add_argument("--signing", action="store_true", help="Comprueba si el objetivo exige SMB signing")
    enum_parser.add_argument("--null-sess", action="store_true",
                              help="Comprueba si el objetivo permite SMB null session")

    # --- smb spider ---
    spider_parser = smb_subparsers.add_parser("spider", help="Rastrea shares y descarga ficheros interesantes")
    add_common_target_args(spider_parser)
    spider_parser.add_argument("--example", action="store_true", help="Muestra ejemplos de uso y sale")
    spider_parser.add_argument("--share", metavar="SHARE", default=None,
                                help="Share concreto a rastrear. Si se omite, rastrea TODOS los shares no especiales")
    spider_parser.add_argument("--ext", default=None,
                                help="Extensiones a buscar, separadas por coma (ej: .txt,.kdbx). "
                                     "Vacío ('') = sin filtro de extensión. Si no se indica, usa las de por defecto.")
    spider_parser.add_argument("--keywords", default=None,
                                help="Palabras clave a buscar en nombres de fichero, separadas por coma")
    spider_parser.add_argument("--depth", type=int, default=5,
                                help="Profundidad máxima de recursión (default: 5)")

    # --- smb spray ---
    spray_parser = smb_subparsers.add_parser("spray", help="Password spraying contra una lista de usuarios")
    add_common_target_args(spray_parser)
    spray_parser.add_argument("--example", action="store_true", help="Muestra ejemplos de uso y sale")
    spray_parser.add_argument("--userlist", default=None, metavar="FILE",
                               help="Fichero con una lista de usuarios, uno por línea (obligatorio salvo con --example)")

    # --- smb shell ---
    shell_parser = smb_subparsers.add_parser("shell", help="Abre una consola interactiva SMB")
    add_common_target_args(shell_parser)
    shell_parser.add_argument("--example", action="store_true", help="Muestra ejemplos de uso y sale")

    # ============================================================
    # Módulo: db (consulta de la base de datos de sesión)
    # ============================================================
    db_parser = subparsers.add_parser("db", help="Consulta la base de datos de sesión (objetivos, credenciales, hallazgos)")
    db_subparsers = db_parser.add_subparsers(dest="db_action", metavar="acción")

    # --- db targets ---
    db_targets_parser = db_subparsers.add_parser("targets", help="Lista todos los objetivos vistos hasta ahora")
    db_targets_parser.add_argument("--example", action="store_true", help="Muestra ejemplos de uso y sale")

    # --- db findings ---
    db_findings_parser = db_subparsers.add_parser("findings", help="Lista los hallazgos guardados para un objetivo")
    db_findings_parser.add_argument("-t", "--target", default=None,
                                     help="IP del objetivo (obligatorio salvo con --example)")
    db_findings_parser.add_argument("--protocol", default=None,
                                     help="Filtra por protocolo (ej: SMB, RPC)")
    db_findings_parser.add_argument("--example", action="store_true", help="Muestra ejemplos de uso y sale")

    # --- db creds ---
    db_creds_parser = db_subparsers.add_parser("creds", help="Lista credenciales guardadas para un objetivo")
    db_creds_parser.add_argument("-t", "--target", default=None,
                                  help="IP del objetivo (obligatorio salvo con --example)")
    db_creds_parser.add_argument("--all", action="store_true",
                                  help="Incluye también credenciales marcadas como no válidas (por defecto solo válidas)")
    db_creds_parser.add_argument("--show-secret", action="store_true",
                                  help="Muestra el secreto (contraseña/hash) en texto plano. Por defecto se oculta.")
    db_creds_parser.add_argument("--example", action="store_true", help="Muestra ejemplos de uso y sale")

    # --- db delete ---
    db_delete_parser = db_subparsers.add_parser("delete", help="Borra TODO lo guardado para un objetivo (irreversible)")
    db_delete_parser.add_argument("-t", "--target", default=None,
                                   help="IP del objetivo a borrar (obligatorio salvo con --example)")
    db_delete_parser.add_argument("--yes", action="store_true",
                                   help="Salta la confirmación interactiva (para uso en scripts)")
    db_delete_parser.add_argument("--example", action="store_true", help="Muestra ejemplos de uso y sale")

    return parser


# ============================================================
# Ejemplos (--example) — uno por cada acción/flag disponible
# ============================================================

EXAMPLES = {
    "smb": {
        "enum": [
            {"flag": "--shares",
             "desc": "Lista los shares disponibles (requiere login previo)",
             "good": "smb enum -t 10.129.1.5 -u iker --shares",
             "bad": "smb enum -t 10.129.1.5 --shares  [sin -u, hara null session -> puede dar Access Denied]"},
            {"flag": "--signing",
             "desc": "Chequeo de solo lectura, no requiere credenciales",
             "good": "smb enum -t 10.129.1.5 --signing",
             "bad": "smb enum -t 10.129.1.5 -u iker -p 'Pass123!' --signing  [credenciales innecesarias, mas ruido en logs]"},
            {"flag": "--null-sess",
             "desc": "Comprueba null session sin usar tus credenciales reales",
             "good": "smb enum -t 10.129.1.5 --null-sess",
             "bad": "smb enum -t 10.129.1.5 -u admin -p 'RealPass!' --null-sess  [null-sess ignora -u/-p, son redundantes aqui]"},
            {"flag": "--smb-version",
             "desc": "Fuerza un dialecto concreto en vez de negociacion automatica",
             "good": "smb enum -t 10.129.1.5 --smb-version v1  [para detectar si SMBv1 legacy esta activo]",
             "bad": "smb enum -t 10.129.1.5 --smb-version v3  [si el objetivo no soporta v3, falla en vez de negociar]"},
        ],
        "spider": [
            {"flag": "--share",
             "desc": "Restringe el rastreo a un unico share",
             "good": "smb spider -t 10.129.1.5 -u iker --share Users",
             "bad": "smb spider -t 10.129.1.5 -u iker --share ADMIN$  [shares especiales rara vez tienen contenido de usuario]"},
            {"flag": "--ext",
             "desc": "Filtra por extension; vacio = sin filtro (todo)",
             "good": "smb spider -t 10.129.1.5 -u iker --ext .kdbx,.txt",
             "bad": "smb spider -t 10.129.1.5 -u iker --ext ''  [descarga TODO, puede tardar mucho y llenar disco]"},
            {"flag": "--keywords",
             "desc": "Busca coincidencias por nombre, ademas de por extension",
             "good": "smb spider -t 10.129.1.5 -u iker --keywords password,backup",
             "bad": "smb spider -t 10.129.1.5 -u iker --keywords a,e,i  [keywords tan cortas generan falsos positivos masivos]"},
            {"flag": "--depth",
             "desc": "Profundidad de recursion en subcarpetas",
             "good": "smb spider -t 10.129.1.5 -u iker --depth 3  [suficiente para perfiles de usuario tipicos]",
             "bad": "smb spider -t 10.129.1.5 -u iker --depth 20  [en C$ puede tardar muchisimo]"},
        ],
        "spray": [
            {"flag": "--userlist",
             "desc": "Fichero con un usuario por linea",
             "good": "smb spray -t 10.129.1.5 --userlist users.txt -p 'Summer2024!'",
             "bad": "smb spray -t 10.129.1.5 --userlist users.txt -p ''  [contrasena vacia casi nunca es util en spray real]"},
        ],
        "shell": [
            {"flag": "(sin flags extra)",
             "desc": "Abre la consola interactiva tras login",
             "good": "smb shell -t 10.129.1.5 -u iker -p 'Summer2024!'",
             "bad": "smb shell -t 10.129.1.5  [sin -u, entraras con null session y la mayoria de comandos fallaran]"},
        ],
    },
    "db": {
        "targets": [
            {"flag": "(sin flags)",
             "desc": "Lista todos los objetivos guardados hasta ahora",
             "good": "db targets",
             "bad": "db targets -t 10.129.1.5  [-t no existe en 'targets', esta accion lista TODOS, no filtra por uno]"},
        ],
        "findings": [
            {"flag": "-t",
             "desc": "Filtra hallazgos por objetivo (obligatorio)",
             "good": "db findings -t 10.129.1.5",
             "bad": "db findings  [sin -t, no sabe de que objetivo mostrar hallazgos]"},
            {"flag": "--protocol",
             "desc": "Filtra ademas por protocolo concreto",
             "good": "db findings -t 10.129.1.5 --protocol SMB",
             "bad": "db findings -t 10.129.1.5 --protocol smb  [minusculas: el filtro no encontrara 'SMB' guardado en mayusculas]"},
        ],
        "creds": [
            {"flag": "--all",
             "desc": "Incluye credenciales invalidas, no solo las que funcionaron",
             "good": "db creds -t 10.129.1.5 --all  [util para ver tambien intentos fallidos de spray]",
             "bad": "db creds -t 10.129.1.5 --all --show-secret  [combinar ambos en pantalla compartida expone credenciales de mas]"},
            {"flag": "--show-secret",
             "desc": "Muestra la contrasena/hash en texto plano (oculto por defecto)",
             "good": "db creds -t 10.129.1.5 --show-secret  [en tu propia terminal privada]",
             "bad": "db creds -t 10.129.1.5 --show-secret  [en una sesion compartida/grabada -> expone credenciales reales]"},
        ],
        "delete": [
            {"flag": "-t",
             "desc": "Borra TODO lo guardado (targets, credenciales, findings, log) de ese objetivo",
             "good": "db delete -t 10.129.1.5  [pide confirmacion antes de borrar]",
             "bad": "db delete -t 10.129.1.5 --yes  [salta confirmacion sin haber revisado antes que datos hay guardados]"},
            {"flag": "--yes",
             "desc": "Salta la confirmacion interactiva",
             "good": "db delete -t 10.129.1.5 --yes  [en un script automatizado de limpieza tras cada engagement]",
             "bad": "db delete -t 10.129.1.5 --yes  [en uso manual normal: te arriesgas a borrar el objetivo equivocado sin darte cuenta]"},
        ],
    },
}


def show_examples(module, action):
    examples = EXAMPLES.get(module, {}).get(action, [])
    if not examples:
        console.print(f"[yellow]No hay ejemplos registrados para '{module} {action}' todavia.[/yellow]")
        return

    table = Table(title=f"Ejemplos - {module} {action}")
    table.add_column("Parametro", style="cyan")
    table.add_column("Que hace")
    table.add_column("[green]Buen uso[/green]")
    table.add_column("[red]Mal uso[/red]")

    for ex in examples:
        table.add_row(ex["flag"], ex["desc"], ex["good"], ex["bad"])

    console.print(table)


# ============================================================
# Acciones: smb
# ============================================================

def run_smb_enum(args):
    if not require_target(args):
        return
    target = Target(ip=args.target, domain=args.domain, timeout=args.timeout)
    creds = Creds(user=args.user, password=args.password, domain=args.domain, hash=args.hash)
    smb = SMBModule(target, creds)

    if not smb.connect(force_dialect=args.smb_version):
        return

    if args.signing:
        smb.check_signing()

    if args.null_sess:
        smb.is_null_session()

    if args.shares:
        if smb.login():
            smb.list_shares()


def run_smb_spider(args):
    if not require_target(args):
        return
    target = Target(ip=args.target, domain=args.domain, timeout=args.timeout)
    creds = Creds(user=args.user, password=args.password, domain=args.domain, hash=args.hash)
    smb = SMBModule(target, creds)

    if not smb.connect():
        return
    if not smb.login():
        return

    extensions = parse_csv(args.ext)
    keywords = parse_csv(args.keywords)
    kwargs = {"max_depth": args.depth, "keywords": keywords}
    if extensions is not None:
        kwargs["extensions"] = extensions

    if args.share:
        smb.spider_share(args.share, **kwargs)
    else:
        smb.spider_all_shares(**kwargs)


def run_smb_spray(args):
    if not require_target(args):
        return
    target = Target(ip=args.target, domain=args.domain, timeout=args.timeout)
    creds = Creds(user=args.user, password=args.password, domain=args.domain, hash=args.hash)
    smb = SMBModule(target, creds)

    if not smb.connect():
        return

    if not args.userlist:
        console.print("[red]Falta --userlist (obligatorio salvo con --example).[/red]")
        return

    try:
        with open(args.userlist) as f:
            users = [line.strip() for line in f if line.strip()]
    except OSError as e:
        console.print(f"[red]No se pudo leer {args.userlist}: {e}[/red]")
        return

    if users:
        smb.password_spray(users, args.password, domain=args.domain)


def run_smb_shell(args):
    if not require_target(args):
        return
    target = Target(ip=args.target, domain=args.domain, timeout=args.timeout)
    creds = Creds(user=args.user, password=args.password, domain=args.domain, hash=args.hash)
    smb = SMBModule(target, creds)

    if not smb.connect():
        return
    if not smb.login():
        return

    shell = SMBShell(smb)
    shell.run()


SMB_ACTIONS = {
    "enum": run_smb_enum,
    "spider": run_smb_spider,
    "spray": run_smb_spray,
    "shell": run_smb_shell,
}


def run_smb(args):
    action = SMB_ACTIONS.get(args.smb_action)
    if action is None:
        console.print("[yellow]No se ha especificado ninguna accion de SMB.[/yellow]")
        console.print("Acciones disponibles: [bold]enum, spider, spray, shell[/bold]")
        console.print("Uso: [dim]lobera.py smb <accion> -h[/dim] para ver las opciones de cada una.\n")
        return

    if getattr(args, "example", False):
        show_examples("smb", args.smb_action)
        return

    action(args)


# ============================================================
# Acciones: db
# ============================================================

def run_db_targets(args):
    targets = get_targets()
    if not targets:
        console.print("[yellow]Todavia no hay ningun objetivo guardado en la base de datos.[/yellow]")
        return

    rows = [(t["ip"], t["domain"] or "-", t["hostname"] or "-", t["first_seen"]) for t in targets]
    print_table("Objetivos vistos", ["IP", "Dominio", "Hostname", "Primera vez visto"], rows)


def run_db_findings(args):
    if not args.target:
        console.print("[red]Falta -t/--target (obligatorio salvo con --example).[/red]")
        return

    findings = get_findings(args.target)
    if args.protocol:
        findings = [f for f in findings if f["protocol"] == args.protocol]

    if not findings:
        console.print(f"[yellow]No hay hallazgos guardados para {args.target}"
                       f"{' con protocolo ' + args.protocol if args.protocol else ''}.[/yellow]")
        return

    rows = [(f["protocol"], f["finding_type"], f["detail"], f["timestamp"]) for f in findings]
    print_table(f"Hallazgos para {args.target}", ["Protocolo", "Tipo", "Detalle", "Timestamp"], rows)


def run_db_creds(args):
    if not args.target:
        console.print("[red]Falta -t/--target (obligatorio salvo con --example).[/red]")
        return

    creds = get_credentials(args.target, only_valid=not args.all)
    if not creds:
        console.print(f"[yellow]No hay credenciales guardadas para {args.target}"
                       f"{' (validas)' if not args.all else ''}.[/yellow]")
        return

    rows = []
    for c in creds:
        secret_display = c["secret"] if args.show_secret else ("*" * 8 if c["secret"] else "")
        hash_format = detect_hash_format(c["secret"], c["secret_type"])
        valid_str = "Si" if c["valid"] else "No"
        rows.append((c["user"] or "(vacio)", secret_display, hash_format, valid_str, c["source"], c["timestamp"]))

    print_table(f"Credenciales para {args.target}",
                ["Usuario", "Secreto", "Formato", "Valida", "Origen", "Timestamp"], rows)

    if not args.show_secret and creds:
        console.print("[dim]Secretos ocultos por defecto. Usa --show-secret para verlos en texto plano.[/dim]")


def run_db_delete(args):
    if not args.target:
        console.print("[red]Falta -t/--target (obligatorio salvo con --example).[/red]")
        return

    # Mostramos primero un resumen de lo que hay, para que la persona sepa qué va a perder
    findings = get_findings(args.target)
    creds = get_credentials(args.target, only_valid=False)
    targets = [t for t in get_targets() if t["ip"] == args.target]

    if not targets and not findings and not creds:
        console.print(f"[yellow]No hay nada guardado para {args.target}. Nada que borrar.[/yellow]")
        return

    console.print(f"[bold red]Vas a borrar TODO lo guardado para {args.target}:[/bold red]")
    console.print(f"  • {len(targets)} registro(s) de target")
    console.print(f"  • {len(creds)} credencial(es)")
    console.print(f"  • {len(findings)} finding(s)")
    console.print("[bold red]Esta acción es irreversible.[/bold red]\n")

    if not args.yes:
        answer = console.input("¿Estás seguro? Escribe [bold]sí[/bold] para confirmar: ").strip().lower()
        if answer not in ("si", "sí", "s", "yes", "y"):
            console.print("[yellow]Cancelado, no se ha borrado nada.[/yellow]")
            return

    counts = delete_target(args.target)
    total = sum(counts.values())
    console.print(f"[green]Borrado completo: {total} fila(s) eliminadas de {args.target}.[/green]")


DB_ACTIONS = {
    "targets": run_db_targets,
    "findings": run_db_findings,
    "creds": run_db_creds,
    "delete": run_db_delete,
}


def run_db(args):
    action = DB_ACTIONS.get(args.db_action)
    if action is None:
        console.print("[yellow]No se ha especificado ninguna accion de db.[/yellow]")
        console.print("Acciones disponibles: [bold]targets, findings, creds[/bold]")
        console.print("Uso: [dim]lobera.py db <accion> -h[/dim] para ver las opciones de cada una.\n")
        return

    if getattr(args, "example", False):
        show_examples("db", args.db_action)
        return

    action(args)


# ============================================================
# Entry point
# ============================================================

def main():
    # Banner y comprobacion/creacion de la base de datos SIEMPRE se ejecutan
    # primero, antes de parsear argumentos -> asi salen incluso si faltan
    # argumentos obligatorios o si se ejecuta "lobera.py" sin nada.
    show_banner()
    is_first_run = init_db()

    # Login obligatorio contra la tabla 'auth' antes de permitir cualquier
    # operacion. Si es la primera ejecucion, init_db() ya genero el usuario
    # y mostro la contrasena temporal en el panel de bienvenida.
    if not auth.login():
        sys.exit(1)

    parser = build_parser()
    args = parser.parse_args()

    if args.module is None:
        # En la primera ejecucion el usuario ya ha visto de sobra (lobo,
        # credenciales, login, cambio de contrasena) -> no le añadimos
        # encima el aviso de "falta modulo" si solo estaba probando el
        # arranque sin dar ningun argumento todavia.
        if not is_first_run:
            console.print("[yellow]No se ha especificado ningun modulo.[/yellow]")
            console.print("Modulos disponibles: [bold]smb, db[/bold]")
            console.print("Uso: [dim]lobera.py <modulo> -h[/dim] para ver las acciones de cada uno.\n")
        return

    if args.module == "smb":
        run_smb(args)
    elif args.module == "db":
        run_db(args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[dim]Interrumpido por el usuario.[/dim]")
        sys.exit(130)
