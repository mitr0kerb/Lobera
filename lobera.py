#!/usr/bin/env python3
# lobera.py

import argparse
import sys

from core.session_db import init_db
from core.target import Target
from core.credentials import Creds
from core.output import console
from modules.smb import SMBModule
from modules.smb_shell import SMBShell
from utils.banner import show_banner


def add_common_target_args(parser):
    """Argumentos comunes a toda acción de cualquier módulo (target, credenciales)."""
    parser.add_argument("-t", "--target", required=True, help="IP o hostname del objetivo")
    parser.add_argument("-u", "--user", default="", help="Usuario")
    parser.add_argument("-p", "--password", default="", help="Contraseña")
    parser.add_argument("-H", "--hash", default=None, help="Hash NT (o LM:NT) para pass-the-hash")
    parser.add_argument("-d", "--domain", default="", help="Dominio")
    parser.add_argument("--timeout", type=int, default=5, help="Timeout de conexión en segundos (default: 5)")


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

    # --- smb enum: reconocimiento, sin tocar nada ---
    enum_parser = smb_subparsers.add_parser("enum", help="Enumeración: shares, signing, null session")
    add_common_target_args(enum_parser)
    enum_parser.add_argument("--smb-version", choices=["v1", "v2", "v2.1", "v3"], default=None,
                              help="Fuerza una versión de SMB (por defecto: negociación automática)")
    enum_parser.add_argument("--shares", action="store_true", help="Lista los shares disponibles")
    enum_parser.add_argument("--signing", action="store_true", help="Comprueba si el objetivo exige SMB signing")
    enum_parser.add_argument("--null-sess", action="store_true",
                              help="Comprueba si el objetivo permite SMB null session")

    # --- smb spider: rastreo y descarga ---
    spider_parser = smb_subparsers.add_parser("spider", help="Rastrea shares y descarga ficheros interesantes")
    add_common_target_args(spider_parser)
    spider_parser.add_argument("--share", metavar="SHARE", default=None,
                                help="Share concreto a rastrear. Si se omite, rastrea TODOS los shares no especiales")
    spider_parser.add_argument("--ext", default=None,
                                help="Extensiones a buscar, separadas por coma (ej: .txt,.kdbx). "
                                     "Vacío ('') = sin filtro de extensión. Si no se indica, usa las de por defecto.")
    spider_parser.add_argument("--keywords", default=None,
                                help="Palabras clave a buscar en nombres de fichero, separadas por coma")
    spider_parser.add_argument("--depth", type=int, default=5,
                                help="Profundidad máxima de recursión (default: 5)")

    # --- smb spray: ataque de fuerza sobre credenciales ---
    spray_parser = smb_subparsers.add_parser("spray", help="Password spraying contra una lista de usuarios")
    add_common_target_args(spray_parser)
    spray_parser.add_argument("--userlist", required=True, metavar="FILE",
                               help="Fichero con una lista de usuarios, uno por línea")

    # --- smb shell: consola interactiva ---
    shell_parser = smb_subparsers.add_parser("shell", help="Abre una consola interactiva SMB")
    add_common_target_args(shell_parser)

    # ============================================================
    # Futuros módulos: rpc, kerberos, ldap, winrm irán aquí igual,
    # cada uno con su propio smb_subparsers-equivalente si aplica.
    # ============================================================

    return parser


def parse_csv(raw):
    if raw is None:
        return None
    if raw == "":
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]


def run_smb_enum(args):
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
    target = Target(ip=args.target, domain=args.domain, timeout=args.timeout)
    creds = Creds(user=args.user, password=args.password, domain=args.domain, hash=args.hash)
    smb = SMBModule(target, creds)

    if not smb.connect():
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
        console.print("[yellow]No se ha especificado ninguna acción de SMB.[/yellow]")
        console.print("Acciones disponibles: [bold]enum, spider, spray, shell[/bold]")
        console.print("Uso: [dim]lobera.py smb <acción> -h[/dim] para ver las opciones de cada una.\n")
        return
    action(args)


def main():
    # Banner y comprobación/creación de la base de datos SIEMPRE se ejecutan
    # primero, antes de parsear argumentos -> así salen incluso si faltan
    # argumentos obligatorios o si se ejecuta "lobera.py" sin nada.
    show_banner()
    init_db()

    parser = build_parser()
    args = parser.parse_args()

    if args.module is None:
        console.print("[yellow]No se ha especificado ningún módulo.[/yellow]")
        console.print("Módulos disponibles: [bold]smb[/bold]")
        console.print("Uso: [dim]lobera.py <módulo> -h[/dim] para ver las acciones de cada uno.\n")
        return

    if args.module == "smb":
        run_smb(args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[dim]Interrumpido por el usuario.[/dim]")
        sys.exit(130)
