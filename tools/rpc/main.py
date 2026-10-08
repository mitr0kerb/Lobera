#!/usr/bin/env python3
# tools/rpc/main.py
"""
lobera-rpc — Enumeración y explotación sobre RPC/MSRPC.

Subcomandos:
  enum         Mapear endpoints RPC del objetivo
  users        Enumerar usuarios vía RPC
  shares       Enumerar recursos compartidos vía RPC
  null         Comprobar sesión nula (null session)
  spooler      Comprobar/explotar Print Spooler (PrintNightmare)
  eternalblue  Comprobar vulnerabilidad EternalBlue (MS17-010)

Uso:
  lobera-rpc enum        -t 10.0.0.1
  lobera-rpc users       -t 10.0.0.1 -u usuario -p contraseña
  lobera-rpc shares      -t 10.0.0.1 -u usuario -p contraseña
  lobera-rpc null        -t 10.0.0.1
  lobera-rpc spooler     -t 10.0.0.1 -u usuario -p contraseña
  lobera-rpc eternalblue -t 10.0.0.1

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


def _cargar_script(ruta_relativa):
    """Carga un script Python por ruta de fichero (soporta guiones en el nombre)."""
    import importlib.util
    ruta = os.path.join(_ROOT, ruta_relativa)
    spec = importlib.util.spec_from_file_location("_script_rpc", ruta)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ──────────────────────────────────────────────────────────────────────────────
# Subcomando: enum
# ──────────────────────────────────────────────────────────────────────────────

def cmd_enum(args):
    console.print(f"\n[bold cyan][ RPC ENUM ] {args.target}[/bold cyan]")
    try:
        from scripts.rpc.enum.endpoint_mapper import run
        run(
            target=args.target,
            port=args.port,
            timeout=args.timeout,
        )
    except ImportError as e:
        console.print(f"[red]Dependencia no disponible: {e}[/red]")


# ──────────────────────────────────────────────────────────────────────────────
# Subcomando: users
# ──────────────────────────────────────────────────────────────────────────────

def cmd_users(args):
    console.print(f"\n[bold cyan][ RPC USERS ] {args.target}[/bold cyan]")
    try:
        from scripts.rpc.enum.users import run
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
# Subcomando: shares
# ──────────────────────────────────────────────────────────────────────────────

def cmd_shares(args):
    console.print(f"\n[bold cyan][ RPC SHARES ] {args.target}[/bold cyan]")
    try:
        from scripts.rpc.enum.shares import run
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
# Subcomando: null
# ──────────────────────────────────────────────────────────────────────────────

def cmd_null(args):
    console.print(f"\n[bold cyan][ RPC NULL SESSION ] {args.target}[/bold cyan]")
    try:
        from scripts.rpc.enum.null_session import run
        run(
            target=args.target,
            port=args.port,
            timeout=args.timeout,
        )
    except ImportError as e:
        console.print(f"[red]Dependencia no disponible: {e}[/red]")


# ──────────────────────────────────────────────────────────────────────────────
# Subcomando: spooler
# ──────────────────────────────────────────────────────────────────────────────

def cmd_spooler(args):
    console.print(f"\n[bold cyan][ RPC PRINT SPOOLER ] {args.target}[/bold cyan]")
    try:
        mod = _cargar_script("scripts/rpc/exploits/printspooler.py")
        mod.run(
            target=args.target,
            port=args.port,
            user=args.user or '',
            password=args.password or '',
            timeout=args.timeout,
        )
    except ImportError as e:
        console.print(f"[red]Dependencia no disponible: {e}[/red]")


# ──────────────────────────────────────────────────────────────────────────────
# Subcomando: eternalblue
# ──────────────────────────────────────────────────────────────────────────────

def cmd_eternalblue(args):
    console.print(f"\n[bold cyan][ RPC ETERNALBLUE CHECK ] {args.target}[/bold cyan]")
    try:
        mod = _cargar_script("scripts/rpc/exploits/eternalblue_check.py")
        mod.run(
            target=args.target,
            port=args.port,
            timeout=args.timeout,
        )
    except ImportError as e:
        console.print(f"[red]Dependencia no disponible: {e}[/red]")


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

def _parser_comun(sub, con_credenciales=True):
    sub.add_argument('-t', '--target', required=True, metavar='IP')
    sub.add_argument('--port', type=int, default=135, metavar='PUERTO',
                     help='Puerto RPC (default: 135)')
    sub.add_argument('--timeout', type=int, default=10)
    if con_credenciales:
        sub.add_argument('-u', '--user', metavar='USUARIO')
        sub.add_argument('-p', '--password', metavar='CONTRASEÑA')


def build_parser():
    parser = argparse.ArgumentParser(
        prog='lobera-rpc',
        description='Enumeración y explotación RPC/MSRPC — lobera',
    )
    subs = parser.add_subparsers(dest='subcomando', required=True)

    # ── enum ──────────────────────────────────────────────────────────────────
    p_enum = subs.add_parser('enum', help='Mapear endpoints RPC del objetivo')
    _parser_comun(p_enum, con_credenciales=False)
    p_enum.set_defaults(func=cmd_enum)

    # ── users ─────────────────────────────────────────────────────────────────
    p_users = subs.add_parser('users', help='Enumerar usuarios vía RPC')
    _parser_comun(p_users)
    p_users.set_defaults(func=cmd_users)

    # ── shares ────────────────────────────────────────────────────────────────
    p_shares = subs.add_parser('shares', help='Enumerar recursos compartidos vía RPC')
    _parser_comun(p_shares)
    p_shares.set_defaults(func=cmd_shares)

    # ── null ──────────────────────────────────────────────────────────────────
    p_null = subs.add_parser('null', help='Comprobar sesión nula (null session)')
    _parser_comun(p_null, con_credenciales=False)
    p_null.set_defaults(func=cmd_null)

    # ── spooler ───────────────────────────────────────────────────────────────
    p_spooler = subs.add_parser('spooler', help='Comprobar/explotar Print Spooler (PrintNightmare)')
    _parser_comun(p_spooler)
    p_spooler.set_defaults(func=cmd_spooler)

    # ── eternalblue ───────────────────────────────────────────────────────────
    p_eb = subs.add_parser('eternalblue', help='Comprobar vulnerabilidad EternalBlue (MS17-010)')
    _parser_comun(p_eb, con_credenciales=False)
    p_eb.set_defaults(func=cmd_eternalblue)

    return parser


def _banner():
    from tools.common import banner, tabla_modos, ejemplos
    banner("lobera-rpc")
    tabla_modos([
        ("enum",        "Mapear endpoints RPC del objetivo"),
        ("users",       "Enumerar usuarios vía RPC"),
        ("shares",      "Enumerar recursos compartidos vía RPC"),
        ("null",        "Comprobar sesión nula (null session)"),
        ("spooler",     "Comprobar/explotar Print Spooler (PrintNightmare)"),
        ("eternalblue", "Comprobar vulnerabilidad EternalBlue (MS17-010)"),
    ])
    ejemplos([
        "lobera-rpc enum        -t 10.10.10.5",
        "lobera-rpc users       -t 10.10.10.5 -u '' -p ''",
        "lobera-rpc shares      -t 10.10.10.5 -u usuario -p Pass123",
        "lobera-rpc null        -t 10.10.10.5",
        "lobera-rpc spooler     -t 10.10.10.5 -u usuario -p Pass123",
        "lobera-rpc eternalblue -t 10.10.10.5",
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
