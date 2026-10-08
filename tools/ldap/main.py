#!/usr/bin/env python3
# tools/ldap/main.py
"""
lobera-ldap — Enumeración y ataque sobre LDAP/Active Directory.

Subcomandos:
  enum        Información general del dominio vía LDAP
  users       Enumerar usuarios del dominio
  admins      Enumerar administradores del dominio
  groups      Enumerar grupos del dominio
  kerberoast  Obtener cuentas con SPN (objetivos Kerberoasting)
  asreproast  Obtener cuentas sin preautenticación Kerberos
  bloodhound  Exportar datos para BloodHound

Uso:
  lobera-ldap enum        -t 10.0.0.1 -u usuario -p contraseña -d dominio.local
  lobera-ldap users       -t 10.0.0.1 -u usuario -p contraseña -d dominio.local
  lobera-ldap admins      -t 10.0.0.1 -u usuario -p contraseña -d dominio.local
  lobera-ldap groups      -t 10.0.0.1 -u usuario -p contraseña -d dominio.local
  lobera-ldap kerberoast  -t 10.0.0.1 -u usuario -p contraseña -d dominio.local
  lobera-ldap asreproast  -t 10.0.0.1 -u usuario -p contraseña -d dominio.local
  lobera-ldap bloodhound  -t 10.0.0.1 -u usuario -p contraseña -d dominio.local

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
    spec = importlib.util.spec_from_file_location("_script_ldap", ruta)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ──────────────────────────────────────────────────────────────────────────────
# Subcomando: enum
# ──────────────────────────────────────────────────────────────────────────────

def cmd_enum(args):
    console.print(f"\n[bold cyan][ LDAP ENUM ] {args.target}[/bold cyan]")
    try:
        mod = _cargar_script("scripts/ldap/enum/domain-info.py")
        mod.run(
            target=args.target,
            port=args.port,
            user=args.user or '',
            password=args.password or '',
            domain=args.domain or '',
            timeout=args.timeout,
        )
    except ImportError as e:
        console.print(f"[red]Dependencia no disponible: {e}[/red]")


# ──────────────────────────────────────────────────────────────────────────────
# Subcomando: users
# ──────────────────────────────────────────────────────────────────────────────

def cmd_users(args):
    console.print(f"\n[bold cyan][ LDAP USERS ] {args.target}[/bold cyan]")
    try:
        from scripts.ldap.enum.users import run
        run(
            target=args.target,
            port=args.port,
            user=args.user or '',
            password=args.password or '',
            domain=args.domain or '',
            timeout=args.timeout,
        )
    except ImportError as e:
        console.print(f"[red]Dependencia no disponible: {e}[/red]")


# ──────────────────────────────────────────────────────────────────────────────
# Subcomando: admins
# ──────────────────────────────────────────────────────────────────────────────

def cmd_admins(args):
    console.print(f"\n[bold cyan][ LDAP ADMINS ] {args.target}[/bold cyan]")
    try:
        from scripts.ldap.enum.admins import run
        run(
            target=args.target,
            port=args.port,
            user=args.user or '',
            password=args.password or '',
            domain=args.domain or '',
            timeout=args.timeout,
        )
    except ImportError as e:
        console.print(f"[red]Dependencia no disponible: {e}[/red]")


# ──────────────────────────────────────────────────────────────────────────────
# Subcomando: groups
# ──────────────────────────────────────────────────────────────────────────────

def cmd_groups(args):
    console.print(f"\n[bold cyan][ LDAP GROUPS ] {args.target}[/bold cyan]")
    try:
        from scripts.ldap.enum.groups import run
        run(
            target=args.target,
            port=args.port,
            user=args.user or '',
            password=args.password or '',
            domain=args.domain or '',
            timeout=args.timeout,
        )
    except ImportError as e:
        console.print(f"[red]Dependencia no disponible: {e}[/red]")


# ──────────────────────────────────────────────────────────────────────────────
# Subcomando: kerberoast
# ──────────────────────────────────────────────────────────────────────────────

def cmd_kerberoast(args):
    console.print(f"\n[bold cyan][ LDAP KERBEROAST ] {args.target}[/bold cyan]")
    try:
        mod = _cargar_script("scripts/ldap/enum/kerberoast-targets.py")
        mod.run(
            target=args.target,
            port=args.port,
            user=args.user or '',
            password=args.password or '',
            domain=args.domain or '',
            timeout=args.timeout,
        )
    except ImportError as e:
        console.print(f"[red]Dependencia no disponible: {e}[/red]")


# ──────────────────────────────────────────────────────────────────────────────
# Subcomando: asreproast
# ──────────────────────────────────────────────────────────────────────────────

def cmd_asreproast(args):
    console.print(f"\n[bold cyan][ LDAP ASREPROAST ] {args.target}[/bold cyan]")
    try:
        mod = _cargar_script("scripts/ldap/enum/asreproast-targets.py")
        mod.run(
            target=args.target,
            port=args.port,
            user=args.user or '',
            password=args.password or '',
            domain=args.domain or '',
            timeout=args.timeout,
        )
    except ImportError as e:
        console.print(f"[red]Dependencia no disponible: {e}[/red]")


# ──────────────────────────────────────────────────────────────────────────────
# Subcomando: bloodhound
# ──────────────────────────────────────────────────────────────────────────────

def cmd_bloodhound(args):
    console.print(f"\n[bold cyan][ LDAP BLOODHOUND ] {args.target}[/bold cyan]")
    try:
        mod = _cargar_script("scripts/ldap/attack/bloodhound-export.py")
        mod.run(
            target=args.target,
            port=args.port,
            user=args.user or '',
            password=args.password or '',
            domain=args.domain or '',
            timeout=args.timeout,
        )
    except ImportError as e:
        console.print(f"[red]Dependencia no disponible: {e}[/red]")


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

def _parser_comun(sub):
    sub.add_argument('-t', '--target', required=True, metavar='IP')
    sub.add_argument('--port', type=int, default=389, metavar='PUERTO',
                     help='Puerto LDAP (default: 389)')
    sub.add_argument('-u', '--user', metavar='USUARIO')
    sub.add_argument('-p', '--password', metavar='CONTRASEÑA')
    sub.add_argument('-d', '--domain', metavar='DOMINIO', default='')
    sub.add_argument('--timeout', type=int, default=10)


def build_parser():
    parser = argparse.ArgumentParser(
        prog='lobera-ldap',
        description='Enumeración y ataque LDAP/Active Directory — lobera',
    )
    subs = parser.add_subparsers(dest='subcomando', required=True)

    # ── enum ──────────────────────────────────────────────────────────────────
    p_enum = subs.add_parser('enum', help='Información general del dominio vía LDAP')
    _parser_comun(p_enum)
    p_enum.set_defaults(func=cmd_enum)

    # ── users ─────────────────────────────────────────────────────────────────
    p_users = subs.add_parser('users', help='Enumerar usuarios del dominio')
    _parser_comun(p_users)
    p_users.set_defaults(func=cmd_users)

    # ── admins ────────────────────────────────────────────────────────────────
    p_admins = subs.add_parser('admins', help='Enumerar administradores del dominio')
    _parser_comun(p_admins)
    p_admins.set_defaults(func=cmd_admins)

    # ── groups ────────────────────────────────────────────────────────────────
    p_groups = subs.add_parser('groups', help='Enumerar grupos del dominio')
    _parser_comun(p_groups)
    p_groups.set_defaults(func=cmd_groups)

    # ── kerberoast ────────────────────────────────────────────────────────────
    p_kerb = subs.add_parser('kerberoast', help='Cuentas con SPN (objetivos Kerberoasting)')
    _parser_comun(p_kerb)
    p_kerb.set_defaults(func=cmd_kerberoast)

    # ── asreproast ────────────────────────────────────────────────────────────
    p_asrep = subs.add_parser('asreproast', help='Cuentas sin preautenticación Kerberos')
    _parser_comun(p_asrep)
    p_asrep.set_defaults(func=cmd_asreproast)

    # ── bloodhound ────────────────────────────────────────────────────────────
    p_bh = subs.add_parser('bloodhound', help='Exportar datos para BloodHound')
    _parser_comun(p_bh)
    p_bh.set_defaults(func=cmd_bloodhound)

    return parser


def _banner():
    from tools.common import banner, tabla_modos, ejemplos
    banner("lobera-ldap")
    tabla_modos([
        ("enum",        "Información general del dominio vía LDAP"),
        ("users",       "Enumerar usuarios del dominio"),
        ("admins",      "Enumerar administradores del dominio"),
        ("groups",      "Enumerar grupos del dominio"),
        ("kerberoast",  "Cuentas con SPN (objetivos Kerberoasting)"),
        ("asreproast",  "Cuentas sin preautenticación Kerberos"),
        ("bloodhound",  "Exportar datos para BloodHound"),
    ])
    ejemplos([
        "lobera-ldap enum       -t 10.10.10.5 -u usuario -p Pass123 -d dominio.local",
        "lobera-ldap users      -t 10.10.10.5 -u usuario -p Pass123 -d dominio.local",
        "lobera-ldap admins     -t 10.10.10.5 -u usuario -p Pass123 -d dominio.local",
        "lobera-ldap kerberoast -t 10.10.10.5 -u usuario -p Pass123 -d dominio.local",
        "lobera-ldap asreproast -t 10.10.10.5 -u usuario -p Pass123 -d dominio.local",
        "lobera-ldap bloodhound -t 10.10.10.5 -u usuario -p Pass123 -d dominio.local",
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
