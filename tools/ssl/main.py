#!/usr/bin/env python3
# tools/ssl/main.py
"""
lobera-ssl — Análisis y ataques SSL/TLS sobre un objetivo.

Subcomandos:
  enum     Enumeración de certificado y metadatos SSL
  ciphers  Enumeración de cifrados soportados
  attack   Ataques conocidos SSL/TLS (POODLE, BEAST, CRIME, etc.)
  check    Comprobación de vulnerabilidades (Heartbleed, etc.)

Uso:
  lobera-ssl enum    -t 10.0.0.1
  lobera-ssl ciphers -t 10.0.0.1 --port 8443
  lobera-ssl attack  -t 10.0.0.1
  lobera-ssl check   -t 10.0.0.1

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
# Subcomando: enum
# ──────────────────────────────────────────────────────────────────────────────

def cmd_enum(args):
    console.print(f"\n[bold cyan][ SSL ENUM ] {args.target}:{args.port}[/bold cyan]")
    try:
        from scripts.ssl.enum.cert_info import run as run_enum
        run_enum(target=args.target, port=args.port, timeout=args.timeout)
    except ImportError:
        console.print("[yellow]Módulo scripts/ssl/enum/cert_info no implementado aún.[/yellow]")


# ──────────────────────────────────────────────────────────────────────────────
# Subcomando: ciphers
# ──────────────────────────────────────────────────────────────────────────────

def cmd_ciphers(args):
    console.print(f"\n[bold cyan][ SSL CIPHERS ] {args.target}:{args.port}[/bold cyan]")
    try:
        from scripts.ssl.enum.cipher_enum import run as run_ciphers
        run_ciphers(target=args.target, port=args.port, timeout=args.timeout)
    except ImportError:
        console.print("[yellow]Módulo scripts/ssl/enum/cipher_enum no implementado aún.[/yellow]")


# ──────────────────────────────────────────────────────────────────────────────
# Subcomando: attack
# ──────────────────────────────────────────────────────────────────────────────

def cmd_attack(args):
    console.print(f"\n[bold cyan][ SSL ATTACK ] {args.target}:{args.port}[/bold cyan]")
    try:
        from scripts.ssl.attack.poodle import run as run_attack
        run_attack(target=args.target, port=args.port, timeout=args.timeout)
    except ImportError:
        console.print("[yellow]Módulo scripts/ssl/attack/poodle no implementado aún.[/yellow]")
        console.print("[dim]Ataques disponibles cuando se implementen: POODLE, BEAST, LUCKY13, CRIME/BREACH, SWEET32, DROWN[/dim]")


# ──────────────────────────────────────────────────────────────────────────────
# Subcomando: check
# ──────────────────────────────────────────────────────────────────────────────

def cmd_check(args):
    console.print(f"\n[bold cyan][ SSL CHECK ] {args.target}:{args.port}[/bold cyan]")
    try:
        from scripts.ssl.enum.heartbleed_check import run as run_check
        run_check(target=args.target, port=args.port, timeout=args.timeout)
    except ImportError:
        console.print("[yellow]Módulo scripts/ssl/enum/heartbleed_check no implementado aún.[/yellow]")


# ──────────────────────────────────────────────────────────────────────────────
# Flags comunes
# ──────────────────────────────────────────────────────────────────────────────

def _flags_comunes(sub):
    sub.add_argument('-t', '--target', required=True, metavar='IP/HOST')
    sub.add_argument('--port', type=int, default=443, metavar='PUERTO',
                     help='Puerto SSL/TLS (default: 443)')
    sub.add_argument('--timeout', type=int, default=10)


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

def build_parser():
    parser = argparse.ArgumentParser(
        prog='lobera-ssl',
        description='Análisis SSL/TLS — lobera',
    )
    subs = parser.add_subparsers(dest='subcomando', required=True)

    # ── enum ──────────────────────────────────────────────────────────────────
    p_enum = subs.add_parser('enum', help='Enumeración de certificado SSL')
    _flags_comunes(p_enum)
    p_enum.set_defaults(func=cmd_enum)

    # ── ciphers ───────────────────────────────────────────────────────────────
    p_ciphers = subs.add_parser('ciphers', help='Enumeración de cifrados SSL/TLS')
    _flags_comunes(p_ciphers)
    p_ciphers.set_defaults(func=cmd_ciphers)

    # ── attack ────────────────────────────────────────────────────────────────
    p_attack = subs.add_parser('attack', help='Ataques SSL/TLS (POODLE, BEAST, etc.)')
    _flags_comunes(p_attack)
    p_attack.set_defaults(func=cmd_attack)

    # ── check ─────────────────────────────────────────────────────────────────
    p_check = subs.add_parser('check', help='Comprobación de vulnerabilidades (Heartbleed, etc.)')
    _flags_comunes(p_check)
    p_check.set_defaults(func=cmd_check)

    return parser


def _banner():
    from tools.common import banner, tabla_modos, ejemplos
    banner("lobera-ssl")
    tabla_modos([
        ("enum",    "Enumeración de certificado y metadatos SSL/TLS"),
        ("ciphers", "Enumeración de cifrados soportados"),
        ("attack",  "Ataques SSL/TLS (POODLE, BEAST, LUCKY13, CRIME, etc.)"),
        ("check",   "Comprobación de vulnerabilidades (Heartbleed, etc.)"),
    ])
    ejemplos([
        "lobera-ssl enum    -t 10.10.10.5",
        "lobera-ssl enum    -t 10.10.10.5 --port 8443",
        "lobera-ssl ciphers -t 10.10.10.5",
        "lobera-ssl attack  -t 10.10.10.5",
        "lobera-ssl check   -t 10.10.10.5",
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
