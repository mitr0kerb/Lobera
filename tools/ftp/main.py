#!/usr/bin/env python3
# tools/ftp/main.py
"""
lobera-ftp — Operaciones FTP sobre un objetivo.

Subcomandos:
  enum    Enumeración de banner y servicio FTP
  anon    Comprobación de acceso anónimo FTP
  spray   Password spray contra FTP
  brute   Fuerza bruta de credenciales FTP
  exploit Explotar backdoor vsftpd
  post    Descarga de archivos (loot)

Uso:
  lobera-ftp enum    -t 10.0.0.1
  lobera-ftp anon    -t 10.0.0.1
  lobera-ftp spray   -t 10.0.0.1 -U usuarios.txt -P passwords.txt
  lobera-ftp brute   -t 10.0.0.1 -u admin -P passwords.txt
  lobera-ftp exploit -t 10.0.0.1
  lobera-ftp post    -t 10.0.0.1 -u admin -p pass123
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
    try:
        from scripts.ftp.enum.banner_grab import run
    except ImportError as e:
        console.print(f"[red]No se pudo importar el módulo de enumeración FTP: {e}[/red]")
        return
    console.print(f"\n[bold cyan][ FTP ENUM ] {args.target}[/bold cyan]")
    run(target=args.target, port=args.port, timeout=args.timeout)


# ──────────────────────────────────────────────────────────────────────────────
# Subcomando: anon
# ──────────────────────────────────────────────────────────────────────────────

def cmd_anon(args):
    try:
        from scripts.ftp.enum.anon_check import run
    except ImportError as e:
        console.print(f"[red]No se pudo importar el módulo de comprobación anónima FTP: {e}[/red]")
        return
    console.print(f"\n[bold cyan][ FTP ANON ] {args.target}[/bold cyan]")
    run(target=args.target, port=args.port, timeout=args.timeout)


# ──────────────────────────────────────────────────────────────────────────────
# Subcomando: spray
# ──────────────────────────────────────────────────────────────────────────────

def cmd_spray(args):
    try:
        from scripts.ftp.attack.password_spray import run
    except ImportError as e:
        console.print(f"[red]No se pudo importar el módulo de spray FTP: {e}[/red]")
        return
    console.print(f"\n[bold cyan][ FTP SPRAY ] {args.target}[/bold cyan]")

    usuarios  = _leer_lista(args.user_list, args.user)
    passwords = _leer_lista(args.pass_list, args.password)
    if not usuarios:
        console.print("[red]Necesitas -u <usuario> o -U <fichero>.[/red]")
        return
    if not passwords:
        console.print("[red]Necesitas -p <pass> o -P <fichero>.[/red]")
        return

    run(
        target=args.target,
        port=args.port,
        usuarios=usuarios,
        passwords=passwords,
        delay=args.delay,
        timeout=args.timeout,
    )


# ──────────────────────────────────────────────────────────────────────────────
# Subcomando: brute
# ──────────────────────────────────────────────────────────────────────────────

def cmd_brute(args):
    try:
        from scripts.ftp.attack.brute_force import run
    except ImportError as e:
        console.print(f"[red]No se pudo importar el módulo de fuerza bruta FTP: {e}[/red]")
        return
    console.print(f"\n[bold cyan][ FTP BRUTE ] {args.target}[/bold cyan]")

    usuarios  = _leer_lista(args.user_list, args.user)
    passwords = _leer_lista(args.pass_list, args.password)
    if not usuarios:
        console.print("[red]Necesitas -u <usuario> o -U <fichero>.[/red]")
        return
    if not passwords:
        console.print("[red]Necesitas -p <pass> o -P <fichero>.[/red]")
        return

    run(
        target=args.target,
        port=args.port,
        usuarios=usuarios,
        passwords=passwords,
        delay=args.delay,
        timeout=args.timeout,
    )


# ──────────────────────────────────────────────────────────────────────────────
# Subcomando: exploit
# ──────────────────────────────────────────────────────────────────────────────

def cmd_exploit(args):
    try:
        from scripts.ftp.exploit.vsftpd_backdoor import run
    except ImportError as e:
        console.print(f"[red]No se pudo importar el módulo de exploit vsftpd: {e}[/red]")
        return
    console.print(f"\n[bold cyan][ FTP EXPLOIT ] {args.target}[/bold cyan]")
    run(target=args.target, port=args.port, timeout=args.timeout)


# ──────────────────────────────────────────────────────────────────────────────
# Subcomando: post
# ──────────────────────────────────────────────────────────────────────────────

def cmd_post(args):
    try:
        from scripts.ftp.post.download_loot import run
    except ImportError as e:
        console.print(f"[red]No se pudo importar el módulo de post-explotación FTP: {e}[/red]")
        return
    console.print(f"\n[bold cyan][ FTP POST ] {args.target}[/bold cyan]")
    run(
        target=args.target,
        port=args.port,
        user=args.user or '',
        password=args.password or '',
        timeout=args.timeout,
    )


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

def _flags_comunes(sub, puerto_default=21):
    sub.add_argument('-t', '--target', required=True, metavar='IP/HOST')
    sub.add_argument('--port', type=int, default=puerto_default, metavar='PUERTO')
    sub.add_argument('--timeout', type=int, default=10)


def build_parser():
    parser = argparse.ArgumentParser(
        prog='lobera-ftp',
        description='Operaciones FTP — lobera',
    )
    subs = parser.add_subparsers(dest='subcomando', required=True)

    # ── enum ──────────────────────────────────────────────────────────────────
    p_enum = subs.add_parser('enum', help='Enumerar banner y servicio FTP')
    _flags_comunes(p_enum)
    p_enum.set_defaults(func=cmd_enum)

    # ── anon ──────────────────────────────────────────────────────────────────
    p_anon = subs.add_parser('anon', help='Comprobar acceso anónimo FTP')
    _flags_comunes(p_anon)
    p_anon.set_defaults(func=cmd_anon)

    # ── spray ─────────────────────────────────────────────────────────────────
    p_spray = subs.add_parser('spray', help='Password spray contra FTP')
    _flags_comunes(p_spray)
    p_spray.add_argument('-u', '--user', metavar='USUARIO')
    p_spray.add_argument('-U', '--user-list', metavar='FICHERO')
    p_spray.add_argument('-p', '--password', metavar='CONTRASEÑA')
    p_spray.add_argument('-P', '--pass-list', metavar='FICHERO')
    p_spray.add_argument('--delay', type=float, default=0.5, metavar='SEGUNDOS')
    p_spray.set_defaults(func=cmd_spray)

    # ── brute ─────────────────────────────────────────────────────────────────
    p_brute = subs.add_parser('brute', help='Fuerza bruta de credenciales FTP')
    _flags_comunes(p_brute)
    p_brute.add_argument('-u', '--user', metavar='USUARIO')
    p_brute.add_argument('-U', '--user-list', metavar='FICHERO')
    p_brute.add_argument('-p', '--password', metavar='CONTRASEÑA')
    p_brute.add_argument('-P', '--pass-list', metavar='FICHERO')
    p_brute.add_argument('--delay', type=float, default=0.5, metavar='SEGUNDOS')
    p_brute.set_defaults(func=cmd_brute)

    # ── exploit ───────────────────────────────────────────────────────────────
    p_exploit = subs.add_parser('exploit', help='Explotar backdoor vsftpd')
    _flags_comunes(p_exploit)
    p_exploit.set_defaults(func=cmd_exploit)

    # ── post ──────────────────────────────────────────────────────────────────
    p_post = subs.add_parser('post', help='Descargar archivos tras comprometer FTP')
    _flags_comunes(p_post)
    p_post.add_argument('-u', '--user', metavar='USUARIO')
    p_post.add_argument('-p', '--password', metavar='CONTRASEÑA')
    p_post.set_defaults(func=cmd_post)

    return parser


def _banner():
    from tools.common import banner, tabla_modos, ejemplos
    banner("lobera-ftp")
    tabla_modos([
        ("enum",    "Enumerar banner y servicio FTP"),
        ("anon",    "Comprobar acceso anónimo FTP"),
        ("spray",   "Password spray contra FTP"),
        ("brute",   "Fuerza bruta de credenciales FTP"),
        ("exploit", "Explotar backdoor vsftpd 2.3.4"),
        ("post",    "Descargar archivos tras compromiso FTP"),
    ])
    ejemplos([
        "lobera-ftp enum    -t 10.10.10.5",
        "lobera-ftp anon    -t 10.10.10.5 --port 21",
        "lobera-ftp spray   -t 10.10.10.5 -U usuarios.txt -P passwords.txt",
        "lobera-ftp brute   -t 10.10.10.5 -u admin -P passwords.txt",
        "lobera-ftp exploit -t 10.10.10.5",
        "lobera-ftp post    -t 10.10.10.5 -u ftpuser -p pass123",
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
