#!/usr/bin/env python3
# tools/winrm/main.py
"""
lobera-winrm — Operaciones WinRM sobre un objetivo Windows/AD.

Subcomandos:
  check   Verificar si WinRM está habilitado y accesible
  exec    Ejecutar comando remoto vía WinRM
  spray   Password spray contra WinRM
  shell   Shell interactiva WinRM

Uso:
  lobera-winrm check  -t 10.0.0.1
  lobera-winrm exec   -t 10.0.0.1 -u admin -p pass -c whoami
  lobera-winrm spray  -t 10.0.0.1 -U usuarios.txt -P passwords.txt
  lobera-winrm shell  -t 10.0.0.1 -u admin -p pass
"""

import sys
import os
import argparse

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from core.output import console
from core.session_db import init_db
from core.hooks import add_args_on_hash_crack


# ──────────────────────────────────────────────────────────────────────────────
# Subcomando: check
# ──────────────────────────────────────────────────────────────────────────────

def cmd_check(args):
    from scripts.winrm.enum.check import run as run_check
    console.print(f"\n[bold cyan][ WINRM CHECK ] {args.target}[/bold cyan]")
    run_check(target=args.target, port=args.port, ssl=args.ssl, timeout=args.timeout)


# ──────────────────────────────────────────────────────────────────────────────
# Subcomando: exec
# ──────────────────────────────────────────────────────────────────────────────

def cmd_exec(args):
    from scripts.winrm.exploits.evil_winrm_payload import run as run_exec
    console.print(f"\n[bold cyan][ WINRM EXEC ] {args.target}[/bold cyan]")
    run_exec(
        target=args.target,
        port=args.port,
        user=args.user or '',
        password=args.password or '',
        domain=args.domain or '',
        cmd=args.cmd,
        ssl=args.ssl,
        timeout=args.timeout,
    )


# ──────────────────────────────────────────────────────────────────────────────
# Subcomando: spray
# ──────────────────────────────────────────────────────────────────────────────

def cmd_spray(args):
    from scripts.winrm.attack.password_spray import run as run_spray
    from core.hooks import on_hash_capturado

    console.print(f"\n[bold cyan][ WINRM SPRAY ] {args.target}[/bold cyan]")

    usuarios  = _leer_lista(args.user_list, args.user)
    passwords = _leer_lista(args.pass_list, args.password)
    if not usuarios:
        console.print("[red]Necesitas -u <usuario> o -U <fichero>.[/red]")
        return
    if not passwords:
        console.print("[red]Necesitas -p <pass> o -P <fichero>.[/red]")
        return

    encontrados = run_spray(
        target=args.target,
        port=args.port,
        usuarios=usuarios,
        passwords=passwords,
        domain=args.domain or '',
        ssl=args.ssl,
        timeout=args.timeout,
        delay=args.delay,
    )

    for cred in encontrados:
        console.print(f"  [green]✓[/green] {cred['user']} : {cred['password']}")


# ──────────────────────────────────────────────────────────────────────────────
# Subcomando: shell
# ──────────────────────────────────────────────────────────────────────────────

def cmd_shell(args):
    from modules.winrm_shell import WinRMShell
    console.print(f"\n[bold cyan][ WINRM SHELL ] {args.target}[/bold cyan]")
    shell = WinRMShell(
        target=args.target,
        port=args.port,
        user=args.user or '',
        password=args.password or '',
        domain=args.domain or '',
        ssl=args.ssl,
        timeout=args.timeout,
    )
    shell.run()


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
# CLI
# ──────────────────────────────────────────────────────────────────────────────

def _parser_comun(sub):
    sub.add_argument('-t', '--target', required=True, metavar='IP')
    sub.add_argument('--port', type=int, default=5985, metavar='PUERTO',
                     help='Puerto WinRM (default: 5985, SSL: 5986)')
    sub.add_argument('-u', '--user', metavar='USUARIO')
    sub.add_argument('-p', '--password', metavar='CONTRASEÑA')
    sub.add_argument('-d', '--domain', metavar='DOMINIO', default='')
    sub.add_argument('--ssl', action='store_true', help='Usar HTTPS (puerto 5986)')
    sub.add_argument('--timeout', type=int, default=10)


def build_parser():
    parser = argparse.ArgumentParser(
        prog='lobera-winrm',
        description='Operaciones WinRM — lobera',
    )
    subs = parser.add_subparsers(dest='subcomando', required=True)

    # ── check ─────────────────────────────────────────────────────────────────
    p_check = subs.add_parser('check', help='Verificar acceso WinRM')
    _parser_comun(p_check)
    p_check.set_defaults(func=cmd_check)

    # ── exec ──────────────────────────────────────────────────────────────────
    p_exec = subs.add_parser('exec', help='Ejecutar comando remoto')
    _parser_comun(p_exec)
    p_exec.add_argument('-c', '--cmd', required=True, metavar='COMANDO')
    p_exec.set_defaults(func=cmd_exec)

    # ── spray ─────────────────────────────────────────────────────────────────
    p_spray = subs.add_parser('spray', help='Password spray WinRM')
    _parser_comun(p_spray)
    p_spray.add_argument('-U', '--user-list', metavar='FICHERO')
    p_spray.add_argument('-P', '--pass-list', metavar='FICHERO')
    p_spray.add_argument('--delay', type=float, default=0.5, metavar='SEGUNDOS')
    add_args_on_hash_crack(p_spray)
    p_spray.set_defaults(func=cmd_spray)

    # ── shell ─────────────────────────────────────────────────────────────────
    p_shell = subs.add_parser('shell', help='Shell interactiva WinRM')
    _parser_comun(p_shell)
    p_shell.set_defaults(func=cmd_shell)

    return parser


def _banner():
    from tools.common import banner, tabla_modos, ejemplos
    banner("lobera-winrm  —  Operaciones WinRM / PowerShell Remoting")
    tabla_modos([
        ("check", "Verificar acceso WinRM con credenciales"),
        ("exec",  "Ejecutar comando remoto vía WinRM"),
        ("spray", "Password spray contra WinRM"),
        ("shell", "Shell interactiva WinRM/PowerShell"),
    ])
    ejemplos([
        "lobera-winrm check  -t 10.10.10.5 -u Administrator -p Pass123",
        "lobera-winrm exec   -t 10.10.10.5 -u Administrator -p Pass123 -c whoami",
        "lobera-winrm spray  -t 10.10.10.5 -u Administrator -P passwords.txt",
        "lobera-winrm shell  -t 10.10.10.5 -u Administrator -p Pass123",
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
