#!/usr/bin/env python3
# tools/ssh/main.py
"""
lobera-ssh — Operaciones SSH sobre un objetivo.

Subcomandos:
  enum    Enumeración de banner, fingerprint y métodos de autenticación
  spray   Password spray contra SSH
  brute   Fuerza bruta de credenciales SSH
  exec    Ejecución de comando remoto (bypass o credenciales)
  shell   Shell interactiva SSH

Uso:
  lobera-ssh enum   -t 10.0.0.1
  lobera-ssh spray  -t 10.0.0.1 -U usuarios.txt -P passwords.txt
  lobera-ssh brute  -t 10.0.0.1 -u root -P passwords.txt
  lobera-ssh exec   -t 10.0.0.1 -u admin -p pass -c whoami
  lobera-ssh shell  -t 10.0.0.1 -u admin -p pass

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
    console.print(f"\n[bold cyan][ SSH ENUM ] {args.target}[/bold cyan]")
    try:
        from scripts.ssh.enum.banner_grab import run as run_enum
        run_enum(target=args.target, port=args.port, timeout=args.timeout)
    except ImportError:
        console.print("[yellow]Módulo scripts/ssh/enum/banner_grab no implementado aún.[/yellow]")


# ──────────────────────────────────────────────────────────────────────────────
# Subcomando: spray
# ──────────────────────────────────────────────────────────────────────────────

def cmd_spray(args):
    console.print(f"\n[bold cyan][ SSH SPRAY ] {args.target}[/bold cyan]")

    usuarios  = _leer_lista(args.user_list, args.user)
    passwords = _leer_lista(args.pass_list, args.password)

    if not usuarios:
        console.print("[red]Necesitas -u <usuario> o -U <fichero>.[/red]")
        return
    if not passwords:
        console.print("[red]Necesitas -p <pass> o -P <fichero>.[/red]")
        return

    try:
        from scripts.ssh.attack.password_spray import run as run_spray
        encontrados = run_spray(
            target=args.target,
            port=args.port,
            usuarios=usuarios,
            passwords=passwords,
            delay=args.delay,
            timeout=args.timeout,
        )
        for cred in (encontrados or []):
            console.print(f"  [green]✓[/green] {cred['user']} : {cred['password']}")
    except ImportError:
        console.print("[yellow]Módulo scripts/ssh/attack/password_spray no implementado aún.[/yellow]")


# ──────────────────────────────────────────────────────────────────────────────
# Subcomando: brute
# ──────────────────────────────────────────────────────────────────────────────

def cmd_brute(args):
    console.print(f"\n[bold cyan][ SSH BRUTE ] {args.target}[/bold cyan]")

    usuarios  = _leer_lista(args.user_list, args.user)
    passwords = _leer_lista(args.pass_list, args.password)

    if not usuarios:
        console.print("[red]Necesitas -u <usuario> o -U <fichero>.[/red]")
        return
    if not passwords:
        console.print("[red]Necesitas -p <pass> o -P <fichero>.[/red]")
        return

    try:
        from scripts.ssh.attack.brute_force import run as run_brute
        encontrados = run_brute(
            target=args.target,
            port=args.port,
            usuarios=usuarios,
            passwords=passwords,
            delay=args.delay,
            timeout=args.timeout,
        )
        for cred in (encontrados or []):
            console.print(f"  [green]✓[/green] {cred['user']} : {cred['password']}")
    except ImportError:
        console.print("[yellow]Módulo scripts/ssh/attack/brute_force no implementado aún.[/yellow]")


# ──────────────────────────────────────────────────────────────────────────────
# Subcomando: exec
# ──────────────────────────────────────────────────────────────────────────────

def cmd_exec(args):
    console.print(f"\n[bold cyan][ SSH EXEC ] {args.target}[/bold cyan]")
    try:
        from scripts.ssh.exploits.libssh_bypass import run as run_exec
        run_exec(
            target=args.target,
            port=args.port,
            user=args.user or '',
            password=args.password or '',
            cmd=args.cmd,
            timeout=args.timeout,
        )
    except ImportError:
        console.print("[yellow]Módulo scripts/ssh/exploits/libssh_bypass no implementado aún.[/yellow]")


# ──────────────────────────────────────────────────────────────────────────────
# Subcomando: shell
# ──────────────────────────────────────────────────────────────────────────────

def cmd_shell(args):
    console.print(f"\n[bold cyan][ SSH SHELL ] {args.target}[/bold cyan]")
    try:
        import paramiko
    except ImportError:
        console.print("[red]Paramiko no instalado. Instala con: pip install paramiko[/red]")
        return

    try:
        cliente = paramiko.SSHClient()
        cliente.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        cliente.connect(
            hostname=args.target,
            port=args.port,
            username=args.user or '',
            password=args.password or '',
            timeout=args.timeout,
        )
        canal = cliente.invoke_shell()
        console.print("[green]Sesión SSH abierta. Escribe 'exit' para salir.[/green]")

        import select
        import termios
        import tty

        fd_orig = sys.stdin.fileno()
        orig_attrs = termios.tcgetattr(fd_orig)
        try:
            tty.setraw(fd_orig)
            while True:
                r, _, _ = select.select([canal, sys.stdin], [], [], 0.1)
                if canal in r:
                    datos = canal.recv(1024)
                    if not datos:
                        break
                    sys.stdout.buffer.write(datos)
                    sys.stdout.buffer.flush()
                if sys.stdin in r:
                    tecla = sys.stdin.buffer.read(1)
                    if not tecla:
                        break
                    canal.send(tecla)
        finally:
            termios.tcsetattr(fd_orig, termios.TCSADRAIN, orig_attrs)

        canal.close()
        cliente.close()
    except Exception as e:
        console.print(f"[red]Error al abrir shell SSH: {e}[/red]")


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
# Flags comunes
# ──────────────────────────────────────────────────────────────────────────────

def _flags_comunes(sub):
    sub.add_argument('-t', '--target', required=True, metavar='IP/HOST')
    sub.add_argument('--port', type=int, default=22, metavar='PUERTO',
                     help='Puerto SSH (default: 22)')
    sub.add_argument('--timeout', type=int, default=10)


def _flags_credenciales(sub):
    sub.add_argument('-u', '--user', metavar='USUARIO')
    sub.add_argument('-U', '--user-list', metavar='FICHERO')
    sub.add_argument('-p', '--password', metavar='CONTRASEÑA')
    sub.add_argument('-P', '--pass-list', metavar='FICHERO')


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

def build_parser():
    parser = argparse.ArgumentParser(
        prog='lobera-ssh',
        description='Operaciones SSH — lobera',
    )
    subs = parser.add_subparsers(dest='subcomando', required=True)

    # ── enum ──────────────────────────────────────────────────────────────────
    p_enum = subs.add_parser('enum', help='Enumeración SSH (banner, fingerprint, métodos)')
    _flags_comunes(p_enum)
    p_enum.set_defaults(func=cmd_enum)

    # ── spray ─────────────────────────────────────────────────────────────────
    p_spray = subs.add_parser('spray', help='Password spray SSH')
    _flags_comunes(p_spray)
    _flags_credenciales(p_spray)
    p_spray.add_argument('--delay', type=float, default=0.5, metavar='SEGUNDOS')
    p_spray.set_defaults(func=cmd_spray)

    # ── brute ─────────────────────────────────────────────────────────────────
    p_brute = subs.add_parser('brute', help='Fuerza bruta SSH')
    _flags_comunes(p_brute)
    _flags_credenciales(p_brute)
    p_brute.add_argument('--delay', type=float, default=0.3, metavar='SEGUNDOS')
    p_brute.set_defaults(func=cmd_brute)

    # ── exec ──────────────────────────────────────────────────────────────────
    p_exec = subs.add_parser('exec', help='Ejecutar comando remoto SSH')
    _flags_comunes(p_exec)
    p_exec.add_argument('-u', '--user', metavar='USUARIO')
    p_exec.add_argument('-p', '--password', metavar='CONTRASEÑA')
    p_exec.add_argument('-c', '--cmd', required=True, metavar='COMANDO')
    p_exec.set_defaults(func=cmd_exec)

    # ── shell ─────────────────────────────────────────────────────────────────
    p_shell = subs.add_parser('shell', help='Shell interactiva SSH')
    _flags_comunes(p_shell)
    p_shell.add_argument('-u', '--user', metavar='USUARIO')
    p_shell.add_argument('-p', '--password', metavar='CONTRASEÑA')
    p_shell.set_defaults(func=cmd_shell)

    return parser


def _banner():
    from tools.common import banner, tabla_modos, ejemplos
    banner("lobera-ssh")
    tabla_modos([
        ("enum",  "Enumeración SSH (banner, fingerprint, métodos auth)"),
        ("spray", "Password spray contra SSH"),
        ("brute", "Fuerza bruta de credenciales SSH"),
        ("exec",  "Ejecutar comando remoto vía SSH"),
        ("shell", "Shell interactiva SSH"),
    ])
    ejemplos([
        "lobera-ssh enum   -t 10.10.10.5",
        "lobera-ssh spray  -t 10.10.10.5 -U usuarios.txt -P passwords.txt",
        "lobera-ssh brute  -t 10.10.10.5 -u root -P passwords.txt",
        "lobera-ssh exec   -t 10.10.10.5 -u admin -p Pass123 -c 'id'",
        "lobera-ssh shell  -t 10.10.10.5 -u admin -p Pass123",
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
