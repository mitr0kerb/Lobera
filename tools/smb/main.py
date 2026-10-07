#!/usr/bin/env python3
# tools/smb/main.py
"""
lobera-smb — Operaciones SMB sobre un objetivo Windows/AD.

Subcomandos:
  enum      Enumerar shares, usuarios, OS, sesiones, firmado, null session...
  spray     Password spray contra SMB (o Pass-the-Hash)
  exec      Ejecutar comando remoto vía SMB (psexec/wmiexec)
  shell     Shell interactiva SMB

Uso:
  lobera-smb enum   -t 10.0.0.1 -u usuario -p contraseña
  lobera-smb spray  -t 10.0.0.1 -U usuarios.txt -P passwords.txt
  lobera-smb exec   -t 10.0.0.1 -u admin -p pass -c whoami
  lobera-smb shell  -t 10.0.0.1 -u admin -p pass
"""

import sys
import os
import argparse

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from core.output import console
from core.session_db import init_db
from core.hooks import add_args_on_hash_crack, on_hash_capturado


# ──────────────────────────────────────────────────────────────────────────────
# Helpers de conexión
# ──────────────────────────────────────────────────────────────────────────────

def _conectar(ip, user, password, domain, timeout=10, dialect=None):
    """Devuelve una SMBConnection autenticada o lanza excepción."""
    from impacket.smbconnection import SMBConnection
    from modules.smb import DIALECT_MAP
    preferred = DIALECT_MAP.get(dialect) if dialect else None
    conn = SMBConnection(remoteName=ip, remoteHost=ip, timeout=timeout,
                         preferredDialect=preferred)
    conn.login(user, password, domain)
    return conn


# ──────────────────────────────────────────────────────────────────────────────
# Subcomando: enum
# ──────────────────────────────────────────────────────────────────────────────

def cmd_enum(args):
    from modules.smb import SMBModule, DIALECT_NAMES
    from core.target import Target
    from core.credentials import Credentials

    target = Target(ip=args.target, domain=args.domain or '', timeout=args.timeout)
    creds  = Credentials(username=args.user or '', password=args.password or '',
                         domain=args.domain or '', nt_hash=args.hash or '')
    mod = SMBModule(target, creds)

    console.print(f"\n[bold cyan][ SMB ENUM ] {args.target}[/bold cyan]")

    if not mod.connect(force_dialect=args.dialect):
        console.print("[red]No se pudo conectar.[/red]")
        return

    if not mod.authenticate():
        console.print("[red]Autenticación fallida.[/red]")
        return

    tareas = {
        'os':      (args.os      or args.all, mod.os_info),
        'shares':  (args.shares  or args.all, mod.list_shares),
        'users':   (args.users   or args.all, mod.list_users),
        'groups':  (args.groups  or args.all, mod.list_groups),
        'sessions':(args.sessions or args.all, mod.list_sessions),
        'signing': (args.signing  or args.all, mod.check_signing),
        'null':    (args.null     or args.all, mod.check_null_session),
        'policy':  (args.policy   or args.all, mod.get_password_policy),
    }
    for nombre, (activo, func) in tareas.items():
        if activo:
            try:
                func()
            except Exception as e:
                console.print(f"  [yellow]{nombre}: {e}[/yellow]")

    mod.disconnect()


# ──────────────────────────────────────────────────────────────────────────────
# Subcomando: spray
# ──────────────────────────────────────────────────────────────────────────────

def cmd_spray(args):
    from scripts.smb.attack.password_spray import run as run_spray
    from core.hooks import on_hash_capturado

    console.print(f"\n[bold cyan][ SMB SPRAY ] {args.target}[/bold cyan]")

    # Leer listas
    usuarios = _leer_lista(args.user_list, args.user)
    if not usuarios:
        console.print("[red]Necesitas -u <usuario> o -U <fichero>.[/red]")
        return

    passwords = _leer_lista(args.pass_list, args.password)
    hashes    = _leer_lista(args.hash_list, args.hash)
    if not passwords and not hashes:
        console.print("[red]Necesitas -p <pass>, -P <fichero>, --hash o --hash-list.[/red]")
        return

    encontrados = run_spray(
        target=args.target,
        port=args.port,
        usuarios=usuarios,
        passwords=passwords,
        hashes=hashes,
        domain=args.domain or '',
        timeout=args.timeout,
        delay=args.delay,
    )

    for cred in encontrados:
        console.print(f"  [green]✓[/green] {cred['user']} : {cred.get('password') or cred.get('hash')}")
        if args.on_hash_crack and cred.get('hash'):
            on_hash_capturado(
                hash_str=cred['hash'], formato='ntlm',
                wordlist=args.on_hash_crack, engine=args.crack_engine,
                rules=args.crack_rules, target_ip=args.target,
                usuario=cred['user'], fuente='smb-spray',
            )


# ──────────────────────────────────────────────────────────────────────────────
# Subcomando: exec
# ──────────────────────────────────────────────────────────────────────────────

def cmd_exec(args):
    from scripts.smb.attack.exec import run as run_exec
    console.print(f"\n[bold cyan][ SMB EXEC ] {args.target}[/bold cyan]")
    run_exec(
        target=args.target,
        port=args.port,
        user=args.user or '',
        password=args.password or '',
        nt_hash=args.hash or '',
        domain=args.domain or '',
        cmd=args.cmd,
        method=args.method,
        timeout=args.timeout,
    )


# ──────────────────────────────────────────────────────────────────────────────
# Subcomando: shell
# ──────────────────────────────────────────────────────────────────────────────

def cmd_shell(args):
    from scripts.smb.shell.interactive import start as start_shell
    console.print(f"\n[bold cyan][ SMB SHELL ] {args.target}[/bold cyan]")
    start_shell(
        target=args.target,
        port=args.port,
        user=args.user or '',
        password=args.password or '',
        nt_hash=args.hash or '',
        domain=args.domain or '',
        timeout=args.timeout,
    )


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _leer_lista(fichero, valor_unico):
    """Devuelve lista de strings desde fichero o valor único."""
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
    """Añade los argumentos de conexión comunes a todos los subcomandos."""
    sub.add_argument('-t', '--target', required=True, metavar='IP', help='IP del objetivo')
    sub.add_argument('--port', type=int, default=445, metavar='PUERTO')
    sub.add_argument('-u', '--user', metavar='USUARIO')
    sub.add_argument('-p', '--password', metavar='CONTRASEÑA')
    sub.add_argument('-H', '--hash', metavar='NTLM', help='NT hash (pass-the-hash)')
    sub.add_argument('-d', '--domain', metavar='DOMINIO', default='')
    sub.add_argument('--timeout', type=int, default=10)
    sub.add_argument('--dialect', choices=['v1', 'v2', 'v2.1', 'v3'],
                     help='Forzar versión de dialecto SMB')


def build_parser():
    parser = argparse.ArgumentParser(
        prog='lobera-smb',
        description='Operaciones SMB — lobera',
    )
    subs = parser.add_subparsers(dest='subcomando', required=True)

    # ── enum ──────────────────────────────────────────────────────────────────
    p_enum = subs.add_parser('enum', help='Enumerar información del objetivo')
    _parser_comun(p_enum)
    grp = p_enum.add_argument_group('qué enumerar (por defecto: todo)')
    grp.add_argument('--all',      action='store_true', help='Todo (default si no se especifica nada)')
    grp.add_argument('--os',       action='store_true', help='Información del SO')
    grp.add_argument('--shares',   action='store_true', help='Shares disponibles')
    grp.add_argument('--users',    action='store_true', help='Usuarios del dominio/local')
    grp.add_argument('--groups',   action='store_true', help='Grupos')
    grp.add_argument('--sessions', action='store_true', help='Sesiones activas')
    grp.add_argument('--signing',  action='store_true', help='Estado del firmado SMB')
    grp.add_argument('--null',     action='store_true', help='Null session')
    grp.add_argument('--policy',   action='store_true', help='Política de contraseñas')
    p_enum.set_defaults(func=cmd_enum)

    # ── spray ─────────────────────────────────────────────────────────────────
    p_spray = subs.add_parser('spray', help='Password spray / Pass-the-Hash')
    _parser_comun(p_spray)
    p_spray.add_argument('-U', '--user-list',  metavar='FICHERO', help='Lista de usuarios')
    p_spray.add_argument('-P', '--pass-list',  metavar='FICHERO', help='Lista de contraseñas')
    p_spray.add_argument('--hash-list',        metavar='FICHERO', help='Lista de NT hashes')
    p_spray.add_argument('--delay', type=float, default=0.5, metavar='SEGUNDOS',
                         help='Pausa entre intentos (default: 0.5)')
    add_args_on_hash_crack(p_spray)
    p_spray.set_defaults(func=cmd_spray)

    # ── exec ──────────────────────────────────────────────────────────────────
    p_exec = subs.add_parser('exec', help='Ejecutar comando remoto')
    _parser_comun(p_exec)
    p_exec.add_argument('-c', '--cmd', required=True, metavar='COMANDO')
    p_exec.add_argument('--method', choices=['psexec', 'wmiexec', 'smbexec'], default='wmiexec',
                        help='Método de ejecución (default: wmiexec)')
    p_exec.set_defaults(func=cmd_exec)

    # ── shell ─────────────────────────────────────────────────────────────────
    p_shell = subs.add_parser('shell', help='Shell interactiva SMB')
    _parser_comun(p_shell)
    p_shell.set_defaults(func=cmd_shell)

    return parser


def main():
    init_db()
    parser = build_parser()
    args = parser.parse_args()

    # Si en enum no se especificó ningún flag concreto, activar --all
    if args.subcomando == 'enum':
        flags = ['os', 'shares', 'users', 'groups', 'sessions', 'signing', 'null', 'policy']
        if not args.all and not any(getattr(args, f) for f in flags):
            args.all = True

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
