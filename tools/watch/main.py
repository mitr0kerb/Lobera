#!/usr/bin/env python3
# tools/watch/main.py
"""
lobera-watch — Monitor de eventos AD en tiempo real vía LDAP.

Detecta y alerta de cambios en el directorio:
  - Nuevos usuarios creados
  - Cambios de contraseña (pwdLastSet)
  - Usuarios añadidos/eliminados de grupos privilegiados
  - Cuentas bloqueadas (lockoutTime)
  - Nuevos equipos unidos al dominio
  - Cambios en GPOs
  - Cuentas con Kerberoasting habilitado (SPN añadido)
  - Delegaciones configuradas/modificadas

Uso:
  lobera-watch -t 10.10.10.5 -u USER -p PASS -d CORP.LOCAL
  lobera-watch -t 10.10.10.5 -u USER -p PASS -d CORP.LOCAL --interval 30
  lobera-watch -t 10.10.10.5 -u USER -p PASS -d CORP.LOCAL --filter users,lockouts
  lobera-watch -t 10.10.10.5 -u USER -H :NTHASH -d CORP.LOCAL --output eventos.log
"""

import sys
import os
import time
import json
import datetime

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from core.output import console


# ── Conexión LDAP ─────────────────────────────────────────────────────────────

def _ldap_connect(target, user, password, domain, nt_hash=None, use_ssl=False):
    """Devuelve conexión ldap3 autenticada."""
    import ldap3

    port   = 636 if use_ssl else 389
    server = ldap3.Server(target, port=port, use_ssl=use_ssl, get_info=ldap3.ALL)

    if nt_hash:
        # NTLM con hash
        user_dn = f"{domain}\\{user}"
        conn = ldap3.Connection(
            server, user=user_dn, password=nt_hash,
            authentication=ldap3.NTLM,
            auto_bind=True
        )
    else:
        user_dn = f"{domain}\\{user}"
        conn = ldap3.Connection(
            server, user=user_dn, password=password,
            authentication=ldap3.NTLM,
            auto_bind=True
        )

    return conn


def _base_dn(domain):
    """Convierte CORP.LOCAL en DC=CORP,DC=LOCAL."""
    return ",".join(f"DC={part}" for part in domain.split("."))


# ── Snapshot LDAP ─────────────────────────────────────────────────────────────

def _snapshot(conn, base_dn, attrs):
    """Obtiene todos los objetos con los atributos dados."""
    from ldap3 import ALL_ATTRIBUTES, SUBTREE
    conn.search(
        search_base=base_dn,
        search_filter="(objectClass=*)",
        search_scope=SUBTREE,
        attributes=attrs,
    )
    result = {}
    for entry in conn.entries:
        dn = entry.entry_dn
        obj = {}
        for attr in attrs:
            try:
                val = getattr(entry, attr).value
                obj[attr] = str(val) if val is not None else None
            except Exception:
                obj[attr] = None
        result[dn] = obj
    return result


def _snapshot_users(conn, base_dn):
    return _snapshot(conn, base_dn, [
        "sAMAccountName", "whenCreated", "pwdLastSet",
        "lockoutTime", "userAccountControl", "servicePrincipalName",
        "memberOf", "msDS-AllowedToDelegateTo",
        "msDS-AllowedToActOnBehalfOfOtherIdentity",
    ])


def _snapshot_computers(conn, base_dn):
    return _snapshot(conn, base_dn, [
        "sAMAccountName", "whenCreated", "operatingSystem",
        "userAccountControl", "msDS-AllowedToDelegateTo",
    ])


def _snapshot_groups(conn, base_dn):
    return _snapshot(conn, base_dn, ["sAMAccountName", "member", "whenChanged"])


def _snapshot_gpos(conn, base_dn):
    conn.search(
        search_base=base_dn,
        search_filter="(objectClass=groupPolicyContainer)",
        attributes=["displayName", "whenChanged", "versionNumber"],
    )
    return {e.entry_dn: {
        "displayName":   str(e.displayName.value),
        "whenChanged":   str(e.whenChanged.value),
        "versionNumber": str(e.versionNumber.value),
    } for e in conn.entries}


# ── Detección de cambios ──────────────────────────────────────────────────────

PRIV_GROUPS = {
    "domain admins", "enterprise admins", "schema admins",
    "administrators", "account operators", "backup operators",
    "print operators", "server operators", "group policy creator owners",
}

UAC_DISABLED = 0x0002


def _check_users(old, new, output_file):
    eventos = []
    ts = datetime.datetime.now().strftime("%H:%M:%S")

    for dn, data in new.items():
        sam = data.get("sAMAccountName") or dn

        if dn not in old:
            eventos.append(("nuevo_usuario", f"[green]+ NUEVO USUARIO:[/green] {sam}"))
            continue

        prev = old[dn]

        # Cambio de contraseña
        if data.get("pwdLastSet") != prev.get("pwdLastSet") and data.get("pwdLastSet"):
            eventos.append(("cambio_password", f"[yellow]~ CONTRASEÑA CAMBIADA:[/yellow] {sam}"))

        # Cuenta bloqueada
        lock_new = data.get("lockoutTime")
        lock_old = prev.get("lockoutTime")
        if lock_new and lock_new != "0" and lock_new != lock_old:
            eventos.append(("lockout", f"[red]! CUENTA BLOQUEADA:[/red] {sam}"))

        # SPN añadido (Kerberoastable)
        spn_new = data.get("servicePrincipalName")
        spn_old = prev.get("servicePrincipalName")
        if spn_new and spn_new != spn_old:
            eventos.append(("kerberoastable", f"[magenta]* SPN AÑADIDO (Kerberoastable):[/magenta] {sam} → {spn_new}"))

        # Delegación configurada
        deleg_new = data.get("msDS-AllowedToDelegateTo")
        deleg_old = prev.get("msDS-AllowedToDelegateTo")
        if deleg_new and deleg_new != deleg_old:
            eventos.append(("delegacion", f"[magenta]* DELEGACIÓN CONFIGURADA:[/magenta] {sam} → {deleg_new}"))

    # Usuarios eliminados
    for dn in old:
        if dn not in new:
            sam = old[dn].get("sAMAccountName") or dn
            eventos.append(("usuario_eliminado", f"[red]- USUARIO ELIMINADO:[/red] {sam}"))

    for tipo, msg in eventos:
        console.print(f"  [{ts}] {msg}")
        if output_file:
            with open(output_file, "a") as f:
                f.write(f"[{ts}] {tipo}: {msg}\n")

    return eventos


def _check_groups(old, new, output_file):
    eventos = []
    ts = datetime.datetime.now().strftime("%H:%M:%S")

    for dn, data in new.items():
        sam = (data.get("sAMAccountName") or "").lower()
        if sam not in PRIV_GROUPS:
            continue

        prev = old.get(dn, {})
        members_new = set((data.get("member") or "").split(";")) - {""}
        members_old = set((prev.get("member") or "").split(";")) - {""}

        for added in members_new - members_old:
            msg = f"[bold red]!! AÑADIDO A {sam.upper()}:[/bold red] {added}"
            eventos.append(("grupo_privilegiado_add", msg))
            console.print(f"  [{ts}] {msg}")

        for removed in members_old - members_new:
            msg = f"[yellow]~ ELIMINADO DE {sam.upper()}:[/yellow] {removed}"
            eventos.append(("grupo_privilegiado_del", msg))
            console.print(f"  [{ts}] {msg}")

    if output_file:
        for tipo, msg in eventos:
            with open(output_file, "a") as f:
                f.write(f"[{ts}] {tipo}: {msg}\n")

    return eventos


def _check_computers(old, new, output_file):
    eventos = []
    ts = datetime.datetime.now().strftime("%H:%M:%S")

    for dn, data in new.items():
        if dn not in old:
            sam = data.get("sAMAccountName") or dn
            os_  = data.get("operatingSystem") or "desconocido"
            msg  = f"[cyan]+ NUEVO EQUIPO:[/cyan] {sam} ({os_})"
            eventos.append(("nuevo_equipo", msg))
            console.print(f"  [{ts}] {msg}")

    if output_file:
        for tipo, msg in eventos:
            with open(output_file, "a") as f:
                f.write(f"[{ts}] {tipo}: {msg}\n")

    return eventos


def _check_gpos(old, new, output_file):
    eventos = []
    ts = datetime.datetime.now().strftime("%H:%M:%S")

    for dn, data in new.items():
        prev = old.get(dn)
        name = data.get("displayName") or dn

        if prev is None:
            msg = f"[cyan]+ NUEVA GPO:[/cyan] {name}"
        elif data.get("whenChanged") != prev.get("whenChanged"):
            msg = f"[yellow]~ GPO MODIFICADA:[/yellow] {name} (v{data.get('versionNumber')})"
        else:
            continue

        eventos.append(("gpo", msg))
        console.print(f"  [{ts}] {msg}")

    if output_file:
        for tipo, msg in eventos:
            with open(output_file, "a") as f:
                f.write(f"[{ts}] {tipo}: {msg}\n")

    return eventos


# ── Loop principal ────────────────────────────────────────────────────────────

def watch_loop(conn, base_dn, interval, filters, output_file):
    """Bucle de monitorización — compara snapshots cada N segundos."""

    all_filters = set(filters) if filters else {"users", "groups", "computers", "gpos"}

    console.print(f"  [dim]Cargando snapshot inicial...[/dim]")

    snap_users     = _snapshot_users(conn, base_dn)     if "users"     in all_filters else {}
    snap_groups    = _snapshot_groups(conn, base_dn)    if "groups"    in all_filters else {}
    snap_computers = _snapshot_computers(conn, base_dn) if "computers" in all_filters else {}
    snap_gpos      = _snapshot_gpos(conn, base_dn)      if "gpos"      in all_filters else {}

    console.print(f"  [green]✓ Snapshot inicial:[/green] "
                  f"{len(snap_users)} usuarios · {len(snap_groups)} grupos · "
                  f"{len(snap_computers)} equipos · {len(snap_gpos)} GPOs")
    console.print(f"  [dim]Monitorizando cada {interval}s... (Ctrl+C para parar)[/dim]\n")

    total_eventos = 0

    while True:
        time.sleep(interval)

        try:
            new_users     = _snapshot_users(conn, base_dn)     if "users"     in all_filters else {}
            new_groups    = _snapshot_groups(conn, base_dn)    if "groups"    in all_filters else {}
            new_computers = _snapshot_computers(conn, base_dn) if "computers" in all_filters else {}
            new_gpos      = _snapshot_gpos(conn, base_dn)      if "gpos"      in all_filters else {}

            ev  = _check_users(snap_users, new_users, output_file)
            ev += _check_groups(snap_groups, new_groups, output_file)
            ev += _check_computers(snap_computers, new_computers, output_file)
            ev += _check_gpos(snap_gpos, new_gpos, output_file)

            total_eventos += len(ev)

            snap_users     = new_users
            snap_groups    = new_groups
            snap_computers = new_computers
            snap_gpos      = new_gpos

        except KeyboardInterrupt:
            raise
        except Exception as e:
            console.print(f"  [red]Error en ciclo: {e}[/red]")


# ── CLI ───────────────────────────────────────────────────────────────────────

def build_parser():
    import argparse

    parser = argparse.ArgumentParser(
        prog="lobera-watch",
        description="Monitor de eventos AD en tiempo real vía LDAP",
    )
    parser.add_argument("-t", "--target",   required=True,  help="IP/hostname del DC")
    parser.add_argument("-u", "--user",     required=True,  help="Usuario de dominio")
    parser.add_argument("-p", "--password", default="",     help="Contraseña")
    parser.add_argument("-H", "--hash",     default=None,   help="Hash NT (pass-the-hash)")
    parser.add_argument("-d", "--domain",   required=True,  help="Dominio FQDN (ej: CORP.LOCAL)")
    parser.add_argument("--interval",       default=60, type=int,
                        help="Segundos entre comprobaciones (default: 60)")
    parser.add_argument("--filter",         default=None,
                        help="Categorías a monitorizar separadas por coma: users,groups,computers,gpos")
    parser.add_argument("--output",         default=None,   help="Fichero de log de eventos")
    parser.add_argument("--ssl",            action="store_true", default=False,
                        help="Usar LDAPS (puerto 636)")
    return parser


def _banner():
    from tools.common import banner, panel_info, tabla_flags, ejemplos

    banner("lobera-watch")

    panel_info("Qué detecta", [
        "[bold green]+[/bold green] Nuevos usuarios creados en el dominio",
        "[bold yellow]~[/bold yellow] Cambios de contraseña  (pwdLastSet)",
        "[bold red]![/bold red] Cuentas bloqueadas  (lockoutTime)",
        "[bold red]!![/bold red] Cambios de membresía en grupos privilegiados  (DA · EA · Admins...)",
        "[bold cyan]+[/bold cyan] Nuevos equipos unidos al dominio",
        "[bold yellow]~[/bold yellow] GPOs creadas o modificadas",
        "[bold magenta]*[/bold magenta] SPNs añadidos  → cuenta Kerberoastable",
        "[bold magenta]*[/bold magenta] Delegaciones configuradas o modificadas",
    ])

    tabla_flags([
        ("-t / --target",   "IP",   "IP o hostname del Domain Controller"),
        ("-u / --user",     "str",  "Usuario de dominio"),
        ("-p / --password", "str",  "Contraseña"),
        ("-H / --hash",     "str",  "Hash NT para pass-the-hash  (formato LM:NT o :NT)"),
        ("-d / --domain",   "FQDN", "Dominio  (ej: CORP.LOCAL)"),
        ("--interval",      "int",  "Segundos entre comprobaciones  (default: 60)"),
        ("--filter",        "list", "Categorías a monitorizar: users,groups,computers,gpos"),
        ("--output",        "file", "Guardar eventos en fichero de log"),
        ("--ssl",           "flag", "Usar LDAPS en lugar de LDAP  (puerto 636)"),
    ], titulo="Opciones")

    ejemplos([
        "# Monitorizar todo con intervalo de 30 segundos",
        "lobera-watch -t 10.10.10.5 -u administrador -p 'P@ss123' -d CORP.LOCAL --interval 30",
        "",
        "# Solo usuarios y lockouts, con log",
        "lobera-watch -t 10.10.10.5 -u svc_audit -p 'P@ss' -d CORP.LOCAL --filter users --output eventos.log",
        "",
        "# Pass-the-hash",
        "lobera-watch -t 10.10.10.5 -u admin -H :aad3b435b51404eeaad3b435b51404ee -d CORP.LOCAL",
        "",
        "# Solo cambios en grupos privilegiados",
        "lobera-watch -t 10.10.10.5 -u auditor -p 'P@ss' -d CORP.LOCAL --filter groups --interval 10",
    ])


def main():
    parser = build_parser()
    args   = parser.parse_args()

    _banner()

    nt_hash = None
    if args.hash:
        parts   = args.hash.split(":")
        nt_hash = parts[-1]

    filters = [f.strip() for f in args.filter.split(",")] if args.filter else None
    base_dn = _base_dn(args.domain)

    console.print(f"  [bold]Objetivo:[/bold] {args.target} ({args.domain})")
    console.print(f"  [bold]Usuario:[/bold]  {args.user}")
    console.print(f"  [bold]Base DN:[/bold]  {base_dn}\n")

    try:
        conn = _ldap_connect(args.target, args.user, args.password,
                             args.domain, nt_hash=nt_hash, use_ssl=args.ssl)
        console.print(f"  [green]✓ Conectado al DC[/green]\n")
    except Exception as e:
        console.print(f"  [red]✗ No se pudo conectar: {e}[/red]")
        sys.exit(1)

    try:
        watch_loop(conn, base_dn, args.interval, filters, args.output)
    except KeyboardInterrupt:
        console.print("\n  [yellow]Monitor detenido[/yellow]")


if __name__ == "__main__":
    main()
