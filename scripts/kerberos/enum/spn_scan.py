# scripts/kerberos/enum/spn_scan.py
#
# Técnica: SPN Scanning (enumeración de cuentas de servicio)
#
# Fundamento:
#   Un SPN (Service Principal Name) es el identificador único de una instancia
#   de servicio en AD. Formato: servicio/host:puerto (ej. MSSQLSvc/srv01:1433).
#   Las cuentas que tienen un SPN son las que el KDC usa para cifrar los
#   Service Tickets de ese servicio → son los objetivos de Kerberoasting.
#
#   Query LDAP:
#       (&(objectClass=user)(servicePrincipalName=*))
#       Atributos: sAMAccountName, servicePrincipalName, pwdLastSet, adminCount
#
#   Señales de alto valor:
#     - adminCount=1: la cuenta ha estado (o está) en un grupo privilegiado.
#     - pwdLastSet muy antiguo: la contraseña lleva mucho sin rotar.
#     - SPNs de SQL, Exchange, o servicios críticos de negocio.
#
#   Sin LDAP disponible: solicita un TGS al KDC para SPNs conocidos
#   (más ruidoso — genera eventos 4769 en el DC).

from scripts.base import BaseScript
from core.output import print_result, print_table, console
from core import session_db


COMMON_SPNS = [
    ("MSSQLSvc", "sql"),
    ("http", "web"),
    ("HTTP", "web"),
    ("WSMAN", "winrm"),
    ("exchangeMDB", "exchange"),
    ("IMAP", "exchange"),
    ("SMTP", "exchange"),
    ("cifs", "file"),
    ("host", "generic"),
    ("ldap", "dc"),
    ("gc", "dc"),
    ("RestrictedKrbHost", "generic"),
]


class SPNScanScript(BaseScript):
    name = "spn-scan"
    description = "Enumera cuentas de servicio con SPN vía LDAP (candidatos a Kerberoasting)"

    examples = [
        {"flag": "(uso básico)",
         "desc": "Requiere credenciales de dominio para LDAP. Si no hay módulo LDAP, usa stub.",
         "good": "kerberos --script=spn-scan -t 10.129.1.5 -d CORP.LOCAL -u jsmith -p 'Pass123!'",
         "bad": "kerberos --script=spn-scan -t 10.129.1.5 -d CORP.LOCAL  [sin -u/-p el bind LDAP anónimo rara vez permite enumerar SPNs]"},
    ]

    def run(self, **kwargs):
        realm = (self.creds.domain or self.target.domain or "").upper()
        if not realm:
            console.print("[red]Falta -d/--domain.[/red]")
            return

        kdc = self.target.ip
        print_result("KRB", kdc, "info", f"spn-scan: enumerando cuentas de servicio en {realm}")

        spn_accounts = self._enumerate_via_ldap(kdc, realm)

        if not spn_accounts:
            console.print("[dim]Módulo LDAP no disponible — intenta: "
                           "kerberos --script=kerberoasting con --spn manual.[/dim]")
            return

        if spn_accounts:
            rows = []
            for acc in spn_accounts:
                for spn in acc.get('spns', []):
                    rows.append((
                        acc['samaccountname'],
                        spn,
                        str(acc.get('pwdlastset', '?')),
                        "SI" if acc.get('admincount') else "",
                    ))
                    session_db.save_finding(kdc, "KRB", "spn_account",
                                             f"{acc['samaccountname']}: {spn}")

            print_table(f"Cuentas con SPN en {realm}",
                         ["Cuenta", "SPN", "PwdLastSet", "AdminCount"], rows)
            print_result("KRB", kdc, "pwned",
                         f"{len(spn_accounts)} cuenta(s) de servicio encontradas "
                         f"— candidatas a Kerberoasting")
            console.print("[dim]Siguiente paso: kerberos --script=kerberoasting "
                           f"-t {kdc} -d {realm} -u <usuario> -p <pass> --spn <SPN>[/dim]")

        return spn_accounts

    def _enumerate_via_ldap(self, kdc: str, realm: str) -> list:
        """
        Realiza la query LDAP para obtener cuentas con SPN.
        Cuando ldap.py esté implementado, usará LDAPModule directamente.
        """
        try:
            from modules.ldap import LDAPModule
            from core.target import Target
            ldap = LDAPModule(
                Target(ip=kdc, domain=realm.lower()),
                self.creds
            )
            return ldap.get_spn_accounts()
        except ImportError:
            return []
        except Exception as e:
            print_result("KRB", kdc, "fail", f"Error LDAP: {e}")
            return []
