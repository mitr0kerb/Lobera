# scripts/ldap/enum/domain-info.py

from scripts.base import BaseScript
from core.output import print_result, print_table, console

try:
    from modules.ldap import LDAPModule
    _LDAP_AVAILABLE = True
except ImportError:
    _LDAP_AVAILABLE = False


class Script(BaseScript):
    name        = "domain-info"
    protocol    = "ldap"
    category    = "enum"
    description = "Enumera información general del dominio: SID, nivel funcional, DCs, política de contraseñas"
    requires_auth = False   # puede funcionar con null session en dominios mal configurados

    EXAMPLES = [
        {
            "flag":  "-t / -d",
            "desc":  "IP del DC y FQDN del dominio (obligatorios)",
            "good":  "lobera.py ldap --script=domain-info -t 10.129.1.5 -d CORP.LOCAL",
            "bad":   "lobera.py ldap --script=domain-info -t 10.129.1.5  [sin -d el base DN queda vacío]",
        },
        {
            "flag":  "--ldaps",
            "desc":  "Fuerza conexión por LDAPS (puerto 636)",
            "good":  "lobera.py ldap --script=domain-info -t 10.129.1.5 -d CORP.LOCAL --ldaps",
            "bad":   "lobera.py ldap --script=domain-info -t 10.129.1.5 -d CORP.LOCAL --ldaps --port=389  [puerto contradice protocolo]",
        },
    ]

    def run(self, **kwargs):
        if not _LDAP_AVAILABLE:
            print_result("LDAP", str(self.target.ip), "fail",
                         "modules/ldap.py no encontrado")
            return None

        ldap = LDAPModule(
            self.target, self.creds,
            use_ssl=kwargs.get("ldaps", False),
            port=kwargs.get("port"),
        )
        if not ldap.connect():
            return None

        try:
            info = ldap.get_domain_info()

            # Información principal
            rows_main = [
                ("Dominio",            info.get("domain", "")),
                ("DN base",            info.get("dn", "")),
                ("SID",                info.get("sid", "")),
                ("Nivel funcional",    info.get("functional_level", "")),
                ("MachineAccountQuota",str(info.get("machine_account_quota", 10))),
            ]
            print_table("Dominio — información general", ["Campo", "Valor"], rows_main)

            # Política de contraseñas
            rows_pwd = [
                ("Longitud mínima",       str(info.get("min_pwd_length", 0))),
                ("Historial",             str(info.get("pwd_history_length", 0))),
                ("Lockout threshold",     str(info.get("lockout_threshold", 0))),
                ("Lockout duration (min)",str(info.get("lockout_duration", 0))),
                ("Max edad contraseña (días)", str(info.get("max_pwd_age", 0))),
            ]
            print_table("Política de contraseñas (dominio)", ["Parámetro", "Valor"], rows_pwd)

            # DCs
            dcs = info.get("dc_list", [])
            if dcs:
                rows_dc = [
                    (dc.get("dns", ""), dc.get("os", ""), dc.get("os_ver", ""))
                    for dc in dcs
                ]
                print_table("Domain Controllers", ["DNS", "OS", "Versión"], rows_dc)
            else:
                console.print("[dim]  (no se pudieron enumerar DCs)[/dim]")

            # Alertas de interés ofensivo
            if info.get("lockout_threshold", 0) == 0:
                print_result("LDAP", str(self.target.ip), "pwned",
                             "lockout_threshold = 0 — password spray sin riesgo de bloqueo")
            if info.get("machine_account_quota", 10) > 0:
                print_result("LDAP", str(self.target.ip), "info",
                             "MachineAccountQuota = {} — cualquier usuario del dominio puede crear cuentas de máquina".format(
                                 info.get("machine_account_quota", 10)))

            return info

        finally:
            ldap.disconnect()
