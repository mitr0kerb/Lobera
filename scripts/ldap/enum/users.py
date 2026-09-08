# scripts/ldap/enum/users.py

from scripts.base import BaseScript
from core.output import print_result, print_table, console

try:
    from modules.ldap import LDAPModule
    _LDAP_AVAILABLE = True
except ImportError:
    _LDAP_AVAILABLE = False


class Script(BaseScript):
    name        = "users"
    protocol    = "ldap"
    category    = "enum"
    description = (
        "Enumera todos los usuarios del dominio con atributos ofensivos clave: "
        "UAC flags, badPwdCount, lastLogon, SPNs, adminCount"
    )
    requires_auth = True

    EXAMPLES = [
        {
            "flag":  "-t / -u / -p / -d",
            "desc":  "Credenciales mínimas para leer el directorio",
            "good":  "lobera.py ldap --script=users -t 10.129.1.5 -u iker -p 'Pass1' -d CORP.LOCAL",
            "bad":   "lobera.py ldap --script=users -t 10.129.1.5  [sin credenciales solo funciona en null sessions]",
        },
        {
            "flag":  "--filter-flag",
            "desc":  "Muestra solo usuarios con ese flag UAC (ej: NO_PREAUTH, DISABLED)",
            "good":  "lobera.py ldap --script=users -t 10.129.1.5 -u iker -p 'Pass1' -d CORP.LOCAL --filter-flag NO_PREAUTH",
            "bad":   "lobera.py ldap --script=users -t 10.129.1.5 -u iker -p 'Pass1' -d CORP.LOCAL --filter-flag no_preauth  [case-sensitive]",
        },
        {
            "flag":  "--enabled-only",
            "desc":  "Filtra cuentas deshabilitadas",
            "good":  "lobera.py ldap --script=users -t 10.129.1.5 -u iker -p 'Pass1' -d CORP.LOCAL --enabled-only",
            "bad":   "lobera.py ldap --script=users -t 10.129.1.5 -u iker -p 'Pass1' -d CORP.LOCAL  [incluye deshabilitadas por defecto]",
        },
    ]

    def run(self, **kwargs):
        if not _LDAP_AVAILABLE:
            print_result("LDAP", str(self.target.ip), "fail",
                         "modules/ldap.py no encontrado")
            return []

        ldap = LDAPModule(
            self.target, self.creds,
            use_ssl=kwargs.get("ldaps", False),
            port=kwargs.get("port"),
        )
        if not ldap.connect():
            return []

        try:
            users = ldap.get_all_users()

            filter_flag  = kwargs.get("filter_flag")
            enabled_only = kwargs.get("enabled_only", False)

            if enabled_only:
                users = [u for u in users if u["enabled"]]
            if filter_flag:
                users = [u for u in users if filter_flag in u["uac_flags"]]

            # Tabla principal (compacta — una fila por usuario)
            rows = []
            for u in users:
                flags_str = ", ".join(u["uac_flags"]) if u["uac_flags"] else "-"
                spn_str   = str(len(u["spns"])) + " SPN(s)" if u["spns"] else "-"
                rows.append((
                    u["user"],
                    "Sí" if u["enabled"] else "[red]No[/red]",
                    str(u["bad_pwd_count"]),
                    u["pwd_last_set"],
                    spn_str,
                    flags_str,
                ))
            print_table(
                "Usuarios del dominio ({})".format(len(users)),
                ["Usuario", "Habilitado", "BadPwd", "PwdLastSet", "SPNs", "UAC Flags"],
                rows,
            )

            # Destacar hallazgos ofensivos
            asrep  = [u["user"] for u in users if u["no_preauth"]]
            kerbst = [u["user"] for u in users if u["spns"]]
            admins = [u["user"] for u in users if u["admin_count"] == 1]

            if asrep:
                print_result("LDAP", str(self.target.ip), "pwned",
                             "ASREPRoastable: {}".format(", ".join(asrep)))
            if kerbst:
                print_result("LDAP", str(self.target.ip), "pwned",
                             "Kerberoastable: {}".format(", ".join(kerbst)))
            if admins:
                print_result("LDAP", str(self.target.ip), "info",
                             "adminCount=1: {}".format(", ".join(admins)))

            return users

        finally:
            ldap.disconnect()
