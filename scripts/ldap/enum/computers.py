# scripts/ldap/enum/computers.py

from scripts.base import BaseScript
from core.output import print_result, print_table, console

try:
    from modules.ldap import LDAPModule
    _LDAP_AVAILABLE = True
except ImportError:
    _LDAP_AVAILABLE = False


class Script(BaseScript):
    name        = "computers"
    protocol    = "ldap"
    category    = "enum"
    description = (
        "Enumera todos los equipos del dominio: OS, última vez visto, "
        "si tienen delegación sin restricción, SPNs registrados."
    )
    requires_auth = True

    EXAMPLES = [
        {
            "flag":  "-t / -u / -p / -d",
            "desc":  "Credenciales mínimas para leer el directorio",
            "good":  "lobera.py ldap --script=computers -t 10.129.1.5 -u iker -p 'Pass1' -d CORP.LOCAL",
            "bad":   "lobera.py ldap --script=computers -t 10.129.1.5  [sin credenciales]",
        },
        {
            "flag":  "--undeleg",
            "desc":  "Muestra solo equipos con delegación sin restricción (TrustedForDelegation)",
            "good":  "lobera.py ldap --script=computers -t 10.129.1.5 -u iker -p 'Pass1' -d CORP.LOCAL --undeleg",
            "bad":   "lobera.py ldap --script=computers -t 10.129.1.5 -u iker -p 'Pass1' -d CORP.LOCAL  [sin filtro, incluye todos]",
        },
        {
            "flag":  "--os-filter",
            "desc":  "Filtra por substring de OS (ej: 'Windows 7', 'Server 2016')",
            "good":  "lobera.py ldap --script=computers -t 10.129.1.5 -u iker -p 'Pass1' -d CORP.LOCAL --os-filter 'Windows 7'",
            "bad":   "lobera.py ldap --script=computers -t 10.129.1.5 -u iker -p 'Pass1' -d CORP.LOCAL --os-filter windows7  [sin espacio no coincide]",
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
            computers = ldap.get_all_computers()

            undeleg   = kwargs.get("undeleg", False)
            os_filter = kwargs.get("os_filter")

            if undeleg:
                computers = [c for c in computers if c["unconstrained_deleg"]]
            if os_filter:
                computers = [c for c in computers
                             if os_filter.lower() in c["os"].lower()]

            rows = []
            for c in computers:
                deleg_str = ("[red]SÍ[/red]" if c["unconstrained_deleg"]
                             else "-")
                spn_str   = str(len(c["spns"])) if c["spns"] else "0"
                rows.append((
                    c["name"].rstrip("$"),
                    c["dns"] or "-",
                    c["os"] or "Desconocido",
                    c["last_logon"],
                    "Sí" if c["enabled"] else "[dim]No[/dim]",
                    deleg_str,
                    spn_str,
                ))

            print_table(
                "Equipos del dominio ({})".format(len(computers)),
                ["Nombre", "DNS", "OS", "Último acceso", "Activo", "UnDeleg", "SPNs"],
                rows,
            )

            # Destacar máquinas con delegación sin restricción (objetivo de PetitPotam/PrinterBug)
            undeleg_machines = [c["name"] for c in computers if c["unconstrained_deleg"]]
            if undeleg_machines:
                print_result("LDAP", str(self.target.ip), "pwned",
                             "Equipos con delegación sin restricción: {}".format(
                                 ", ".join(undeleg_machines)))
                console.print(
                    "  [dim]→ Posible objetivo para PetitPotam / PrinterBug "
                    "(forzar TGT del DC hacia estas máquinas)[/dim]"
                )

            # OS legacy
            legacy_os = ["Windows XP", "Windows 7", "Windows Vista",
                         "Server 2003", "Server 2008"]
            legacy = [c["name"] for c in computers
                      if any(lo in c.get("os", "") for lo in legacy_os)]
            if legacy:
                print_result("LDAP", str(self.target.ip), "info",
                             "OS legacy detectados: {}".format(", ".join(legacy)))

            return computers

        finally:
            ldap.disconnect()
