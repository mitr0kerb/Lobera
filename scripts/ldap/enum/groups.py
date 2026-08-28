# scripts/ldap/enum/groups.py

from scripts.base import BaseScript
from core.output import print_result, print_table, console

try:
    from modules.ldap import LDAPModule, PRIVILEGED_RIDS
    _LDAP_AVAILABLE = True
except ImportError:
    _LDAP_AVAILABLE = False
    PRIVILEGED_RIDS = {}


class Script(BaseScript):
    name        = "groups"
    protocol    = "ldap"
    category    = "enum"
    description = (
        "Enumera todos los grupos del dominio. Destaca grupos privilegiados "
        "(Domain Admins, Enterprise Admins, Administrators…) y su composición."
    )
    requires_auth = True

    EXAMPLES = [
        {
            "flag":  "-t / -u / -p / -d",
            "desc":  "Credenciales mínimas para leer el directorio",
            "good":  "lobera.py ldap --script=groups -t 10.129.1.5 -u iker -p 'Pass1' -d CORP.LOCAL",
            "bad":   "lobera.py ldap --script=groups  [sin -t ni credenciales]",
        },
        {
            "flag":  "--privileged-only",
            "desc":  "Muestra solo grupos con adminCount=1 o RID privilegiado",
            "good":  "lobera.py ldap --script=groups -t 10.129.1.5 -u iker -p 'Pass1' -d CORP.LOCAL --privileged-only",
            "bad":   "lobera.py ldap --script=groups -t 10.129.1.5 -u iker -p 'Pass1' -d CORP.LOCAL  [lista cientos de grupos]",
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
            groups = ldap.get_all_groups()
            privileged_only = kwargs.get("privileged_only", False)

            priv_rids = set(PRIVILEGED_RIDS.keys())

            if privileged_only:
                groups = [
                    g for g in groups
                    if g["admin_count"] == 1 or g["rid"] in priv_rids
                ]

            rows = []
            for g in sorted(groups, key=lambda x: x["member_count"], reverse=True):
                is_priv = g["rid"] in priv_rids or g["admin_count"] == 1
                name_str = ("[bold red]{}[/bold red]".format(g["name"])
                            if is_priv else g["name"])
                rows.append((
                    name_str,
                    str(g["member_count"]),
                    g["sid"].rsplit("-", 1)[-1] if g["sid"] else "-",
                    g["description"][:60] if g["description"] else "-",
                ))

            print_table(
                "Grupos del dominio ({})".format(len(groups)),
                ["Nombre", "Miembros", "RID", "Descripción"],
                rows,
            )

            # Detalle de grupos críticos con miembros
            admin_groups = ldap.get_admin_groups()
            if admin_groups:
                console.print()
                console.print("[bold red]Grupos privilegiados con miembros:[/bold red]")
                for group_name, members in admin_groups.items():
                    print_result("LDAP", str(self.target.ip), "pwned",
                                 "{}: {} miembro(s)".format(group_name, len(members)))
                    for m in members:
                        # Mostrar solo el CN para legibilidad
                        cn = m.split(",")[0].replace("CN=", "") if "CN=" in m else m
                        console.print("    [yellow]→[/yellow] {}".format(cn))

            return groups

        finally:
            ldap.disconnect()
