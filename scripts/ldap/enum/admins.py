# scripts/ldap/enum/admins.py

from scripts.base import BaseScript
from core.output import print_result, print_table, console

try:
    from modules.ldap import LDAPModule, PRIVILEGED_RIDS
    _LDAP_AVAILABLE = True
except ImportError:
    _LDAP_AVAILABLE = False
    PRIVILEGED_RIDS = {}


class Script(BaseScript):
    name        = "admins"
    protocol    = "ldap"
    category    = "enum"
    description = (
        "Enumera miembros de grupos privilegiados del dominio: "
        "Domain Admins, Enterprise Admins, Administrators, Schema Admins, "
        "Account Operators, Server Operators, Backup Operators."
    )
    requires_auth = True

    EXAMPLES = [
        {
            "flag":  "-t / -u / -p / -d",
            "desc":  "Credenciales de cualquier usuario del dominio (no hace falta DA)",
            "good":  "lobera.py ldap --script=admins -t 10.129.1.5 -u iker -p 'Pass1' -d CORP.LOCAL",
            "bad":   "lobera.py ldap --script=admins -t 10.129.1.5  [sin credenciales muchos DCs deniegan]",
        },
    ]

    def run(self, **kwargs):
        if not _LDAP_AVAILABLE:
            print_result("LDAP", str(self.target.ip), "fail",
                         "modules/ldap.py no encontrado")
            return {}

        ldap = LDAPModule(
            self.target, self.creds,
            use_ssl=kwargs.get("ldaps", False),
            port=kwargs.get("port"),
        )
        if not ldap.connect():
            return {}

        try:
            admin_groups = ldap.get_admin_groups()

            if not admin_groups:
                console.print("[yellow]No se encontraron miembros en grupos privilegiados "
                              "(¿permisos insuficientes?)[/yellow]")
                return {}

            all_members_flat = []

            for group_name, members in admin_groups.items():
                print_result("LDAP", str(self.target.ip), "pwned",
                             "{}: {} miembro(s)".format(group_name, len(members)))

                rows = []
                for m in members:
                    # Extraer CN del DN para legibilidad
                    cn = m.split(",")[0].replace("CN=", "").replace("cn=", "") if "=" in m else m
                    # Intentar determinar si es grupo o usuario por el OU
                    obj_type = "Grupo" if "CN=Users" not in m and any(
                        g in m for g in ["Group", "Groups"]) else "?"
                    rows.append((cn, m))
                    all_members_flat.append({"group": group_name, "member_dn": m, "cn": cn})

                print_table(
                    "  Miembros de {}".format(group_name),
                    ["CN", "DN completo"],
                    rows,
                )

            # Resumen total de cuentas privilegiadas únicas
            unique_members = set(
                item["member_dn"] for item in all_members_flat
            )
            console.print(
                "\n[bold]Total cuentas privilegiadas únicas:[/bold] {}".format(
                    len(unique_members))
            )

            return admin_groups

        finally:
            ldap.disconnect()
