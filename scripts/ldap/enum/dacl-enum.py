# scripts/ldap/enum/dacl-enum.py

from scripts.base import BaseScript
from core.output import print_result, print_table, console

try:
    from modules.ldap import LDAPModule
    _LDAP_AVAILABLE = True
except ImportError:
    _LDAP_AVAILABLE = False


class Script(BaseScript):
    name        = "dacl-enum"
    protocol    = "ldap"
    category    = "enum"
    description = (
        "Enumera ACEs interesantes (GenericAll, WriteDACL, GenericWrite, "
        "WriteOwner, WriteProperty) en objetos críticos del dominio: "
        "raíz del dominio y grupos privilegiados. "
        "Permite detectar rutas de escalada de privilegios sin BloodHound."
    )
    requires_auth = True

    EXAMPLES = [
        {
            "flag":  "-t / -u / -p / -d",
            "desc":  "Credenciales para leer nTSecurityDescriptor (por defecto visible a todos los usuarios del dominio)",
            "good":  "lobera.py ldap --script=dacl-enum -t 10.129.1.5 -u iker -p 'Pass1' -d CORP.LOCAL",
            "bad":   "lobera.py ldap --script=dacl-enum -t 10.129.1.5  [sin credenciales no se puede leer DACL]",
        },
        {
            "flag":  "--target-dn",
            "desc":  "Analiza un objeto específico en vez de los predefinidos",
            "good":  "lobera.py ldap --script=dacl-enum -t 10.129.1.5 -u iker -p 'Pass1' -d CORP.LOCAL --target-dn 'CN=Domain Admins,CN=Users,DC=corp,DC=local'",
            "bad":   "lobera.py ldap --script=dacl-enum -t 10.129.1.5 -u iker -p 'Pass1' -d CORP.LOCAL --target-dn 'Domain Admins'  [necesita DN completo]",
        },
    ]

    # Nombres amigables para SIDs conocidos (Well-Known SIDs)
    WELL_KNOWN = {
        "S-1-1-0":   "Everyone",
        "S-1-5-11":  "Authenticated Users",
        "S-1-5-32-545": "Users",
        "S-1-5-32-544": "Administrators (local)",
    }

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
            target_dn = kwargs.get("target_dn")
            aces = ldap.get_interesting_aces(target_dn=target_dn)

            if not aces:
                console.print("[yellow]No se encontraron ACEs interesantes "
                              "(o no tienes permisos para leer nTSecurityDescriptor)[/yellow]")
                return []

            rows = []
            for ace in aces:
                trustee = self.WELL_KNOWN.get(ace["trustee_sid"], ace["trustee_sid"])
                rights  = ", ".join(ace["rights"])
                # Extraer el CN del objeto para legibilidad
                obj_cn  = ace["object_dn"].split(",")[0].replace("DC=", "").replace("CN=", "")
                rows.append((
                    obj_cn,
                    trustee,
                    rights,
                ))

            print_table(
                "ACEs interesantes ({} encontradas)".format(len(aces)),
                ["Objeto", "Trustee (SID / nombre)", "Derechos"],
                rows,
            )

            # Clasificar por tipo de abuso
            generic_all   = [a for a in aces if "GenericAll"   in a["rights"]]
            write_dacl    = [a for a in aces if "WriteDACL"    in a["rights"]]
            generic_write = [a for a in aces if "GenericWrite"  in a["rights"]]
            write_owner   = [a for a in aces if "WriteOwner"   in a["rights"]]

            if generic_all:
                print_result("LDAP", str(self.target.ip), "pwned",
                             "GenericAll en {} objeto(s) — control total".format(len(generic_all)))
            if write_dacl:
                print_result("LDAP", str(self.target.ip), "pwned",
                             "WriteDACL en {} objeto(s) — puede añadir ACEs arbitrarias".format(
                                 len(write_dacl)))
            if generic_write:
                print_result("LDAP", str(self.target.ip), "info",
                             "GenericWrite en {} objeto(s) — puede modificar atributos".format(
                                 len(generic_write)))
            if write_owner:
                print_result("LDAP", str(self.target.ip), "info",
                             "WriteOwner en {} objeto(s) — puede cambiar propietario y luego WriteDACL".format(
                                 len(write_owner)))

            console.print(
                "\n[dim]→ Para explotación detallada de ACLs ver el script "
                "ldap --script=acl-abuse[/dim]"
            )

            return aces

        finally:
            ldap.disconnect()
