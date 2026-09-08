# scripts/rpc/enum/users.py

from scripts.base import BaseScript
from core.output import print_result, print_table, console

try:
    from modules.rpc import RPCModule
    _RPC_OK = True
except ImportError:
    _RPC_OK = False


class Script(BaseScript):
    name        = "users"
    protocol    = "rpc"
    category    = "enum"
    description = "Enumera usuarios del dominio vía SAMR (sin necesidad de LDAP). Muestra RID, estado, flags UAC."

    EXAMPLES = [
        {
            "flag":  "-t / -u / -p / -d",
            "desc":  "Credenciales mínimas (null session funciona en entornos legacy)",
            "good":  "lobera.py rpc --script=users -t 10.129.1.5 -u iker -p 'Pass1' -d CORP.LOCAL",
            "bad":   "lobera.py rpc --script=users -t 10.129.1.5  [null session suele fallar en DCs modernos]",
        },
    ]

    def run(self, **kwargs):
        if not _RPC_OK:
            print_result("RPC", str(self.target.ip), "fail", "modules/rpc.py no disponible"); return []
        rpc = RPCModule(self.target, self.creds)
        if not rpc.connect(): return []
        try:
            users = rpc.get_users()
            rows = [
                (
                    str(u["rid"]),
                    u["username"],
                    u["full_name"] or "-",
                    "[red]No[/red]" if u["disabled"] else "Sí",
                    "SÍ" if u["no_preauth"] else "-",
                    "SÍ" if u["no_pwd_exp"] else "-",
                    u["description"][:40] if u["description"] else "-",
                )
                for u in users
            ]
            print_table(
                "Usuarios vía SAMR ({})".format(len(users)),
                ["RID", "Usuario", "Nombre completo", "Activo", "NoPreauth", "PwdNoExpira", "Descripción"],
                rows,
            )
            asrep = [u["username"] for u in users if u["no_preauth"]]
            if asrep:
                print_result("RPC", str(self.target.ip), "pwned",
                             "ASREPRoastable: {}".format(", ".join(asrep)))
            return users
        finally:
            rpc.disconnect()
