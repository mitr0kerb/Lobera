# scripts/rpc/enum/groups.py

from scripts.base import BaseScript
from core.output import print_result, print_table, console

try:
    from modules.rpc import RPCModule
    _RPC_OK = True
except ImportError:
    _RPC_OK = False


class Script(BaseScript):
    name        = "groups"
    protocol    = "rpc"
    category    = "enum"
    description = "Enumera grupos del dominio vía SAMR con conteo de miembros. También muestra Local Admins vía BUILTIN."

    EXAMPLES = [
        {
            "flag":  "-t / -u / -p",
            "desc":  "Credenciales estándar de dominio",
            "good":  "lobera.py rpc --script=groups -t 10.129.1.5 -u iker -p 'Pass1' -d CORP.LOCAL",
            "bad":   "lobera.py rpc --script=groups -t 10.129.1.5  [null session suele dar acceso denegado]",
        },
        {
            "flag":  "--local-admins",
            "desc":  "Muestra también los miembros del grupo Administrators local",
            "good":  "lobera.py rpc --script=groups -t 10.129.1.5 -u iker -p 'Pass1' -d CORP.LOCAL --local-admins",
            "bad":   "lobera.py rpc --script=groups -t 10.129.1.5 -u iker -p 'Pass1' -d CORP.LOCAL  [sin --local-admins no muestra builtin admins]",
        },
    ]

    def run(self, **kwargs):
        if not _RPC_OK:
            print_result("RPC", str(self.target.ip), "fail", "modules/rpc.py no disponible"); return []
        rpc = RPCModule(self.target, self.creds)
        if not rpc.connect(): return []
        try:
            groups = rpc.get_groups()
            rows = [
                (str(g["rid"]), g["name"], str(g["member_count"]))
                for g in sorted(groups, key=lambda x: x["member_count"], reverse=True)
            ]
            print_table(
                "Grupos vía SAMR ({})".format(len(groups)),
                ["RID", "Nombre", "Miembros"],
                rows,
            )
            if kwargs.get("local_admins"):
                console.print()
                admins = rpc.enumerate_local_admins()
                if admins:
                    print_table(
                        "Local Administrators",
                        ["SID", "Nombre"],
                        [(a["sid"], a["name"]) for a in admins],
                    )
            return groups
        finally:
            rpc.disconnect()
