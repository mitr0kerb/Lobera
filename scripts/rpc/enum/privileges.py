# scripts/rpc/enum/privileges.py

from scripts.base import BaseScript
from core.output import print_result, print_table, console
from core import session_db

try:
    from modules.rpc import RPCModule, INTERESTING_PRIVS
    _RPC_OK = True
except ImportError:
    _RPC_OK = False
    INTERESTING_PRIVS = {}


class Script(BaseScript):
    name        = "privileges"
    protocol    = "rpc"
    category    = "enum"
    description = (
        "Enumera privilegios del sistema vía LSA y qué cuentas los tienen. "
        "Destaca privilegios abusables para privesc (SeDebug, SeImpersonate, SeBackup…)."
    )

    EXAMPLES = [
        {
            "flag":  "-t / -u / -p",
            "desc":  "Requiere autenticación (cualquier usuario del dominio)",
            "good":  "lobera.py rpc --script=privileges -t 10.129.1.5 -u iker -p 'Pass1' -d CORP.LOCAL",
            "bad":   "lobera.py rpc --script=privileges -t 10.129.1.5  [sin auth LSA devuelve acceso denegado]",
        },
        {
            "flag":  "--interesting-only",
            "desc":  "Muestra solo los privilegios abusables para privesc",
            "good":  "lobera.py rpc --script=privileges -t 10.129.1.5 -u iker -p 'Pass1' -d CORP.LOCAL --interesting-only",
            "bad":   "lobera.py rpc --script=privileges -t 10.129.1.5 -u iker -p 'Pass1' -d CORP.LOCAL  [lista todos, más de 30]",
        },
        {
            "flag":  "--priv",
            "desc":  "Consulta quién tiene un privilegio específico",
            "good":  "lobera.py rpc --script=privileges -t 10.129.1.5 -u iker -p 'Pass1' --priv SeImpersonatePrivilege",
            "bad":   "lobera.py rpc --script=privileges -t 10.129.1.5 -u iker -p 'Pass1' --priv seimpersonate  [nombre case-sensitive]",
        },
    ]

    def run(self, **kwargs):
        if not _RPC_OK:
            print_result("RPC", str(self.target.ip), "fail", "modules/rpc.py no disponible"); return []
        rpc = RPCModule(self.target, self.creds)
        if not rpc.connect(): return []
        try:
            specific_priv    = kwargs.get("priv")
            interesting_only = kwargs.get("interesting_only", False)

            if specific_priv:
                # Modo: quién tiene ese privilegio concreto
                holders = rpc.enumerate_accounts_with_privilege(specific_priv)
                abuse   = INTERESTING_PRIVS.get(specific_priv, "")
                if holders:
                    print_result("RPC", str(self.target.ip), "pwned",
                                 "{}: {}".format(specific_priv, ", ".join(h["name"] for h in holders)))
                    if abuse:
                        console.print("  [yellow]Abuso:[/yellow] {}".format(abuse))
                    print_table(
                        "Cuentas con {}".format(specific_priv),
                        ["SID", "Nombre"],
                        [(h["sid"], h["name"]) for h in holders],
                    )
                else:
                    print_result("RPC", str(self.target.ip), "info",
                                 "{}: ninguna cuenta (o acceso denegado)".format(specific_priv))
                return holders

            # Modo: enumerar todos
            privs = rpc.enumerate_privileges()
            if interesting_only:
                privs = [p for p in privs if p["interesting"]]

            rows = [
                (
                    p["name"],
                    "[bold red]SÍ[/bold red]" if p["interesting"] else "-",
                    p["abuse_note"][:60] if p["abuse_note"] else "-",
                )
                for p in privs
            ]
            print_table(
                "Privilegios ({})".format(len(privs)),
                ["Nombre", "Abusable", "Nota de abuso"],
                rows,
            )

            # Para cada privilegio abusable, consultar quién lo tiene
            interesting = [p for p in privs if p["interesting"]]
            if interesting:
                console.print()
                console.print("[bold yellow]Consultando titulares de privilegios abusables...[/bold yellow]")
                for p in interesting:
                    holders = rpc.enumerate_accounts_with_privilege(p["name"])
                    if holders:
                        print_result("RPC", str(self.target.ip), "pwned",
                                     "{}: {}".format(p["name"],
                                                     ", ".join(h["name"] for h in holders)))
                        session_db.save_finding(
                            str(self.target.ip), "RPC", "abusable_privilege",
                            "{}: {}".format(p["name"],
                                           ", ".join(h["name"] for h in holders)),
                        )

            return privs
        finally:
            rpc.disconnect()
