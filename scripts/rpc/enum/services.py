# scripts/rpc/enum/services.py

from scripts.base import BaseScript
from core.output import print_result, print_table, console

try:
    from modules.rpc import RPCModule
    _RPC_OK = True
except ImportError:
    _RPC_OK = False

# Servicios que suelen correr con privilegios SYSTEM y son interesantes para DLL hijacking / unquoted paths
INTERESTING_SERVICES = {
    "spooler":      "Print Spooler — vulnerable a PrintNightmare (CVE-2021-1675)",
    "LanmanServer": "SMB Server — habilita conexiones de red",
    "wuauserv":     "Windows Update — puede usarse para ejecución SYSTEM",
    "BITS":         "Background Intelligent Transfer — mismo contexto que wuauserv",
    "RemoteRegistry": "Registro remoto — necesario para reg_query/reg_enum",
    "TermService":  "Remote Desktop — RDP activo",
    "WinRM":        "Windows Remote Management — PowerShell remoto",
    "Schedule":     "Task Scheduler — vector de persistencia",
    "seclogon":     "Secondary Logon — explotable en ciertas versiones",
    "VSS":          "Volume Shadow Copy — puede usarse para volcado de NTDS.dit",
}


class Script(BaseScript):
    name        = "services"
    protocol    = "rpc"
    category    = "enum"
    description = (
        "Enumera servicios Windows vía SCM remoto. "
        "Destaca servicios interesantes para explotación (Spooler, WinRM, RDP, BITS…)."
    )

    EXAMPLES = [
        {
            "flag":  "-t / -u / -p",
            "desc":  "Requiere autenticación con privilegios suficientes para leer SCM",
            "good":  "lobera.py rpc --script=services -t 10.129.1.5 -u iker -p 'Pass1'",
            "bad":   "lobera.py rpc --script=services -t 10.129.1.5  [null session → acceso denegado al SCM]",
        },
        {
            "flag":  "--running-only",
            "desc":  "Filtra solo servicios actualmente en estado RUNNING",
            "good":  "lobera.py rpc --script=services -t 10.129.1.5 -u iker -p 'Pass1' --running-only",
            "bad":   "lobera.py rpc --script=services -t 10.129.1.5 -u iker -p 'Pass1'  [lista todos, puede ser muy larga]",
        },
        {
            "flag":  "--interesting-only",
            "desc":  "Solo servicios conocidos como vectores de ataque",
            "good":  "lobera.py rpc --script=services -t 10.129.1.5 -u iker -p 'Pass1' --interesting-only",
            "bad":   "lobera.py rpc --script=services -t 10.129.1.5 -u iker -p 'Pass1'  [sin filtro, cientos de servicios]",
        },
    ]

    def run(self, **kwargs):
        if not _RPC_OK:
            print_result("RPC", str(self.target.ip), "fail", "modules/rpc.py no disponible"); return []
        rpc = RPCModule(self.target, self.creds)
        if not rpc.connect(): return []
        try:
            services = rpc.list_services()

            running_only      = kwargs.get("running_only", False)
            interesting_only  = kwargs.get("interesting_only", False)

            if running_only:
                services = [s for s in services if s["state"] == "RUNNING"]

            if interesting_only:
                services = [
                    s for s in services
                    if s["name"].lower() in {k.lower() for k in INTERESTING_SERVICES}
                ]

            rows = []
            for s in services:
                note = next(
                    (v for k, v in INTERESTING_SERVICES.items()
                     if k.lower() == s["name"].lower()),
                    ""
                )
                state_str = (
                    "[bold green]{}[/bold green]".format(s["state"])
                    if s["state"] == "RUNNING"
                    else "[dim]{}[/dim]".format(s["state"])
                )
                rows.append((
                    s["name"],
                    s["display_name"][:35],
                    state_str,
                    "[yellow]{}[/yellow]".format(note[:50]) if note else "-",
                ))

            print_table(
                "Servicios ({})".format(len(services)),
                ["Nombre", "Display Name", "Estado", "Nota ofensiva"],
                rows,
            )

            # Destacar Spooler activo
            spooler_running = any(
                s["name"].lower() == "spooler" and s["state"] == "RUNNING"
                for s in services
            )
            if spooler_running:
                print_result("RPC", str(self.target.ip), "pwned",
                             "Print Spooler RUNNING → posible PrintNightmare / SpoolFool")

            return services
        finally:
            rpc.disconnect()
