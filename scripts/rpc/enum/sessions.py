# scripts/rpc/enum/sessions.py

from scripts.base import BaseScript
from core.output import print_result, print_table, console

try:
    from modules.rpc import RPCModule
    _RPC_OK = True
except ImportError:
    _RPC_OK = False


class Script(BaseScript):
    name        = "sessions"
    protocol    = "rpc"
    category    = "enum"
    description = (
        "Enumera sesiones activas (SRVSVC), usuarios con sesión interactiva (WKSSVC) "
        "y ficheros abiertos en el servidor. Útil para saber quién está conectado."
    )

    EXAMPLES = [
        {
            "flag":  "-t / -u / -p",
            "desc":  "Requiere autenticación",
            "good":  "lobera.py rpc --script=sessions -t 10.129.1.5 -u iker -p 'Pass1'",
            "bad":   "lobera.py rpc --script=sessions -t 10.129.1.5  [null session suele devolver lista vacía]",
        },
        {
            "flag":  "--open-files",
            "desc":  "Incluye también ficheros abiertos (puede ser muy largo en DCs activos)",
            "good":  "lobera.py rpc --script=sessions -t 10.129.1.5 -u iker -p 'Pass1' --open-files",
            "bad":   "lobera.py rpc --script=sessions -t 10.129.1.5 -u iker -p 'Pass1'  [sin --open-files no muestra ficheros]",
        },
    ]

    def run(self, **kwargs):
        if not _RPC_OK:
            print_result("RPC", str(self.target.ip), "fail", "modules/rpc.py no disponible"); return {}
        rpc = RPCModule(self.target, self.creds)
        if not rpc.connect(): return {}
        try:
            result = {}

            # Sesiones SRVSVC (conexiones de red activas)
            sessions = rpc.get_active_sessions()
            if sessions:
                print_table(
                    "Sesiones activas vía SRVSVC ({})".format(len(sessions)),
                    ["Usuario", "Cliente", "Tiempo (min)", "Idle (min)"],
                    [(s["user"], s["client"], str(s["time_min"]), str(s["idle_min"])) for s in sessions],
                )
                result["sessions"] = sessions
            else:
                console.print("[dim]  No hay sesiones activas vía SRVSVC (o acceso denegado)[/dim]")

            # Usuarios interactivos WKSSVC
            logged_on = rpc.get_logged_on_users()
            if logged_on:
                print_table(
                    "Usuarios con sesión interactiva (WKSSVC)",
                    ["Usuario", "Dominio", "Servidor de logon"],
                    [(u["username"], u["domain"], u["logon_server"]) for u in logged_on],
                )
                result["logged_on"] = logged_on
            else:
                console.print("[dim]  No hay usuarios interactivos visibles (o acceso denegado)[/dim]")

            # Ficheros abiertos (opcional)
            if kwargs.get("open_files"):
                open_files = rpc.get_open_files()
                if open_files:
                    print_table(
                        "Ficheros abiertos ({})".format(len(open_files)),
                        ["ID", "Usuario", "Ruta", "Locks"],
                        [(str(f["file_id"]), f["user"], f["path"], str(f["num_locks"])) for f in open_files],
                    )
                    result["open_files"] = open_files

            return result
        finally:
            rpc.disconnect()
