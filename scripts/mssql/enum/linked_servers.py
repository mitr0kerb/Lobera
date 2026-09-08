# scripts/mssql/enum/linked_servers.py
from scripts.base import BaseScript
from modules.mssql import MSSQLModule
from core.output import print_check

class Script(BaseScript):
    name        = "linked-servers"
    protocol    = "mssql"
    category    = "enum"
    description = "Enumera servidores enlazados (linked servers) y sus credenciales almacenadas."

    def run(self, **kwargs):
        port = int(kwargs.get("port") or 1433)
        mod  = MSSQLModule(self.target, self.creds)
        if not mod.connect(port=port):
            return None
        if not mod.login():
            mod.disconnect(); return None
        try:
            servers = mod.list_linked_servers()
            if servers:
                print_check(str(len(servers)) + " linked server(s) -> posible pivoting", ok=False)
            return servers
        finally:
            mod.disconnect()
