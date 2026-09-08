# scripts/mssql/enum/instance_enum.py
from scripts.base import BaseScript
from modules.mssql import MSSQLModule
from core.output import print_result, print_table
from core import session_db

class Script(BaseScript):
    name        = "instance-enum"
    protocol    = "mssql"
    category    = "enum"
    description = "Descubre instancias MSSQL via SQL Browser (UDP 1434) y resolucion de puertos dinamicos."

    def run(self, **kwargs):
        instances = MSSQLModule.discover_instances(
            self.target.ip, timeout=int(kwargs.get("timeout") or 3)
        )
        if not instances:
            print_result("MSSQL", self.target.ip, "info",
                         "SQL Browser (UDP 1434): sin instancias detectadas")
            return []
        rows = []
        for inst in instances:
            name = inst.get("InstanceName", "?")
            tcp  = inst.get("tcp", "?")
            pipe = inst.get("np", "")
            rows.append((name, tcp, pipe))
            session_db.save_finding(self.target.ip, "MSSQL", "instance",
                                    name + ":tcp=" + tcp)
        print_table("Instancias MSSQL en " + self.target.ip,
                    ["Instancia", "Puerto TCP", "Named Pipe"], rows)
        return instances
