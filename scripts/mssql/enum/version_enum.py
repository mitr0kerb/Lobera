# scripts/mssql/enum/version_enum.py
from scripts.base import BaseScript
from modules.mssql import MSSQLModule
from core.output import print_table
from core import session_db

class Script(BaseScript):
    name        = "version-enum"
    protocol    = "mssql"
    category    = "enum"
    description = "Enumera version, edicion, nivel de parche y nombre del servidor MSSQL sin credenciales."

    def run(self, **kwargs):
        port     = int(kwargs.get("port") or 1433)
        instance = kwargs.get("instance", "")
        mod = MSSQLModule(self.target, self.creds)
        if not mod.connect(port=port, instance=instance):
            return None
        try:
            rows = mod.query(
                "SELECT @@VERSION AS ver, SERVERPROPERTY('Edition') AS edition, "
                "SERVERPROPERTY('ProductLevel') AS level, "
                "SERVERPROPERTY('MachineName') AS machine",
                silent=True
            )
            if not rows:
                return None
            r       = rows[0]
            ver     = str(r.get("ver", "?"))[:120]
            edition = str(r.get("edition", "?"))
            level   = str(r.get("level", "?"))
            machine = str(r.get("machine", "?"))
            print_table("Version MSSQL - " + self.target.ip, ["Campo","Valor"], [
                ("Version",  ver),
                ("Edicion",  edition),
                ("Parche",   level),
                ("Maquina",  machine),
            ])
            session_db.save_finding(self.target.ip, "MSSQL", "version", ver)
            return {"version": ver, "edition": edition, "level": level, "machine": machine}
        finally:
            mod.disconnect()
