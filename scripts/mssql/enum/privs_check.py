# scripts/mssql/enum/privs_check.py
from scripts.base import BaseScript
from modules.mssql import MSSQLModule
from core.output import print_check

class Script(BaseScript):
    name        = "privs-check"
    protocol    = "mssql"
    category    = "enum"
    description = "Comprueba sysadmin, xp_cmdshell, impersonation y bases de datos TRUSTWORTHY."

    def run(self, **kwargs):
        port = int(kwargs.get("port") or 1433)
        mod  = MSSQLModule(self.target, self.creds)
        if not mod.connect(port=port):
            return None
        if not mod.login():
            mod.disconnect(); return None
        try:
            privs = mod.check_privs()
            rows  = mod.query(
                "SELECT name FROM sys.databases WHERE is_trustworthy_on=1 AND name!='msdb'",
                silent=True
            )
            trustworthy = [list(r.values())[0] for r in (rows or [])]
            privs["trustworthy_dbs"] = trustworthy
            if trustworthy:
                print_check("TRUSTWORTHY ON: " + ", ".join(trustworthy) + " - vector CLR", ok=False)
            return privs
        finally:
            mod.disconnect()
