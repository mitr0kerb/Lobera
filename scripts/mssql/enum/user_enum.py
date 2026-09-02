# scripts/mssql/enum/user_enum.py
from scripts.base import BaseScript
from modules.mssql import MSSQLModule
from core.output import print_check
from core import session_db

class Script(BaseScript):
    name        = "user-enum"
    protocol    = "mssql"
    category    = "enum"
    description = "Enumera logins, usuarios y roles MSSQL. Detecta SA y sysadmin."

    def run(self, **kwargs):
        port = int(kwargs.get("port") or 1433)
        mod  = MSSQLModule(self.target, self.creds)
        if not mod.connect(port=port):
            return None
        if not mod.login():
            mod.disconnect(); return None
        try:
            logins = mod.list_logins()
            rows   = mod.query(
                "SELECT name FROM sys.server_principals "
                "WHERE IS_SRVROLEMEMBER('sysadmin', name)=1",
                silent=True
            )
            if rows:
                names = [list(r.values())[0] for r in rows]
                print_check("Sysadmins: " + ", ".join(names), ok=False)
                for n in names:
                    session_db.save_finding(self.target.ip, "MSSQL", "sysadmin", n)
            return logins
        finally:
            mod.disconnect()
