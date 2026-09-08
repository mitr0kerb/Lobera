# scripts/mssql/enum/auth_check.py
from scripts.base import BaseScript
from modules.mssql import MSSQLModule
from core.output import print_check
from core import session_db
from core.credentials import Creds as _Creds
from core.target import Target as _Target

class Script(BaseScript):
    name        = "auth-check"
    protocol    = "mssql"
    category    = "enum"
    description = "Comprueba autenticacion SQL (SA vacia) y Windows habilitada."

    def run(self, **kwargs):
        port   = int(kwargs.get("port") or 1433)
        result = {"sa_empty": False, "sql_auth": False}

        mod = MSSQLModule(self.target, self.creds)
        if mod.connect(port=port):
            result["sa_empty"] = mod.check_sa_empty()
            mod.disconnect()

        if result["sa_empty"]:
            print_check("SA con contrasena vacia -> acceso total sin credenciales", ok=False)
        else:
            print_check("SA no tiene contrasena vacia", ok=True)

        probe_creds  = _Creds(user="lobera_probe_x", password="lobera_probe_x")
        probe_target = _Target(self.target.ip, domain="", timeout=self.target.timeout)
        probe_mod    = MSSQLModule(probe_target, probe_creds)
        if probe_mod.connect(port=port):
            probe_mod.login()
            result["sql_auth"] = True
            probe_mod.disconnect()
            session_db.save_finding(self.target.ip, "MSSQL", "sql_auth_enabled",
                                    "autenticacion SQL Server habilitada")
            print_check("Autenticacion SQL habilitada -> spray posible", ok=False)

        return result
