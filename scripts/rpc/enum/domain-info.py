# scripts/rpc/enum/domain-info.py

from scripts.base import BaseScript
from core.output import print_result, print_table, console

try:
    from modules.rpc import RPCModule
    _RPC_OK = True
except ImportError:
    _RPC_OK = False


class Script(BaseScript):
    name        = "domain-info"
    protocol    = "rpc"
    category    = "enum"
    description = (
        "Información del dominio vía SAMR + LSA: nombre, SID, "
        "política de contraseñas, dominios de confianza, DNS domain."
    )

    EXAMPLES = [
        {
            "flag":  "-t / -u / -p / -d",
            "desc":  "Credenciales de cualquier usuario del dominio",
            "good":  "lobera.py rpc --script=domain-info -t 10.129.1.5 -u iker -p 'Pass1' -d CORP.LOCAL",
            "bad":   "lobera.py rpc --script=domain-info -t 10.129.1.5  [sin auth falla en DCs modernos]",
        },
    ]

    def run(self, **kwargs):
        if not _RPC_OK:
            print_result("RPC", str(self.target.ip), "fail", "modules/rpc.py no disponible"); return {}
        rpc = RPCModule(self.target, self.creds)
        if not rpc.connect(): return {}
        try:
            samr_info = rpc.get_domain_info()
            lsa_info  = rpc.get_lsa_domain_info()
            trusts    = rpc.enumerate_trusted_domains()

            rows_main = [
                ("Dominio (SAMR)",       samr_info.get("domain_name", "-")),
                ("Dominio DNS (LSA)",     lsa_info.get("dns_domain", "-")),
                ("NetBIOS (LSA)",         lsa_info.get("netbios_name", "-")),
                ("SID",                   samr_info.get("domain_sid") or lsa_info.get("domain_sid", "-")),
            ]
            print_table("Información del dominio", ["Campo", "Valor"], rows_main)

            rows_pwd = [
                ("Longitud mínima",        str(samr_info.get("min_pwd_length", 0))),
                ("Historial",              str(samr_info.get("pwd_history_length", 0))),
                ("Lockout threshold",      str(samr_info.get("lockout_threshold", 0))),
                ("Lockout duration (min)", str(samr_info.get("lockout_duration", 0))),
                ("Max edad (días)",        str(samr_info.get("max_pwd_age", 0))),
                ("Complejidad",            "Sí" if samr_info.get("complexity_enabled") else "No"),
            ]
            print_table("Política de contraseñas", ["Parámetro", "Valor"], rows_pwd)

            if samr_info.get("lockout_threshold", 1) == 0:
                print_result("RPC", str(self.target.ip), "pwned",
                             "lockout_threshold=0 → spray sin bloqueo")

            if trusts:
                print_table(
                    "Dominios de confianza ({})".format(len(trusts)),
                    ["Nombre", "SID", "Dirección", "Tipo"],
                    [(t["name"], t["sid"], t["direction"], t["type"]) for t in trusts],
                )

            return {"samr": samr_info, "lsa": lsa_info, "trusts": trusts}
        finally:
            rpc.disconnect()
