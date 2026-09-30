
# scripts/smb/attack/delegation_check.py
"""
Busca cuentas con delegación sin restricciones accesibles via SMB.
Consulta SAMR para cuentas de equipo con el flag TrustedForDelegation.
"""
from core.output import console, print_result, print_table
from core import session_db
from scripts.base import BaseScript

try:
    from impacket.smbconnection import SMBConnection
    from impacket.dcerpc.v5 import transport, samr
    _OK = True
except ImportError:
    _OK = False

# Flag UAC: TRUSTED_FOR_DELEGATION = 0x80000
_TRUSTED_FOR_DELEGATION = 0x80000


class Script(BaseScript):
    name        = "delegation-check"
    protocol    = "smb"
    category    = "attack"
    description = (
        "Busca cuentas con delegación sin restricciones via SAMR (flag UAC TrustedForDelegation). "
        "Estas cuentas pueden capturar TGTs cuando cualquier usuario se autentica en ellas."
    )

    def run(self, **kwargs):
        if not _OK:
            console.print("[red]impacket no está instalado.[/red]"); return None

        ip      = self.target.ip
        domain  = self.creds.domain   or ""
        user    = self.creds.user     or ""
        passwd  = self.creds.password or ""
        nt_hash = self.creds.hash     or ""
        timeout = self.target.timeout or 5

        lm_hash = ""
        if nt_hash and ":" in nt_hash:
            lm_hash, nt_hash = nt_hash.split(":", 1)

        vulnerable = []
        try:
            conn = SMBConnection(ip, ip, timeout=timeout)
            conn.login(user, passwd, domain, lm_hash, nt_hash)
            rpctransport = transport.SMBTransport(ip, filename="\\\\samr", smb_connection=conn)
            dce = rpctransport.get_dce_rpc()
            dce.connect(); dce.bind(samr.MSRPC_UUID_SAMR)

            resp = samr.hSamrConnect(dce)
            server_handle = resp["ServerHandle"]
            resp2 = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
            domain_name = resp2["Buffer"]["Buffer"][0]["Name"]
            resp3 = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain_name)
            resp4 = samr.hSamrOpenDomain(dce, server_handle, domainId=resp3["DomainId"])
            dh = resp4["DomainHandle"]

            # Enumerar usuarios y equipos (RIDs 500–3000 heurístico)
            for rid in range(500, 3001):
                try:
                    rh = samr.hSamrOpenUser(dce, dh, userId=rid)
                    info = samr.hSamrQueryInformationUser2(
                        dce, rh["UserHandle"],
                        samr.USER_INFORMATION_CLASS.UserAllInformation
                    )
                    uac  = int(info["Buffer"]["All"]["UserAccountControl"])
                    name = str(info["Buffer"]["All"]["UserName"])
                    samr.hSamrCloseHandle(dce, rh["UserHandle"])
                    if uac & _TRUSTED_FOR_DELEGATION and name:
                        account_type = "Equipo" if name.endswith("$") else "Usuario"
                        vulnerable.append((name, account_type, f"UAC=0x{uac:08x}"))
                        session_db.DB.SaveFinding(
                            ip, "SMB", "unconstrained_delegation",
                            f"account={name} type={account_type}"
                        )
                except Exception:
                    continue

            dce.disconnect(); conn.logoff()
        except Exception as e:
            print_result("SMB", ip, "fail", f"SAMR error: {e}"); return None

        if vulnerable:
            print_table(f"Cuentas con delegación sin restricciones en {ip}",
                        ["Cuenta", "Tipo", "UAC"], vulnerable)
            print_result("SMB", ip, "pwned",
                         f"{len(vulnerable)} cuenta(s) con delegación sin restricciones")
        else:
            print_result("SMB", ip, "ok", "No se encontraron cuentas con delegación sin restricciones")
        return vulnerable
