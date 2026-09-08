
# scripts/smb/enum/groups.py
"""Enumerate local groups via SAMR pipe over SMB."""
from core.output import console, print_result, print_table
from core import session_db
from scripts.base import BaseScript

try:
    from impacket.smbconnection import SMBConnection
    from impacket.dcerpc.v5 import transport, samr
    _OK = True
except ImportError:
    _OK = False


class Script(BaseScript):
    name        = "groups"
    protocol    = "smb"
    category    = "enum"
    description = "Enumerate local/domain groups via SAMR pipe over SMB."

    def run(self, **kwargs):
        if not _OK:
            console.print("[red]impacket not installed.[/red]"); return None

        ip      = self.target.ip
        domain  = self.creds.domain   or ""
        user    = self.creds.user     or ""
        passwd  = self.creds.password or ""
        nt_hash = self.creds.hash     or ""
        timeout = self.target.timeout or 5

        lm_hash = ""
        if nt_hash and ":" in nt_hash:
            lm_hash, nt_hash = nt_hash.split(":", 1)

        try:
            conn = SMBConnection(ip, ip, timeout=timeout)
            conn.login(user, passwd, domain, lm_hash, nt_hash)
            rpctransport = transport.SMBTransport(
                ip, filename=r"\samr", smb_connection=conn
            )
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)

            resp = samr.hSamrConnect(dce)
            server_handle = resp["ServerHandle"]
            resp2 = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
            domain_name = resp2["Buffer"]["Buffer"][0]["Name"]
            resp3 = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain_name)
            resp4 = samr.hSamrOpenDomain(dce, server_handle,
                                          domainId=resp3["DomainId"])
            domain_handle = resp4["DomainHandle"]

            groups = []
            resp5 = samr.hSamrEnumerateGroupsInDomain(dce, domain_handle)
            for group in resp5["Buffer"]["Buffer"]:
                gname = str(group["Name"])
                rid   = str(group["RelativeId"])
                groups.append((rid, gname))
                session_db.DB.SaveFinding(ip, "SMB", "group_found",
                                           f"RID={rid} group={gname}")
            dce.disconnect()
            conn.logoff()
        except Exception as e:
            print_result("SMB", ip, "fail", f"SAMR error: {e}"); return None

        if groups:
            print_table(f"Groups on {ip}", ["RID", "Group"], groups)
            print_result("SMB", ip, "ok", f"{len(groups)} group(s) found")
        else:
            print_result("SMB", ip, "info", "No groups found")
        return groups
