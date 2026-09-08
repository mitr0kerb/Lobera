
# scripts/smb/enum/users.py
"""
Enumerate domain/local users via RID cycling over SMB (SAMR pipe).
Works with null session or valid credentials.
No LDAP required — pure SMB named pipe.
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


class Script(BaseScript):
    name        = "users"
    protocol    = "smb"
    category    = "enum"
    description = "Enumerate users via RID cycling over SAMR pipe (works with null session)."

    def run(self, **kwargs):
        if not _OK:
            console.print("[red]impacket not installed.[/red]"); return None

        ip      = self.target.ip
        domain  = self.creds.domain   or ""
        user    = self.creds.user     or ""
        passwd  = self.creds.password or ""
        nt_hash = self.creds.hash     or ""
        timeout = self.target.timeout or 5
        rid_end = int(kwargs.get("rid_end", 1200))

        lm_hash = ""
        if nt_hash and ":" in nt_hash:
            lm_hash, nt_hash = nt_hash.split(":", 1)

        try:
            conn = SMBConnection(ip, ip, timeout=timeout)
            conn.login(user, passwd, domain, lm_hash, nt_hash)
        except Exception as e:
            print_result("SMB", ip, "fail", f"Connection failed: {e}"); return None

        try:
            rpctransport = transport.SMBTransport(
                ip, filename=r"\samr", smb_connection=conn
            )
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)

            resp = samr.hSamrConnect(dce)
            server_handle = resp["ServerHandle"]

            resp2 = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
            domains = resp2["Buffer"]["Buffer"]
            domain_name = domains[0]["Name"]

            resp3 = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain_name)
            domain_sid = resp3["DomainId"]

            resp4 = samr.hSamrOpenDomain(dce, server_handle, domainId=domain_sid)
            domain_handle = resp4["DomainHandle"]

            users = []
            for rid in range(500, rid_end + 1):
                try:
                    resp5 = samr.hSamrOpenUser(dce, domain_handle, userId=rid)
                    user_handle = resp5["UserHandle"]
                    info = samr.hSamrQueryInformationUser2(
                        dce, user_handle,
                        samr.USER_INFORMATION_CLASS.UserAllInformation
                    )
                    uname = str(info["Buffer"]["All"]["UserName"])
                    if uname:
                        users.append((str(rid), uname))
                        session_db.DB.SaveFinding(
                            ip, "SMB", "user_found", f"RID={rid} user={uname}"
                        )
                    samr.hSamrCloseHandle(dce, user_handle)
                except Exception:
                    continue

            dce.disconnect()
            conn.logoff()
        except Exception as e:
            print_result("SMB", ip, "fail", f"SAMR error: {e}"); return None

        if users:
            print_table(f"Users on {ip} ({domain_name})", ["RID", "Username"], users)
            print_result("SMB", ip, "ok", f"{len(users)} user(s) found")
        else:
            print_result("SMB", ip, "info", "No users found via RID cycling")
        return users
