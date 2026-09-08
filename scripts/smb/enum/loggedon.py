
# scripts/smb/enum/loggedon.py
"""Enumerate logged-on users via NetWkstaUserEnum (WKSSVC pipe)."""
from core.output import console, print_result, print_table
from core import session_db
from scripts.base import BaseScript

try:
    from impacket.smbconnection import SMBConnection
    from impacket.dcerpc.v5 import transport, wkst
    _OK = True
except ImportError:
    _OK = False


class Script(BaseScript):
    name        = "loggedon"
    protocol    = "smb"
    category    = "enum"
    description = "Enumerate logged-on users via WKSSVC (NetWkstaUserEnum). Requires admin."

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
            rpctransport = transport.SMBTransport(ip, filename="\\\\wkssvc", smb_connection=conn)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(wkst.MSRPC_UUID_WKST)
            resp = wkst.hNetrWkstaUserEnum(dce, 1)
            users = []
            for entry in resp["UserInfo"]["WkstaUserInfo"]["Level1"]["Buffer"]:
                uname  = str(entry["wkui1_username"]).strip("\x00")
                dom    = str(entry["wkui1_logon_domain"]).strip("\x00")
                server = str(entry["wkui1_logon_server"]).strip("\x00")
                if uname:
                    users.append((uname, dom, server))
                    session_db.DB.SaveFinding(ip, "SMB", "loggedon_user",
                                              f"user={uname} domain={dom}")
            dce.disconnect(); conn.logoff()
        except Exception as e:
            print_result("SMB", ip, "fail", f"WKSSVC error: {e}"); return None

        if users:
            print_table(f"Logged-on users on {ip}", ["Username", "Domain", "Logon Server"], users)
            print_result("SMB", ip, "ok", f"{len(users)} logged-on user(s)")
        else:
            print_result("SMB", ip, "info", "No logged-on users found (or access denied)")
        return users
