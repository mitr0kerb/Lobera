
# scripts/smb/enum/sessions.py
"""Enumerate active SMB sessions via NetSessEnum (SRVSVC pipe)."""
from core.output import console, print_result, print_table
from core import session_db
from scripts.base import BaseScript

try:
    from impacket.smbconnection import SMBConnection
    from impacket.dcerpc.v5 import transport, srvs
    _OK = True
except ImportError:
    _OK = False


class Script(BaseScript):
    name        = "sessions"
    protocol    = "smb"
    category    = "enum"
    description = "Enumerate active SMB sessions on the server via SRVSVC (NetSessEnum)."

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
            rpctransport = transport.SMBTransport(ip, filename="\\\\srvsvc", smb_connection=conn)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(srvs.MSRPC_UUID_SRVS)
            resp = srvs.hNetrSessionEnum(dce, "\x00", NULL=None, level=10)
            sessions = []
            for s in resp["InfoStruct"]["SessionInfo"]["Level10"]["Buffer"]:
                client = str(s["sesi10_cname"]).strip("\x00").lstrip("\\")
                suser  = str(s["sesi10_username"]).strip("\x00")
                time_  = str(s["sesi10_time"])
                sessions.append((client, suser, time_))
                session_db.DB.SaveFinding(ip, "SMB", "active_session",
                                          f"client={client} user={suser}")
            dce.disconnect(); conn.logoff()
        except Exception as e:
            print_result("SMB", ip, "fail", f"SRVSVC error: {e}"); return None

        if sessions:
            print_table(f"Active sessions on {ip}", ["Client", "User", "Time (s)"], sessions)
            print_result("SMB", ip, "ok", f"{len(sessions)} session(s) found")
        else:
            print_result("SMB", ip, "info", "No active sessions found")
        return sessions
