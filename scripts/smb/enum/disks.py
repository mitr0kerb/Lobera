
# scripts/smb/enum/disks.py
"""Enumerate disk drives on the remote server via SRVSVC."""
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
    name        = "disks"
    protocol    = "smb"
    category    = "enum"
    description = "Enumerate disk drives on the remote server via SRVSVC (NetrServerDiskEnum)."

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
            dce.connect(); dce.bind(srvs.MSRPC_UUID_SRVS)
            resp  = srvs.hNetrServerDiskEnum(dce, 0)
            disks = []
            for disk in resp["DiskInfoStruct"]["Buffer"]:
                drive = str(disk["Disk"]).strip("\x00")
                if drive and drive not in ("\x00", ""):
                    disks.append((drive,))
                    session_db.DB.SaveFinding(ip, "SMB", "disk_found", f"drive={drive}")
            dce.disconnect(); conn.logoff()
        except Exception as e:
            print_result("SMB", ip, "fail", f"SRVSVC error: {e}"); return None

        if disks:
            print_table(f"Disks on {ip}", ["Drive"], disks)
            print_result("SMB", ip, "ok", f"{len(disks)} disk(s) found")
        else:
            print_result("SMB", ip, "info", "No disks enumerated (or access denied)")
        return disks
