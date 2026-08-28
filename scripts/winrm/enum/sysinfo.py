# scripts/winrm/enum/sysinfo.py

from scripts.base import BaseScript
from core.output import print_result, print_table, console
from core import session_db

try:
    from modules.winrm import WinRMModule
    _WINRM_OK = True
except ImportError:
    _WINRM_OK = False


class Script(BaseScript):
    name        = "sysinfo"
    protocol    = "winrm"
    category    = "enum"
    description = (
        "Recopila información completa del sistema vía WinRM/PowerShell: "
        "OS, versión, arquitectura, usuarios locales, grupos, procesos, "
        "red, servicios, software instalado y AV."
    )

    EXAMPLES = [
        {
            "flag":  "-t / -u / -p",
            "desc":  "Credenciales de administrador local o de dominio",
            "good":  "lobera.py winrm --script=sysinfo -t 10.129.1.5 -u Administrator -p 'Pass1'",
            "bad":   "lobera.py winrm --script=sysinfo -t 10.129.1.5  [sin credenciales WinRM rechaza la conexión]",
        },
        {
            "flag":  "-k / --ccache",
            "desc":  "Autenticar con ticket Kerberos",
            "good":  "lobera.py winrm --script=sysinfo -t 10.129.1.5 -u admin -d CORP.LOCAL -k",
            "bad":   "lobera.py winrm --script=sysinfo -t 10.129.1.5 -k  [sin -u el ticket no sabe qué usuario usar]",
        },
    ]

    def run(self, **kwargs):
        if not _WINRM_OK:
            print_result("WINRM", str(self.target.ip), "fail",
                         "modules/winrm.py no disponible"); return None

        w = WinRMModule(self.target, self.creds,
                        use_ssl=kwargs.get("ssl", False),
                        port=kwargs.get("port"))
        if not w.connect(): return None

        try:
            # Información base
            print_result("WINRM", str(self.target.ip), "info", "Recopilando info del sistema...")
            info = w.get_sysinfo()
            if info:
                rows = [(k, v) for k, v in info.items()]
                print_table("Sistema", ["Campo","Valor"], rows)

            # Usuarios locales
            console.print("\n[bold cyan]── Usuarios locales ──[/bold cyan]")
            w.get_local_users()

            # Administradores locales
            console.print("\n[bold cyan]── Administradores locales ──[/bold cyan]")
            w.get_local_admins()

            # Red
            console.print("\n[bold cyan]── Red ──[/bold cyan]")
            w.get_network_info()

            # AV
            console.print("\n[bold cyan]── Antivirus ──[/bold cyan]")
            w.get_av_status()

            return info
        finally:
            w.disconnect()
