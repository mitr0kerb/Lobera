# modules/winrm_shell.py — consola interactiva WinRM

import pyfiglet
from core.output import console

try:
    from modules.winrm import WinRMModule
    _WINRM_OK = True
except ImportError:
    _WINRM_OK = False


class WinRMShell:
    """Consola interactiva sobre WinRMModule."""

    def __init__(self, target, creds, use_ssl=False, port=None):
        self.target  = target
        self.creds   = creds
        self.use_ssl = use_ssl
        self.port    = port
        self.winrm   = None
        self._mode   = "ps"   # "ps" | "cmd"

    def run(self):
        self._mini_banner()
        if not _WINRM_OK:
            console.print("[red]modules/winrm.py no disponible.[/red]"); return

        self.winrm = WinRMModule(self.target, self.creds,
                                 use_ssl=self.use_ssl, port=self.port)
        if not self.winrm.connect():
            return

        console.print(
            "  Modo: [bold cyan]PowerShell[/bold cyan] (cambia con [bold]mode cmd[/bold])\n"
            "  Escribe [bold]help[/bold] para ver comandos especiales.\n"
        )

        while True:
            try:
                prompt = self._prompt()
                raw    = console.input(prompt).strip()
            except (EOFError, KeyboardInterrupt):
                console.print("\n[dim]Saliendo...[/dim]")
                break

            if not raw:
                continue

            parts = raw.split(None, 1)
            cmd   = parts[0].lower()
            rest  = parts[1] if len(parts) > 1 else ""

            if cmd in ("exit", "quit"):
                break
            elif cmd == "help":
                self._help()
            elif cmd == "cls":
                console.clear()
            elif cmd == "mode":
                self._set_mode(rest)
            elif cmd == "upload":
                self._upload(rest)
            elif cmd == "download":
                self._download(rest)
            elif cmd == "sysinfo":
                self._sysinfo()
            elif cmd == "privesc":
                self._privesc()
            elif cmd == "av":
                self._av()
            elif cmd == "laps":
                self._laps(rest)
            else:
                # Ejecución directa
                if self._mode == "ps":
                    self.winrm.run_ps(raw)
                else:
                    self.winrm.run_cmd(raw)

        if self.winrm:
            self.winrm.disconnect()

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------

    def _mini_banner(self):
        art = pyfiglet.figlet_format("WinRM Shell", font="small")
        console.print(f"[bold cyan]{art}[/bold cyan]")
        proto = "WINRM-SSL" if self.use_ssl else "WINRM"
        console.print(
            f"  [bold cyan]{proto}[/bold cyan] → "
            f"[dim]{self.target.ip}:{self.port or '5985'}[/dim]  "
            f"[dim]usuario: {self.creds.user or 'anónimo'}[/dim]\n"
        )

    def _prompt(self):
        mode_label = "[bold cyan]PS[/bold cyan]" if self._mode == "ps" else "[bold white]CMD[/bold white]"
        return f"{mode_label} [cyan][WINRM@{self.target.ip}][/cyan]> "

    def _set_mode(self, mode):
        if mode in ("ps", "powershell"):
            self._mode = "ps"
            console.print("[dim]Modo: PowerShell[/dim]")
        elif mode in ("cmd", "command"):
            self._mode = "cmd"
            console.print("[dim]Modo: cmd.exe[/dim]")
        else:
            console.print("[red]Modo desconocido. Usar: mode ps | mode cmd[/red]")

    def _upload(self, rest):
        parts = rest.split(None, 1)
        if len(parts) < 2:
            console.print("[red]Uso: upload <local_path> <remote_path>[/red]"); return
        self.winrm.upload_file(parts[0], parts[1])

    def _download(self, rest):
        parts = rest.split(None, 1)
        if len(parts) < 2:
            console.print("[red]Uso: download <remote_path> <local_path>[/red]"); return
        self.winrm.download_file(parts[0], parts[1])

    def _sysinfo(self):
        info = self.winrm.get_sysinfo()
        if info:
            from core.output import print_table
            print_table("System Info", ["Campo","Valor"],
                        [(k, v) for k, v in info.items()])

    def _privesc(self):
        self.winrm.check_privesc()

    def _av(self):
        self.winrm.get_av_status()

    def _laps(self, computer=""):
        self.winrm.get_laps_password(computer or None)

    def _help(self):
        console.print("""
[bold cyan]═══ WinRM Shell — Comandos especiales ═══[/bold cyan]

  [white]mode ps[/white]                     Cambiar a modo PowerShell (default)
  [white]mode cmd[/white]                    Cambiar a modo cmd.exe
  [white]upload[/white] <local> <remoto>     Subir fichero al objetivo
  [white]download[/white] <remoto> <local>   Descargar fichero del objetivo
  [white]sysinfo[/white]                     Información del sistema
  [white]privesc[/white]                     Comprobaciones de privesc (AlwaysInstallElevated, unquoted paths…)
  [white]av[/white]                          Estado del antivirus / Windows Defender
  [white]laps[/white] [equipo]               Intentar leer contraseña LAPS

  [white]cls[/white]  /  [white]help[/white]  /  [white]exit[/white]

[dim]Cualquier otro input se ejecuta directamente en el modo activo (PS o CMD).[/dim]
""")
