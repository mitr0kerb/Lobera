# modules/smb_shell.py

import os
import pyfiglet
from core.output import console


class SMBShell:
    def __init__(self, smb_module):
        self.smb = smb_module
        self.current_share = None
        self.current_path = ""

    def _mini_banner(self):
        banner = pyfiglet.figlet_format("SMB Shell", font="small")
        console.print(f"[bold green]{banner}[/bold green]")

    def _prompt(self):
        version = self.smb.dialect_name or "SMB"
        user = self.smb.creds.user or "anonymous"
        share_part = f" - Using: [red]{self.current_share}[/red]" if self.current_share else ""
        return f"[cyan][{version}@{user}{share_part}][/cyan]> "

    def run(self):
        self._mini_banner()
        console.print("Escribe 'help' para ver comandos\n")
        while True:
            try:
                cmd_line = console.input(self._prompt()).strip()
            except (EOFError, KeyboardInterrupt):
                console.print("\nSaliendo...")
                break

            if not cmd_line:
                continue

            parts = cmd_line.split(maxsplit=1)
            cmd = parts[0].lower()
            arg = parts[1] if len(parts) > 1 else ""

            if cmd in ("exit", "quit"):
                break
            elif cmd == "help":
                self._help()
            elif cmd == "shares":
                self.smb.list_shares()
            elif cmd == "use":
                self._use(arg)
            elif cmd == "pwd":
                self._pwd()
            elif cmd == "ls":
                self._ls()
            elif cmd == "cd":
                self._cd(arg)
            elif cmd == "get":
                self._get(arg)
            elif cmd == "cls":
                self._cls()
            else:
                console.print(f"[red]Comando desconocido: {cmd}[/red] (escribe 'help')")

    def _help(self):
        console.print("""
[bold]Comandos disponibles:[/bold]
  shares          Lista los shares disponibles
  use <share>     Selecciona un share para trabajar
  pwd             Muestra dónde estás (share + ruta actual)
  ls              Lista el contenido de la ruta actual
  cd <carpeta>    Entra en una subcarpeta ('cd ..' para subir)
  get <fichero>   Descarga un fichero de la ruta actual
  cls             Limpia la pantalla
  exit / quit     Sale de la consola
""")

    def _use(self, share_name):
        if not share_name:
            console.print("[red]Uso: use <nombre_share>[/red]")
            return

        share_name = share_name.strip()

        # Validamos que el share exista de verdad antes de "usarlo" (sin imprimir tabla)
        shares = self.smb.list_shares(silent=True)
        matching = [s for s in shares if s[0].lower() == share_name.lower()]

        if not matching:
            console.print(f"[red]No existe el share '{share_name}' en este objetivo[/red]")
            return

        self.current_share = matching[0][0]  # usamos el nombre real (respeta mayúsculas y símbolos como $)
        self.current_path = ""
        console.print(f"Usando share: [green]{self.current_share}[/green]")

    def _pwd(self):
        if not self.current_share:
            console.print("No hay share seleccionado (usa 'use <share>')")
            return
        location = f"{self.current_share}{self.current_path}"
        console.print(f"Ubicación actual: [cyan]{location}[/cyan]")

    def _ls(self):
        if not self.current_share:
            console.print("[red]No hay share seleccionado (usa 'use <share>')[/red]")
            return
        self.smb.list_files(self.current_share, self.current_path)

    def _cd(self, folder):
        if not self.current_share:
            console.print("[red]No hay share seleccionado (usa 'use <share>')[/red]")
            return
        if not folder:
            console.print("[red]Uso: cd <carpeta>[/red] (o 'cd ..' para subir)")
            return

        # normalizamos: quitamos barras sueltas al final/inicio y espacios,
        # para que "..", "../" y "..\\" se traten igual
        folder = folder.strip().strip("/").strip("\\")

        if folder in (".", ""):
            return  # quedarse donde estás

        if folder == "..":
            if self.current_path:
                parts = self.current_path.rsplit("\\", 1)
                self.current_path = parts[0] if len(parts) > 1 else ""
            return

        # Validamos que la carpeta exista de verdad antes de "entrar" (sin imprimir tabla)
        entries = self.smb.list_files(self.current_share, self.current_path, silent=True)
        matching = [e for e in entries if e[0].lower() == folder.lower() and e[1] == "Sí"]

        if not matching:
            console.print(f"[red]No existe la carpeta '{folder}' en la ruta actual[/red]")
            return

        self.current_path = f"{self.current_path}\\{matching[0][0]}"  # usamos el nombre real (respeta mayúsculas)

    def _get(self, filename):
        if not self.current_share:
            console.print("[red]No hay share seleccionado (usa 'use <share>')[/red]")
            return
        if not filename:
            console.print("[red]Uso: get <fichero>[/red]")
            return

        remote_path = f"{self.current_path}\\{filename}"
        local_path = os.path.join("loot", self.smb.target.ip, self.current_share.strip("\\"),
                                    self.current_path.strip("\\"), filename)
        self.smb.download_file(self.current_share, remote_path, local_path)

    def _cls(self):
        console.clear()
