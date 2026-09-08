# scripts/smb/shell/interactive.py
"""
SMB interactive shell with tab completion.
Commands: shares, use, ls, cd, get, cat, put, pwd, exit
Tab completes: commands and remote paths from the live server.
get downloads to the current working directory (not loot/).
"""

import os
import readline
import sys
import tempfile
from pathlib import Path

from rich.table import Table
from rich import box

from core.output import console
from core.target import Target
from core.credentials import Creds
from core import session_db
from scripts.base import BaseScript

try:
    from impacket.smbconnection import SMBConnection, SessionError
    _IMPACKET_OK = True
except ImportError:
    _IMPACKET_OK = False

COLOR = "green"


class _SMBCompleter:
    COMMANDS = [
        "shares", "use ", "ls", "cd ", "cd ..", "pwd",
        "get ", "put ", "cat ", "exit", "help", "clear",
    ]

    def __init__(self):
        self._conn    = None
        self._share   = None
        self._cwd_ref = None
        self._cache   = {}

    def attach(self, conn, share, cwd_ref):
        self._conn    = conn
        self._share   = share
        self._cwd_ref = cwd_ref

    def _list_remote(self, path):
        if not self._conn or not self._share:
            return []
        key = f"{self._share}:{path}"
        if key in self._cache:
            return self._cache[key]
        try:
            entries = self._conn.listPath(self._share, path + "\\*")
            names = [e.get_longname() for e in entries
                     if e.get_longname() not in (".", "..")]
            self._cache[key] = names
            return names
        except Exception:
            self._cache[key] = []
            return []

    def invalidate_cache(self, path=None):
        if path is None:
            self._cache.clear()
        else:
            self._cache.pop(f"{self._share}:{path}", None)

    def complete(self, text, state):
        if state == 0:
            buf   = readline.get_line_buffer()
            parts = buf.lstrip().split()

            if not buf.strip() or (len(parts) == 1 and not buf.endswith(" ")):
                self._matches = [c for c in self.COMMANDS if c.startswith(text)]
            elif parts[0] in ("cd", "get", "cat", "put", "ls"):
                cwd = self._cwd_ref() if self._cwd_ref else ""
                arg = buf.split(" ", 1)[1] if " " in buf else ""
                if "\\" in arg or "/" in arg:
                    sep_idx    = max(arg.rfind("\\"), arg.rfind("/"))
                    prefix     = arg[:sep_idx + 1]
                    stem       = arg[sep_idx + 1:]
                    remote_dir = os.path.join(cwd, prefix).replace("/", "\\")
                else:
                    prefix     = ""
                    stem       = arg
                    remote_dir = cwd or ""
                entries = self._list_remote(remote_dir)
                self._matches = [
                    prefix + e for e in entries if e.lower().startswith(stem.lower())
                ]
            else:
                self._matches = []

        try:
            return self._matches[state]
        except IndexError:
            return None


class Script(BaseScript):
    name        = "interactive-shell"
    protocol    = "smb"
    category    = "shell"
    description = "Interactive SMB shell: shares, ls, cd, get, put. Tab completes remote paths."

    def run(self, **kwargs):
        if not _IMPACKET_OK:
            console.print("[red]impacket not installed. Run: pip install impacket[/red]")
            return

        ip      = self.target.ip
        domain  = self.creds.domain   or ""
        user    = self.creds.user     or ""
        passwd  = self.creds.password or ""
        nt_hash = self.creds.hash     or ""
        timeout = self.target.timeout or 120

        try:
            conn    = SMBConnection(ip, ip, timeout=timeout)
            lm_hash = ""
            if nt_hash and ":" in nt_hash:
                lm_hash, nt_hash = nt_hash.split(":", 1)
            conn.login(user, passwd, domain, lm_hash, nt_hash)
        except Exception as e:
            console.print(f"[red]Connection failed: {e}[/red]")
            return

        console.print(f"[bold {COLOR}]Connected to {ip} as {user or '(anonymous)'}[/bold {COLOR}]")
        console.print("[dim]Type 'help' for commands. Press Tab to autocomplete remote paths.[/dim]\n")
        session_db.DB.SaveTarget(ip, "", domain)

        share    = None
        cwd      = ""
        cwd_ref  = lambda: cwd

        completer = _SMBCompleter()
        readline.set_completer(completer.complete)
        readline.set_completer_delims(" \t")
        readline.parse_and_bind("tab: complete")

        def prompt():
            loc = (f"\\\\{ip}\\{share}" + (f"\\{cwd}" if cwd else "")) if share else f"\\\\{ip}"
            return f"\033[1;32m[smb: {loc}]\033[0m > "

        def print_help():
            t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
            t.add_column(style="bold green")
            t.add_column(style="dim")
            for cmd, desc in [
                ("shares",       "List available shares"),
                ("use <share>",  "Connect to a share"),
                ("ls [path]",    "List directory contents"),
                ("cd <path>",    "Change remote directory"),
                ("cd ..",        "Go up one directory"),
                ("pwd",          "Print current remote path"),
                ("get <file>",   "Download file to current local directory"),
                ("put <file>",   "Upload local file"),
                ("cat <file>",   "Print file contents"),
                ("clear",        "Clear screen"),
                ("exit",         "Exit shell"),
            ]:
                t.add_row(cmd, desc)
            console.print(t)

        def list_shares():
            try:
                items = conn.listShares()
                t = Table(box=box.SIMPLE, show_header=True, border_style=COLOR)
                t.add_column("Share",   style=f"bold {COLOR}")
                t.add_column("Type",    style="dim")
                t.add_column("Comment", style="dim")
                for s in items:
                    name    = s["shi1_netname"][:-1]
                    stype   = {0: "DISK", 1: "PRINT", 3: "IPC"}.get(s["shi1_type"] & 0x3, "OTHER")
                    comment = s["shi1_remark"][:-1] if s["shi1_remark"] else ""
                    t.add_row(name, stype, comment)
                console.print(t)
            except Exception as e:
                console.print(f"[red]shares: {e}[/red]")

        def do_ls(path=""):
            if not share:
                console.print("[yellow]No share selected. Use: use <share>[/yellow]")
                return
            remote  = (cwd + "\\" + path).strip("\\") if path else cwd
            pattern = remote + "\\*" if remote else "*"
            try:
                entries = conn.listPath(share, pattern)
                t = Table(box=box.SIMPLE, show_header=True, border_style=COLOR)
                t.add_column("Name",     style="bold")
                t.add_column("Size",     justify="right", style="dim")
                t.add_column("Modified", style="dim")
                for e in sorted(entries, key=lambda x: x.get_longname()):
                    n = e.get_longname()
                    if n in (".", ".."):
                        continue
                    is_dir = bool(e.get_attributes() & 0x10)
                    size   = "-" if is_dir else f"{e.get_filesize():,}"
                    mtime  = e.get_mtime().strftime("%Y-%m-%d %H:%M") if e.get_mtime() else "-"
                    name_s = f"[bold blue]{n}/[/bold blue]" if is_dir else n
                    t.add_row(name_s, size, mtime)
                console.print(t)
            except Exception as e:
                console.print(f"[red]ls: {e}[/red]")

        def do_cd(path):
            nonlocal cwd
            if not share:
                console.print("[yellow]No share selected.[/yellow]")
                return
            if path == "..":
                cwd = cwd.rsplit("\\", 1)[0] if "\\" in cwd else ""
                completer.invalidate_cache(cwd)
                return
            target_path = (cwd + "\\" + path).strip("\\") if cwd else path
            try:
                conn.listPath(share, target_path + "\\*")
                cwd = target_path
                completer.invalidate_cache(cwd)
            except Exception as e:
                console.print(f"[red]cd: {path}: {e}[/red]")

        def do_get(remote_name):
            if not share:
                console.print("[yellow]No share selected.[/yellow]")
                return
            remote_path = (cwd + "\\" + remote_name).strip("\\") if cwd else remote_name
            local_path  = Path(os.getcwd()) / remote_name.split("\\")[-1].split("/")[-1]
            try:
                with open(local_path, "wb") as fh:
                    conn.getFile(share, remote_path, fh.write)
                size = local_path.stat().st_size
                console.print(
                    f"[green]✓[/green] [bold]{remote_name}[/bold] → "
                    f"[cyan]{local_path}[/cyan] ({size:,} bytes)"
                )
                session_db.DB.SaveFinding(
                    self.target.ip, "SMB", "file_downloaded",
                    f"{share}/{remote_path} → {local_path}"
                )
            except Exception as e:
                console.print(f"[red]get: {e}[/red]")

        def do_put(local_name):
            if not share:
                console.print("[yellow]No share selected.[/yellow]")
                return
            local_path  = Path(local_name)
            if not local_path.exists():
                console.print(f"[red]put: {local_name}: not found[/red]")
                return
            remote_path = (cwd + "\\" + local_path.name).strip("\\") if cwd else local_path.name
            try:
                with open(local_path, "rb") as fh:
                    conn.putFile(share, remote_path, fh.read)
                console.print(f"[green]✓[/green] Uploaded [bold]{local_path.name}[/bold] → {remote_path}")
                completer.invalidate_cache(cwd)
            except Exception as e:
                console.print(f"[red]put: {e}[/red]")

        def do_cat(remote_name):
            if not share:
                console.print("[yellow]No share selected.[/yellow]")
                return
            remote_path = (cwd + "\\" + remote_name).strip("\\") if cwd else remote_name
            buf = []
            try:
                conn.getFile(share, remote_path, buf.append)
                content = b"".join(buf)
                console.print(content.decode("utf-8", errors="replace"))
            except Exception as e:
                console.print(f"[red]cat: {e}[/red]")

        while True:
            try:
                line = input(prompt()).strip()
            except (EOFError, KeyboardInterrupt):
                console.print("\n[dim]Exiting SMB shell.[/dim]")
                break
            if not line:
                continue
            parts = line.split(maxsplit=1)
            cmd   = parts[0].lower()
            arg   = parts[1] if len(parts) > 1 else ""

            if cmd in ("exit", "quit"):
                console.print("[dim]Exiting SMB shell.[/dim]")
                break
            elif cmd == "help":
                print_help()
            elif cmd == "shares":
                list_shares()
            elif cmd == "use":
                if not arg:
                    console.print("[red]Usage: use <share>[/red]")
                else:
                    try:
                        conn.listPath(arg, "*")
                        share = arg
                        cwd   = ""
                        completer.attach(conn, share, cwd_ref)
                        completer.invalidate_cache()
                        console.print(f"[{COLOR}]Share: [bold]{share}[/bold][/{COLOR}]")
                    except Exception as e:
                        console.print(f"[red]use: {arg}: {e}[/red]")
            elif cmd == "ls":
                do_ls(arg)
            elif cmd == "cd":
                if arg:
                    do_cd(arg)
            elif cmd == "pwd":
                loc = (f"\\\\{ip}\\{share}" + (f"\\{cwd}" if cwd else "")) if share else f"\\\\{ip}"
                console.print(f"  [cyan]{loc}[/cyan]")
            elif cmd == "get":
                if not arg:
                    console.print("[red]Usage: get <remote_file>[/red]")
                else:
                    do_get(arg)
            elif cmd == "put":
                if not arg:
                    console.print("[red]Usage: put <local_file>[/red]")
                else:
                    do_put(arg)
            elif cmd == "cat":
                if not arg:
                    console.print("[red]Usage: cat <remote_file>[/red]")
                else:
                    do_cat(arg)
            elif cmd == "clear":
                os.system("clear")
            else:
                console.print(f"[red]Unknown command: '{cmd}'[/red] — type [bold]help[/bold]")

        try:
            conn.logoff()
        except Exception:
            pass
