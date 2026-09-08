# utils/banner.py

import pyfiglet
from core.output import console

VERSION = "1.0"
AUTHOR = "mitr0kerb"


def show_banner():
    ascii_art = pyfiglet.figlet_format("LOBERA", font="slant")
    console.print(f"[bold cyan]{ascii_art}[/bold cyan]")
    console.print(f"[dim]  AD enumeration & attack toolkit — SMB · RPC · Kerberos · LDAP · WinRM[/dim]")
    console.print(f"[dim]  v{VERSION} — by [/dim][bold cyan]{AUTHOR}[/bold cyan]\n")
