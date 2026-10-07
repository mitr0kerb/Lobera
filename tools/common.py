# tools/common.py
"""
Utilidades visuales compartidas por todas las herramientas de la suite Lobera.
"""

import sys
import os

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from core.output import console
from rich.panel import Panel
from rich.table import Table
from rich import box


def banner(subtitulo: str, version: str = "0.2"):
    """Imprime el logo ASCII de Lobera + subtítulo de la herramienta."""
    try:
        import pyfiglet
        art = pyfiglet.figlet_format("LOBERA", font="slant")
    except Exception:
        art = "LOBERA"

    console.print(f"[bold cyan]{art}[/bold cyan]")
    console.print(
        f"  [bold cyan]{subtitulo}[/bold cyan]  "
        f"[dim]v{version} — by mitr0kerb[/dim]\n"
    )


def panel_info(titulo: str, lineas: list[str]):
    """Panel informativo con fondo oscuro."""
    contenido = "\n".join(lineas)
    console.print(Panel(
        contenido,
        title=f"[bold cyan]{titulo}[/bold cyan]",
        border_style="cyan",
        padding=(0, 2),
    ))
    console.print()


def tabla_modos(filas: list[tuple], titulo: str = "Modos"):
    """
    Tabla de modos/subcomandos.
    filas: [(modo, descripcion), ...]
    """
    t = Table(
        title=f"[bold cyan]{titulo}[/bold cyan]",
        box=box.ROUNDED,
        border_style="cyan",
        show_header=True,
        header_style="bold cyan",
        padding=(0, 1),
    )
    t.add_column("Modo",        style="bold green",  no_wrap=True)
    t.add_column("Descripción", style="white")
    for modo, desc in filas:
        t.add_row(modo, desc)
    console.print(t)
    console.print()


def tabla_flags(filas: list[tuple], titulo: str = "Opciones principales"):
    """
    Tabla de flags/opciones.
    filas: [(flag, tipo, descripcion), ...]
    """
    t = Table(
        title=f"[bold cyan]{titulo}[/bold cyan]",
        box=box.ROUNDED,
        border_style="dim",
        show_header=True,
        header_style="bold white",
        padding=(0, 1),
    )
    t.add_column("Flag",        style="bold yellow", no_wrap=True)
    t.add_column("Tipo",        style="dim cyan",    no_wrap=True)
    t.add_column("Descripción", style="white")
    for flag, tipo, desc in filas:
        t.add_row(flag, tipo, desc)
    console.print(t)
    console.print()


def ejemplos(lineas: list[str], titulo: str = "Ejemplos"):
    """Bloque de ejemplos de uso."""
    console.print(f"  [bold cyan]{titulo}[/bold cyan]")
    console.print()
    for linea in lineas:
        if linea.startswith("#"):
            console.print(f"  [dim]{linea}[/dim]")
        else:
            console.print(f"  [bold green]$[/bold green] [yellow]{linea}[/yellow]")
    console.print()
