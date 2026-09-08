# scripts/smb/scanner.py

import os
from getpass import getpass

import pyfiglet
from rich.panel import Panel
from rich.prompt import Prompt

from core.output import console
from core.target import Target
from core.credentials import Creds
from core.scanner import Scanner, ScanStep
from scripts.smb.scan_params import SCAN_ORDER, REQUIRED, OPTIONAL, EXPORT_FORMATS

PROTOCOL = "SMB"
COLOR    = "green"


def _print_scanner_menu():
    art = pyfiglet.figlet_format("SMB-SCAN", font="slant")
    console.print(f"[bold {COLOR}]{art}[/bold {COLOR}]")
    console.print(
        Panel(
            "[bold]Scripts que se ejecutarán:[/bold]\n\n"
            "  [cyan]FASE 1 — Fingerprint (sin credenciales)[/cyan]\n"
            "    • signing-check   → detecta vulnerabilidad a NTLM relay\n"
            "    • null-session    → comprueba acceso anónimo\n"
            "    • shares          → lista shares accesibles\n\n"
            "  [cyan]FASE 2 — Enumeración autenticada[/cyan]\n"
            "    • gpp-password    → busca credenciales GPP (MS14-025)\n\n"
            "  [cyan]FASE 3 — Ataque encadenado (condicional)[/cyan]\n"
            "    • spider          → rastrea shares con ficheros interesantes\n"
            "    • password-spray  → spray si se proporciona wordlist\n\n"
            "[dim]Los scripts de FASE 2 y 3 se ejecutan solo si las condiciones lo permiten.[/dim]",
            title=f"[bold {COLOR}]SMB Scanner — Lobera[/bold {COLOR}]",
            border_style=COLOR,
            expand=False,
        )
    )
    console.print()


def _collect_params(prefilled):
    console.rule(f"[bold {COLOR}]Parámetros del scan[/bold {COLOR}]")
    console.print()

    params = {}

    for field in REQUIRED:
        key     = field["key"]
        label   = field["label"]
        secret  = field["secret"]
        default = field.get("default")
        req     = field["required"]
        hint    = field.get("hint", "")

        prefill = prefilled.get(key)
        if prefill is not None and prefill != "" and prefill != default:
            params[key] = prefill
            masked = "*" * 8 if secret else prefill
            console.print(f"  [dim]{label}:[/dim] [cyan]{masked}[/cyan] [dim](por CLI)[/dim]")
            continue

        hint_str = f" [dim]({hint})[/dim]" if hint else ""

        while True:
            if secret:
                value = getpass(f"  {label}{' *' if req else ''}: ")
            else:
                raw = Prompt.ask(
                    f"  [bold]{label}[/bold]{'[bold red] *[/bold red]' if req else ''}{hint_str}",
                    default="",
                )
                value = raw

            if req and not value:
                console.print("  [red]Este campo es obligatorio.[/red]")
                continue
            break

        params[key] = value if value else default

    console.print()
    console.print("  [dim]─── Parámetros opcionales ───[/dim]")
    console.print()

    for field in OPTIONAL:
        key     = field["key"]
        label   = field["label"]
        default = field.get("default")
        hint    = field.get("hint", "")
        hint_str = f" [dim]({hint})[/dim]" if hint else ""

        prefill = prefilled.get(key)
        if prefill and os.path.isfile(prefill):
            params[key] = prefill
            console.print(f"  [dim]{label}:[/dim] [cyan]{prefill}[/cyan] [dim](por CLI)[/dim]")
            continue

        value = Prompt.ask(f"  [bold]{label}[/bold]{hint_str}", default="")
        params[key] = value if value else default

    console.print()
    return params


def _collect_verbose():
    console.rule(f"[bold {COLOR}]Nivel de detalle[/bold {COLOR}]")
    console.print()
    console.print("  [bold][1][/bold] Básico   — solo hallazgos críticos")
    console.print("  [bold][2][/bold] Normal   — hallazgos + acciones tomadas  [dim](recomendado)[/dim]")
    console.print("  [bold][3][/bold] Debug    — todo el output de cada script")
    console.print()
    choice = Prompt.ask("  Elige nivel", choices=["1", "2", "3"], default="2")
    console.print()
    return int(choice)


def _collect_output():
    console.rule(f"[bold {COLOR}]Destino de resultados[/bold {COLOR}]")
    console.print()
    console.print("  [bold][s][/bold] Guardar en base de datos de sesión [dim](recomendado)[/dim]")
    console.print("  [bold][n][/bold] Exportar a fichero  [dim](json, html, xml, yaml)[/dim]")
    console.print()

    choice = Prompt.ask("  Opción", choices=["s", "n"], default="s")

    if choice == "s":
        console.print()
        return True, None, None

    fmt = Prompt.ask(
        "  Formato",
        choices=EXPORT_FORMATS,
        default="json",
    )

    from datetime import datetime
    default_name = f"lobera_smb_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{fmt}"
    path = Prompt.ask("  Nombre del fichero", default=default_name)

    if not path.endswith(f".{fmt}"):
        path = f"{path}.{fmt}"

    console.print()
    return False, path, fmt


def run_smb_scanner(prefilled_args):
    """
    Punto de entrada del SMB scanner.
    prefilled_args: Namespace de argparse.
    """
    _print_scanner_menu()

    prefilled = {
        "target":   getattr(prefilled_args, "target",   None),
        "user":     getattr(prefilled_args, "user",     None),
        "password": getattr(prefilled_args, "password", None),
        "hash":     getattr(prefilled_args, "hash",     None),
        "domain":   getattr(prefilled_args, "domain",   None),
        "userlist": getattr(prefilled_args, "userlist", None),
    }

    params          = _collect_params(prefilled)
    verbose         = _collect_verbose()
    save_to_db, export_path, export_fmt = _collect_output()

    target = Target(
        ip=params["target"],
        domain=params.get("domain") or "",
        timeout=getattr(prefilled_args, "timeout", 5),
    )
    creds = Creds(
        user=params.get("user") or "",
        password=params.get("password") or "",
        domain=params.get("domain") or "",
        hash=params.get("hash"),
    )

    steps = [
        ScanStep(entry["script"], entry["condition"])
        for entry in SCAN_ORDER
    ]

    scanner = Scanner(
        target=target,
        creds=creds,
        steps=steps,
        protocol=PROTOCOL,
        color=COLOR,
        verbose=verbose,
        save_to_db=save_to_db,
        export_path=export_path,
        export_fmt=export_fmt,
    )
    scanner.ctx.params = params

    scanner.run()
