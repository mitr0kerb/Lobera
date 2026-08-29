# scripts/winrm/scanner.py

import os
import getpass as _getpass

import pyfiglet
from rich.panel import Panel
from rich.prompt import Prompt

from core.output import console
from core.target import Target
from core.credentials import Creds
from core.scanner import Scanner, ScanStep, ScanContext
from scripts.winrm.scan_params import SCAN_ORDER, REQUIRED, OPTIONAL, EXPORT_FORMATS

PROTOCOL = "WINRM"
COLOR    = "cyan"


def _print_scanner_menu():
    art = pyfiglet.figlet_format("WRM-SCAN", font="slant")
    console.print(f"[bold {COLOR}]{art}[/bold {COLOR}]")
    console.print(
        Panel(
            "[bold]Fases del autopwn:[/bold]\n\n"
            "  [cyan]FASE 1 — Comprobación de acceso[/cyan]\n"
            "    • check            → verifica si WinRM está activo\n\n"
            "  [cyan]FASE 2 — Enumeración autenticada[/cyan]\n"
            "    • sysinfo          → OS, hostname, dominio, usuarios, procesos\n\n"
            "  [cyan]FASE 3 — Escalada de privilegios[/cyan]\n"
            "    • privesc-check    → vectores de escalada\n\n"
            "  [cyan]FASE 4 — Ataques[/cyan]\n"
            "    • password-spray   → spray contra lista de usuarios\n"
            "    • evil-winrm-payload → reverse shell / bypass AMSI\n\n"
            "[dim]Solo se ejecutan los scripts cuyas condiciones se cumplan.[/dim]",
            title=f"[bold {COLOR}]WinRM Autopwn Scanner — Lobera[/bold {COLOR}]",
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
        key, label, secret, default, req = (
            field["key"], field["label"], field["secret"],
            field.get("default"), field["required"]
        )
        prefill = prefilled.get(key)
        if prefill is not None and prefill != "" and prefill != default:
            params[key] = prefill
            masked = "*" * 8 if secret else prefill
            console.print(f"  [dim]{label}:[/dim] [cyan]{masked}[/cyan] [dim](por CLI)[/dim]")
            continue
        hint = "[bold red] *[/bold red]" if req else " [dim](enter para omitir)[/dim]"
        while True:
            if secret:
                value = _getpass.getpass(f"  {label}{'  *' if req else ' (enter para omitir)'}: ")
            else:
                value = Prompt.ask(f"  [bold]{label}[/bold]{hint}", default="")
            if req and not value:
                console.print("  [red]Este campo es obligatorio.[/red]")
                continue
            break
        params[key] = value if value else default

    console.print()
    console.print("  [dim]─── Parámetros opcionales ───[/dim]")
    console.print()

    for field in OPTIONAL:
        key, label, default = field["key"], field["label"], field.get("default")
        prefill = prefilled.get(key)
        if prefill:
            params[key] = prefill
            console.print(f"  [dim]{label}:[/dim] [cyan]{prefill}[/cyan] [dim](por CLI)[/dim]")
            continue
        value = Prompt.ask(f"  [bold]{label}[/bold]", default="")
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
    fmt = Prompt.ask("  Formato", choices=EXPORT_FORMATS, default="json")
    from datetime import datetime
    default_name = f"lobera_winrm_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{fmt}"
    path = Prompt.ask("  Nombre del fichero", default=default_name)
    if not path.endswith(f".{fmt}"):
        path = f"{path}.{fmt}"
    console.print()
    return False, path, fmt


class WinRMScanContext(ScanContext):
    def _cond_has_auth(self):
        p = self.params
        return bool(p.get("user")) and (bool(p.get("password")) or bool(p.get("hash")))

    def _cond_has_userlist(self):
        ul = self.params.get("userlist")
        return bool(ul) and os.path.isfile(str(ul))

    def _cond_has_listener(self):
        return bool(self.params.get("listener"))


class WinRMScanner(Scanner):
    def _on_result(self, script_name, result):
        handlers = {
            "check":              self._on_check,
            "sysinfo":            self._on_sysinfo,
            "privesc-check":      self._on_privesc,
            "password-spray":     self._on_spray,
            "evil-winrm-payload": self._on_payload,
        }
        handler = handlers.get(script_name)
        if handler:
            handler(result)

    def _on_check(self, result):
        if result:
            self._critical("WinRM activo y accesible → acceso remoto posible")
        else:
            self._ok("WinRM: no accesible o credenciales incorrectas")

    def _on_sysinfo(self, result):
        if result:
            self._ok("sysinfo: información del sistema obtenida")
        else:
            self._info("sysinfo: sin resultado")

    def _on_privesc(self, result):
        if result:
            n = len(result) if isinstance(result, list) else 1
            self._critical(f"privesc-check: {n} vector(es) de escalada encontrado(s)")
        else:
            self._ok("privesc-check: sin vectores de escalada detectados")

    def _on_spray(self, result):
        if result:
            self._critical(f"Password spray WinRM: {len(result)} credencial(es) válida(s)")
        else:
            self._ok("Password spray WinRM: ninguna credencial válida")

    def _on_payload(self, result):
        if result:
            self._critical("Payload WinRM: ejecutado con éxito")
        else:
            self._info("Payload WinRM: sin resultado")

    def _build_kwargs(self, script_name):
        p = self.ctx.params
        base = {
            "user":     p.get("user", ""),
            "password": p.get("password", ""),
            "hash":     p.get("hash"),
            "domain":   p.get("domain", ""),
            "ssl":      bool(p.get("ssl", False)),
            "port":     int(p["port"]) if p.get("port") else None,
        }
        extras = {
            "password-spray":     {
                "userlist": p.get("userlist"),
                "delay":    float(p.get("delay") or 1),
            },
            "evil-winrm-payload": {
                "action":   p.get("action"),
                "listener": p.get("listener", ""),
                "lport":    int(p.get("lport") or 4444),
                "url":      p.get("url", ""),
                "out_dir":  p.get("out_dir", "."),
            },
        }
        base.update(extras.get(script_name, {}))
        return base


def run_winrm_scanner(prefilled_args):
    _print_scanner_menu()

    prefilled = {
        "target":   getattr(prefilled_args, "target",   None),
        "user":     getattr(prefilled_args, "user",     None),
        "password": getattr(prefilled_args, "password", None),
        "hash":     getattr(prefilled_args, "hash",     None),
        "domain":   getattr(prefilled_args, "domain",   None),
        "ssl":      getattr(prefilled_args, "ssl",      None),
        "port":     getattr(prefilled_args, "port",     None),
        "userlist": getattr(prefilled_args, "userlist", None),
    }

    params          = _collect_params(prefilled)
    verbose         = _collect_verbose()
    save_to_db, export_path, export_fmt = _collect_output()

    target = Target(
        ip=params.get("target", ""),
        domain=params.get("domain", ""),
        timeout=getattr(prefilled_args, "timeout", 5),
    )
    creds = Creds(
        user=params.get("user", ""),
        password=params.get("password", ""),
        domain=params.get("domain", ""),
        hash=params.get("hash"),
    )

    steps = [ScanStep(e["script"], e["condition"]) for e in SCAN_ORDER]

    scanner = WinRMScanner(
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
    scanner.ctx = WinRMScanContext(params)
    scanner.run()
