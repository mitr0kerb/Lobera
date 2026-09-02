# scripts/ftp/scanner.py

import os
import getpass as _getpass

import pyfiglet
from rich.panel import Panel
from rich.prompt import Prompt

from core.output import console
from core.target import Target
from core.credentials import Creds
from core.scanner import Scanner, ScanStep, ScanContext
from scripts.ftp.scan_params import SCAN_ORDER, REQUIRED, OPTIONAL, EXPORT_FORMATS

PROTOCOL = "FTP"
COLOR    = "orange1"


def _print_scanner_menu():
    art = pyfiglet.figlet_format("FTP-SCAN", font="slant")
    console.print(f"[bold {COLOR}]{art}[/bold {COLOR}]")
    console.print(
        Panel(
            "[bold]Fases del autopwn:[/bold]\n\n"
            "  [cyan]FASE 1 — Enumeración sin credenciales[/cyan]\n"
            "    • banner-grab      → software, versión, OS fingerprint\n"
            "    • service-info     → SYST, FEAT, TLS/FTPS\n"
            "    • anon-check       → acceso anónimo, escritura\n"
            "    • user-enum        → enumeración de usuarios (requiere userlist)\n\n"
            "  [cyan]FASE 2 — Ataques[/cyan]\n"
            "    • password-spray   → spray contra lista de usuarios\n"
            "    • write-check      → detecta directorios escribibles\n"
            "    • bounce-scan      → FTP Bounce Attack (RFC 959)\n\n"
            "  [cyan]FASE 3 — Exploits[/cyan]\n"
            "    • vsftpd-backdoor  → CVE-2011-2523\n"
            "    • proftpd-bypass   → CVE-2011-4130 mod_copy\n"
            "    • ssl-strip        → STARTTLS downgrade detection\n"
            "    • anonymous-webshell → FTP anon write + webshell\n\n"
            "  [cyan]FASE 4 — Post-explotación[/cyan]\n"
            "    • list-files       → listado recursivo, detecta ficheros sensibles\n"
            "    • download-loot    → descarga automática de loot\n"
            "    • pivot-setup      → mapeo de red interna\n\n"
            "[dim]Solo se ejecutan los scripts cuyas condiciones se cumplan.[/dim]",
            title=f"[bold {COLOR}]FTP Autopwn Scanner — Lobera[/bold {COLOR}]",
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
                console.print("  [red]Este campo es obligatorio.[/red]"); continue
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
    choice = Prompt.ask("  Elige nivel", choices=["1","2","3"], default="2")
    console.print()
    return int(choice)


def _collect_output():
    console.rule(f"[bold {COLOR}]Destino de resultados[/bold {COLOR}]")
    console.print()
    console.print("  [bold][s][/bold] Guardar en base de datos de sesión [dim](recomendado)[/dim]")
    console.print("  [bold][n][/bold] Exportar a fichero  [dim](json, html, xml, yaml)[/dim]")
    console.print()
    choice = Prompt.ask("  Opción", choices=["s","n"], default="s")
    if choice == "s":
        console.print(); return True, None, None
    fmt = Prompt.ask("  Formato", choices=EXPORT_FORMATS, default="json")
    from datetime import datetime
    default_name = f"lobera_ftp_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{fmt}"
    path = Prompt.ask("  Nombre del fichero", default=default_name)
    if not path.endswith(f".{fmt}"): path = f"{path}.{fmt}"
    console.print()
    return False, path, fmt


class FTPScanContext(ScanContext):
    def _cond_has_auth(self):
        p = self.params
        return bool(p.get("user")) and bool(p.get("password"))

    def _cond_has_userlist(self):
        ul = self.params.get("userlist")
        return bool(ul) and os.path.isfile(str(ul))

    def _cond_has_anon(self):
        return True  # siempre se intenta; el script evalúa internamente


class FTPScanner(Scanner):
    def _on_result(self, script_name, result):
        handlers = {
            "banner-grab":        self._on_banner,
            "service-info":       self._on_info,
            "anon-check":         self._on_anon,
            "user-enum":          self._on_user_enum,
            "password-spray":     self._on_spray,
            "write-check":        self._on_write,
            "bounce-scan":        self._on_bounce,
            "vsftpd-backdoor":    self._on_exploit,
            "proftpd-bypass":     self._on_exploit,
            "ssl-strip":          self._on_ssl,
            "anonymous-webshell": self._on_webshell,
            "list-files":         self._on_list,
            "download-loot":      self._on_loot,
            "pivot-setup":        self._on_pivot,
        }
        handler = handlers.get(script_name)
        if handler: handler(result)

    def _on_banner(self, result):
        if result: self._ok(f"banner-grab: {result.get('banner','?')}")
        else: self._info("banner-grab: sin resultado")

    def _on_info(self, result):
        if result: self._ok("service-info: capacidades del servidor obtenidas")
        else: self._info("service-info: sin resultado")

    def _on_anon(self, result):
        if result and result.get("anon_ok"):
            self._critical("Acceso anónimo permitido → enumeración sin credenciales posible")
        else:
            self._ok("anon-check: acceso anónimo denegado")

    def _on_user_enum(self, result):
        if result:
            self._critical(f"user-enum: {len(result)} usuario(s) válido(s) identificados")
        else:
            self._ok("user-enum: ningún usuario identificado")

    def _on_spray(self, result):
        if result:
            self._critical(f"password-spray: {len(result)} credencial(es) válida(s)")
        else:
            self._ok("password-spray: ninguna credencial válida")

    def _on_write(self, result):
        if result:
            self._critical(f"write-check: {len(result) if isinstance(result,list) else 1} directorio(s) escribible(s)")
        else:
            self._ok("write-check: sin directorios escribibles")

    def _on_bounce(self, result):
        if result:
            self._critical("bounce-scan: servidor vulnerable a FTP Bounce Attack")
        else:
            self._ok("bounce-scan: no vulnerable")

    def _on_exploit(self, result):
        if result: self._critical("Exploit completado con éxito")
        else: self._ok("Exploit: sin resultado o no vulnerable")

    def _on_ssl(self, result):
        if result and result.get("vulnerable"):
            self._critical("ssl-strip: STARTTLS downgrade posible → credenciales en claro")
        else:
            self._ok("ssl-strip: TLS forzado o no aplicable")

    def _on_webshell(self, result):
        if result: self._critical("anonymous-webshell: webshell subida con éxito")
        else: self._ok("anonymous-webshell: no fue posible subir webshell")

    def _on_list(self, result):
        if result:
            self._ok(f"list-files: {len(result) if isinstance(result,list) else 1} fichero(s) encontrado(s)")
        else:
            self._info("list-files: sin resultados")

    def _on_loot(self, result):
        if result: self._critical(f"download-loot: {len(result)} fichero(s) descargado(s)")
        else: self._ok("download-loot: sin loot descargado")

    def _on_pivot(self, result):
        if result:
            self._ok(f"pivot-setup: {len(result) if isinstance(result,list) else 1} host(s) internos encontrados")
        else:
            self._info("pivot-setup: sin hosts internos detectados")

    def _build_kwargs(self, script_name):
        p = self.ctx.params
        base = {
            "user":     p.get("user", ""),
            "password": p.get("password", ""),
            "port":     int(p["port"]) if p.get("port") else 21,
        }
        extras = {
            "user-enum":      {"userlist": p.get("userlist")},
            "password-spray": {"userlist": p.get("userlist"), "delay": float(p.get("delay") or 1)},
            "brute-force":    {"passlist": p.get("passlist"), "delay": float(p.get("delay") or 0)},
        }
        base.update(extras.get(script_name, {}))
        return base


def run_ftp_scanner(prefilled_args):
    _print_scanner_menu()

    prefilled = {
        "target":   getattr(prefilled_args, "target",   None),
        "user":     getattr(prefilled_args, "user",     None),
        "password": getattr(prefilled_args, "password", None),
        "port":     getattr(prefilled_args, "port",     None),
        "userlist": getattr(prefilled_args, "userlist", None),
        "passlist":  getattr(prefilled_args, "passlist",  None),
        "delay":    getattr(prefilled_args, "delay",    None),
    }

    params              = _collect_params(prefilled)
    verbose             = _collect_verbose()
    save_to_db, export_path, export_fmt = _collect_output()

    target = Target(
        ip=params.get("target", ""),
        domain="",
        timeout=int(params.get("timeout") or getattr(prefilled_args, "timeout", 5)),
    )
    creds = Creds(
        user=params.get("user", ""),
        password=params.get("password", ""),
        domain="",
        hash=None,
    )

    steps = [ScanStep(e["script"], e["condition"]) for e in SCAN_ORDER]

    scanner = FTPScanner(
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
    scanner.ctx = FTPScanContext(params)
    scanner.run()
