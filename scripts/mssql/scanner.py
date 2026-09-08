# scripts/mssql/scanner.py

import os
import getpass as _getpass

import pyfiglet
from rich.panel import Panel
from rich.prompt import Prompt

from core.output import console
from core.target import Target
from core.credentials import Creds
from core.scanner import Scanner, ScanStep, ScanContext
from scripts.mssql.scan_params import SCAN_ORDER, REQUIRED, OPTIONAL, EXPORT_FORMATS

PROTOCOL = "MSSQL"
COLOR    = "bright_red"


def _print_scanner_menu():
    art = pyfiglet.figlet_format("MSSQL-SCAN", font="slant")
    console.print(f"[bold {COLOR}]{art}[/bold {COLOR}]")
    console.print(
        Panel(
            "[bold]Fases del autopwn:[/bold]\n\n"
            "  [cyan]FASE 1 — Enumeración sin credenciales[/cyan]\n"
            "    • version-enum      → versión, edición, parches\n"
            "    • instance-enum     → descubrimiento de instancias (UDP 1434)\n"
            "    • auth-check        → auth SQL/Windows habilitada, SA vacía\n\n"
            "  [cyan]FASE 2 — Enumeración autenticada[/cyan]\n"
            "    • db-enum           → bases de datos, tablas, columnas sensibles\n"
            "    • user-enum         → logins, usuarios, roles\n"
            "    • privs-check       → sysadmin, xp_cmdshell, impersonation\n"
            "    • linked-servers    → servidores enlazados y credenciales\n\n"
            "  [cyan]FASE 3 — Ataques[/cyan]\n"
            "    • password-spray    → spray contra lista de usuarios\n"
            "    • xp-cmdshell       → ejecución OS via xp_cmdshell\n"
            "    • ntlm-steal        → captura hash NTLM via xp_dirtree\n\n"
            "  [cyan]FASE 4 — Exploits[/cyan]\n"
            "    • xp-cmdshell-enable → habilita xp_cmdshell via sp_configure\n"
            "    • clr-exec          → ejecución via CLR Assembly\n"
            "    • agent-job         → ejecución via SQL Server Agent\n"
            "    • linked-exec       → ejecución via linked server chain\n\n"
            "  [cyan]FASE 5 — Post-explotación[/cyan]\n"
            "    • dump-hashes       → extrae hashes de sys.sql_logins\n"
            "    • read-file         → lectura de ficheros via OPENROWSET\n"
            "    • custom-query      → query SQL arbitraria\n\n"
            "[dim]Solo se ejecutan los scripts cuyas condiciones se cumplan.[/dim]",
            title=f"[bold {COLOR}]MSSQL Autopwn Scanner — Lobera[/bold {COLOR}]",
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
    default_name = f"lobera_mssql_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{fmt}"
    path = Prompt.ask("  Nombre del fichero", default=default_name)
    if not path.endswith(f".{fmt}"): path = f"{path}.{fmt}"
    console.print()
    return False, path, fmt


class MSSQLScanContext(ScanContext):
    def _cond_has_auth(self):
        p = self.params
        return bool(p.get("user")) and (bool(p.get("password")) or bool(p.get("hash")))

    def _cond_has_userlist(self):
        ul = self.params.get("userlist")
        return bool(ul) and os.path.isfile(str(ul))

    def _cond_has_auth_and_cmd(self):
        return self._cond_has_auth() and bool(self.params.get("command"))

    def _cond_has_auth_and_query(self):
        return self._cond_has_auth() and bool(self.params.get("query"))

    def _cond_has_attacker_ip(self):
        return self._cond_has_auth() and bool(self.params.get("attacker_ip"))


class MSSQLScanner(Scanner):
    def _on_result(self, script_name, result):
        handlers = {
            "version-enum":       self._on_version,
            "instance-enum":      self._on_instances,
            "auth-check":         self._on_auth,
            "db-enum":            self._on_db_enum,
            "user-enum":          self._on_user_enum,
            "privs-check":        self._on_privs,
            "linked-servers":     self._on_linked,
            "password-spray":     self._on_spray,
            "xp-cmdshell":        self._on_exec,
            "ntlm-steal":         self._on_ntlm,
            "xp-cmdshell-enable": self._on_enable,
            "clr-exec":           self._on_exec,
            "agent-job":          self._on_exec,
            "linked-exec":        self._on_exec,
            "dump-hashes":        self._on_hashes,
            "read-file":          self._on_read,
            "custom-query":       self._on_query,
        }
        handler = handlers.get(script_name)
        if handler: handler(result)

    def _on_version(self, result):
        if result: self._ok(f"version-enum: {result.get('version','?')}")
        else: self._info("version-enum: sin resultado")

    def _on_instances(self, result):
        if result: self._ok(f"instance-enum: {len(result)} instancia(s) encontrada(s)")
        else: self._info("instance-enum: sin instancias detectadas")

    def _on_auth(self, result):
        if result and result.get("sa_empty"):
            self._critical("auth-check: SA con contraseña vacía → acceso total sin credenciales")
        elif result and result.get("sql_auth"):
            self._critical("auth-check: autenticación SQL habilitada → spray posible")
        else:
            self._ok("auth-check: sin vectores obvios")

    def _on_db_enum(self, result):
        if result: self._ok(f"db-enum: {len(result) if isinstance(result,list) else 1} base(s) accesible(s)")
        else: self._info("db-enum: sin resultados")

    def _on_user_enum(self, result):
        if result: self._ok(f"user-enum: {len(result)} login(s) encontrado(s)")
        else: self._info("user-enum: sin usuarios")

    def _on_privs(self, result):
        if result and (result.get("sysadmin") or result.get("xp_cmdshell")):
            criticos = ", ".join(k for k, v in result.items() if v)
            self._critical(f"privs-check: privilegios críticos → {criticos}")
        else:
            self._ok("privs-check: sin privilegios críticos")

    def _on_linked(self, result):
        if result: self._critical(f"linked-servers: {len(result)} servidor(es) enlazado(s) → pivoting posible")
        else: self._ok("linked-servers: sin servidores enlazados")

    def _on_spray(self, result):
        if result: self._critical(f"password-spray: {len(result)} credencial(es) válida(s)")
        else: self._ok("password-spray: ninguna credencial válida")

    def _on_exec(self, result):
        if result: self._critical("Ejecución OS completada con éxito")
        else: self._info("Ejecución OS: sin resultado o fallida")

    def _on_ntlm(self, result):
        if result: self._critical("ntlm-steal: hash NTLM capturado → revisar Responder/ntlmrelayx")
        else: self._info("ntlm-steal: sin captura")

    def _on_enable(self, result):
        if result: self._critical("xp-cmdshell-enable: xp_cmdshell habilitado con éxito")
        else: self._ok("xp-cmdshell-enable: no fue posible habilitar")

    def _on_hashes(self, result):
        if result: self._critical(f"dump-hashes: {len(result)} hash(es) extraído(s) → cracking offline")
        else: self._ok("dump-hashes: sin hashes o permisos insuficientes")

    def _on_read(self, result):
        if result: self._critical("read-file: contenido de fichero leído con éxito")
        else: self._ok("read-file: sin resultado o permisos insuficientes")

    def _on_query(self, result):
        if result: self._ok(f"custom-query: {len(result) if isinstance(result,list) else 1} fila(s) devuelta(s)")
        else: self._info("custom-query: sin resultados")

    def _build_kwargs(self, script_name):
        p = self.ctx.params
        base = {
            "user":     p.get("user", ""),
            "password": p.get("password", ""),
            "hash":     p.get("hash"),
            "domain":   p.get("domain", ""),
            "port":     int(p["port"]) if p.get("port") else 1433,
            "instance": p.get("instance", ""),
        }
        extras = {
            "password-spray":     {"userlist": p.get("userlist"), "delay": float(p.get("delay") or 1)},
            "xp-cmdshell":        {"command": p.get("command", "whoami")},
            "clr-exec":           {"command": p.get("command", "whoami")},
            "agent-job":          {"command": p.get("command", "whoami")},
            "linked-exec":        {"command": p.get("command", "whoami")},
            "ntlm-steal":         {"attacker_ip": p.get("attacker_ip", "")},
            "custom-query":       {"query": p.get("query", "")},
        }
        base.update(extras.get(script_name, {}))
        return base


def run_mssql_scanner(prefilled_args):
    _print_scanner_menu()

    prefilled = {
        "target":      getattr(prefilled_args, "target",      None),
        "user":        getattr(prefilled_args, "user",        None),
        "password":    getattr(prefilled_args, "password",    None),
        "hash":        getattr(prefilled_args, "hash",        None),
        "domain":      getattr(prefilled_args, "domain",      None),
        "port":        getattr(prefilled_args, "port",        None),
        "instance":    getattr(prefilled_args, "instance",    None),
        "userlist":    getattr(prefilled_args, "userlist",    None),
        "command":     getattr(prefilled_args, "command",     None),
        "attacker_ip": getattr(prefilled_args, "attacker_ip", None),
    }

    params              = _collect_params(prefilled)
    verbose             = _collect_verbose()
    save_to_db, export_path, export_fmt = _collect_output()

    target = Target(
        ip=params.get("target", ""),
        domain=params.get("domain", ""),
        timeout=int(params.get("timeout") or getattr(prefilled_args, "timeout", 5)),
    )
    creds = Creds(
        user=params.get("user", ""),
        password=params.get("password", ""),
        domain=params.get("domain", ""),
        hash=params.get("hash"),
    )

    steps = [ScanStep(e["script"], e["condition"]) for e in SCAN_ORDER]

    scanner = MSSQLScanner(
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
    scanner.ctx = MSSQLScanContext(params)
    scanner.run()
