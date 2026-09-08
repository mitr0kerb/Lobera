# scripts/rpc/scanner.py

import os
import getpass as _getpass

import pyfiglet
from rich.panel import Panel
from rich.prompt import Prompt

from core.output import console
from core.target import Target
from core.credentials import Creds
from core.scanner import Scanner, ScanStep, ScanContext
from scripts.rpc.scan_params import SCAN_ORDER, REQUIRED, OPTIONAL, EXPORT_FORMATS

PROTOCOL = "RPC"
COLOR    = "blue"


def _print_scanner_menu():
    art = pyfiglet.figlet_format("RPC-SCAN", font="slant")
    console.print(f"[bold {COLOR}]{art}[/bold {COLOR}]")
    console.print(
        Panel(
            "[bold]Fases del autopwn:[/bold]\n\n"
            "  [cyan]FASE 1 — Enumeración autenticada[/cyan]\n"
            "    • domain-info / users / groups / sessions / privileges / services\n\n"
            "  [cyan]FASE 2 — Sin credenciales[/cyan]\n"
            "    • rid-brute    → fuerza bruta de RID (funciona con null session)\n\n"
            "  [cyan]FASE 3 — Exploits[/cyan]\n"
            "    • printnightmare → CVE-2021-1675/34527\n"
            "    • petitpotam     → CVE-2021-36942 (requiere listener)\n"
            "    • sam-dump       → extrae hashes SAM/LSA (requiere DA)\n\n"
            "  [cyan]FASE 4 — Ejecución remota[/cyan]\n"
            "    • exec-service   → ejecuta comando via SCM (requiere command)\n\n"
            "[dim]Solo se ejecutan los scripts cuyas condiciones se cumplan.[/dim]",
            title=f"[bold {COLOR}]RPC Autopwn Scanner — Lobera[/bold {COLOR}]",
            border_style=COLOR, expand=False,
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
            console.print(f"  [dim]{label}:[/dim] [cyan]{'*'*8 if secret else prefill}[/cyan] [dim](por CLI)[/dim]")
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
    default_name = f"lobera_rpc_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{fmt}"
    path = Prompt.ask("  Nombre del fichero", default=default_name)
    if not path.endswith(f".{fmt}"): path = f"{path}.{fmt}"
    console.print()
    return False, path, fmt


class RPCScanContext(ScanContext):
    def _cond_has_auth(self):
        p = self.params
        return bool(p.get("user")) and (bool(p.get("password")) or bool(p.get("hash")))

    def _cond_has_listener(self):
        return bool(self.params.get("listener"))

    def _cond_has_command(self):
        return bool(self.params.get("command"))


class RPCScanner(Scanner):
    def _on_result(self, script_name, result):
        handlers = {
            "domain-info":    self._on_enum,
            "users":          self._on_users,
            "groups":         self._on_enum,
            "sessions":       self._on_enum,
            "privileges":     self._on_privileges,
            "services":       self._on_services,
            "rid-brute":      self._on_rid_brute,
            "printnightmare": self._on_exploit,
            "petitpotam":     self._on_exploit,
            "sam-dump":       self._on_sam_dump,
            "exec-service":   self._on_exec,
        }
        handler = handlers.get(script_name)
        if handler: handler(result)

    def _on_enum(self, result):
        n = len(result) if isinstance(result, list) else (1 if result else 0)
        if n: self._ok(f"{n} resultado(s) obtenidos")
        else: self._info("Sin resultados")

    def _on_users(self, result):
        if result: self._ok(f"{len(result)} usuario(s) enumerados")
        else: self._info("Sin usuarios encontrados")

    def _on_privileges(self, result):
        if result: self._critical(f"Privilegios peligrosos encontrados: {len(result) if isinstance(result,list) else 1}")
        else: self._ok("Sin privilegios peligrosos detectados")

    def _on_services(self, result):
        if result: self._ok(f"{len(result)} servicio(s) encontrados")
        else: self._info("Sin servicios encontrados")

    def _on_rid_brute(self, result):
        if result: self._critical(f"RID brute: {len(result)} usuario(s) encontrados")
        else: self._ok("RID brute: ningún usuario encontrado")

    def _on_exploit(self, result):
        if result: self._critical("Exploit completado con éxito")
        else: self._ok("Exploit: sin resultado o no vulnerable")

    def _on_sam_dump(self, result):
        if result: self._critical("SAM dump: hashes extraídos con éxito")
        else: self._ok("SAM dump: sin resultado")

    def _on_exec(self, result):
        if result: self._critical("exec-service: comando ejecutado remotamente")
        else: self._info("exec-service: sin resultado")

    def _build_kwargs(self, script_name):
        p = self.ctx.params
        base = {
            "user":     p.get("user",""),
            "password": p.get("password",""),
            "hash":     p.get("hash"),
            "domain":   p.get("domain",""),
        }
        extras = {
            "groups":         {"local_admins": bool(p.get("local_admins",False))},
            "sessions":       {"open_files": bool(p.get("open_files",False))},
            "privileges":     {"priv": p.get("priv"), "interesting_only": bool(p.get("interesting_only",False))},
            "services":       {"running_only": bool(p.get("running_only",False)), "interesting_only": bool(p.get("interesting_only",False))},
            "registry":       {"hive": p.get("hive","HKLM"), "key": p.get("key"), "value": p.get("value")},
            "exec-service":   {"command": p.get("command"), "svc_name": p.get("svc_name","LobSvc"), "wait": int(p.get("wait",3))},
            "rid-brute":      {"rid_start": int(p.get("rid_start",500)), "rid_end": int(p.get("rid_end",10000))},
            "printnightmare": {"action": p.get("action","check"), "dll_path": p.get("dll_path","")},
            "petitpotam":     {"action": p.get("action","check"), "listener": p.get("listener",""), "pipe": p.get("pipe","lsarpc")},
            "sam-dump":       {"out_dir": p.get("out_dir",".")},
        }
        base.update(extras.get(script_name, {}))
        return base


def run_rpc_scanner(prefilled_args):
    _print_scanner_menu()
    prefilled = {k: getattr(prefilled_args, k, None)
                 for k in ["target","user","password","hash","domain","listener","out_dir","command"]}
    params          = _collect_params(prefilled)
    verbose         = _collect_verbose()
    save_to_db, export_path, export_fmt = _collect_output()
    target = Target(ip=params.get("target",""), domain=params.get("domain",""), timeout=getattr(prefilled_args,"timeout",5))
    creds  = Creds(user=params.get("user",""), password=params.get("password",""), domain=params.get("domain",""), hash=params.get("hash"))
    steps  = [ScanStep(e["script"], e["condition"]) for e in SCAN_ORDER]
    scanner = RPCScanner(
        target=target, creds=creds, steps=steps,
        protocol=PROTOCOL, color=COLOR, verbose=verbose,
        save_to_db=save_to_db, export_path=export_path, export_fmt=export_fmt,
    )
    scanner.ctx = RPCScanContext(params)
    scanner.run()
