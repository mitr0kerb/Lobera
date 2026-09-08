# scripts/ssh/scanner.py

import os
import getpass as _getpass

import pyfiglet
from rich.panel import Panel
from rich.prompt import Prompt

from core.output import console
from core.target import Target
from core.credentials import Creds
from core.scanner import Scanner, ScanStep, ScanContext
from scripts.ssh.scan_params import SCAN_ORDER, REQUIRED, OPTIONAL, EXPORT_FORMATS

PROTOCOL = "SSH"
COLOR    = "turquoise2"


def _print_scanner_menu():
    art = pyfiglet.figlet_format("SSH-SCAN", font="slant")
    console.print(f"[bold {COLOR}]{art}[/bold {COLOR}]")
    console.print(Panel(
        "[bold]Fases del autopwn:[/bold]\n\n"
        "  [cyan]FASE 1 — Fingerprint sin credenciales[/cyan]\n"
        "    • banner-grab / host-key-fingerprint / key-exchange-enum\n"
        "    • auth-methods / terrapin-check\n\n"
        "  [cyan]FASE 2 — CVE checks sin credenciales[/cyan]\n"
        "    • regresshion (CVE-2024-6387) / libssh-bypass (CVE-2018-10933)\n\n"
        "  [cyan]FASE 3 — Enumeración con userlist[/cyan]\n"
        "    • user-enum (CVE-2018-15473) / password-spray\n\n"
        "  [cyan]FASE 4 — Post-explotación autenticada[/cyan]\n"
        "    • config-dump / key-harvest / lateral-move\n\n"
        "[dim]Solo se ejecutan los scripts cuyas condiciones se cumplan.[/dim]",
        title=f"[bold {COLOR}]SSH Autopwn Scanner — Lobera[/bold {COLOR}]",
        border_style=COLOR, expand=False,
    ))
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
            console.print(
                f"  [dim]{label}:[/dim] "
                f"[cyan]{'*'*8 if secret else prefill}[/cyan] "
                f"[dim](por CLI)[/dim]"
            )
            continue
        hint = "[bold red] *[/bold red]" if req else " [dim](enter para omitir)[/dim]"
        while True:
            if secret:
                value = _getpass.getpass(
                    f"  {label}{'  *' if req else ' (enter para omitir)'}: "
                )
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
            console.print(
                f"  [dim]{label}:[/dim] [cyan]{prefill}[/cyan] [dim](por CLI)[/dim]"
            )
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
    default_name = f"lobera_ssh_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{fmt}"
    path = Prompt.ask("  Nombre del fichero", default=default_name)
    if not path.endswith(f".{fmt}"): path = f"{path}.{fmt}"
    console.print()
    return False, path, fmt


class SSHScanContext(ScanContext):
    def _cond_has_auth(self):
        p = self.params
        return bool(p.get("user")) and bool(p.get("password"))

    def _cond_has_userlist(self):
        ul = self.params.get("userlist")
        return bool(ul) and os.path.isfile(str(ul))

    def _cond_has_userlist_and_auth(self):
        return self._cond_has_userlist() and bool(self.params.get("password"))

    def _cond_has_pub_key(self):
        return bool(self.params.get("pub_key"))


class SSHScanner(Scanner):
    def _on_result(self, script_name, result):
        handlers = {
            "banner-grab":          self._on_banner,
            "host-key-fingerprint": self._on_hostkey,
            "key-exchange-enum":    self._on_kex,
            "auth-methods":         self._on_auth_methods,
            "terrapin-check":       self._on_terrapin,
            "regresshion":          self._on_regresshion,
            "libssh-bypass":        self._on_libssh,
            "user-enum":            self._on_user_enum,
            "password-spray":       self._on_spray,
            "config-dump":          self._on_config,
            "key-harvest":          self._on_key_harvest,
            "lateral-move":         self._on_lateral,
        }
        handler = handlers.get(script_name)
        if handler: handler(result)

    def _on_banner(self, result):
        if result:
            self._ok(f"banner: {result.get('banner','')}")

    def _on_hostkey(self, result):
        if result:
            self._ok(f"host key: {result.get('type','')} {result.get('sha256','')}")

    def _on_kex(self, result):
        if not result: return
        weak = (result.get("weak_kex",[]) +
                result.get("weak_ciphers",[]) +
                result.get("weak_macs",[]))
        if weak: self._critical(f"Algoritmos débiles: {', '.join(weak)}")
        else:    self._ok("Sin algoritmos débiles")

    def _on_auth_methods(self, result):
        if result and "password" in result:
            self._critical("Password auth habilitado → vulnerable a brute force")
        elif result:
            self._ok(f"métodos: {', '.join(result)}")

    def _on_terrapin(self, result):
        if result and result.get("vulnerable"):
            self._critical("VULNERABLE a Terrapin (CVE-2023-48795)")
        elif result:
            self._ok("No vulnerable a Terrapin")

    def _on_regresshion(self, result):
        if result and result.get("vulnerable"):
            self._critical(
                f"VULNERABLE a regreSSHion (CVE-2024-6387) "
                f"— versión {result.get('version','')}"
            )
        elif result:
            self._ok(f"No vulnerable — versión {result.get('version','')}")

    def _on_libssh(self, result):
        if result is True:
            self._critical("VULNERABLE a libssh auth bypass (CVE-2018-10933)")
        else:
            self._ok("No vulnerable a CVE-2018-10933")

    def _on_user_enum(self, result):
        if result:
            self._critical(f"Usuarios válidos: {', '.join(result)}")
        else:
            self._ok("user-enum: sin usuarios confirmados")

    def _on_spray(self, result):
        if result:
            self._critical(f"Password spray: {len(result)} credencial(es) válida(s)")
        else:
            self._ok("Password spray: sin credenciales válidas")

    def _on_config(self, result):
        if result:
            self._ok(f"config-dump: {len(result)} directiva(s) extraídas")

    def _on_key_harvest(self, result):
        if result:
            self._critical(f"key-harvest: {len(result)} fichero(s) recolectados")
        else:
            self._ok("key-harvest: sin claves encontradas")

    def _on_lateral(self, result):
        if result:
            self._critical(f"Movimiento lateral: {len(result)} host(s) accesibles")
        else:
            self._ok("lateral-move: sin hosts accesibles")

    def _build_kwargs(self, script_name):
        p = self.ctx.params
        base = {
            "user":    p.get("user", ""),
            "password":p.get("password", ""),
            "port":    int(p.get("port") or 22),
            "timeout": int(p.get("timeout") or 5),
        }
        extras = {
            "auth-methods":    {"user": p.get("user", "root")},
            "user-enum":       {"userlist": p.get("userlist"),
                                "threshold": float(p.get("threshold") or 50)},
            "password-spray":  {"userlist": p.get("userlist"),
                                "password": p.get("password",""),
                                "delay":    float(p.get("delay") or 1)},
            "libssh-bypass":   {"user": p.get("user","root")},
            "key-harvest":     {"out_dir": p.get("out_dir")},
            "persistence":     {"pub_key":     p.get("pub_key"),
                                "target_user": p.get("target_user")},
            "terrapin-exploit":{"attacker_ip": p.get("attacker_ip")},
        }
        base.update(extras.get(script_name, {}))
        return base


def run_ssh_scanner(prefilled_args):
    _print_scanner_menu()

    prefilled = {k: getattr(prefilled_args, k, None)
                 for k in ["target","user","password","port","userlist","pub_key"]}

    params          = _collect_params(prefilled)
    verbose         = _collect_verbose()
    save_to_db, export_path, export_fmt = _collect_output()

    target = Target(
        ip=params.get("target",""),
        domain="",
        timeout=int(params.get("timeout") or 5),
    )
    creds = Creds(
        user=params.get("user",""),
        password=params.get("password",""),
        domain="",
        hash=None,
    )

    steps = [ScanStep(e["script"], e["condition"]) for e in SCAN_ORDER]

    scanner = SSHScanner(
        target=target, creds=creds, steps=steps,
        protocol=PROTOCOL, color=COLOR, verbose=verbose,
        save_to_db=save_to_db, export_path=export_path, export_fmt=export_fmt,
    )
    scanner.ctx = SSHScanContext(params)
    scanner.run()
