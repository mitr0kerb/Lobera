# scripts/ldap/scanner.py

import os
import getpass as _getpass

import pyfiglet
from rich.panel import Panel
from rich.prompt import Prompt

from core.output import console
from core.target import Target
from core.credentials import Creds
from core.scanner import Scanner, ScanStep, ScanContext
from scripts.ldap.scan_params import SCAN_ORDER, REQUIRED, OPTIONAL, EXPORT_FORMATS

PROTOCOL = "LDAP"
COLOR    = "yellow"


def _print_scanner_menu():
    art = pyfiglet.figlet_format("LDAP-SCAN", font="slant")
    console.print(f"[bold {COLOR}]{art}[/bold {COLOR}]")
    console.print(
        Panel(
            "[bold]Fases del autopwn:[/bold]\n\n"
            "  [cyan]FASE 1 — Enumeración autenticada[/cyan]\n"
            "    • domain-info / users / groups / computers / admins / password-policy\n\n"
            "  [cyan]FASE 2 — Targets para ataques Kerberos[/cyan]\n"
            "    • asreproast-targets / kerberoast-targets\n\n"
            "  [cyan]FASE 3 — Análisis de ACLs[/cyan]\n"
            "    • dacl-enum  (requiere target_dn)\n\n"
            "  [cyan]FASE 4 — Exportación y ataques[/cyan]\n"
            "    • bloodhound-export / password-spray-ldap / acl-abuse / ntlm-relay-setup\n\n"
            "[dim]Solo se ejecutan los scripts cuyas condiciones se cumplan.[/dim]",
            title=f"[bold {COLOR}]LDAP Autopwn Scanner — Lobera[/bold {COLOR}]",
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
        key     = field["key"]
        label   = field["label"]
        default = field.get("default")

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
    default_name = f"lobera_ldap_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{fmt}"
    path = Prompt.ask("  Nombre del fichero", default=default_name)
    if not path.endswith(f".{fmt}"):
        path = f"{path}.{fmt}"
    console.print()
    return False, path, fmt


class LDAPScanContext(ScanContext):
    """Contexto con evaluadores específicos de LDAP."""

    def _cond_has_auth(self):
        p = self.params
        return bool(p.get("user")) and (bool(p.get("password")) or bool(p.get("hash")))

    def _cond_has_userlist(self):
        ul = self.params.get("userlist")
        return bool(ul) and os.path.isfile(str(ul))

    def _cond_has_target_dn(self):
        return bool(self.params.get("target_dn"))

    def _cond_has_target_obj(self):
        return bool(self.params.get("target_obj"))

    def _cond_has_attacker_ip(self):
        return bool(self.params.get("attacker_ip"))


class LDAPScanner(Scanner):
    """Scanner LDAP con handlers de resultado específicos."""

    def _on_result(self, script_name, result):
        handlers = {
            "domain-info":         self._on_domain_info,
            "users":               self._on_enum,
            "groups":              self._on_enum,
            "computers":           self._on_enum,
            "admins":              self._on_admins,
            "password-policy":     self._on_policy,
            "asreproast-targets":  self._on_roast_targets,
            "kerberoast-targets":  self._on_roast_targets,
            "dacl-enum":           self._on_dacl,
            "bloodhound-export":   self._on_bloodhound,
            "password-spray-ldap": self._on_spray,
            "acl-abuse":           self._on_acl_abuse,
            "ntlm-relay-setup":    self._on_relay,
        }
        handler = handlers.get(script_name)
        if handler:
            handler(result)

    def _on_domain_info(self, result):
        if result:
            self._ok("domain-info: información del dominio obtenida")
        else:
            self._info("domain-info: sin resultado")

    def _on_enum(self, result):
        if result:
            self._ok(f"{len(result)} objeto(s) encontrados")
        else:
            self._info("Sin resultados")

    def _on_admins(self, result):
        if result:
            self._critical(f"Administradores: {len(result)} cuenta(s) privilegiada(s) encontradas")
        else:
            self._ok("admins: sin cuentas privilegiadas")

    def _on_policy(self, result):
        if result:
            self._ok("password-policy: política de contraseñas obtenida")
        else:
            self._info("password-policy: sin resultado")

    def _on_roast_targets(self, result):
        if result:
            self._critical(f"{len(result)} cuenta(s) candidata(s) a roasting → lanzar ataque Kerberos")
        else:
            self._ok("Sin cuentas candidatas a roasting")

    def _on_dacl(self, result):
        if result:
            self._critical(f"DACL: {len(result)} ACE(s) peligroso(s) encontrado(s)")
        else:
            self._ok("DACL: sin permisos peligrosos detectados")

    def _on_bloodhound(self, result):
        if result:
            self._ok("BloodHound: datos exportados correctamente")
        else:
            self._info("BloodHound: sin datos exportados")

    def _on_spray(self, result):
        if result:
            self._critical(f"Password spray LDAP: {len(result)} credencial(es) válida(s)")
        else:
            self._ok("Password spray LDAP: ninguna credencial válida")

    def _on_acl_abuse(self, result):
        if result:
            self._critical("ACL abuse: acción completada con éxito")
        else:
            self._ok("ACL abuse: sin resultado")

    def _on_relay(self, result):
        if result:
            self._critical("NTLM relay: configuración completada")
        else:
            self._info("NTLM relay: sin resultado")

    def _build_kwargs(self, script_name):
        p = self.ctx.params
        base = {
            "user":     p.get("user", ""),
            "password": p.get("password", ""),
            "hash":     p.get("hash"),
            "domain":   p.get("domain", ""),
            "ldaps":    bool(p.get("ldaps", False)),
            "port":     int(p["port"]) if p.get("port") else None,
        }
        extras = {
            "users":               {"filter_flag": p.get("filter_flag"),
                                    "enabled_only": bool(p.get("enabled_only", False))},
            "groups":              {"privileged_only": bool(p.get("privileged_only", False))},
            "computers":           {"os_filter": p.get("os_filter"),
                                    "undeleg": bool(p.get("undeleg", False))},
            "dacl-enum":           {"target_dn": p.get("target_dn")},
            "asreproast-targets":  {"save_list": p.get("save_list")},
            "kerberoast-targets":  {"save_list": p.get("save_list")},
            "bloodhound-export":   {"out_dir": p.get("out_dir")},
            "acl-abuse":           {"action": p.get("action", "detect"),
                                    "source_user": p.get("source_user"),
                                    "target_obj": p.get("target_obj"),
                                    "new_password": p.get("new_password"),
                                    "save_key": p.get("save_key")},
            "password-spray-ldap": {"userlist": p.get("userlist"),
                                    "delay": float(p.get("delay") or 0),
                                    "continue_on_lockout": bool(p.get("continue_on_lockout", False))},
            "ntlm-relay-setup":    {"mode": p.get("mode", "dump"),
                                    "relay_target_user": p.get("relay_target_user", "TARGET_USER"),
                                    "attacker_ip": p.get("attacker_ip")},
        }
        base.update(extras.get(script_name, {}))
        return base


def run_ldap_scanner(prefilled_args):
    """Punto de entrada del LDAP autopwn scanner."""
    _print_scanner_menu()

    prefilled = {
        "target":   getattr(prefilled_args, "target",   None),
        "domain":   getattr(prefilled_args, "domain",   None),
        "user":     getattr(prefilled_args, "user",     None),
        "password": getattr(prefilled_args, "password", None),
        "hash":     getattr(prefilled_args, "hash",     None),
        "ldaps":    getattr(prefilled_args, "ldaps",    None),
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

    scanner = LDAPScanner(
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
    scanner.ctx = LDAPScanContext(params)
    scanner.run()
