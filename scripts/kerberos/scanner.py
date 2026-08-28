# scripts/kerberos/scanner.py

import os
import getpass as _getpass

import pyfiglet
from rich.panel import Panel
from rich.prompt import Prompt

from core.output import console
from core.target import Target
from core.credentials import Creds
from core.scanner import Scanner, ScanStep, ScanContext
from scripts.kerberos.scan_params import SCAN_ORDER, REQUIRED, OPTIONAL, EXPORT_FORMATS

PROTOCOL = "KRB"
COLOR    = "magenta"


def _print_scanner_menu():
    art = pyfiglet.figlet_format("KRB-SCAN", font="slant")
    console.print(f"[bold {COLOR}]{art}[/bold {COLOR}]")
    console.print(
        Panel(
            "[bold]Fases del autopwn:[/bold]\n\n"
            "  [cyan]FASE 1 — Sin credenciales[/cyan]\n"
            "    • user-enum        → enumera usuarios via AS-REQ\n"
            "    • asrep-roasting   → extrae hashes de cuentas sin pre-auth\n\n"
            "  [cyan]FASE 2 — Con credenciales[/cyan]\n"
            "    • spn-scan         → busca SPNs via LDAP\n"
            "    • kerberoasting    → extrae hashes TGS\n"
            "    • overpass-the-hash → NT hash → TGT Kerberos\n\n"
            "  [cyan]FASE 3 — Con hash krbtgt + SID[/cyan]\n"
            "    • golden-ticket / diamond-ticket / sapphire-ticket\n\n"
            "  [cyan]FASE 4 — Con ticket (.ccache)[/cyan]\n"
            "    • pass-the-ticket\n\n"
            "  [cyan]FASE 5-7 — Delegación, credenciales y exploits[/cyan]\n"
            "    • unconstrained-deleg / constrained-s4u / rbcd\n"
            "    • shadow-credentials / adcs\n"
            "    • sam-spoofing / ms14-068 / kerber-loss / reset-nightmare\n\n"
            "[dim]Solo se ejecutan los scripts cuyas condiciones se cumplan.[/dim]",
            title=f"[bold {COLOR}]Kerberos Autopwn Scanner — Lobera[/bold {COLOR}]",
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
    default_name = f"lobera_krb_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{fmt}"
    path = Prompt.ask("  Nombre del fichero", default=default_name)
    if not path.endswith(f".{fmt}"):
        path = f"{path}.{fmt}"
    console.print()
    return False, path, fmt


class KerberosScanContext(ScanContext):
    """Contexto con evaluadores específicos de Kerberos."""

    def _cond_has_userlist(self):
        ul = self.params.get("userlist")
        return bool(ul) and os.path.isfile(str(ul))

    def _cond_has_auth(self):
        p = self.params
        return bool(p.get("user")) and (bool(p.get("password")) or bool(p.get("hash")))

    def _cond_has_hash(self):
        return bool(self.params.get("hash"))

    def _cond_has_krbtgt_sid(self):
        return bool(self.params.get("krbtgt_hash")) and bool(self.params.get("domain_sid"))

    def _cond_has_ccache(self):
        ccache = self.params.get("ccache")
        if ccache and os.path.isfile(str(ccache)):
            return True
        return any(
            f.get("finding_type") == "ccache_generated"
            for f in self.findings
        )

    def _cond_has_auth_and_spn(self):
        return self._cond_has_auth() and bool(self.params.get("spn"))


class KerberosScanner(Scanner):
    """Scanner Kerberos con handlers de resultado específicos."""

    def _on_result(self, script_name, result):
        handlers = {
            "user-enum":          self._on_user_enum,
            "asrep-roasting":     self._on_asrep,
            "spn-scan":           self._on_spn_scan,
            "kerberoasting":      self._on_kerberoasting,
            "overpass-the-hash":  self._on_overpass,
            "golden-ticket":      self._on_ticket,
            "diamond-ticket":     self._on_ticket,
            "sapphire-ticket":    self._on_ticket,
            "pass-the-ticket":    self._on_ptt,
            "sam-spoofing":       self._on_exploit,
            "ms14-068":           self._on_exploit,
            "kerber-loss":        self._on_exploit,
            "reset-nightmare":    self._on_exploit,
            "shadow-credentials": self._on_exploit,
            "adcs":               self._on_exploit,
        }
        handler = handlers.get(script_name)
        if handler:
            handler(result)

    def _on_user_enum(self, result):
        if result:
            self._critical(f"{len(result)} usuario(s) válido(s) → candidatos a AS-REP Roasting / Kerberoasting")
        else:
            self._ok("user-enum: ningún usuario válido encontrado")

    def _on_asrep(self, result):
        if result:
            self._critical(f"AS-REP Roasting: {len(result)} hash(es) → hashcat -m 18200")
        else:
            self._ok("AS-REP Roasting: ninguna cuenta sin pre-auth")

    def _on_spn_scan(self, result):
        if result:
            self._critical(f"SPN scan: {len(result)} cuenta(s) con SPN → candidatas a Kerberoasting")
        else:
            self._ok("SPN scan: ninguna cuenta con SPN")

    def _on_kerberoasting(self, result):
        if result:
            self._critical(f"Kerberoasting: {len(result)} hash(es) TGS → hashcat -m 13100")
        else:
            self._ok("Kerberoasting: ningún hash TGS extraído")

    def _on_overpass(self, result):
        if result:
            self._critical("Overpass-the-Hash: TGT obtenido → .ccache generado")
        else:
            self._ok("Overpass-the-Hash: no se pudo obtener TGT")

    def _on_ticket(self, result):
        if result:
            self._critical("Ticket forjado con éxito → usar con pass-the-ticket")
        else:
            self._ok("Ticket: no se pudo forjar")

    def _on_ptt(self, result):
        if result:
            self._critical("Pass-the-Ticket: ticket cargado y KRB5CCNAME activo")
        else:
            self._ok("Pass-the-Ticket: no se pudo cargar el ticket")

    def _on_exploit(self, result):
        if result:
            self._critical("Exploit completado con éxito")
        else:
            self._ok("Exploit: sin resultado o no vulnerable")

    def _build_kwargs(self, script_name):
        p = self.ctx.params
        base = {
            "user":     p.get("user", ""),
            "password": p.get("password", ""),
            "hash":     p.get("hash"),
            "domain":   p.get("domain", ""),
        }
        extras = {
            "user-enum":          {"userlist": p.get("userlist")},
            "asrep-roasting":     {"userlist": p.get("userlist")},
            "kerberoasting":      {"spn": p.get("spn")},
            "overpass-the-hash":  {},
            "golden-ticket":      {
                "krbtgt_hash": p.get("krbtgt_hash"),
                "domain_sid":  p.get("domain_sid"),
                "user_id":     int(p.get("user_id") or 500),
                "groups":      p.get("groups", "513,512,520,518,519"),
            },
            "diamond-ticket":     {
                "krbtgt_hash": p.get("krbtgt_hash"),
                "user_id":     int(p.get("user_id") or 500),
                "groups":      p.get("groups", "513,512,520,518,519"),
            },
            "sapphire-ticket":    {
                "krbtgt_hash": p.get("krbtgt_hash"),
                "target_user": p.get("target_user", "Administrator"),
            },
            "pass-the-ticket":    {"ccache": p.get("ccache")},
            "constrained-s4u":    {
                "spn":         p.get("spn"),
                "target_user": p.get("target_user", "Administrator"),
            },
            "rbcd": {
                "target_computer":  p.get("target_computer"),
                "attacker_account": p.get("attacker_account"),
                "target_user":      p.get("target_user", "Administrator"),
            },
            "shadow-credentials": {"target_user": p.get("target_user", "Administrator")},
            "sam-spoofing":       {
                "dc_name":     p.get("dc_name"),
                "target_user": p.get("target_user", "Administrator"),
            },
            "ms14-068":           {"user_sid": p.get("user_sid")},
            "kerber-loss":        {
                "spn":              p.get("spn"),
                "attacker_account": p.get("attacker_account"),
                "vector":           p.get("vector", "dos-colision"),
            },
            "reset-nightmare":    {
                "target_user":  p.get("target_user", "Administrator"),
                "new_password": p.get("new_password"),
            },
            "adcs": {
                "ca":       p.get("ca"),
                "template": p.get("template"),
                "alt_name": p.get("alt_name"),
            },
        }
        base.update(extras.get(script_name, {}))
        return base


def run_kerberos_scanner(prefilled_args):
    """Punto de entrada del Kerberos autopwn scanner."""
    _print_scanner_menu()

    prefilled = {
        "target":      getattr(prefilled_args, "target",      None),
        "domain":      getattr(prefilled_args, "domain",      None),
        "user":        getattr(prefilled_args, "user",        None),
        "password":    getattr(prefilled_args, "password",    None),
        "hash":        getattr(prefilled_args, "hash",        None),
        "domain_sid":  getattr(prefilled_args, "domain_sid",  None),
        "krbtgt_hash": getattr(prefilled_args, "krbtgt_hash", None),
        "userlist":    getattr(prefilled_args, "userlist",    None),
        "spn":         getattr(prefilled_args, "spn",         None),
        "ccache":      getattr(prefilled_args, "ccache",      None),
        "target_user": getattr(prefilled_args, "target_user", None),
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

    scanner = KerberosScanner(
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
    scanner.ctx = KerberosScanContext(params)

    scanner.run()
