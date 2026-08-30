# scripts/ssl/scanner.py

import os
import getpass as _getpass

import pyfiglet
from rich.panel import Panel
from rich.prompt import Prompt

from core.output import console
from core.target import Target
from core.credentials import Creds
from core.scanner import Scanner, ScanStep, ScanContext
from scripts.ssl.scan_params import SCAN_ORDER, REQUIRED, OPTIONAL, EXPORT_FORMATS

PROTOCOL = "SSL"
COLOR    = "gold1"


def _print_scanner_menu():
    art = pyfiglet.figlet_format("SSL-SCAN", font="slant")
    console.print(f"[bold {COLOR}]{art}[/bold {COLOR}]")
    console.print(Panel(
        "[bold]Fases del autopwn:[/bold]\n\n"
        "  [cyan]FASE 1 — Enumeración e información[/cyan]\n"
        "    • cert-info / protocol-version / cipher-enum\n"
        "    • san-enum / hsts-check / ocsp-check / ct-log-search\n\n"
        "  [cyan]FASE 2 — CVE checks[/cyan]\n"
        "    • heartbleed (CVE-2014-0160)\n"
        "    • poodle (CVE-2014-3566)\n"
        "    • openssl-cve-2022-0778\n\n"
        "  [cyan]FASE 3 — Exploits propios[/cyan]\n"
        "    • cert-spoof-check\n"
        "    • tls-poison\n"
        "    • alpn-confusion\n\n"
        "[dim]Solo se ejecutan los scripts cuyas condiciones se cumplan.[/dim]",
        title=f"[bold {COLOR}]SSL Autopwn Scanner — Lobera[/bold {COLOR}]",
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
    default_name = f"lobera_ssl_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{fmt}"
    path = Prompt.ask("  Nombre del fichero", default=default_name)
    if not path.endswith(f".{fmt}"): path = f"{path}.{fmt}"
    console.print()
    return False, path, fmt


class SSLScanContext(ScanContext):
    def _cond_has_domain(self):
        return bool(self.params.get("domain"))


class SSLScanner(Scanner):
    def _on_result(self, script_name, result):
        handlers = {
            "cert-info":             self._on_cert_info,
            "protocol-version":      self._on_protocol,
            "cipher-enum":           self._on_ciphers,
            "san-enum":              self._on_san,
            "hsts-check":            self._on_hsts,
            "ocsp-check":            self._on_ocsp,
            "ct-log-search":         self._on_ct,
            "heartbleed":            self._on_heartbleed,
            "poodle":                self._on_poodle,
            "openssl-cve-2022-0778": self._on_openssl,
            "cert-spoof-check":      self._on_spoof,
            "tls-poison":            self._on_tls_poison,
            "alpn-confusion":        self._on_alpn,
        }
        handler = handlers.get(script_name)
        if handler: handler(result)

    def _on_cert_info(self, result):
        if not result: return
        days = result.get("days_left", 999)
        if days < 0:    self._critical("Certificado EXPIRADO")
        elif days < 30: self._critical(f"Certificado expira en {days} días")
        else:           self._ok(f"Certificado válido — {days} días restantes")

    def _on_protocol(self, result):
        if not result: return
        deprecated = [v for v, s in result.items()
                      if s and v in {"TLSv1.0","TLSv1.1","SSLv3"}]
        if deprecated:
            self._critical(f"Protocolos obsoletos: {', '.join(deprecated)}")
        else:
            self._ok("Sin versiones obsoletas de SSL/TLS")

    def _on_ciphers(self, result):
        if not result: return
        weak = result.get("weak", [])
        if weak: self._critical(f"{len(weak)} cipher(s) débil(es): {', '.join(weak[:3])}")
        else:    self._ok("Sin cipher suites débiles")

    def _on_san(self, result):
        if result: self._ok(f"{len(result)} SAN(s) encontrados")

    def _on_hsts(self, result):
        if not result: return
        if not result.get("hsts"):
            self._critical("HSTS no configurado — downgrade a HTTP posible")
        else:
            self._ok("HSTS configurado")

    def _on_ocsp(self, result):
        if result and result.get("ocsp_url"):
            self._ok(f"OCSP URL: {result['ocsp_url']}")

    def _on_ct(self, result):
        if result:
            self._critical(f"CT logs: {len(result)} entradas encontradas")

    def _on_heartbleed(self, result):
        if result is True: self._critical("VULNERABLE a Heartbleed (CVE-2014-0160)")
        else:              self._ok("No vulnerable a Heartbleed")

    def _on_poodle(self, result):
        if result is True: self._critical("VULNERABLE a POODLE (CVE-2014-3566)")
        else:              self._ok("No vulnerable a POODLE")

    def _on_openssl(self, result):
        if not result: return
        if result.get("potentially_vulnerable"):
            self._critical(f"POTENCIALMENTE VULNERABLE a CVE-2022-0778 — {result.get('openssl_version')}")
        else:
            self._ok("No vulnerable a CVE-2022-0778")

    def _on_spoof(self, result):
        if result: self._critical(f"cert-spoof-check: {len(result)} problema(s)")
        else:      self._ok("cert-spoof-check: sin problemas de spoofing")

    def _on_tls_poison(self, result):
        if not result: return
        if result.get("supports_resumption"):
            self._critical("TLS session resumption activa — verificar rotación de ticket keys")
        else:
            self._ok("Sin reutilización de session tickets")

    def _on_alpn(self, result):
        if not result: return
        if result.get("accepts_spdy"):
            self._critical("Servidor acepta SPDY (protocolo obsoleto)")
        elif result.get("accepts_multiple"):
            self._ok("ALPN acepta múltiples protocolos — revisar config WAF")
        else:
            self._ok("Sin confusión ALPN detectada")

    def _build_kwargs(self, script_name):
        p = self.ctx.params
        base = {
            "port":    int(p.get("port") or 443),
            "timeout": int(p.get("timeout") or 5),
            "sni":     p.get("sni"),
        }
        extras = {
            "ct-log-search": {"domain": p.get("domain"), "wildcard": True},
            "tls-poison":    {"attempts": int(p.get("attempts") or 3)},
        }
        base.update(extras.get(script_name, {}))
        return base


def run_ssl_scanner(prefilled_args):
    _print_scanner_menu()

    prefilled = {k: getattr(prefilled_args, k, None)
                 for k in ["target","port","sni","domain"]}

    params          = _collect_params(prefilled)
    verbose         = _collect_verbose()
    save_to_db, export_path, export_fmt = _collect_output()

    target = Target(
        ip=params.get("target",""),
        domain=params.get("domain",""),
        timeout=int(params.get("timeout") or 5),
    )
    creds = Creds(user="", password="", domain="", hash=None)

    steps = [ScanStep(e["script"], e["condition"]) for e in SCAN_ORDER]

    scanner = SSLScanner(
        target=target, creds=creds, steps=steps,
        protocol=PROTOCOL, color=COLOR, verbose=verbose,
        save_to_db=save_to_db, export_path=export_path, export_fmt=export_fmt,
    )
    scanner.ctx = SSLScanContext(params)
    scanner.run()
