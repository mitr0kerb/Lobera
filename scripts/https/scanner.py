# scripts/https/scanner.py
import os
import pyfiglet
from rich.panel import Panel
from rich.prompt import Prompt
from core.output import console
from core.target import Target
from core.credentials import Creds
from core.scanner import Scanner, ScanStep, ScanContext
from scripts.https.scan_params import SCAN_ORDER, REQUIRED, OPTIONAL, EXPORT_FORMATS

PROTOCOL = "HTTPS"
COLOR    = "deep_sky_blue1"

def _print_scanner_menu():
    art = pyfiglet.figlet_format("HTTPS-SCAN", font="slant")
    console.print(f"[bold {COLOR}]{art}[/bold {COLOR}]")
    console.print(Panel(
        "[bold]Fases del autopwn:[/bold]\n\n"
        "  [cyan]FASE 1 — Enumeración[/cyan]\n"
        "    • banner-grab / tech-detect / security-headers\n"
        "    • certificate-pinning / robots-sitemap / cors-check\n"
        "    • js-secrets / dir-bruteforce\n\n"
        "  [cyan]FASE 2 — Ataques[/cyan]\n"
        "    • cache-poisoning / oauth-misconfig / jwt-attack\n"
        "    • sqli-detect / xss-detect / lfi-detect / ssrf-detect\n\n"
        "  [cyan]FASE 3 — Exploits[/cyan]\n"
        "    • tls-stripping / php-cgi-rce / log4shell\n"
        "    • spring4shell / jenkins-file-read\n\n"
        "  [cyan]FASE 4 — Post[/cyan]\n"
        "    • extract-links / crawl\n\n"
        "[dim]Solo se ejecutan los scripts cuyas condiciones se cumplan.[/dim]",
        title=f"[bold {COLOR}]HTTPS Autopwn Scanner — Lobera[/bold {COLOR}]",
        border_style=COLOR, expand=False))
    console.print()

def _collect_params(prefilled):
    console.rule(f"[bold {COLOR}]Parámetros del scan[/bold {COLOR}]"); console.print()
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
            console.print(f"  [dim]{label}:[/dim] [cyan]{'*'*8 if secret else prefill}[/cyan] [dim](por CLI)[/dim]")
            continue
        hint = "[bold red] *[/bold red]" if req else " [dim](enter para omitir)[/dim]"
        while True:
            value = Prompt.ask(f"  [bold]{label}[/bold]{hint}", default="")
            if req and not value: console.print("  [red]Este campo es obligatorio.[/red]"); continue
            break
        params[key] = value if value else default
    console.print(); console.print("  [dim]─── Parámetros opcionales ───[/dim]"); console.print()
    for field in OPTIONAL:
        key     = field["key"]
        label   = field["label"]
        default = field.get("default")
        prefill = prefilled.get(key)
        if prefill:
            params[key] = prefill
            console.print(f"  [dim]{label}:[/dim] [cyan]{prefill}[/cyan] [dim](por CLI)[/dim]"); continue
        value = Prompt.ask(f"  [bold]{label}[/bold]", default="")
        params[key] = value if value else default
    console.print(); return params

def _collect_verbose():
    console.rule(f"[bold {COLOR}]Nivel de detalle[/bold {COLOR}]"); console.print()
    console.print("  [bold][1][/bold] Básico")
    console.print("  [bold][2][/bold] Normal  [dim](recomendado)[/dim]")
    console.print("  [bold][3][/bold] Debug")
    console.print()
    choice = Prompt.ask("  Elige nivel", choices=["1","2","3"], default="2"); console.print()
    return int(choice)

def _collect_output():
    console.rule(f"[bold {COLOR}]Destino de resultados[/bold {COLOR}]"); console.print()
    console.print("  [bold][s][/bold] Base de datos  [bold][n][/bold] Fichero"); console.print()
    choice = Prompt.ask("  Opción", choices=["s","n"], default="s")
    if choice == "s": console.print(); return True, None, None
    fmt = Prompt.ask("  Formato", choices=EXPORT_FORMATS, default="json")
    from datetime import datetime
    default_name = f"lobera_https_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{fmt}"
    path = Prompt.ask("  Nombre del fichero", default=default_name)
    if not path.endswith(f".{fmt}"): path = f"{path}.{fmt}"
    console.print(); return False, path, fmt

class HTTPSScanContext(ScanContext):
    def _cond_has_param(self):     return bool(self.params.get("param"))
    def _cond_has_wordlist(self):
        ul = self.params.get("wordlist")
        return bool(ul) and os.path.isfile(str(ul))
    def _cond_has_listener(self):  return bool(self.params.get("listener"))
    def _cond_has_client_id(self): return bool(self.params.get("client_id"))

class HTTPSScanner(Scanner):
    def _on_result(self, script_name, result):
        handlers = {
            "banner-grab":         self._on_banner,
            "tech-detect":         self._on_tech,
            "security-headers":    self._on_sec_headers,
            "certificate-pinning": self._on_cert_pin,
            "robots-sitemap":      self._on_robots,
            "cors-check":          self._on_cors,
            "js-secrets":          self._on_js,
            "dir-bruteforce":      self._on_dirs,
            "cache-poisoning":     self._on_cache,
            "oauth-misconfig":     self._on_oauth,
            "jwt-attack":          self._on_jwt,
            "sqli-detect":         self._on_sqli,
            "xss-detect":          self._on_xss,
            "lfi-detect":          self._on_lfi,
            "ssrf-detect":         self._on_ssrf,
            "tls-stripping":       self._on_tls,
            "php-cgi-rce":         self._on_php,
            "log4shell":           self._on_log4shell,
            "spring4shell":        self._on_spring,
            "jenkins-file-read":   self._on_jenkins,
            "extract-links":       self._on_links,
            "crawl":               self._on_crawl,
        }
        handler = handlers.get(script_name)
        if handler: handler(result)

    def _on_banner(self, r):
        if r: self._ok(f"HTTP {r.get('status','')} — techs: {', '.join(r.get('technologies',[]))}")
    def _on_tech(self, r):
        if r and r.get("technologies"): self._ok(f"Tecnologías: {', '.join(r['technologies'])}")
    def _on_sec_headers(self, r):
        if not r: return
        grade = r.get("grade","?"); pct = r.get("score",0)
        if grade in ("F","D"):   self._critical(f"Security headers: grado {grade} ({pct}%)")
        elif grade in ("A","A+"): self._ok(f"Security headers: grado {grade} ({pct}%)")
        else:                     self._warn(f"Security headers: grado {grade} ({pct}%)")
    def _on_cert_pin(self, r):
        if r and not r.get("has_pinning"): self._warn("Sin certificate pinning detectado")
        elif r: self._ok("Certificate pinning presente")
    def _on_robots(self, r):
        if r and r.get("interesting"): self._critical(f"Rutas interesantes: {', '.join(r['interesting'][:3])}")
        elif r: self._ok("robots.txt sin rutas interesantes")
    def _on_cors(self, r):
        if r: self._critical(f"CORS misconfigured — {len(r)} problema(s)")
        else: self._ok("CORS correcto")
    def _on_js(self, r):
        if r: self._critical(f"Secretos en JS: {len(r)} hallazgo(s)")
        else: self._ok("Sin secretos en JS")
    def _on_dirs(self, r):
        if r: self._critical(f"{len(r)} ruta(s) encontrada(s)")
        else: self._ok("Dir bruteforce sin resultados")
    def _on_cache(self, r):
        if r: self._critical(f"Cache poisoning — {len(r)} vector(es)")
        else: self._ok("Sin cache poisoning")
    def _on_oauth(self, r):
        if r and r.get("findings"): self._critical(f"OAuth misconfigured — {len(r['findings'])} problema(s)")
        elif r: self._ok("OAuth sin misconfiguraciones obvias")
    def _on_jwt(self, r):
        if r and r.get("findings"): self._critical(f"JWT vulnerable — {len(r['findings'])} ataque(s)")
        else: self._ok("JWT sin vulnerabilidades obvias")
    def _on_sqli(self, r):
        if r: self._critical(f"SQL INJECTION — {len(r)} payload(s)")
        else: self._ok("Sin SQLi")
    def _on_xss(self, r):
        if r: self._critical(f"XSS REFLEJADO — {len(r)} payload(s)")
        else: self._ok("Sin XSS")
    def _on_lfi(self, r):
        if r: self._critical(f"LFI DETECTADA — {len(r)} payload(s)")
        else: self._ok("Sin LFI")
    def _on_ssrf(self, r):
        if r: self._critical(f"SSRF DETECTADA — {len(r)} payload(s)")
        else: self._ok("Sin SSRF")
    def _on_tls(self, r):
        if r and r.get("vulnerable"): self._critical("TLS STRIPPING posible")
        else: self._ok("Sin TLS stripping")
    def _on_php(self, r):
        if r: self._critical(f"PHP CGI RCE — {len(r)} hit(s)")
        else: self._ok("Sin PHP CGI RCE")
    def _on_log4shell(self, r):
        if r: self._critical(f"Log4Shell: {len(r)} payload(s) — verificar OOB")
    def _on_spring(self, r):
        if r and r.get("vulnerable"): self._critical("SPRING4SHELL RCE confirmado")
        else: self._ok("Sin Spring4Shell")
    def _on_jenkins(self, r):
        if r: self._critical(f"JENKINS FILE READ — {len(r)} fichero(s) leído(s)")
        elif r is not None: self._ok("Jenkins sin file read confirmado")
    def _on_links(self, r):
        if r: self._ok(f"{len(r.get('internal',[]))} links, {len(r.get('api',[]))} API endpoints")
    def _on_crawl(self, r):
        if r: self._ok(f"Crawl: {len(r.get('pages',[]))} páginas, {len(r.get('forms',[]))} forms")

    def _warn(self, msg):
        from core.output import print_result
        print_result(PROTOCOL, self.target.ip, "info", msg)

    def _build_kwargs(self, script_name):
        p = self.ctx.params
        base = {
            "port":    int(p.get("port") or 443),
            "timeout": int(p.get("timeout") or 5),
            "path":    p.get("path") or "/",
            "sni":     p.get("sni") or p.get("target",""),
        }
        extras = {
            "sqli-detect":       {"param": p.get("param","id")},
            "xss-detect":        {"param": p.get("param","q")},
            "lfi-detect":        {"param": p.get("param","file")},
            "ssrf-detect":       {"param": p.get("param","url")},
            "oauth-misconfig":   {"client_id": p.get("client_id","client")},
            "dir-bruteforce":    {"wordlist": p.get("wordlist")},
            "log4shell":         {"listener": p.get("listener","lobera.oob.example.com")},
            "tls-stripping":     {"http_port": int(p.get("http_port") or 80)},
            "jenkins-file-read": {"file_path": p.get("file_path","/etc/passwd")},
            "crawl":             {"max_depth": int(p.get("max_depth") or 3),
                                  "max_pages":  int(p.get("max_pages") or 30)},
        }
        base.update(extras.get(script_name, {}))
        return base

def run_https_scanner(prefilled_args):
    _print_scanner_menu()
    prefilled = {k: getattr(prefilled_args, k, None)
                 for k in ["target","port","sni","path","param","wordlist",
                            "listener","client_id","http_port"]}
    params               = _collect_params(prefilled)
    verbose              = _collect_verbose()
    save_to_db, export_path, export_fmt = _collect_output()
    target  = Target(ip=params.get("target",""), domain="",
                     timeout=int(params.get("timeout") or 5))
    creds   = Creds(user="", password="", domain="", hash=None)
    steps   = [ScanStep(e["script"], e["condition"]) for e in SCAN_ORDER]
    scanner = HTTPSScanner(target=target, creds=creds, steps=steps,
                           protocol=PROTOCOL, color=COLOR, verbose=verbose,
                           save_to_db=save_to_db, export_path=export_path,
                           export_fmt=export_fmt)
    scanner.ctx = HTTPSScanContext(params)
    scanner.run()
