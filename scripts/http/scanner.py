# scripts/http/scanner.py
import os
import pyfiglet
from rich.panel import Panel
from rich.prompt import Prompt
from core.output import console
from core.target import Target
from core.credentials import Creds
from core.scanner import Scanner, ScanStep, ScanContext
from scripts.http.scan_params import SCAN_ORDER, REQUIRED, OPTIONAL, EXPORT_FORMATS

PROTOCOL = "HTTP"
COLOR    = "bright_cyan"

def _print_scanner_menu():
    art = pyfiglet.figlet_format("HTTP-SCAN", font="slant")
    console.print(f"[bold {COLOR}]{art}[/bold {COLOR}]")
    console.print(Panel(
        "[bold]Fases del autopwn:[/bold]\n\n"
        "  [cyan]FASE 1 — Enumeración[/cyan]\n"
        "    • banner-grab / tech-detect / robots-sitemap\n"
        "    • ssl-redirect / cors-check / js-secrets / http2-check\n\n"
        "  [cyan]FASE 2 — Ataques[/cyan]\n"
        "    • header-injection / open-redirect / jwt-attack\n"
        "    • sqli-detect / xss-detect / lfi-detect / ssrf-detect\n"
        "    • graphql-enum\n\n"
        "  [cyan]FASE 3 — Exploits[/cyan]\n"
        "    • shellshock / apache-path-traversal / php-cgi-rce\n"
        "    • log4shell / http-request-smuggling\n\n"
        "  [cyan]FASE 4 — Post[/cyan]\n"
        "    • extract-links / crawl\n\n"
        "[dim]Solo se ejecutan los scripts cuyas condiciones se cumplan.[/dim]",
        title=f"[bold {COLOR}]HTTP Autopwn Scanner — Lobera[/bold {COLOR}]",
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
    default_name = f"lobera_http_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{fmt}"
    path = Prompt.ask("  Nombre del fichero", default=default_name)
    if not path.endswith(f".{fmt}"): path = f"{path}.{fmt}"
    console.print(); return False, path, fmt

class HTTPScanContext(ScanContext):
    def _cond_has_param(self):    return bool(self.params.get("param"))
    def _cond_has_wordlist(self):
        ul = self.params.get("wordlist")
        return bool(ul) and os.path.isfile(str(ul))
    def _cond_has_listener(self): return bool(self.params.get("listener"))

class HTTPScanner(Scanner):
    def _on_result(self, script_name, result):
        handlers = {
            "banner-grab":            self._on_banner,
            "tech-detect":            self._on_tech,
            "robots-sitemap":         self._on_robots,
            "ssl-redirect":           self._on_redirect,
            "cors-check":             self._on_cors,
            "js-secrets":             self._on_js,
            "http2-check":            self._on_http2,
            "dir-bruteforce":         self._on_dirs,
            "header-injection":       self._on_header_inj,
            "open-redirect":          self._on_open_redirect,
            "sqli-detect":            self._on_sqli,
            "xss-detect":             self._on_xss,
            "lfi-detect":             self._on_lfi,
            "ssrf-detect":            self._on_ssrf,
            "graphql-enum":           self._on_graphql,
            "jwt-attack":             self._on_jwt,
            "log4shell":              self._on_log4shell,
            "apache-path-traversal":  self._on_apache,
            "shellshock":             self._on_shellshock,
            "php-cgi-rce":            self._on_php,
            "http-request-smuggling": self._on_smuggling,
            "extract-links":          self._on_links,
            "crawl":                  self._on_crawl,
        }
        handler = handlers.get(script_name)
        if handler: handler(result)

    def _on_banner(self, r):
        if r: self._ok(f"HTTP {r.get('status','')} — techs: {', '.join(r.get('technologies',[]))}")
    def _on_tech(self, r):
        if r and r.get("technologies"): self._ok(f"Tecnologías: {', '.join(r['technologies'])}")
    def _on_robots(self, r):
        if r and r.get("interesting"): self._critical(f"Rutas interesantes: {', '.join(r['interesting'][:3])}")
        elif r: self._ok("robots.txt sin rutas interesantes")
    def _on_redirect(self, r):
        if r and not r.get("redirects"): self._critical("Sin redirección HTTP→HTTPS")
        elif r: self._ok("Redirección HTTP→HTTPS correcta")
    def _on_cors(self, r):
        if r: self._critical(f"CORS misconfigured — {len(r)} problema(s)")
        else: self._ok("CORS correcto")
    def _on_js(self, r):
        if r: self._critical(f"Secretos en JS: {len(r)} hallazgo(s)")
        else: self._ok("Sin secretos en JS")
    def _on_http2(self, r):
        if r and r.get("HTTP/2 Cleartext (h2c)"): self._critical("h2c cleartext soportado")
        elif r: self._ok(f"HTTP/2: {r.get('HTTP/2', False)}")
    def _on_dirs(self, r):
        if r: self._critical(f"{len(r)} ruta(s) encontrada(s)")
        else: self._ok("Dir bruteforce sin resultados")
    def _on_header_inj(self, r):
        if r: self._critical(f"Host header injection — {len(r)} vector(es)")
        else: self._ok("Sin header injection")
    def _on_open_redirect(self, r):
        if r: self._critical(f"Open redirect — {len(r)} param(s)")
        else: self._ok("Sin open redirects")
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
    def _on_graphql(self, r):
        if r and r.get("endpoint"): self._critical(f"GraphQL: {r['endpoint']}")
        else: self._ok("GraphQL no detectado")
    def _on_jwt(self, r):
        if r and r.get("findings"): self._critical(f"JWT vulnerable — {len(r['findings'])} ataque(s)")
        else: self._ok("JWT sin vulnerabilidades obvias")
    def _on_log4shell(self, r):
        if r: self._critical(f"Log4Shell: {len(r)} payload(s) — verificar OOB")
    def _on_apache(self, r):
        if r and (r.get("traversal") or r.get("rce")): self._critical("APACHE PATH TRAVERSAL/RCE")
        else: self._ok("Sin Apache path traversal")
    def _on_shellshock(self, r):
        if r: self._critical(f"SHELLSHOCK — {len(r)} ruta(s) vulnerable(s)")
        else: self._ok("Sin Shellshock")
    def _on_php(self, r):
        if r: self._critical(f"PHP CGI RCE — {len(r)} hit(s)")
        else: self._ok("Sin PHP CGI RCE")
    def _on_smuggling(self, r):
        if r: self._critical("HTTP REQUEST SMUGGLING posible")
        else: self._ok("Sin Request Smuggling")
    def _on_links(self, r):
        if r: self._ok(f"{len(r.get('internal',[]))} links, {len(r.get('api',[]))} API endpoints")
    def _on_crawl(self, r):
        if r: self._ok(f"Crawl: {len(r.get('pages',[]))} páginas, {len(r.get('forms',[]))} forms")

    def _build_kwargs(self, script_name):
        p = self.ctx.params
        base = {
            "port":    int(p.get("port") or 80),
            "timeout": int(p.get("timeout") or 5),
            "path":    p.get("path") or "/",
        }
        extras = {
            "sqli-detect":            {"param": p.get("param","id")},
            "xss-detect":             {"param": p.get("param","q")},
            "lfi-detect":             {"param": p.get("param","file")},
            "ssrf-detect":            {"param": p.get("param","url")},
            "open-redirect":          {"param": p.get("param")},
            "dir-bruteforce":         {"wordlist": p.get("wordlist")},
            "log4shell":              {"listener": p.get("listener","lobera.oob.example.com")},
            "crawl":                  {"max_depth": int(p.get("max_depth") or 3),
                                       "max_pages":  int(p.get("max_pages") or 30)},
        }
        base.update(extras.get(script_name, {}))
        return base

def run_http_scanner(prefilled_args):
    _print_scanner_menu()
    prefilled = {k: getattr(prefilled_args, k, None)
                 for k in ["target","port","path","param","wordlist","listener"]}
    params               = _collect_params(prefilled)
    verbose              = _collect_verbose()
    save_to_db, export_path, export_fmt = _collect_output()
    target  = Target(ip=params.get("target",""), domain="",
                     timeout=int(params.get("timeout") or 5))
    creds   = Creds(user="", password="", domain="", hash=None)
    steps   = [ScanStep(e["script"], e["condition"]) for e in SCAN_ORDER]
    scanner = HTTPScanner(target=target, creds=creds, steps=steps,
                          protocol=PROTOCOL, color=COLOR, verbose=verbose,
                          save_to_db=save_to_db, export_path=export_path,
                          export_fmt=export_fmt)
    scanner.ctx = HTTPScanContext(params)
    scanner.run()
