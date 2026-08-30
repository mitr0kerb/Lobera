# scripts/http/enum/js_secrets.py
import urllib.request, urllib.error, re
from scripts.base import BaseScript
from core.output import print_result, print_table, console
from core import session_db

SECRET_PATTERNS = [
    ("AWS Access Key",     r"AKIA[0-9A-Z]{16}"),
    ("Google API Key",     r"AIza[0-9A-Za-z\-_]{35}"),
    ("GitHub Token",       r"gh[pousr]_[0-9a-zA-Z]{36}"),
    ("Slack Token",        r"xox[baprs]-[0-9a-zA-Z\-]{10,48}"),
    ("JWT Token",          r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"),
    ("Bearer Token",       r"(?i)bearer\s+[a-zA-Z0-9\-_\.]{20,}"),
    ("API Key genérica",   r"(?i)api[_\-]?key['\"\s:=]+['\"]([a-zA-Z0-9\-_]{16,64})['\"]"),
    ("Password hardcoded", r"(?i)password['\"\s:=]+['\"]([^'\"]{6,})['\"]"),
    ("Secret hardcoded",   r"(?i)secret['\"\s:=]+['\"]([^'\"]{6,})['\"]"),
    ("Endpoint interno",   r"https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)[^\s'\"]*"),
    ("Firebase URL",       r"https://[a-z0-9\-]+\.firebaseio\.com"),
    ("Stripe Key",         r"(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24}"),
    ("Private Key",        r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
]

class Script(BaseScript):
    name        = "js-secrets"
    protocol    = "http"
    category    = "enum"
    description = "Script propio: descarga ficheros JS y busca API keys, tokens, endpoints internos y secretos hardcoded."

    EXAMPLES = [
        {"flag": "-t / --port", "desc": "IP y puerto",
         "good": "http --script=js-secrets -t 10.10.10.5 --port 80",
         "bad":  "http --script=js-secrets (sin -t)"},
    ]

    def run(self, **kwargs):
        port    = int(kwargs.get("port") or 80)
        timeout = int(kwargs.get("timeout") or self.target.timeout or 5)
        ip      = self.target.ip
        base    = f"http://{ip}:{port}"
        js_urls = set()

        try:
            req  = urllib.request.Request(f"{base}/", headers={"User-Agent": "Mozilla/5.0"})
            resp = urllib.request.urlopen(req, timeout=timeout)
            body = resp.read(512 * 1024).decode("utf-8", errors="replace")
            for match in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', body, re.I):
                src = match.group(1)
                if src.startswith("http"):
                    js_urls.add(src)
                elif src.startswith("/"):
                    js_urls.add(f"{base}{src}")
                else:
                    js_urls.add(f"{base}/{src}")
            for common in ["app.js","main.js","bundle.js","vendor.js",
                           "assets/js/app.js","static/js/main.js"]:
                js_urls.add(f"{base}/{common}")
        except Exception as e:
            print_result("HTTP", ip, "fail", f"error: {e}")
            return None

        print_result("HTTP", ip, "info", f"js-secrets: analizando {len(js_urls)} fichero(s)")
        all_findings = []

        for js_url in sorted(js_urls)[:20]:
            try:
                req  = urllib.request.Request(js_url, headers={"User-Agent": "Mozilla/5.0"})
                resp = urllib.request.urlopen(req, timeout=timeout)
                if resp.status != 200:
                    continue
                content = resp.read(2 * 1024 * 1024).decode("utf-8", errors="replace")
                for pattern_name, pattern in SECRET_PATTERNS:
                    for match in re.findall(pattern, content)[:3]:
                        val = match if isinstance(match, str) else match
                        snippet = val[:80]
                        all_findings.append((pattern_name, snippet, js_url.split("/")[-1]))
                        session_db.save_finding(ip, "HTTP", "js_secret",
                                                f"{pattern_name}: {snippet[:40]}")
            except Exception:
                pass

        if all_findings:
            print_table(f"Secretos en JS — {ip}:{port}",
                        ["Tipo", "Valor", "Fichero"], all_findings)
            print_result("HTTP", ip, "pwned", f"{len(all_findings)} secreto(s) encontrado(s)")
        else:
            print_result("HTTP", ip, "info", "Sin secretos detectados")

        return all_findings
