# scripts/http/enum/ssl_redirect.py
import urllib.request, urllib.error
from scripts.base import BaseScript
from core.output import print_result, print_table, print_check, console
from core import session_db

class Script(BaseScript):
    name        = "ssl-redirect"
    protocol    = "http"
    category    = "enum"
    description = "Comprueba si el servidor redirige HTTP a HTTPS y si la redirección está correctamente configurada."

    EXAMPLES = [
        {"flag": "-t / --port", "desc": "IP y puerto HTTP",
         "good": "http --script=ssl-redirect -t 10.10.10.5 --port 80",
         "bad":  "http --script=ssl-redirect (sin -t)"},
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
        ip      = self.target.ip
        url     = f"http://{ip}:{port}/"
        opener  = urllib.request.build_opener(self._NoRedirect())

        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            try:
                resp     = opener.open(req, timeout=timeout)
                status   = resp.status
                location = resp.headers.get("location", "")
                hsts     = resp.headers.get("strict-transport-security", "")
            except urllib.error.HTTPError as e:
                status   = e.code
                location = e.headers.get("location","") if e.headers else ""
                hsts     = e.headers.get("strict-transport-security","") if e.headers else ""
        except Exception as e:
            print_result("HTTP", ip, "fail", f"error: {e}")
            return None

        redirects = status in (301,302,307,308) and location.lower().startswith("https://")
        has_hsts  = bool(hsts)

        rows = [
            ("Código HTTP",       str(status)),
            ("Location",          location or "—"),
            ("Redirige a HTTPS",  "Sí" if redirects else "NO"),
            ("HSTS presente",     hsts[:60] if hsts else "NO"),
        ]
        print_table(f"SSL Redirect — {ip}:{port}", ["Check", "Valor"], rows)

        if not redirects:
            print_result("HTTP", ip, "pwned", "Sin redirección HTTP→HTTPS")
            session_db.save_finding(ip, "HTTP", "no_https_redirect", f"port={port}")
        else:
            print_check(f"Redirección HTTP→HTTPS correcta ({status})", ok=True)

        if redirects and not has_hsts:
            print_check("HSTS ausente — first-visit stripping posible", ok=False)
            session_db.save_finding(ip, "HTTP", "hsts_missing", f"port={port}")

        return {"redirects": redirects, "hsts": has_hsts, "status": status, "location": location}
