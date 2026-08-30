# scripts/http/attack/header_injection.py
import urllib.request, urllib.error
from scripts.base import BaseScript
from core.output import print_result, print_table, print_check, console
from core import session_db

class Script(BaseScript):
    name        = "header-injection"
    protocol    = "http"
    category    = "attack"
    description = "Detecta Host header injection y web cache poisoning via headers no cacheados."

    EXAMPLES = [
        {"flag": "-t / --port", "desc": "IP y puerto",
         "good": "http --script=header-injection -t 10.10.10.5 --port 80",
         "bad":  "http --script=header-injection (sin -t)"},
    ]

    POISON_HEADERS = [
        "X-Forwarded-Host", "X-Host", "X-Forwarded-Server",
        "X-HTTP-Host-Override", "Forwarded",
    ]

    def run(self, **kwargs):
        port    = int(kwargs.get("port") or 80)
        timeout = int(kwargs.get("timeout") or self.target.timeout or 5)
        ip      = self.target.ip
        base    = f"http://{ip}:{port}"
        evil    = "evil.lobera.internal"
        findings = []

        for header in self.POISON_HEADERS:
            try:
                req = urllib.request.Request(f"{base}/", headers={
                    "User-Agent": "Mozilla/5.0",
                    "Host":       f"{ip}:{port}",
                    header:       evil,
                    "Connection": "close",
                })
                try:
                    resp = urllib.request.urlopen(req, timeout=timeout)
                    body = resp.read(65536).decode("utf-8", errors="replace")
                    hdrs = {k.lower(): v for k, v in resp.headers.items()}
                except urllib.error.HTTPError as e:
                    body = e.read(65536).decode("utf-8", errors="replace") if e else ""
                    hdrs = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}

                location = hdrs.get("location","")
                if evil in location:
                    findings.append((header, f"Location: {location[:50]}", "Crítico"))
                    session_db.save_finding(ip, "HTTP", "cache_poisoning_via_host", f"header={header}")
                elif evil in body:
                    findings.append((header, "Reflejado en body", "Alto"))
                    session_db.save_finding(ip, "HTTP", "host_header_injection", f"header={header}")
                elif evil in str(hdrs):
                    findings.append((header, "Reflejado en headers", "Medio"))
            except Exception:
                pass

        if findings:
            print_table(f"Header Injection — {ip}:{port}",
                        ["Header", "Efecto", "Severidad"], findings)
            print_result("HTTP", ip, "pwned", f"HOST HEADER INJECTION — {len(findings)} vector(es)")
        else:
            print_check("Sin Host header injection", ok=True)

        return findings
