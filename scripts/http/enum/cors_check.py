# scripts/http/enum/cors_check.py
import urllib.request, urllib.error
from scripts.base import BaseScript
from core.output import print_result, print_table, print_check, console
from core import session_db

EVIL_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "null",
    "https://evil.target.com",
]

class Script(BaseScript):
    name        = "cors-check"
    protocol    = "http"
    category    = "enum"
    description = "Detecta CORS misconfiguration: origins arbitrarios, null origin, credenciales con wildcard."

    EXAMPLES = [
        {"flag": "-t / --port", "desc": "IP y puerto",
         "good": "http --script=cors-check -t 10.10.10.5 --port 80",
         "bad":  "http --script=cors-check (sin -t)"},
    ]

    def run(self, **kwargs):
        port    = int(kwargs.get("port") or 80)
        timeout = int(kwargs.get("timeout") or self.target.timeout or 5)
        path    = kwargs.get("path") or "/"
        ip      = self.target.ip
        url     = f"http://{ip}:{port}{path}"
        findings = []

        for origin in EVIL_ORIGINS:
            try:
                req = urllib.request.Request(url, headers={
                    "User-Agent": "Mozilla/5.0",
                    "Origin":     origin,
                    "Connection": "close",
                })
                try:
                    resp    = urllib.request.urlopen(req, timeout=timeout)
                    headers = {k.lower(): v for k, v in resp.headers.items()}
                except urllib.error.HTTPError as e:
                    headers = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}

                acao = headers.get("access-control-allow-origin", "")
                acac = headers.get("access-control-allow-credentials", "")

                if acao:
                    if acao == "*" and acac.lower() == "true":
                        findings.append(("CRÍTICO", origin, "Wildcard + credentials=true"))
                        session_db.save_finding(ip, "HTTP", "cors_wildcard_creds", f"port={port}")
                    elif acao == origin or acao == "*":
                        lvl = "ALTO" if acac.lower() == "true" else "MEDIO"
                        findings.append((lvl, origin, f"ACAO={acao} Creds={acac or 'false'}"))
                        session_db.save_finding(ip, "HTTP", "cors_misconfigured", f"origin={origin}")
                    elif origin == "null" and "null" in acao:
                        findings.append(("ALTO", origin, "Null origin aceptado"))
                        session_db.save_finding(ip, "HTTP", "cors_null_origin", f"port={port}")
            except Exception:
                pass

        if findings:
            print_table(f"CORS Misconfiguration — {ip}:{port}",
                        ["Severidad", "Origin", "Detalle"], findings)
            print_result("HTTP", ip, "pwned", f"CORS mal configurado — {len(findings)} problema(s)")
        else:
            print_check("CORS correctamente configurado", ok=True)

        return findings
