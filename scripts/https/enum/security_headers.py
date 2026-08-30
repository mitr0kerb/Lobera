# scripts/https/enum/security_headers.py
import ssl, urllib.request, urllib.error
from scripts.base import BaseScript
from core.output import print_result, print_table, print_check, console
from core import session_db

HEADERS_CONFIG = {
    "strict-transport-security": {
        "required": True, "desc": "HSTS",
        "check": lambda v: "max-age" in v and int(v.split("max-age=")[1].split(";")[0].strip()) >= 31536000,
        "recommendation": "max-age=31536000; includeSubDomains; preload",
    },
    "content-security-policy": {
        "required": True, "desc": "CSP — previene XSS",
        "check": lambda v: "default-src" in v or "script-src" in v,
        "recommendation": "default-src 'self'; script-src 'self'",
    },
    "x-frame-options": {
        "required": True, "desc": "Previene clickjacking",
        "check": lambda v: v.upper() in ("DENY","SAMEORIGIN"),
        "recommendation": "DENY o SAMEORIGIN",
    },
    "x-content-type-options": {
        "required": True, "desc": "Previene MIME sniffing",
        "check": lambda v: v.lower() == "nosniff",
        "recommendation": "nosniff",
    },
    "referrer-policy": {
        "required": False, "desc": "Controla Referer",
        "check": lambda v: v.lower() in ("no-referrer","strict-origin","strict-origin-when-cross-origin"),
        "recommendation": "strict-origin-when-cross-origin",
    },
    "permissions-policy": {
        "required": False, "desc": "Acceso a APIs del navegador",
        "check": lambda v: len(v) > 0,
        "recommendation": "camera=(), microphone=(), geolocation=()",
    },
    "cross-origin-opener-policy": {
        "required": False, "desc": "COOP — aislamiento de ventana",
        "check": lambda v: "same-origin" in v.lower(),
        "recommendation": "same-origin",
    },
}

DANGEROUS_CSP = ["unsafe-inline","unsafe-eval","unsafe-hashes","data:","*","http:"]

class Script(BaseScript):
    name        = "security-headers"
    protocol    = "https"
    category    = "enum"
    description = "Script propio: analiza CSP, HSTS, X-Frame, Permissions-Policy y más. Puntúa la postura de seguridad."

    EXAMPLES = [
        {"flag": "-t / --port", "desc": "IP y puerto HTTPS",
         "good": "https --script=security-headers -t 10.10.10.5 --port 443",
         "bad":  "https --script=security-headers (sin -t)"},
    ]

    def run(self, **kwargs):
        port    = int(kwargs.get("port") or 443)
        timeout = int(kwargs.get("timeout") or self.target.timeout or 5)
        ip      = self.target.ip
        url     = f"https://{ip}:{port}/"

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

        try:
            req    = urllib.request.Request(url, headers={"User-Agent":"Mozilla/5.0"})
            opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
            try:
                resp    = opener.open(req, timeout=timeout)
                headers = {k.lower(): v for k, v in resp.headers.items()}
            except urllib.error.HTTPError as e:
                headers = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
        except Exception as e:
            print_result("HTTPS", ip, "fail", f"error: {e}")
            return None

        score = 0; max_score = 0; rows = []; issues = []

        for header, config in HEADERS_CONFIG.items():
            value    = headers.get(header, "")
            required = config["required"]
            max_score += 2 if required else 1
            if not value:
                rows.append((header, "AUSENTE", config["recommendation"]))
                if required:
                    issues.append(f"FALTA {header}")
                    session_db.save_finding(ip, "HTTPS", "missing_security_header", header)
            else:
                try:
                    ok = config["check"](value)
                except Exception:
                    ok = True
                if ok:
                    score += 2 if required else 1
                    rows.append((header, "OK", value[:60]))
                else:
                    score += 1
                    rows.append((header, "MAL CONFIG", value[:60]))
                    issues.append(f"MAL: {header}")
                    session_db.save_finding(ip, "HTTPS", "misconfigured_header",
                                            f"{header}={value[:60]}")

        print_table(f"Security Headers — {ip}:{port}",
                    ["Header","Estado","Valor / Recomendación"], rows)

        csp = headers.get("content-security-policy","")
        if csp:
            dangerous = [d for d in DANGEROUS_CSP if d in csp]
            if dangerous:
                print_result("HTTPS", ip, "pwned", f"CSP peligrosa: {', '.join(dangerous)}")
                session_db.save_finding(ip, "HTTPS", "unsafe_csp", ", ".join(dangerous))

        pct   = int(score / max_score * 100) if max_score else 0
        grade = ("A+" if pct==100 else "A" if pct>=90 else "B" if pct>=75 else
                 "C" if pct>=60 else "D" if pct>=40 else "F")
        print_result("HTTPS", ip, "info",
                     f"Puntuación: {score}/{max_score} ({pct}%) — Grado: {grade}")
        session_db.save_finding(ip, "HTTPS", "security_headers_score", f"{pct}% grade={grade}")

        return {"score": pct, "grade": grade, "issues": issues}
