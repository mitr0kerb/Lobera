# scripts/ssl/attack/poodle.py
# CVE-2014-3566
import ssl, socket
from scripts.base import BaseScript
from core.output import print_result, print_table, print_check, console
from core import session_db

class Script(BaseScript):
    name        = "poodle"
    protocol    = "ssl"
    category    = "attack"
    description = "CVE-2014-3566 (POODLE): detecta si el servidor acepta SSLv3 (padding oracle sobre SSL 3.0 CBC)."

    EXAMPLES = [
        {"flag": "-t / --port", "desc": "IP y puerto SSL",
         "good": "ssl --script=poodle -t 10.10.10.5 --port 443",
         "bad":  "ssl --script=poodle (sin -t)"},
    ]

    def run(self, **kwargs):
        port    = int(kwargs.get("port") or 443)
        timeout = int(kwargs.get("timeout") or self.target.timeout or 5)
        ip      = self.target.ip

        print_result("SSL", ip, "info",
                     f"POODLE (CVE-2014-3566): comprobando SSLv3 en {ip}:{port}")

        sslv3_supported = False
        try:
            if hasattr(ssl, "PROTOCOL_SSLv3"):
                ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv3)
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                raw  = socket.create_connection((ip, port), timeout=timeout)
                conn = ctx.wrap_socket(raw, server_hostname=ip)
                conn.close()
                sslv3_supported = True
        except Exception:
            pass

        # TLS 1.0 check (POODLE-TLS variante)
        tls10_supported = False
        if hasattr(ssl.TLSVersion, "TLSv1"):
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname  = False
                ctx.verify_mode     = ssl.CERT_NONE
                ctx.minimum_version = ssl.TLSVersion.TLSv1
                ctx.maximum_version = ssl.TLSVersion.TLSv1
                raw  = socket.create_connection((ip, port), timeout=timeout)
                conn = ctx.wrap_socket(raw, server_hostname=ip)
                conn.close()
                tls10_supported = True
            except Exception:
                pass

        rows = [
            ("SSLv3 soportado",   "Sí" if sslv3_supported else "No"),
            ("TLS 1.0 soportado", "Sí" if tls10_supported else "No"),
            ("CVE",               "CVE-2014-3566 (POODLE)"),
            ("Mitigación",        "Deshabilitar SSLv3 y TLS 1.0"),
        ]
        print_table(f"POODLE Check — {ip}:{port}", ["Campo", "Valor"], rows)

        if sslv3_supported:
            print_result("SSL", ip, "pwned",
                         "VULNERABLE a CVE-2014-3566 (POODLE) — SSLv3 habilitado")
            session_db.save_finding(ip, "SSL", "poodle_cve_2014_3566", f"port={port}")
            return True
        elif tls10_supported:
            print_result("SSL", ip, "info",
                         "TLS 1.0 aceptado — posible POODLE-TLS si usa CBC")
            session_db.save_finding(ip, "SSL", "poodle_tls10", f"port={port}")
            return False
        else:
            print_check("No vulnerable a POODLE", ok=True)
            return False
