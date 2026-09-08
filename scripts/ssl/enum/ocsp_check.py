# scripts/ssl/enum/ocsp_check.py
import ssl, socket
from scripts.base import BaseScript
from core.output import print_result, print_table, console
from core import session_db

class Script(BaseScript):
    name        = "ocsp-check"
    protocol    = "ssl"
    category    = "enum"
    description = "Comprueba el estado de revocación del certificado via OCSP."

    EXAMPLES = [
        {"flag": "-t / --port", "desc": "IP y puerto SSL",
         "good": "ssl --script=ocsp-check -t 10.10.10.5 --port 443",
         "bad":  "ssl --script=ocsp-check (sin -t)"},
    ]

    def run(self, **kwargs):
        port    = int(kwargs.get("port") or 443)
        timeout = int(kwargs.get("timeout") or self.target.timeout or 5)
        sni     = kwargs.get("sni") or self.target.ip
        ip      = self.target.ip

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            raw  = socket.create_connection((ip, port), timeout=timeout)
            conn = ctx.wrap_socket(raw, server_hostname=sni)
            cert = conn.getpeercert()
            conn.close()
        except Exception as e:
            print_result("SSL", ip, "fail", f"error: {e}")
            return None

        ocsp_urls = list(cert.get("OCSP", []))

        if not ocsp_urls:
            print_result("SSL", ip, "info",
                         "El certificado no contiene información OCSP")
            return {"status": "no_ocsp"}

        print_result("SSL", ip, "info", f"OCSP URL: {ocsp_urls[0]}")

        rows = [
            ("OCSP URL",      ocsp_urls[0]),
            ("Stapling",      "Verificación via Python ssl no disponible directamente"),
        ]
        print_table(f"OCSP info — {ip}:{port}", ["Campo", "Valor"], rows)
        session_db.save_finding(ip, "SSL", "ocsp_url", ocsp_urls[0])
        return {"ocsp_url": ocsp_urls[0]}
