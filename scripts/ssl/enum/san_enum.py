# scripts/ssl/enum/san_enum.py
import ssl, socket
from scripts.base import BaseScript
from core.output import print_result, print_table, console
from core import session_db

class Script(BaseScript):
    name        = "san-enum"
    protocol    = "ssl"
    category    = "enum"
    description = "Extrae todos los SANs del certificado. Descubre subdominios y hosts relacionados."

    EXAMPLES = [
        {"flag": "-t / --port", "desc": "IP y puerto",
         "good": "ssl --script=san-enum -t 10.10.10.5 --port 443",
         "bad":  "ssl --script=san-enum (sin -t)"},
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

        san_list = [(t, v) for t, v in cert.get("subjectAltName", [])]
        dns_sans = [v for t, v in san_list if t == "DNS"]
        ip_sans  = [v for t, v in san_list if t == "IP Address"]

        if not san_list:
            print_result("SSL", ip, "info", "No se encontraron SANs")
            return []

        print_table(f"Subject Alternative Names — {ip}:{port}",
                    ["Tipo", "Valor"], [(t, v) for t, v in san_list])

        print_result("SSL", ip, "info",
                     f"{len(dns_sans)} DNS SAN(s), {len(ip_sans)} IP SAN(s)")

        wildcards = [s for s in dns_sans if s.startswith("*")]
        if wildcards:
            print_result("SSL", ip, "info",
                         f"Wildcards: {', '.join(wildcards)}")

        for v in dns_sans: session_db.save_finding(ip, "SSL", "san_dns", v)
        for v in ip_sans:  session_db.save_finding(ip, "SSL", "san_ip",  v)

        return san_list
