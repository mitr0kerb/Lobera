# scripts/ssl/enum/protocol_version.py
import ssl, socket
from scripts.base import BaseScript
from core.output import print_result, print_table, print_check, console
from core import session_db

DEPRECATED = {"TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2"}

class Script(BaseScript):
    name        = "protocol-version"
    protocol    = "ssl"
    category    = "enum"
    description = "Detecta qué versiones de SSL/TLS acepta el servidor. Alerta sobre versiones obsoletas y peligrosas."

    EXAMPLES = [
        {"flag": "-t / --port", "desc": "IP y puerto",
         "good": "ssl --script=protocol-version -t 10.10.10.5 --port 443",
         "bad":  "ssl --script=protocol-version (sin -t)"},
    ]

    def run(self, **kwargs):
        port    = int(kwargs.get("port") or 443)
        timeout = int(kwargs.get("timeout") or self.target.timeout or 5)
        ip      = self.target.ip

        tls_versions = []
        if hasattr(ssl.TLSVersion, "TLSv1"):   tls_versions.append(("TLSv1.0",  ssl.TLSVersion.TLSv1))
        if hasattr(ssl.TLSVersion, "TLSv1_1"): tls_versions.append(("TLSv1.1",  ssl.TLSVersion.TLSv1_1))
        if hasattr(ssl.TLSVersion, "TLSv1_2"): tls_versions.append(("TLSv1.2",  ssl.TLSVersion.TLSv1_2))
        if hasattr(ssl.TLSVersion, "TLSv1_3"): tls_versions.append(("TLSv1.3",  ssl.TLSVersion.TLSv1_3))

        results = {}
        for ver_name, ver_val in tls_versions:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname  = False
                ctx.verify_mode     = ssl.CERT_NONE
                ctx.minimum_version = ver_val
                ctx.maximum_version = ver_val
                raw  = socket.create_connection((ip, port), timeout=timeout)
                conn = ctx.wrap_socket(raw, server_hostname=ip)
                conn.close()
                results[ver_name] = True
            except Exception:
                results[ver_name] = False

        deprecated_found = []
        rows = []
        for ver, supported in results.items():
            if supported:
                status = "[bold red]DEPRECADO[/bold red]" if ver in DEPRECATED else "[green]ok[/green]"
                if ver in DEPRECATED:
                    deprecated_found.append(ver)
            else:
                status = "[dim]no soportado[/dim]"
            rows.append((ver, "Sí" if supported else "No", status))

        print_table(f"Versiones SSL/TLS — {ip}:{port}",
                    ["Versión", "Soportada", "Estado"], rows)

        if deprecated_found:
            print_result("SSL", ip, "pwned",
                         f"Versiones obsoletas habilitadas: {', '.join(deprecated_found)}")
            for v in deprecated_found:
                session_db.save_finding(ip, "SSL", "deprecated_protocol", v)
        else:
            print_check("Sin versiones obsoletas de SSL/TLS", ok=True)

        return results
