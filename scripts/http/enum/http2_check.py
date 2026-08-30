# scripts/http/enum/http2_check.py
import ssl, socket, urllib.request, urllib.error
from scripts.base import BaseScript
from core.output import print_result, print_table, print_check, console
from core import session_db

class Script(BaseScript):
    name        = "http2-check"
    protocol    = "http"
    category    = "enum"
    description = "Script propio: detecta HTTP/2 y HTTP/3 via ALPN. Comprueba h2c cleartext upgrade inseguro."

    EXAMPLES = [
        {"flag": "-t / --port", "desc": "IP y puerto",
         "good": "http --script=http2-check -t 10.10.10.5 --port 443",
         "bad":  "http --script=http2-check -t 10.10.10.5 --port 80 (h2 requiere TLS)"},
    ]

    def run(self, **kwargs):
        port    = int(kwargs.get("port") or 80)
        timeout = int(kwargs.get("timeout") or self.target.timeout or 5)
        ip      = self.target.ip
        results = {}

        for alpn_proto, label in [("h2","HTTP/2"),("h3","HTTP/3 (QUIC)")]:
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                ctx.set_alpn_protocols([alpn_proto, "http/1.1"])
                raw  = socket.create_connection((ip, port), timeout=timeout)
                conn = ctx.wrap_socket(raw, server_hostname=ip)
                negotiated = conn.selected_alpn_protocol()
                conn.close()
                results[label] = negotiated == alpn_proto
            except Exception:
                results[label] = False

        h2c = False
        try:
            req = urllib.request.Request(f"http://{ip}:{port}/", headers={
                "User-Agent": "Mozilla/5.0",
                "Connection": "Upgrade, HTTP2-Settings",
                "Upgrade":    "h2c",
                "HTTP2-Settings": "AAMAAABkAAQAAP__",
            })
            try:
                resp = urllib.request.urlopen(req, timeout=timeout)
                if resp.status == 101: h2c = True
            except urllib.error.HTTPError as e:
                if e.code == 101: h2c = True
        except Exception:
            pass

        results["HTTP/2 Cleartext (h2c)"] = h2c

        rows = [(proto, "Sí" if v else "No") for proto, v in results.items() if isinstance(v, bool)]
        if rows:
            print_table(f"HTTP/2 + HTTP/3 — {ip}:{port}", ["Protocolo", "Soportado"], rows)

        if results.get("HTTP/2"):
            print_result("HTTP", ip, "info", "HTTP/2 soportado")
            session_db.save_finding(ip, "HTTP", "http2_supported", f"port={port}")

        if h2c:
            print_result("HTTP", ip, "pwned", "h2c cleartext soportado — upgrade sin TLS")
            session_db.save_finding(ip, "HTTP", "h2c_supported", f"port={port}")
        else:
            print_check("h2c no soportado", ok=True)

        return results
