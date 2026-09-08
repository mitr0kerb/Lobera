# scripts/ssl/enum/hsts_check.py
import ssl, socket
from scripts.base import BaseScript
from core.output import print_result, print_table, print_check, console
from core import session_db

class Script(BaseScript):
    name        = "hsts-check"
    protocol    = "ssl"
    category    = "enum"
    description = "Verifica la presencia y configuración correcta de HSTS."

    EXAMPLES = [
        {"flag": "-t / --port", "desc": "IP y puerto HTTPS",
         "good": "ssl --script=hsts-check -t 10.10.10.5 --port 443",
         "bad":  "ssl --script=hsts-check (sin -t)"},
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
            conn.send(f"GET / HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n".encode())
            response = b""
            conn.settimeout(5)
            try:
                while True:
                    chunk = conn.recv(4096)
                    if not chunk: break
                    response += chunk
                    if b"\r\n\r\n" in response: break
            except Exception:
                pass
            conn.close()
        except Exception as e:
            print_result("SSL", ip, "fail", f"error: {e}")
            return None

        headers = {}
        try:
            header_section = response.split(b"\r\n\r\n")[0].decode("utf-8", errors="replace")
            for line in header_section.split("\r\n")[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
        except Exception:
            pass

        hsts_header = headers.get("strict-transport-security", "")
        has_hsts    = bool(hsts_header)
        max_age     = None
        include_sub = False
        preload     = False

        if hsts_header:
            for d in hsts_header.split(";"):
                d = d.strip().lower()
                if d.startswith("max-age="):
                    try: max_age = int(d.split("=")[1])
                    except Exception: pass
                elif d == "includesubdomains": include_sub = True
                elif d == "preload":           preload     = True

        rows = [
            ("HSTS presente",      "Sí" if has_hsts else "[bold red]NO[/bold red]"),
            ("Header completo",    hsts_header or "—"),
            ("max-age",            f"{max_age}s ({max_age//86400}d)" if max_age else "—"),
            ("includeSubDomains",  "Sí" if include_sub else "No"),
            ("preload",            "Sí" if preload else "No"),
        ]
        print_table(f"HSTS Check — {ip}:{port}", ["Check", "Valor"], rows)

        if not has_hsts:
            print_result("SSL", ip, "pwned", "HSTS no configurado — downgrade a HTTP posible")
            session_db.save_finding(ip, "SSL", "hsts_missing", f"{ip}:{port}")
        elif max_age and max_age < 31536000:
            print_check(f"HSTS max-age bajo ({max_age}s < 31536000s)", ok=False)
            session_db.save_finding(ip, "SSL", "hsts_low_maxage", str(max_age))
        else:
            print_check("HSTS correctamente configurado", ok=True)

        return {"hsts": has_hsts, "max_age": max_age,
                "include_subdomains": include_sub, "preload": preload}
