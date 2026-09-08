# scripts/ssl/enum/cipher_enum.py
import ssl, socket
from scripts.base import BaseScript
from core.output import print_result, print_table, print_check, console
from core import session_db

WEAK_KEYWORDS = {"RC4","DES","3DES","EXPORT","NULL","anon","MD5","IDEA","SEED","PSK"}

class Script(BaseScript):
    name        = "cipher-enum"
    protocol    = "ssl"
    category    = "enum"
    description = "Enumera cipher suites soportadas y marca las débiles o inseguras."

    EXAMPLES = [
        {"flag": "-t / --port", "desc": "IP y puerto",
         "good": "ssl --script=cipher-enum -t 10.10.10.5 --port 443",
         "bad":  "ssl --script=cipher-enum (sin -t)"},
    ]

    def run(self, **kwargs):
        port    = int(kwargs.get("port") or 443)
        timeout = int(kwargs.get("timeout") or self.target.timeout or 5)
        ip      = self.target.ip

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            raw  = socket.create_connection((ip, port), timeout=timeout)
            conn = ctx.wrap_socket(raw, server_hostname=ip)
            negotiated = conn.cipher()
            shared     = conn.shared_ciphers() or []
            conn.close()
        except Exception as e:
            print_result("SSL", ip, "fail", f"error conectando: {e}")
            return None

        print_result("SSL", ip, "info",
                     f"cipher negociado: {negotiated[0] if negotiated else '?'} "
                     f"(bits: {negotiated[2] if negotiated and len(negotiated)>2 else '?'})")

        weak_found = []
        rows = []
        for cipher_info in shared:
            name = cipher_info[0] if cipher_info else "?"
            bits = cipher_info[2] if len(cipher_info) > 2 else "?"
            is_weak = any(kw.upper() in name.upper() for kw in WEAK_KEYWORDS)
            if is_weak:
                weak_found.append(name)
                status = "[bold red]DÉBIL[/bold red]"
            else:
                status = "[green]ok[/green]"
            rows.append((name, str(bits), status))

        if rows:
            print_table(f"Cipher suites — {ip}:{port}",
                        ["Cipher", "Bits", "Estado"], rows)

        if weak_found:
            print_result("SSL", ip, "pwned",
                         f"{len(weak_found)} cipher(s) débil(es) encontrado(s)")
            session_db.save_finding(ip, "SSL", "weak_ciphers", ", ".join(weak_found))
        else:
            print_check("Sin cipher suites débiles detectadas", ok=True)

        return {"negotiated": negotiated, "shared": shared, "weak": weak_found}
