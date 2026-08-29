# scripts/ssh/enum/banner_grab.py
import socket
from scripts.base import BaseScript
from core.output import print_result, print_table, console
from core import session_db

class Script(BaseScript):
    name        = "banner-grab"
    protocol    = "ssh"
    category    = "enum"
    description = "Obtiene el banner SSH, versión del servidor y fingerprint del OS."

    EXAMPLES = [
        {"flag": "-t", "desc": "IP del objetivo",
         "good": "ssh --script=banner-grab -t 10.10.10.5",
         "bad":  "ssh --script=banner-grab (sin -t)"},
    ]

    def run(self, **kwargs):
        port    = int(kwargs.get("port") or 22)
        timeout = int(kwargs.get("timeout") or self.target.timeout or 5)
        ip      = self.target.ip

        try:
            sock   = socket.create_connection((ip, port), timeout=timeout)
            banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
            sock.close()
        except Exception as e:
            print_result("SSH", ip, "fail", f"no se pudo conectar al puerto {port}: {e}")
            return None

        parts  = banner.split("-", 2)
        proto  = parts[1] if len(parts) > 1 else "?"
        sw     = parts[2] if len(parts) > 2 else banner

        banner_lower = banner.lower()
        if "ubuntu" in banner_lower:    os_hint = "Ubuntu"
        elif "debian" in banner_lower:  os_hint = "Debian"
        elif "freebsd" in banner_lower: os_hint = "FreeBSD"
        elif "windows" in banner_lower: os_hint = "Windows"
        elif "openssh" in banner_lower: os_hint = "Linux/Unix (OpenSSH)"
        else:                           os_hint = "desconocido"

        print_result("SSH", ip, "info", f"banner: {banner}")

        rows = [
            ("Banner completo",  banner),
            ("Protocolo SSH",    proto),
            ("Software/versión", sw),
            ("OS fingerprint",   os_hint),
            ("Puerto",           str(port)),
        ]
        print_table(f"Banner SSH — {ip}", ["Campo", "Valor"], rows)

        session_db.save_finding(ip, "SSH", "banner",  banner)
        session_db.save_finding(ip, "SSH", "os_hint", os_hint)

        return {"banner": banner, "proto": proto, "software": sw, "os_hint": os_hint}
