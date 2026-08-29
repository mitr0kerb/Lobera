# scripts/ssh/enum/terrapin_check.py
# CVE-2023-48795
import socket
import paramiko
from scripts.base import BaseScript
from core.output import print_result, print_table, print_check, console
from core import session_db

CHACHA_CIPHER = "chacha20-poly1305@openssh.com"
ETM_MACS = {
    "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com",
    "hmac-sha-256-etm@openssh.com",  "hmac-md5-etm@openssh.com",
    "hmac-sha1-etm@openssh.com",     "hmac-ripemd160-etm@openssh.com",
    "umac-64-etm@openssh.com",       "umac-128-etm@openssh.com",
}

class Script(BaseScript):
    name        = "terrapin-check"
    protocol    = "ssh"
    category    = "enum"
    description = "CVE-2023-48795: detecta si el servidor es vulnerable al ataque Terrapin (prefix truncation SSH)."

    EXAMPLES = [
        {"flag": "-t", "desc": "IP objetivo",
         "good": "ssh --script=terrapin-check -t 10.10.10.5",
         "bad":  "ssh --script=terrapin-check (sin -t)"},
    ]

    def run(self, **kwargs):
        port    = int(kwargs.get("port") or 22)
        timeout = int(kwargs.get("timeout") or self.target.timeout or 5)
        ip      = self.target.ip

        try:
            sock = socket.create_connection((ip, port), timeout=timeout)
            t    = paramiko.Transport(sock)
            t.start_client(timeout=timeout)
            server_version = t.remote_version or ""
            ciphers        = set(t._preferred_ciphers or [])
            macs           = set(t._preferred_macs or [])
            try: t.close(); sock.close()
            except Exception: pass
        except Exception as e:
            print_result("SSH", ip, "fail", f"error conectando: {e}")
            return None

        has_chacha  = CHACHA_CIPHER in ciphers
        has_etm     = bool(macs & ETM_MACS)
        has_strict  = "strict" in server_version.lower()
        vulnerable  = (has_chacha or has_etm) and not has_strict
        etm_found   = list(macs & ETM_MACS)

        rows = [
            ("Versión servidor",         server_version),
            ("ChaCha20-Poly1305 activo", "Sí" if has_chacha else "No"),
            ("CBC+ETM activo",           "Sí" if has_etm else "No"),
            ("Strict KEX mitigación",    "Sí" if has_strict else "No"),
            ("Vulnerable a Terrapin",    "[bold red]SÍ[/bold red]" if vulnerable else "[green]NO[/green]"),
        ]
        print_table(f"Terrapin Check (CVE-2023-48795) — {ip}",
                    ["Check", "Resultado"], rows)

        if etm_found:
            print_result("SSH", ip, "info",
                         f"MACs ETM disponibles: {', '.join(etm_found)}")

        if vulnerable:
            print_result("SSH", ip, "pwned",
                         "VULNERABLE a Terrapin — downgrade de extensiones posible")
            session_db.save_finding(ip, "SSH", "terrapin_vulnerable",
                                    f"chacha20={has_chacha} etm={has_etm}")
        else:
            print_check("No vulnerable a Terrapin o mitigado con strict-kex", ok=True)

        return {"vulnerable": vulnerable, "has_chacha": has_chacha,
                "has_etm": has_etm, "has_strict_kex": has_strict}
