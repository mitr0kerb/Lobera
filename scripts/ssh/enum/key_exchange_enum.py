# scripts/ssh/enum/key_exchange_enum.py
import socket
import paramiko
from scripts.base import BaseScript
from core.output import print_result, print_table, print_check, console
from core import session_db

WEAK_KEX     = {"diffie-hellman-group1-sha1","diffie-hellman-group14-sha1","ecdh-sha2-nistp256"}
WEAK_CIPHERS = {"arcfour","arcfour128","arcfour256","3des-cbc","blowfish-cbc","cast128-cbc"}
WEAK_MACS    = {"hmac-md5","hmac-sha1","hmac-md5-96","hmac-sha1-96"}

class Script(BaseScript):
    name        = "key-exchange-enum"
    protocol    = "ssh"
    category    = "enum"
    description = "Enumera algoritmos KEX, ciphers y MACs del servidor. Detecta algoritmos débiles."

    EXAMPLES = [
        {"flag": "-t", "desc": "IP objetivo",
         "good": "ssh --script=key-exchange-enum -t 10.10.10.5",
         "bad":  "ssh --script=key-exchange-enum (sin -t)"},
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
            kex     = list(t._preferred_kex or [])
            ciphers = list(t._preferred_ciphers or [])
            macs    = list(t._preferred_macs or [])
            try: t.close(); sock.close()
            except Exception: pass
        except Exception as e:
            print_result("SSH", ip, "fail", f"error enumerando capacidades: {e}")
            return None

        print_result("SSH", ip, "info", f"versión: {server_version}")

        weak_kex_found    = [k for k in kex     if k in WEAK_KEX]
        weak_cipher_found = [c for c in ciphers if c in WEAK_CIPHERS]
        weak_mac_found    = [m for m in macs    if m in WEAK_MACS]

        kex_rows = [(k, "[red]DÉBIL[/red]" if k in WEAK_KEX else "[green]ok[/green]") for k in kex]
        if kex_rows:
            print_table(f"Algoritmos KEX — {ip}", ["Algoritmo", "Estado"], kex_rows)

        cipher_rows = [(c, "[red]DÉBIL[/red]" if c in WEAK_CIPHERS else "[green]ok[/green]") for c in ciphers]
        if cipher_rows:
            print_table(f"Ciphers — {ip}", ["Cipher", "Estado"], cipher_rows)

        mac_rows = [(m, "[red]DÉBIL[/red]" if m in WEAK_MACS else "[green]ok[/green]") for m in macs]
        if mac_rows:
            print_table(f"MACs — {ip}", ["MAC", "Estado"], mac_rows)

        if weak_kex_found:
            print_check(f"KEX débiles: {', '.join(weak_kex_found)}", ok=False)
            session_db.save_finding(ip, "SSH", "weak_kex", ", ".join(weak_kex_found))
        if weak_cipher_found:
            print_check(f"Ciphers débiles: {', '.join(weak_cipher_found)}", ok=False)
            session_db.save_finding(ip, "SSH", "weak_ciphers", ", ".join(weak_cipher_found))
        if weak_mac_found:
            print_check(f"MACs débiles: {', '.join(weak_mac_found)}", ok=False)
            session_db.save_finding(ip, "SSH", "weak_macs", ", ".join(weak_mac_found))
        if not weak_kex_found and not weak_cipher_found and not weak_mac_found:
            print_check("Sin algoritmos débiles detectados", ok=True)

        return {"kex": kex, "ciphers": ciphers, "macs": macs,
                "weak_kex": weak_kex_found, "weak_ciphers": weak_cipher_found,
                "weak_macs": weak_mac_found}
