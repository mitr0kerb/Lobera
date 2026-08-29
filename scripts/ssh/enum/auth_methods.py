# scripts/ssh/enum/auth_methods.py
import paramiko
import socket
from scripts.base import BaseScript
from core.output import print_result, print_table, print_check, console
from core import session_db

WEAK_METHODS = {"password", "keyboard-interactive"}
DANGEROUS    = {"none"}

class Script(BaseScript):
    name        = "auth-methods"
    protocol    = "ssh"
    category    = "enum"
    description = "Enumera métodos de autenticación permitidos por el servidor para un usuario dado."

    EXAMPLES = [
        {"flag": "-u", "desc": "Usuario a probar (default: root)",
         "good": "ssh --script=auth-methods -t 10.10.10.5 -u admin",
         "bad":  "ssh --script=auth-methods -t 10.10.10.5"},
    ]

    def run(self, **kwargs):
        port     = int(kwargs.get("port") or 22)
        timeout  = int(kwargs.get("timeout") or self.target.timeout or 5)
        username = self.creds.user or kwargs.get("user") or "root"
        ip       = self.target.ip

        try:
            sock = socket.create_connection((ip, port), timeout=timeout)
            t    = paramiko.Transport(sock)
            t.start_client(timeout=timeout)
        except Exception as e:
            print_result("SSH", ip, "fail", f"no se pudo conectar: {e}")
            return None

        methods = []
        try:
            t.auth_none(username)
        except paramiko.BadAuthenticationType as e:
            methods = e.allowed_types
        except Exception:
            pass
        finally:
            try: t.close(); sock.close()
            except Exception: pass

        if not methods:
            print_result("SSH", ip, "info",
                         f"no se pudieron obtener métodos para '{username}'")
            return None

        rows = []
        for m in methods:
            risk = ("🔴 débil"    if m in WEAK_METHODS else
                    "⚠ peligroso" if m in DANGEROUS    else
                    "✓ normal")
            rows.append((m, risk))

        print_table(f"Métodos de auth para '{username}' en {ip}",
                    ["Método", "Valoración"], rows)

        if "password" in methods:
            print_check("Password auth habilitado → vulnerable a brute force", ok=False)
        if "none" in methods:
            print_result("SSH", ip, "pwned",
                         f"auth 'none' permitida para '{username}' — acceso sin credenciales")
            session_db.save_finding(ip, "SSH", "auth_none", f"usuario: {username}")

        session_db.save_finding(ip, "SSH", "auth_methods", ", ".join(methods))
        return methods
