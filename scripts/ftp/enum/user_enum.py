# scripts/ftp/enum/user_enum.py
import ftplib
import socket
import time
from scripts.base import BaseScript
from core.output import print_result, print_table, print_check, console
from core import session_db

DEFAULT_USERS = [
    "admin", "administrator", "root", "ftp", "ftpuser", "user",
    "test", "backup", "upload", "anonymous", "guest", "support",
    "www", "web", "data", "share", "transfer", "sftp",
]

class Script(BaseScript):
    name        = "user-enum"
    protocol    = "ftp"
    category    = "enum"
    description = "Script propio: enumera usuarios FTP válidos via análisis de respuestas diferenciales al comando USER."

    def run(self, **kwargs):
        port     = int(kwargs.get("port") or 21)
        timeout  = int(kwargs.get("timeout") or self.target.timeout or 5)
        userlist = kwargs.get("userlist")
        ip       = self.target.ip

        users = list(DEFAULT_USERS)
        if userlist:
            try:
                with open(userlist) as f:
                    users = [l.strip() for l in f if l.strip()]
            except OSError as e:
                console.print(f"[red]No se pudo leer userlist: {e}[/red]")
                return None

        print_result("FTP", ip, "info",
                     f"user-enum: probando {len(users)} usuarios via respuesta diferencial")

        valid_users = []
        results     = []

        for user in users:
            try:
                sock = socket.create_connection((ip, port), timeout=timeout)
                sock.recv(1024)

                t_start = time.time()
                sock.send(f"USER {user}\r\n".encode())
                resp = sock.recv(1024).decode("utf-8", errors="replace").strip()
                t_elapsed = time.time() - t_start

                code = resp[:3] if resp else "???"
                sock.close()

                if code == "331":
                    valid_users.append(user)
                    results.append((user, code, f"{t_elapsed:.3f}s", "POSIBLE"))
                    session_db.save_finding(ip, "FTP", "ftp_user_enum", user)
                else:
                    results.append((user, code, f"{t_elapsed:.3f}s", "—"))

            except Exception:
                results.append((user, "ERR", "—", "—"))

        if results:
            print_table(f"FTP User Enumeration — {ip}:{port}",
                        ["Usuario", "Código", "Tiempo", "Estado"], results[:40])

        if valid_users:
            print_result("FTP", ip, "pwned",
                         f"user-enum: {len(valid_users)} usuario(s) probable(s): "
                         f"{', '.join(valid_users[:5])}")
        else:
            print_check("Sin usuarios confirmados por enumeración", ok=True)

        return {"valid_users": valid_users, "results": results}
