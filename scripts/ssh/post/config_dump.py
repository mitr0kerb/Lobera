# scripts/ssh/post/config_dump.py
import paramiko
from scripts.base import BaseScript
from core.output import print_result, print_table, console
from core import session_db

SSHD_CONFIG_PATHS = [
    "/etc/ssh/sshd_config",
    "/etc/sshd_config",
    "/usr/local/etc/sshd_config",
]

INTERESTING_KEYS = {
    "PermitRootLogin", "PasswordAuthentication", "PubkeyAuthentication",
    "PermitEmptyPasswords", "AllowUsers", "DenyUsers", "AllowGroups",
    "DenyGroups", "Port", "ListenAddress", "Protocol", "AuthorizedKeysFile",
    "UsePAM", "X11Forwarding", "AllowTcpForwarding", "PermitTunnel",
    "MaxAuthTries", "LoginGraceTime",
}

class Script(BaseScript):
    name        = "config-dump"
    protocol    = "ssh"
    category    = "post"
    description = "Lee sshd_config via sesión autenticada y extrae configuración relevante de seguridad."

    EXAMPLES = [
        {"flag": "-u / -p", "desc": "Credenciales con acceso al sistema",
         "good": "ssh --script=config-dump -t 10.10.10.5 -u root -p Pass123!",
         "bad":  "ssh --script=config-dump -t 10.10.10.5 (sin credenciales)"},
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

        config_content = None
        for path in SSHD_CONFIG_PATHS:
            _, stdout, _ = client.exec_command(f"cat {path} 2>/dev/null")
            out = stdout.read().decode("utf-8", errors="replace")
            if out.strip():
                config_content = out
                print_result("SSH", ip, "info", f"config en {path}")
                break

        client.close()

        if not config_content:
            print_result("SSH", ip, "fail", "no se pudo leer sshd_config")
            return None

        findings = {}
        for line in config_content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) == 2 and parts[0] in INTERESTING_KEYS:
                findings[parts[0]] = parts[1]

        if findings:
            print_table(f"sshd_config — {ip}",
                        ["Directiva", "Valor"],
                        [(k, v) for k, v in sorted(findings.items())])

        if findings.get("PermitRootLogin", "").lower() == "yes":
            print_result("SSH", ip, "pwned", "PermitRootLogin = yes")
            session_db.save_finding(ip, "SSH", "permit_root_login", "yes")
        if findings.get("PermitEmptyPasswords", "").lower() == "yes":
            print_result("SSH", ip, "pwned", "PermitEmptyPasswords = yes")
            session_db.save_finding(ip, "SSH", "empty_passwords", "yes")
        if findings.get("X11Forwarding", "").lower() == "yes":
            print_result("SSH", ip, "info", "X11Forwarding = yes")

        return findings
