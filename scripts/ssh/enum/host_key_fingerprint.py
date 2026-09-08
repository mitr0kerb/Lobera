# scripts/ssh/enum/host_key_fingerprint.py
import socket
import hashlib
import base64
import paramiko
from scripts.base import BaseScript
from core.output import print_result, print_table, print_check, console
from core import session_db

KNOWN_BAD_FINGERPRINTS = {
    "96:a9:49:97:cd:3f:e3:1e:e8:ac:42:a7:5e:1a:54:58",
    "dd:3b:b8:2e:85:04:06:e9:ab:ff:a8:d1:08:94:e0:5b",
}

class Script(BaseScript):
    name        = "host-key-fingerprint"
    protocol    = "ssh"
    category    = "enum"
    description = "Extrae el host key del servidor SSH y compara contra fingerprints conocidos (honeypots, defaults)."

    EXAMPLES = [
        {"flag": "-t", "desc": "IP objetivo",
         "good": "ssh --script=host-key-fingerprint -t 10.10.10.5",
         "bad":  "ssh --script=host-key-fingerprint (sin -t)"},
    ]

    def run(self, **kwargs):
        port    = int(kwargs.get("port") or 22)
        timeout = int(kwargs.get("timeout") or self.target.timeout or 5)
        ip      = self.target.ip

        try:
            sock = socket.create_connection((ip, port), timeout=timeout)
            t    = paramiko.Transport(sock)
            t.start_client(timeout=timeout)
            key  = t.get_remote_server_key()
            try: t.close(); sock.close()
            except Exception: pass
        except Exception as e:
            print_result("SSH", ip, "fail", f"error obteniendo host key: {e}")
            return None

        key_type = key.get_name()
        md5_raw  = hashlib.md5(key.asbytes()).hexdigest()
        md5_fp   = ":".join(md5_raw[i:i+2] for i in range(0, len(md5_raw), 2))
        sha256_raw = hashlib.sha256(key.asbytes()).digest()
        sha256_fp  = "SHA256:" + base64.b64encode(sha256_raw).decode().rstrip("=")
        bits       = getattr(key, "_bits", "?")

        rows = [
            ("Tipo",              key_type),
            ("Bits",              str(bits)),
            ("MD5 fingerprint",   md5_fp),
            ("SHA256 fingerprint",sha256_fp),
        ]
        print_table(f"Host key — {ip}", ["Campo", "Valor"], rows)

        if md5_fp in KNOWN_BAD_FINGERPRINTS:
            print_result("SSH", ip, "pwned",
                         f"HONEYPOT detectado — fingerprint {md5_fp}")
            session_db.save_finding(ip, "SSH", "honeypot_detected", md5_fp)
        else:
            print_check("Fingerprint no coincide con honeypots conocidos", ok=True)

        session_db.save_finding(ip, "SSH", "host_key_fingerprint",
                                f"{key_type} {sha256_fp}")
        return {"type": key_type, "bits": bits, "md5": md5_fp, "sha256": sha256_fp}
