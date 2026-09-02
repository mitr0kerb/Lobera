# scripts/ftp/enum/anon_check.py
import ftplib
from scripts.base import BaseScript
from core.output import print_result, print_table, print_check, console
from core import session_db

class Script(BaseScript):
    name        = "anon-check"
    protocol    = "ftp"
    category    = "enum"
    description = "Comprueba si el servidor FTP permite acceso anónimo. Prueba anonymous, ftp, guest. Lista directorio raíz y detecta escritura."

    ANON_CREDS = [
        ("anonymous", "anonymous@"),
        ("anonymous", ""),
        ("ftp",       "ftp"),
        ("ftp",       ""),
        ("guest",     ""),
    ]

    def run(self, **kwargs):
        port    = int(kwargs.get("port") or 21)
        timeout = int(kwargs.get("timeout") or self.target.timeout or 5)
        ip      = self.target.ip

        for user, pwd in self.ANON_CREDS:
            try:
                ftp = ftplib.FTP()
                ftp.connect(ip, port, timeout)
                ftp.login(user, pwd)

                entries = []
                try:
                    ftp.retrlines("LIST", entries.append)
                except Exception:
                    pass

                can_write = False
                try:
                    import io
                    ftp.storbinary("STOR lobera_anon_test.txt", io.BytesIO(b"lobera"))
                    ftp.delete("lobera_anon_test.txt")
                    can_write = True
                except Exception:
                    pass

                ftp.quit()

                print_result("FTP", ip, "pwned",
                             f"ACCESO ANÓNIMO PERMITIDO con '{user}' — "
                             f"{'ESCRITURA POSIBLE' if can_write else 'solo lectura'}")

                rows = [(e[:80],) for e in entries[:20]]
                if rows:
                    print_table(f"Directorio raíz — {ip}:{port}", ["Entrada"], rows)

                session_db.save_finding(ip, "FTP", "anon_access",
                                        f"user={user} write={can_write}")
                session_db.save_credential(ip, user, pwd, "ftp_anonymous",
                                           valid=True, source="ftp_anon_check")

                return {"user": user, "allowed": True, "can_write": can_write, "entries": entries}

            except ftplib.error_perm:
                continue
            except Exception:
                continue

        print_check("Acceso anónimo no permitido", ok=True)
        return {"allowed": False}
