# scripts/ftp/attack/write_check.py
import ftplib
import io
from scripts.base import BaseScript
from core.output import print_result, print_table, print_check, console
from core import session_db

class Script(BaseScript):
    name        = "write-check"
    protocol    = "ftp"
    category    = "attack"
    description = "Script propio: comprueba permisos de escritura FTP en múltiples directorios. Detecta posibilidad de webshell upload."

    TEST_DIRS = ["/", "/pub", "/upload", "/incoming", "/files",
                 "/www", "/htdocs", "/var/www", "/home/ftp"]
    TEST_FILE = "lobera_write_test_7f3a.txt"
    TEST_DATA = b"lobera_write_test"

    def run(self, **kwargs):
        port     = int(kwargs.get("port") or 21)
        timeout  = int(kwargs.get("timeout") or self.target.timeout or 5)
        user     = kwargs.get("user") or self.creds.user or "anonymous"
        password = kwargs.get("password") or self.creds.password or "anonymous@"
        ip       = self.target.ip

        try:
            ftp = ftplib.FTP()
            ftp.connect(ip, port, timeout)
            ftp.login(user, password)
        except Exception as e:
            print_result("FTP", ip, "fail", f"no se pudo autenticar: {e}")
            return None

        writable = []

        for test_dir in self.TEST_DIRS:
            try:
                ftp.cwd(test_dir)
                ftp.storbinary(f"STOR {self.TEST_FILE}", io.BytesIO(self.TEST_DATA))
                try: ftp.delete(self.TEST_FILE)
                except Exception: pass
                writable.append(test_dir)
                print_result("FTP", ip, "pwned",
                             f"ESCRITURA POSIBLE en {test_dir} — webshell upload factible")
                session_db.save_finding(ip, "FTP", "writable_dir", test_dir)
            except ftplib.error_perm:
                pass
            except Exception:
                pass

        try: ftp.quit()
        except Exception: pass

        if writable:
            print_table(f"Directorios con escritura — {ip}:{port}",
                        ["Directorio"], [(d,) for d in writable])
        else:
            print_check("Sin permisos de escritura detectados", ok=True)

        return writable
