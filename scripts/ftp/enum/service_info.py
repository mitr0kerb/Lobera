# scripts/ftp/enum/service_info.py
import ftplib
from scripts.base import BaseScript
from core.output import print_result, print_table, print_check, console
from core import session_db

class Script(BaseScript):
    name        = "service-info"
    protocol    = "ftp"
    category    = "enum"
    description = "Enumera información del servicio FTP: SYST, FEAT, modo pasivo/activo, encoding y capacidades del servidor."

    def run(self, **kwargs):
        port     = int(kwargs.get("port") or 21)
        timeout  = int(kwargs.get("timeout") or self.target.timeout or 5)
        user     = kwargs.get("user") or self.creds.user or "anonymous"
        password = kwargs.get("password") or self.creds.password or "anonymous@"
        ip       = self.target.ip

        try:
            ftp = ftplib.FTP()
            ftp.connect(ip, port, timeout)
            try:
                ftp.login(user, password)
            except ftplib.error_perm:
                print_result("FTP", ip, "fail", f"no se pudo autenticar como '{user}'")
                return None

            info = {}

            try:
                info["SYST"] = ftp.sendcmd("SYST")
            except Exception:
                info["SYST"] = "No soportado"

            features = []
            try:
                feat_resp = ftp.sendcmd("FEAT")
                features  = [l.strip() for l in feat_resp.splitlines()[1:]
                              if l.strip() and l.strip() != "END"]
                info["FEAT"] = ", ".join(features) if features else "No soportado"
            except Exception:
                info["FEAT"] = "No soportado"

            try:
                info["CWD"] = ftp.pwd()
            except Exception:
                info["CWD"] = "?"

            try:
                ftp.set_pasv(True)
                ftp.nlst()
                info["Passive mode"] = "Soportado"
            except Exception:
                info["Passive mode"] = "No disponible"

            try:
                ftp.sendcmd("AUTH TLS")
                info["FTPS/TLS"] = "Soportado (AUTH TLS)"
            except ftplib.error_perm as e:
                info["FTPS/TLS"] = "No soportado" if ("530" in str(e) or "500" in str(e)) else "Posiblemente soportado"
            except Exception:
                info["FTPS/TLS"] = "Desconocido"

            ftp.quit()

            rows = [(k, v) for k, v in info.items()]
            print_table(f"Info del servicio FTP — {ip}:{port}", ["Parámetro", "Valor"], rows)

            if features:
                print_table(f"Capacidades (FEAT) — {ip}:{port}",
                            ["Feature"], [(f,) for f in features[:20]])

            session_db.save_finding(ip, "FTP", "service_info", str(info))

            if "AUTH TLS" not in str(info.get("FTPS/TLS", "")):
                print_check("FTP sin cifrado TLS — credenciales en claro", ok=False)
                session_db.save_finding(ip, "FTP", "no_tls", f"port={port}")

            return info

        except Exception as e:
            print_result("FTP", ip, "fail", f"error: {e}")
            return None
