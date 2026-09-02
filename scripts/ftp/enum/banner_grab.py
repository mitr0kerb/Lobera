# scripts/ftp/enum/banner_grab.py
import socket
from scripts.base import BaseScript
from core.output import print_result, print_table, console
from core import session_db

class Script(BaseScript):
    name        = "banner-grab"
    protocol    = "ftp"
    category    = "enum"
    description = "Obtiene el banner FTP, versión del servidor y sistema operativo. Detecta vsftpd, ProFTPD, Pure-FTPd, IIS FTP y FileZilla."

    def run(self, **kwargs):
        port    = int(kwargs.get("port") or 21)
        timeout = int(kwargs.get("timeout") or self.target.timeout or 5)
        ip      = self.target.ip

        try:
            sock   = socket.create_connection((ip, port), timeout=timeout)
            banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
            sock.close()
        except Exception as e:
            print_result("FTP", ip, "fail", f"no se pudo conectar: {e}")
            return None

        banner_lower = banner.lower()
        if "vsftpd"    in banner or "vsftpd" in banner_lower:      sw = "vsftpd"
        elif "proftpd"  in banner_lower:                             sw = "ProFTPD"
        elif "pure-ftpd" in banner_lower:                            sw = "Pure-FTPd"
        elif "microsoft" in banner_lower or "iis" in banner_lower:  sw = "Microsoft IIS FTP"
        elif "filezilla" in banner_lower:                            sw = "FileZilla FTP"
        elif "wu-ftpd"  in banner_lower:                             sw = "WU-FTPd"
        elif "bftpd"    in banner_lower:                             sw = "bftpd"
        else:                                                        sw = "Desconocido"

        if "unix" in banner_lower or "linux" in banner_lower: os_hint = "Unix/Linux"
        elif "windows" in banner_lower:                         os_hint = "Windows"
        else:                                                   os_hint = "Desconocido"

        rows = [
            ("Banner completo",  banner[:100]),
            ("Software",         sw),
            ("OS fingerprint",   os_hint),
            ("Puerto",           str(port)),
        ]
        print_result("FTP", ip, "info", f"banner: {banner[:80]}")
        print_table(f"Banner FTP — {ip}:{port}", ["Campo", "Valor"], rows)

        session_db.save_finding(ip, "FTP", "banner", banner)
        session_db.save_finding(ip, "FTP", "software", sw)

        return {"banner": banner, "software": sw, "os_hint": os_hint}
