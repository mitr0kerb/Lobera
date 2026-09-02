# scripts/ftp/enum/list_files.py
import ftplib
import os
from scripts.base import BaseScript
from core.output import print_result, print_table, console
from core import session_db

INTERESTING_EXTENSIONS = {
    ".conf", ".cfg", ".config", ".ini", ".env", ".bak", ".backup",
    ".sql", ".db", ".sqlite", ".dump", ".tar", ".gz", ".zip",
    ".key", ".pem", ".crt", ".p12", ".pfx", ".passwd", ".shadow",
    ".htpasswd", ".log", ".txt", ".xml", ".json", ".yaml", ".yml",
}

INTERESTING_NAMES = {
    "passwd", "shadow", "config", "backup", "database", "dump",
    "admin", "credentials", "secret", "private", "key", "token",
    "id_rsa", "authorized_keys", "wp-config", ".env", ".htpasswd",
}

class Script(BaseScript):
    name        = "list-files"
    protocol    = "ftp"
    category    = "enum"
    description = "Lista recursivamente ficheros del servidor FTP. Detecta configs, backups, claves, dumps de BD y otros ficheros sensibles."

    def run(self, **kwargs):
        port      = int(kwargs.get("port") or 21)
        timeout   = int(kwargs.get("timeout") or self.target.timeout or 5)
        user      = kwargs.get("user") or self.creds.user or "anonymous"
        password  = kwargs.get("password") or self.creds.password or "anonymous@"
        path      = kwargs.get("path") or "/"
        max_depth = int(kwargs.get("max_depth") or 3)
        ip        = self.target.ip

        try:
            ftp = ftplib.FTP()
            ftp.connect(ip, port, timeout)
            ftp.login(user, password)
        except Exception as e:
            print_result("FTP", ip, "fail", f"no se pudo autenticar: {e}")
            return None

        interesting = []
        all_files   = []

        def _recurse(current_path, depth):
            if depth > max_depth:
                return
            try:
                entries = []
                ftp.cwd(current_path)
                ftp.retrlines("LIST", entries.append)
                for entry in entries:
                    parts = entry.split(None, 8)
                    if len(parts) < 9:
                        continue
                    perms    = parts[0]
                    fname    = parts[8]
                    is_dir   = perms.startswith("d")
                    fpath    = f"{current_path.rstrip('/')}/{fname}"
                    all_files.append(fpath)

                    fname_lower = fname.lower()
                    ext         = os.path.splitext(fname_lower)[1]
                    if (ext in INTERESTING_EXTENSIONS or
                            any(kw in fname_lower for kw in INTERESTING_NAMES)):
                        interesting.append((fpath, "DIR" if is_dir else "FILE"))
                        print_result("FTP", ip, "pwned", f"fichero sensible: {fpath}")
                        session_db.save_finding(ip, "FTP", "sensitive_file", fpath)

                    if is_dir and depth < max_depth:
                        try:
                            _recurse(fpath, depth + 1)
                        except Exception:
                            pass
            except Exception:
                pass

        _recurse(path, 0)

        try:
            ftp.quit()
        except Exception:
            pass

        print_result("FTP", ip, "info",
                     f"list-files: {len(all_files)} ficheros, {len(interesting)} sensibles")

        if interesting:
            print_table(f"Ficheros sensibles — {ip}:{port}",
                        ["Ruta", "Tipo"], interesting[:30])

        return {"all_files": all_files, "interesting": interesting}
