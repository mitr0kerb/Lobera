# modules/ftp.py
import ftplib
import socket
import time
import os

from core.output import print_result, print_table, print_check, console
from core import session_db

PROTO = "FTP"

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


class FTPModule:
    def __init__(self, target, creds):
        self.target  = target
        self.creds   = creds
        self._ftp    = None
        self._port   = 21
        self._banner = ""

    def _proto(self): return PROTO

    def connect(self, port=21, timeout=None):
        self._port = port
        timeout    = timeout or self.target.timeout or 5
        try:
            self._ftp = ftplib.FTP()
            self._ftp.connect(self.target.ip, port, timeout)
            self._banner = self._ftp.getwelcome()
            session_db.save_target(self.target.ip, domain=self.target.domain)
            print_result(PROTO, self.target.ip, "ok",
                         f"conectado al puerto {port} — {self._banner}")
            return True
        except Exception as e:
            print_result(PROTO, self.target.ip, "fail",
                         f"no se pudo conectar al puerto {port}: {e}")
            self._ftp = None
            return False

    def login(self, user=None, password=None):
        if self._ftp is None:
            print_result(PROTO, self.target.ip, "fail",
                         "no hay conexión activa, llama a connect() primero")
            return False
        user     = user or self.creds.user or "anonymous"
        password = password or self.creds.password or "anonymous@"
        try:
            self._ftp.login(user, password)
            session_db.save_credential(self.target.ip, user, password,
                                       "ftp_password", valid=True, source="ftp_login")
            print_result(PROTO, self.target.ip, "pwned",
                         f"login correcto como '{user}'")
            return True
        except ftplib.error_perm as e:
            print_result(PROTO, self.target.ip, "fail",
                         f"autenticación fallida para '{user}': {e}")
            return False
        except Exception as e:
            print_result(PROTO, self.target.ip, "fail",
                         f"error de login: {e}")
            return False

    def disconnect(self):
        if self._ftp:
            try: self._ftp.quit()
            except Exception: pass
            finally: self._ftp = None

    def list_dir(self, path="/"):
        if self._ftp is None:
            return []
        try:
            entries = []
            self._ftp.cwd(path)
            self._ftp.retrlines("LIST", entries.append)
            return entries
        except Exception as e:
            print_result(PROTO, self.target.ip, "fail",
                         f"error listando {path}: {e}")
            return []

    def list_mlsd(self, path="/"):
        if self._ftp is None:
            return []
        try:
            return list(self._ftp.mlsd(path))
        except Exception:
            return []

    def get_system_type(self):
        if self._ftp is None:
            return ""
        try:
            return self._ftp.sendcmd("SYST")
        except Exception:
            return ""

    def get_features(self):
        if self._ftp is None:
            return []
        try:
            resp = self._ftp.sendcmd("FEAT")
            return [line.strip() for line in resp.splitlines()[1:]]
        except Exception:
            return []

    def download_file(self, remote_path, local_path):
        if self._ftp is None:
            return False
        try:
            with open(local_path, "wb") as f:
                self._ftp.retrbinary(f"RETR {remote_path}", f.write)
            return True
        except Exception as e:
            print_result(PROTO, self.target.ip, "fail",
                         f"error descargando {remote_path}: {e}")
            return False

    def upload_file(self, local_path, remote_path):
        if self._ftp is None:
            return False
        try:
            with open(local_path, "rb") as f:
                self._ftp.storbinary(f"STOR {remote_path}", f)
            return True
        except Exception as e:
            print_result(PROTO, self.target.ip, "fail",
                         f"error subiendo {local_path}: {e}")
            return False

    def check_write(self, test_path="/lobera_write_test.txt"):
        if self._ftp is None:
            return False
        try:
            import io
            self._ftp.storbinary(f"STOR {test_path}", io.BytesIO(b"lobera_test"))
            self._ftp.delete(test_path)
            return True
        except Exception:
            return False

    def is_anonymous_allowed(self):
        try:
            tmp = ftplib.FTP()
            tmp.connect(self.target.ip, self._port,
                        self.target.timeout or 5)
            tmp.login("anonymous", "anonymous@")
            tmp.quit()
            return True
        except Exception:
            return False
