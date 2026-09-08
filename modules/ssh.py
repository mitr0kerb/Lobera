# modules/ssh.py

import os
import socket
import time
import threading
from typing import Optional

import paramiko
from paramiko.transport import Transport

from core.output import print_result, print_table, print_check, console
from core import session_db

PROTO = "SSH"


class SSHModule:
    def __init__(self, target, creds):
        self.target         = target
        self.creds          = creds
        self.client         = None
        self.transport      = None
        self.banner         = None
        self.server_version = None
        self._port          = 22

    def _proto(self):
        return PROTO

    def connect(self, port=22, timeout=None):
        self._port = port
        timeout    = timeout or self.target.timeout
        try:
            sock = socket.create_connection((self.target.ip, port), timeout=timeout)
            self.transport = Transport(sock)
            self.transport.start_client(timeout=timeout)
            self.banner         = self.transport.remote_version or ""
            self.server_version = self._parse_version(self.banner)
            session_db.save_target(self.target.ip, domain=self.target.domain)
            print_result(PROTO, self.target.ip, "ok",
                         f"conectado al puerto {port} — {self.banner}")
            return True
        except Exception as e:
            print_result(PROTO, self.target.ip, "fail",
                         f"no se pudo conectar al puerto {port}: {e}")
            self.transport = None
            return False

    def connect_client(self, port=22, timeout=None):
        self._port = port
        timeout    = timeout or self.target.timeout
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            kwargs = dict(
                hostname=self.target.ip,
                port=port,
                username=self.creds.user,
                timeout=timeout,
                allow_agent=False,
                look_for_keys=False,
            )
            if hasattr(self.creds, "key_path") and self.creds.key_path:
                kwargs["key_filename"] = self.creds.key_path
            else:
                kwargs["password"] = self.creds.password or ""
            self.client.connect(**kwargs)
            session_db.save_target(self.target.ip, domain=self.target.domain)
            print_result(PROTO, self.target.ip, "pwned",
                         f"login correcto como {self.creds.user}")
            return True
        except paramiko.AuthenticationException:
            print_result(PROTO, self.target.ip, "fail",
                         f"autenticación fallida para {self.creds.user}")
            return False
        except Exception as e:
            print_result(PROTO, self.target.ip, "fail", f"error de conexión: {e}")
            return False

    def disconnect(self):
        if self.client:
            try: self.client.close()
            except Exception: pass
            self.client = None
        if self.transport:
            try: self.transport.close()
            except Exception: pass
            self.transport = None

    def login(self, username=None, password=None, key_path=None):
        if self.transport is None:
            print_result(PROTO, self.target.ip, "fail",
                         "no hay transport activo, llama a connect() primero")
            return False
        username = username or self.creds.user or ""
        password = password or self.creds.password or ""
        key_path = key_path or getattr(self.creds, "key_path", None)
        try:
            if key_path and os.path.isfile(key_path):
                key = paramiko.RSAKey.from_private_key_file(key_path)
                self.transport.auth_publickey(username, key)
            else:
                self.transport.auth_password(username, password)
            session_db.save_credential(
                self.target.ip, username,
                key_path if key_path else password,
                "key" if key_path else "password",
                valid=True, source="ssh_login"
            )
            print_result(PROTO, self.target.ip, "pwned",
                         f"login correcto como {username}")
            return True
        except paramiko.AuthenticationException:
            print_result(PROTO, self.target.ip, "fail",
                         f"autenticación fallida para {username}")
            return False
        except Exception as e:
            print_result(PROTO, self.target.ip, "fail",
                         f"error de autenticación: {e}")
            return False

    def get_auth_methods(self, username=None):
        username = username or self.creds.user or "root"
        if self.transport is None:
            return []
        try:
            self.transport.auth_none(username)
        except paramiko.BadAuthenticationType as e:
            return e.allowed_types
        except Exception:
            pass
        return []

    def get_host_key(self):
        if self.transport is None:
            return None
        try:
            key          = self.transport.get_remote_server_key()
            fp           = key.get_fingerprint().hex()
            fp_formatted = ":".join(fp[i:i+2] for i in range(0, len(fp), 2))
            return {
                "type":        key.get_name(),
                "fingerprint": fp_formatted,
                "bits":        getattr(key, "_bits", "?"),
            }
        except Exception:
            return None

    def exec_command(self, command, timeout=10):
        if self.client is None:
            print_result(PROTO, self.target.ip, "fail",
                         "no hay sesión activa, llama a connect_client() primero")
            return None, None, None
        try:
            stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
            out = stdout.read().decode("utf-8", errors="replace").strip()
            err = stderr.read().decode("utf-8", errors="replace").strip()
            return out, err, stdout.channel.recv_exit_status()
        except Exception as e:
            print_result(PROTO, self.target.ip, "fail",
                         f"error ejecutando comando: {e}")
            return None, None, None

    def check_terrapin(self, port=22, timeout=5):
        vulnerable_ciphers  = {"chacha20-poly1305@openssh.com"}
        vulnerable_macs_etm = {
            "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com",
            "hmac-sha1-etm@openssh.com",     "hmac-md5-etm@openssh.com",
        }
        try:
            sock = socket.create_connection((self.target.ip, port), timeout=timeout)
            t    = Transport(sock)
            t.start_client(timeout=timeout)
            server_ciphers = set(t._preferred_ciphers or [])
            server_macs    = set(t._preferred_macs or [])
            server_version = t.remote_version or ""
            has_chacha     = bool(server_ciphers & vulnerable_ciphers)
            has_etm        = bool(server_macs & vulnerable_macs_etm)
            has_strict     = "strict" in server_version.lower()
            t.close(); sock.close()
            return {
                "chacha20_available": has_chacha,
                "etm_available":      has_etm,
                "strict_kex":         has_strict,
                "vulnerable":         (has_chacha or has_etm) and not has_strict,
                "server_version":     server_version,
            }
        except Exception as e:
            return {"error": str(e), "vulnerable": False}

    @staticmethod
    def _parse_version(banner):
        if not banner:
            return "desconocido"
        parts = banner.split("_")
        if len(parts) >= 2:
            return parts[1].split(" ")[0]
        return banner
