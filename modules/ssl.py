# modules/ssl.py

import ssl
import socket
import struct
import time
import hashlib
import base64
import datetime
from typing import Optional, List, Dict, Any

from core.output import print_result, print_table, print_check, console
from core import session_db

PROTO = "SSL"

WEAK_CIPHERS   = {"RC4","DES","3DES","EXPORT","NULL","anon","MD5","PSK","IDEA","SEED"}
WEAK_PROTOCOLS = {"SSLv2","SSLv3","TLSv1","TLSv1.1"}


class SSLModule:
    def __init__(self, target, creds=None):
        self.target  = target
        self.creds   = creds
        self.context = None
        self.conn    = None
        self.cert    = None
        self._port   = 443

    def _proto(self): return PROTO

    def connect(self, port=443, timeout=None, verify=False, sni=None):
        self._port = port
        timeout    = timeout or self.target.timeout or 5
        host       = sni or self.target.ip
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            raw       = socket.create_connection((self.target.ip, port), timeout=timeout)
            self.conn = ctx.wrap_socket(raw, server_hostname=host)
            self.context = ctx
            cipher = self.conn.cipher()
            ver    = self.conn.version()
            print_result(PROTO, self.target.ip, "ok",
                         f"TLS conectado al puerto {port} — {ver} / {cipher[0] if cipher else '?'}")
            session_db.save_target(self.target.ip, domain=self.target.domain)
            return True
        except ssl.SSLError as e:
            print_result(PROTO, self.target.ip, "fail", f"SSL error: {e}")
            return False
        except Exception as e:
            print_result(PROTO, self.target.ip, "fail", f"no se pudo conectar: {e}")
            return False

    def disconnect(self):
        if self.conn:
            try: self.conn.close()
            except Exception: pass
            self.conn = None

    def get_certificate(self, port=443, timeout=5, sni=None):
        host = sni or self.target.ip
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            raw  = socket.create_connection((self.target.ip, port), timeout=timeout)
            conn = ctx.wrap_socket(raw, server_hostname=host)
            cert_der  = conn.getpeercert(binary_form=True)
            cert_dict = conn.getpeercert()
            conn.close()
            return cert_dict, cert_der
        except Exception:
            return None, None

    def get_supported_protocols(self, port=443, timeout=5):
        protocols   = {}
        tls_versions = []
        if hasattr(ssl.TLSVersion, "TLSv1"):   tls_versions.append(("TLSv1.0",  ssl.TLSVersion.TLSv1))
        if hasattr(ssl.TLSVersion, "TLSv1_1"): tls_versions.append(("TLSv1.1",  ssl.TLSVersion.TLSv1_1))
        if hasattr(ssl.TLSVersion, "TLSv1_2"): tls_versions.append(("TLSv1.2",  ssl.TLSVersion.TLSv1_2))
        if hasattr(ssl.TLSVersion, "TLSv1_3"): tls_versions.append(("TLSv1.3",  ssl.TLSVersion.TLSv1_3))
        for ver_name, ver_val in tls_versions:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                ctx.minimum_version = ver_val
                ctx.maximum_version = ver_val
                raw  = socket.create_connection((self.target.ip, port), timeout=timeout)
                conn = ctx.wrap_socket(raw, server_hostname=self.target.ip)
                conn.close()
                protocols[ver_name] = True
            except Exception:
                protocols[ver_name] = False
        return protocols

    def get_cipher_list(self, port=443, timeout=5):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            raw  = socket.create_connection((self.target.ip, port), timeout=timeout)
            conn = ctx.wrap_socket(raw, server_hostname=self.target.ip)
            negotiated = conn.cipher()
            shared     = conn.shared_ciphers() or []
            conn.close()
            return negotiated, shared
        except Exception:
            return None, []

    def check_heartbleed(self, port=443, timeout=5):
        """CVE-2014-0160 — Heartbleed raw check."""
        try:
            sock = socket.create_connection((self.target.ip, port), timeout=timeout)
            hello_payload = bytes([
                0x03, 0x02,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00, 0x00,0x02, 0x00,0x2f, 0x01,0x00,
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
                sock.close(); return False
            hb = bytes([0x18,0x03,0x02,0x00,0x03,0x01,0x40,0x00])
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
            return bool(resp and resp[0:1] == b"\x18")
        except Exception:
            return False
