# scripts/smb/enum/signing.py

from scripts.base import BaseScript
from modules.smb import SMBModule


class SigningCheckScript(BaseScript):
    name = "signing-check"
    description = "Comprueba si el objetivo exige SMB signing (no requiere credenciales)"

    def run(self, **kwargs):
        smb = SMBModule(self.target, self.creds)
        if not smb.connect():
            return
        result = smb.check_signing()
        smb.disconnect()
        return result
