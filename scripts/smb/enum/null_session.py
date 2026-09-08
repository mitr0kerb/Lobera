# scripts/smb/enum/null_session.py

from scripts.base import BaseScript
from modules.smb import SMBModule


class NullSessionScript(BaseScript):
    name = "null-session"
    description = "Comprueba si el objetivo permite SMB null session (sin usar tus credenciales reales)"

    def run(self, **kwargs):
        smb = SMBModule(self.target, self.creds)
        if not smb.connect():
            return
        result = smb.is_null_session()
        smb.disconnect()
        return result
