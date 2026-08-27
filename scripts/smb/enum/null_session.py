# scripts/smb/enum/null_session.py

from scripts.base import BaseScript
from modules.smb import SMBModule


class NullSessionScript(BaseScript):
    name = "null-session"
    description = "Comprueba si el objetivo permite autenticación null session"

    examples = [
        {"flag": "(uso básico)",
         "desc": "No usa tus credenciales reales aunque se pasen con -u/-p",
         "good": "smb --script=null-session -t 10.129.1.5",
         "bad": "smb --script=null-session -t 10.129.1.5 -u admin -p 'RealPass!'  [-u/-p se ignoran, son redundantes aquí]"},
    ]

    def run(self, **kwargs):
        smb = SMBModule(self.target, self.creds)
        if not smb.connect():
            return
        smb.is_null_session()
