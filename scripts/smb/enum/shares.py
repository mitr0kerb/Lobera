# scripts/smb/enum/shares.py

from scripts.base import BaseScript
from modules.smb import SMBModule


class SharesScript(BaseScript):
    name = "shares"
    description = "Lista los shares disponibles en el objetivo (requiere login)"

    examples = [
        {"flag": "(uso básico)",
         "desc": "Requiere -u/-p o -H para login; sin credenciales hace null session",
         "good": "smb --script=shares -t 10.129.1.5 -u iker -p 'Pass123!'",
         "bad": "smb --script=shares -t 10.129.1.5  [sin -u, null session puede dar Access Denied]"},
    ]

    def run(self, **kwargs):
        smb = SMBModule(self.target, self.creds)
        if not smb.connect():
            return
        if not smb.login():
            return
        smb.list_shares()
