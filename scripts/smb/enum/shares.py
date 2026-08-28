# scripts/smb/enum/shares.py

from scripts.base import BaseScript
from modules.smb import SMBModule


class SharesScript(BaseScript):
    name = "shares"
    description = "Lista los shares SMB disponibles (requiere login)"

    examples = [
        {"flag": "-u / --user",
         "desc": "Usuario para login. Sin él, se intenta null session",
         "good": "smb --script=shares -t 10.129.1.5 -u iker -p 'Pass123!'",
         "bad": "smb --script=shares -t 10.129.1.5  [sin -u, null session puede dar Access Denied]"},
        {"flag": "-H / --hash",
         "desc": "Pass-the-hash en vez de contraseña",
         "good": "smb --script=shares -t 10.129.1.5 -u administrator -H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c",
         "bad": "smb --script=shares -t 10.129.1.5 -H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c  [sin -u, no se sabe que usuario autenticar]"},
    ]

    def run(self, **kwargs):
        smb = SMBModule(self.target, self.creds)
        if not smb.connect():
            return
        if not smb.login():
            return
        results = smb.list_shares()
        smb.disconnect()
        return results
