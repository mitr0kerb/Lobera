# scripts/smb/enum/signing.py

from scripts.base import BaseScript
from modules.smb import SMBModule


class SigningScript(BaseScript):
    name = "signing-check"
    description = "Comprueba si el objetivo exige SMB signing (vulnerable a NTLM relay si no lo exige)"

    examples = [
        {"flag": "(uso básico)",
         "desc": "Chequeo de solo lectura, no necesita credenciales",
         "good": "smb --script=signing-check -t 10.129.1.5",
         "bad": "smb --script=signing-check -t 10.129.1.5 -u iker -p 'Pass123!'  [credenciales innecesarias, mas ruido en logs]"},
    ]

    def run(self, **kwargs):
        smb = SMBModule(self.target, self.creds)
        if not smb.connect():
            return
        smb.check_signing()
