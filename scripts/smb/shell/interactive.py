# scripts/smb/shell/interactive.py

from scripts.base import BaseScript
from modules.smb import SMBModule
from modules.smb_shell import SMBShell


class InteractiveShellScript(BaseScript):
    name = "interactive-shell"
    description = "Abre una consola interactiva SMB (shares, use, ls, cd, get...)"

    examples = [
        {"flag": "(uso básico)",
         "desc": "Necesita login real para tener permisos útiles en la shell",
         "good": "smb --script=interactive-shell -t 10.129.1.5 -u iker -p 'Summer2024!'",
         "bad": "smb --script=interactive-shell -t 10.129.1.5  [sin -u, entrarás con null session y la mayoría de comandos fallarán]"},
    ]

    def run(self, **kwargs):
        smb = SMBModule(self.target, self.creds)
        if not smb.connect():
            return
        if not smb.login():
            return
        shell = SMBShell(smb)
        shell.run()
