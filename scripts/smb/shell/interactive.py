# scripts/smb/shell/interactive.py

from scripts.base import BaseScript
from modules.smb import SMBModule
from modules.smb_shell import SMBShell


class InteractiveShellScript(BaseScript):
    name = "interactive-shell"
    description = "Abre una consola interactiva SMB (shares, use, cd, ls, get...)"

    def run(self, **kwargs):
        # La shell interactiva necesita un timeout generoso: comandos como
        # 'get archivo_grande.zip' o 'ls C:\' pueden tardar minutos.
        # El timeout del objeto Target (default 5 s) es adecuado para
        # conexión y login, pero NO para operaciones de usuario arbitrarias.
        # Creamos una copia del target con timeout extendido solo para la shell.
        import dataclasses
        if hasattr(self.target, '__dataclass_fields__'):
            shell_target = dataclasses.replace(self.target, timeout=120)
        else:
            # Fallback: mutación directa de atributo (si Target no es dataclass)
            import copy as _copy
            shell_target = _copy.copy(self.target)
            shell_target.timeout = 120

        smb = SMBModule(shell_target, self.creds)
        if not smb.connect():
            return
        if not smb.login():
            return

        shell = SMBShell(smb)
        shell.run()
