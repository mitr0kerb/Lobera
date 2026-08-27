# core/kerberos_transport.py
#
# Capa de transporte Kerberos — envía y recibe mensajes crudos al puerto 88.
#
# Por qué TCP Y UDP:
#   - UDP (puerto 88): el cliente lo intenta primero. El mensaje viaja en
#     un único datagrama, sin handshake. Si la respuesta es demasiado grande
#     para caber en un UDP (>1500 bytes habitualmente), el KDC responde con
#     KRB-ERROR code 52 (KRB_ERR_RESPONSE_TOO_BIG) y el cliente debe
#     reintentar por TCP.
#   - TCP (puerto 88): siempre disponible en DCs modernos (desde Windows 2000 SP3).
#     Añade un prefijo de 4 bytes big-endian con la longitud total del mensaje
#     — esto NO existe en UDP, es solo una convención TCP de Kerberos (RFC 4120 §7.2.2).
#
# Por qué NO usamos impacket.krb5.kerberosv5 aquí:
#   El objetivo pedagógico es entender qué bytes viajan por el cable. Usamos
#   sockets crudos de la stdlib para el transporte, y pyasn1 para la
#   serialización. impacket lo hace todo opaco.

import socket
import struct

KRB_PORT = 88
DEFAULT_TIMEOUT = 5  # segundos


def _send_recv_tcp(host: str, data: bytes, timeout: int = DEFAULT_TIMEOUT) -> bytes:
    """
    Envía un mensaje Kerberos por TCP y devuelve la respuesta del KDC.

    Formato en wire (RFC 4120 §7.2.2):
        [4 bytes big-endian: longitud del payload] [payload ASN.1 DER]

    El KDC responde con el mismo framing: 4 bytes de longitud + payload.
    Leemos hasta que tenemos exactamente esos bytes.
    """
    # Prefijo de longitud TCP de Kerberos
    framed = struct.pack(">I", len(data)) + data

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect((host, KRB_PORT))
        sock.sendall(framed)

        # Leemos los primeros 4 bytes (longitud de la respuesta)
        raw_len = _recv_exactly(sock, 4)
        resp_len = struct.unpack(">I", raw_len)[0]

        # Leemos exactamente resp_len bytes
        return _recv_exactly(sock, resp_len)


def _recv_exactly(sock: socket.socket, n: int) -> bytes:
    """
    Lee exactamente n bytes de un socket. Kerberos sobre TCP no garantiza que
    el sistema operativo entregue todo de una vez (TCP es un stream, no un
    protocolo de mensajes) — hay que acumular en un buffer hasta tener todo.
    """
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(
                f"Conexión cerrada por el KDC tras recibir {len(buf)}/{n} bytes"
            )
        buf.extend(chunk)
    return bytes(buf)


def _send_recv_udp(host: str, data: bytes, timeout: int = DEFAULT_TIMEOUT) -> bytes:
    """
    Envía un mensaje Kerberos por UDP y devuelve la respuesta del KDC.

    En UDP NO hay prefijo de longitud — el datagrama es el mensaje completo.
    Si la respuesta es demasiado grande, el KDC responde KRB_ERR_RESPONSE_TOO_BIG
    (error code 52) y hay que reintentar por TCP.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(data, (host, KRB_PORT))
        # Tamaño máximo para un datagrama UDP Kerberos: 65535 bytes, pero en
        # la práctica los KDCs rechazan lo que supere el MTU (~1464 bytes útiles).
        response, _ = sock.recvfrom(65535)
        return response


def send_krb_message(
    host: str,
    data: bytes,
    prefer_tcp: bool = True,
    timeout: int = DEFAULT_TIMEOUT
) -> bytes:
    """
    Punto de entrada principal. Envía un mensaje Kerberos al KDC y devuelve
    la respuesta cruda (bytes ASN.1 DER sin framing TCP).

    prefer_tcp=True (default):
        Intenta TCP directamente. En entornos de laboratorio es más fiable
        que UDP y evita el problema de tamaño. Se puede forzar UDP con False.

    prefer_tcp=False:
        Intenta UDP primero. Si el KDC responde KRB_ERR_RESPONSE_TOO_BIG
        (error code 52), reintenta automáticamente por TCP.

    Lanza:
        socket.timeout: si el KDC no responde en 'timeout' segundos.
        ConnectionError: si el KDC cierra la conexión inesperadamente.
        OSError: para errores de red genéricos (host inalcanzable, etc.).
    """
    if prefer_tcp:
        return _send_recv_tcp(host, data, timeout)

    try:
        response = _send_recv_udp(host, data, timeout)

        # Detección rápida de KRB_ERR_RESPONSE_TOO_BIG:
        # Un KRB-ERROR tiene tag 0x7e (APPLICATION 30). Dentro, el error-code
        # es un INTEGER en el campo [6]. Error code 52 = 0x34.
        # Hacemos una detección heurística sin parsear ASN.1 completo aquí
        # para mantener el transporte independiente de pyasn1.
        if _is_response_too_big(response):
            return _send_recv_tcp(host, data, timeout)

        return response

    except socket.timeout:
        # UDP puede perder paquetes; fallback a TCP antes de propagar el error
        return _send_recv_tcp(host, data, timeout)


def _is_response_too_big(data: bytes) -> bool:
    """
    Detección heurística de KRB_ERR_RESPONSE_TOO_BIG (error code 52) en una
    respuesta KRB-ERROR recibida por UDP, sin parsear ASN.1 completo.

    KRB-ERROR ::= [APPLICATION 30] SEQUENCE { ... error-code [6] Int32 ... }

    El tag de APPLICATION 30 en BER/DER es 0x7e (01 11110 en binario):
        clase=APPLICATION (01), constructed=1, tag=30 (11110).
    Error code 52 decimal = 0x34.

    Esta búsqueda de bytes es frágil (podría dar falso positivo si 0x34 aparece
    en otro campo), pero es suficiente para el fallback de transporte. El parseo
    completo lo hace asn1_helpers.py sobre la respuesta final.
    """
    if not data or data[0] != 0x7e:
        return False
    return b'\x02\x01\x34' in data   # INTEGER value 52 (0x34) en DER


def check_kdc_reachable(host: str, timeout: int = 3) -> bool:
    """
    Comprobación rápida de conectividad al KDC (puerto 88 TCP).
    No envía ningún mensaje Kerberos, solo verifica que el puerto está abierto.
    Útil para dar un error claro antes de intentar un AS-REQ.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, KRB_PORT))
            return True
    except (socket.timeout, OSError):
        return False
