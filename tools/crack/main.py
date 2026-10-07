#!/usr/bin/env python3
# tools/crack/main.py
"""
lobera-crack — Cracker offline de hashes para entornos Windows/AD.

Formatos soportados:
  ntlm       — NT hash (32 hex) — SAM, NTDS, Pass-the-Hash
  netntlmv1  — NetNTLMv1 capturado con Responder
  netntlmv2  — NetNTLMv2 capturado con Responder
  krb5asrep  — Kerberos 5 AS-REP ($krb5asrep$) — AS-REP Roasting
  krb5tgs    — Kerberos 5 TGS  ($krb5tgs$)   — Kerberoasting

Motores:
  hashcat    — GPU/CPU vía hashcat (prioridad si está instalado)
  cpu        — Implementación Python pura (fallback sin dependencias)

Uso:
  lobera-crack -H <hash>            --wordlist rockyou.txt
  lobera-crack -f hashes.txt        --wordlist rockyou.txt
  lobera-crack -H <hash>            --wordlist rockyou.txt --engine cpu
  lobera-crack --from-db            --wordlist rockyou.txt
"""

import sys
import os
import re
import struct
import subprocess
import tempfile
import time

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from core.output import console


# ──────────────────────────────────────────────────────────────────────────────
# MD4 puro en Python
# Windows usa MD4 para generar el NT hash: NT = MD4(password.encode('utf-16-le'))
# OpenSSL moderno desactivó MD4 por seguridad, así que lo implementamos nosotros.
# Referencia: RFC 1320
# ──────────────────────────────────────────────────────────────────────────────

def _md4(data: bytes) -> bytes:
    """Implementación completa de MD4 (RFC 1320) en Python puro."""

    def _f(x, y, z): return (x & y) | (~x & z)
    def _g(x, y, z): return (x & y) | (x & z) | (y & z)
    def _h(x, y, z): return x ^ y ^ z
    def _rol(x, n):  return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
    def _add(*args): return sum(args) & 0xFFFFFFFF

    # Padding: añadir bit 1, ceros, y longitud en 64 bits little-endian
    msg = bytearray(data)
    orig_len = len(data) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack('<Q', orig_len)

    # Estado inicial
    A, B, C, D = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    for i in range(0, len(msg), 64):
        X = list(struct.unpack_from('<16I', msg, i))
        a, b, c, d = A, B, C, D

        # Ronda 1
        for k, s in zip([0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
                         [3,7,11,19]*4):
            a = _rol(_add(a, _f(b, c, d), X[k]), s)
            a, b, c, d = d, a, b, c

        # Ronda 2
        for k, s in zip([0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15],
                         [3,5,9,13]*4):
            a = _rol(_add(a, _g(b, c, d), X[k], 0x5A827999), s)
            a, b, c, d = d, a, b, c

        # Ronda 3
        for k, s in zip([0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15],
                         [3,9,11,15]*4):
            a = _rol(_add(a, _h(b, c, d), X[k], 0x6ED9EBA1), s)
            a, b, c, d = d, a, b, c

        A = _add(A, a)
        B = _add(B, b)
        C = _add(C, c)
        D = _add(D, d)

    return struct.pack('<4I', A, B, C, D)


def _nt_hash(password: str) -> str:
    """NT hash = MD4(password en UTF-16-LE). Devuelve hex en minúsculas."""
    return _md4(password.encode('utf-16-le')).hex()


# ──────────────────────────────────────────────────────────────────────────────
# Detección de formato
# ──────────────────────────────────────────────────────────────────────────────

NTLM_RE      = re.compile(r'^[0-9a-fA-F]{32}$')
NETNTLMV1_RE = re.compile(r'^[^:]+::[^:]+:[0-9a-fA-F]+:[0-9a-fA-F]+:[0-9a-fA-F]+$')
NETNTLMV2_RE = re.compile(r'^[^:]+::[^:]+:[0-9a-fA-F]+:[0-9a-fA-F]+:[0-9a-fA-F]+$')
KRB5ASREP_RE = re.compile(r'^\$krb5asrep\$', re.IGNORECASE)
KRB5TGS_RE   = re.compile(r'^\$krb5tgs\$', re.IGNORECASE)

# Modos hashcat por formato
HASHCAT_MODES = {
    'ntlm':      1000,
    'netntlmv1': 5500,
    'netntlmv2': 5600,
    'krb5asrep': 18200,
    'krb5tgs':   13100,
}


def detect_format(hash_str: str) -> str:
    """
    Detecta el formato del hash automáticamente.
    Devuelve: 'ntlm', 'netntlmv1', 'netntlmv2', 'krb5asrep', 'krb5tgs', o 'unknown'.

    NetNTLMv1 y v2 tienen la misma forma externa — se distinguen por el prefijo
    del tipo que viene en el hash completo de Responder. Si no hay prefijo explícito
    asumimos v2 (más común en redes modernas).
    """
    h = hash_str.strip()
    if KRB5ASREP_RE.match(h):
        return 'krb5asrep'
    if KRB5TGS_RE.match(h):
        return 'krb5tgs'
    if NTLM_RE.match(h):
        return 'ntlm'
    # NetNTLM: usuario::dominio:challenge:respuesta:blob
    # v1: respuesta = 48 hex chars; v2: respuesta es más larga
    if '::' in h:
        partes = h.split(':')
        if len(partes) >= 6:
            resp = partes[4]
            return 'netntlmv1' if len(resp) == 48 else 'netntlmv2'
    return 'unknown'


# ──────────────────────────────────────────────────────────────────────────────
# Motor CPU puro
# ──────────────────────────────────────────────────────────────────────────────

def _crack_ntlm_cpu(hash_str: str, wordlist_path: str) -> str | None:
    """
    Crackea un NT hash por fuerza bruta/diccionario en CPU.
    Lee la wordlist línea a línea (no la carga entera en RAM).
    Devuelve la contraseña en claro o None.
    """
    target = hash_str.strip().lower()
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                word = line.rstrip('\n')
                if _nt_hash(word) == target:
                    return word
    except FileNotFoundError:
        console.print(f"  [red]✗ Wordlist no encontrada: {wordlist_path}[/red]")
    return None


def _crack_netntlmv2_cpu(hash_str: str, wordlist_path: str) -> str | None:
    """
    Crackea NetNTLMv2 en CPU.

    Formato: usuario::dominio:ServerChallenge:NTProofStr:blob
    NTProofStr = HMAC-MD5(NT_hash_del_usuario, SC + blob)
    Verificación: recalculamos HMAC-MD5(MD4(word), SC+blob) y comparamos con NTProofStr.
    """
    import hmac
    import hashlib

    h = hash_str.strip()
    partes = h.split(':')
    if len(partes) < 6:
        console.print("  [red]✗ Formato NetNTLMv2 inválido[/red]")
        return None

    server_challenge = bytes.fromhex(partes[3])
    ntproofstr       = partes[4].lower()
    blob             = bytes.fromhex(partes[5])
    sc_blob          = server_challenge + blob

    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                word = line.rstrip('\n')
                nt = _md4(word.encode('utf-16-le'))
                proof = hmac.new(nt, sc_blob, hashlib.md5).hexdigest()
                if proof == ntproofstr:
                    return word
    except FileNotFoundError:
        console.print(f"  [red]✗ Wordlist no encontrada: {wordlist_path}[/red]")
    return None


def crack_cpu(hash_str: str, fmt: str, wordlist_path: str) -> str | None:
    """Despacha al motor CPU correcto según el formato."""
    if fmt == 'ntlm':
        return _crack_ntlm_cpu(hash_str, wordlist_path)
    elif fmt == 'netntlmv2':
        return _crack_netntlmv2_cpu(hash_str, wordlist_path)
    elif fmt == 'netntlmv1':
        console.print("  [yellow]⚠  NetNTLMv1 en CPU no implementado — usa hashcat[/yellow]")
        return None
    elif fmt in ('krb5asrep', 'krb5tgs'):
        console.print("  [yellow]⚠  Kerberos en CPU no implementado — usa hashcat[/yellow]")
        return None
    else:
        console.print(f"  [red]✗ Formato desconocido: {fmt}[/red]")
        return None


# ──────────────────────────────────────────────────────────────────────────────
# Motor hashcat
# ──────────────────────────────────────────────────────────────────────────────

def _find_hashcat() -> str | None:
    """Devuelve la ruta a hashcat si está en PATH, o None."""
    for candidate in ['hashcat', 'hashcat.bin']:
        try:
            r = subprocess.run([candidate, '--version'],
                               capture_output=True, timeout=5)
            if r.returncode == 0:
                return candidate
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
    return None


def crack_hashcat(hash_str: str, fmt: str, wordlist_path: str,
                  rules: list[str] | None = None,
                  extra_args: list[str] | None = None) -> str | None:
    """
    Llama a hashcat con el modo correcto para el formato dado.
    Devuelve la contraseña crackeada o None.

    hashcat guarda los resultados en un potfile (~/.local/share/hashcat/hashcat.potfile).
    Parseamos su stdout línea a línea buscando 'hash:password'.
    """
    hc = _find_hashcat()
    if hc is None:
        return None

    mode = HASHCAT_MODES.get(fmt)
    if mode is None:
        console.print(f"  [red]✗ Sin modo hashcat para formato: {fmt}[/red]")
        return None

    # Escribir el hash en un fichero temporal
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as tmp:
        tmp.write(hash_str.strip() + '\n')
        hash_file = tmp.name

    potfile = os.path.join(tempfile.gettempdir(), 'lobera_hashcat.pot')

    cmd = [
        hc,
        '-m', str(mode),
        hash_file,
        wordlist_path,
        '--potfile-path', potfile,
        '--quiet',
        '--status',
        '--status-timer', '5',
        '-o', '/dev/null',   # no output file; leemos potfile
    ]
    if rules:
        for rule in rules:
            cmd += ['-r', rule]
    if extra_args:
        cmd += extra_args

    cracked = None
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT,
                                text=True, errors='ignore')
        for line in proc.stdout:
            line = line.strip()
            if line:
                console.print(f"  [dim]{line}[/dim]")
        proc.wait()

        # Leer potfile para obtener la contraseña
        if os.path.exists(potfile):
            target = hash_str.strip().lower()
            with open(potfile, 'r', errors='ignore') as pf:
                for entry in pf:
                    entry = entry.strip()
                    if ':' in entry and entry.lower().startswith(target.lower()):
                        cracked = entry.split(':', 1)[1]
                        break
    except Exception as e:
        console.print(f"  [red]✗ Error ejecutando hashcat: {e}[/red]")
    finally:
        os.unlink(hash_file)

    return cracked


# ──────────────────────────────────────────────────────────────────────────────
# Interfaz principal de crackeo
# ──────────────────────────────────────────────────────────────────────────────

def crack(hash_str: str, wordlist: str,
          fmt: str | None = None,
          engine: str = 'auto',
          rules: list[str] | None = None) -> dict:
    """
    Punto de entrada principal.

    Parámetros:
      hash_str  — hash a crackear (en cualquier formato soportado)
      wordlist  — ruta a la wordlist
      fmt       — formato explícito; si None, se detecta automáticamente
      engine    — 'auto' (hashcat si disponible, cpu si no), 'hashcat', 'cpu'
      rules     — lista de ficheros de reglas para hashcat

    Devuelve dict:
      {'hash': str, 'format': str, 'password': str|None, 'engine': str, 'elapsed': float}
    """
    if fmt is None:
        fmt = detect_format(hash_str)

    t0 = time.time()
    password = None
    engine_used = engine

    hc = _find_hashcat()

    if engine == 'auto':
        engine_used = 'hashcat' if hc else 'cpu'

    console.print(f"  [dim]Formato detectado: [bold]{fmt}[/bold][/dim]")
    console.print(f"  [dim]Motor: [bold]{engine_used}[/bold]{'  (hashcat no encontrado)' if engine == 'auto' and not hc else ''}[/dim]")

    if engine_used == 'hashcat':
        if hc is None:
            console.print("  [yellow]⚠  hashcat no encontrado — usando CPU[/yellow]")
            engine_used = 'cpu'
        else:
            password = crack_hashcat(hash_str, fmt, wordlist, rules=rules)

    if engine_used == 'cpu':
        password = crack_cpu(hash_str, fmt, wordlist)

    elapsed = time.time() - t0
    return {
        'hash':     hash_str.strip(),
        'format':   fmt,
        'password': password,
        'engine':   engine_used,
        'elapsed':  elapsed,
    }


def crack_file(hash_file: str, wordlist: str,
               fmt: str | None = None,
               engine: str = 'auto',
               rules: list[str] | None = None) -> list[dict]:
    """
    Crackea todos los hashes de un fichero (uno por línea).
    Devuelve lista de resultados.
    """
    results = []
    try:
        with open(hash_file, 'r', errors='ignore') as f:
            hashes = [l.strip() for l in f if l.strip() and not l.startswith('#')]
    except FileNotFoundError:
        console.print(f"  [red]✗ Fichero no encontrado: {hash_file}[/red]")
        return []

    # hashcat puede procesar todos de golpe — más eficiente
    hc = _find_hashcat()
    use_engine = engine
    if engine == 'auto':
        use_engine = 'hashcat' if hc else 'cpu'

    if use_engine == 'hashcat' and hc:
        # Para múltiples hashes con hashcat, los mandamos todos juntos
        # Detectar formato del primero (asumimos homogéneo)
        file_fmt = fmt or detect_format(hashes[0]) if hashes else 'unknown'
        mode = HASHCAT_MODES.get(file_fmt)
        if mode:
            potfile = os.path.join(tempfile.gettempdir(), 'lobera_hashcat.pot')
            cmd = [hc, '-m', str(mode), hash_file, wordlist,
                   '--potfile-path', potfile, '--quiet']
            if rules:
                for rule in rules:
                    cmd += ['-r', rule]
            try:
                subprocess.run(cmd, timeout=3600)
            except Exception as e:
                console.print(f"  [red]✗ hashcat: {e}[/red]")

            # Parsear potfile
            cracked_map = {}
            if os.path.exists(potfile):
                with open(potfile, 'r', errors='ignore') as pf:
                    for entry in pf:
                        entry = entry.strip()
                        if ':' in entry:
                            h, p = entry.split(':', 1)
                            cracked_map[h.lower()] = p

            for h in hashes:
                results.append({
                    'hash':     h,
                    'format':   file_fmt,
                    'password': cracked_map.get(h.strip().lower()),
                    'engine':   'hashcat',
                    'elapsed':  0,
                })
            return results

    # CPU: uno a uno
    for h in hashes:
        r = crack(h, wordlist, fmt=fmt, engine='cpu', rules=rules)
        results.append(r)
    return results


def crack_from_db(wordlist: str, engine: str = 'auto',
                  only_uncracked: bool = True) -> list[dict]:
    """
    Lee hashes de la BD de lobera (tabla credentials donde secret_type in
    ('ntlm','netntlmv2','krb5asrep','krb5tgs')) e intenta crackearlos.
    Guarda los resultados en la BD.
    """
    from core import session_db

    conn = session_db._connect()
    cur = conn.cursor()
    query = """
        SELECT id, target_ip, user, secret, secret_type
        FROM credentials
        WHERE secret_type IN ('ntlm','netntlmv1','netntlmv2','krb5asrep','krb5tgs')
    """
    if only_uncracked:
        query += " AND valid = 0"
    cur.execute(query)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()

    if not rows:
        console.print("  [dim]No hay hashes sin crackear en la BD[/dim]")
        return []

    console.print(f"  [dim]{len(rows)} hash(es) encontrados en la BD[/dim]")
    results = []
    for row in rows:
        console.print(f"\n  [bold]→ {row['user']}@{row['target_ip']}[/bold]  [{row['secret_type']}]")
        r = crack(row['secret'], wordlist, fmt=row['secret_type'], engine=engine)
        r['user'] = row['user']
        r['target_ip'] = row['target_ip']
        results.append(r)

        if r['password']:
            # Guardar la contraseña crackeada como credencial válida
            session_db.save_credential(
                target_ip=row['target_ip'],
                user=row['user'],
                secret=r['password'],
                secret_type='password',
                valid=1,
                source='lobera-crack',
            )
            console.print(f"  [bold green]✓ Crackeado: {r['password']}[/bold green]  ({r['elapsed']:.1f}s)")
        else:
            console.print(f"  [dim]Sin resultado  ({r['elapsed']:.1f}s)[/dim]")

    return results


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

def _print_result(r: dict):
    h_short = r['hash'][:40] + ('…' if len(r['hash']) > 40 else '')
    if r['password']:
        console.print(f"  [bold green]✓ CRACKEADO[/bold green]  {h_short}")
        console.print(f"    [bold]Contraseña:[/bold] [yellow]{r['password']}[/yellow]")
    else:
        console.print(f"  [red]✗ Sin resultado[/red]  {h_short}")
    console.print(f"    [dim]Formato: {r['format']}  Motor: {r['engine']}  Tiempo: {r['elapsed']:.1f}s[/dim]")


def build_parser():
    import argparse
    parser = argparse.ArgumentParser(
        prog='lobera-crack',
        description='Cracker offline de hashes — NTLM, NetNTLMv2, Kerberos AS-REP/TGS',
    )

    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument('-H', '--hash',     metavar='HASH',  help='Hash individual a crackear')
    src.add_argument('-f', '--file',     metavar='FILE',  help='Fichero con hashes (uno por línea)')
    src.add_argument('--from-db',        action='store_true', help='Leer hashes sin crackear de la BD de lobera')

    parser.add_argument('-w', '--wordlist', metavar='FILE', required=True,
                        help='Wordlist (ej. /usr/share/wordlists/rockyou.txt)')
    parser.add_argument('--format', dest='fmt', default=None,
                        choices=list(HASHCAT_MODES.keys()),
                        help='Forzar formato (por defecto: autodetección)')
    parser.add_argument('--engine', default='auto',
                        choices=['auto', 'hashcat', 'cpu'],
                        help='Motor de crackeo (default: auto)')
    parser.add_argument('-r', '--rules', metavar='FILE', action='append',
                        help='Fichero de reglas hashcat (se puede repetir)')
    parser.add_argument('--only-uncracked', action='store_true', default=True,
                        help='Con --from-db: solo hashes aún no crackeados (default)')
    return parser


def _banner():
    from tools.common import banner, tabla_flags, ejemplos
    banner("lobera-crack  —  Cracker offline de hashes Windows/AD")
    tabla_flags([
        ("-H / --hash",    "str",  "Hash individual a crackear"),
        ("-f / --file",    "file", "Fichero con un hash por línea"),
        ("--from-db",      "flag", "Leer hashes sin crackear de la BD de sesión"),
        ("-w / --wordlist", "file", "Diccionario (obligatorio)"),
        ("--format",       "str",  "ntlm | netntlmv1 | netntlmv2 | krb5asrep | krb5tgs"),
        ("--engine",       "str",  "auto | hashcat | cpu (default: auto)"),
        ("-r / --rules",   "file", "Fichero de reglas hashcat"),
    ])
    ejemplos([
        "lobera-crack -H aad3b435b51404eeaad3b435b51404ee:... -w rockyou.txt",
        "lobera-crack -f hashes.txt -w rockyou.txt --format netntlmv2",
        "lobera-crack --from-db -w rockyou.txt --engine hashcat",
    ])


def main():
    import sys
    if not sys.argv[1:]:
        _banner()
        return
    parser = build_parser()
    args = parser.parse_args()
    _banner()

    hc = _find_hashcat()
    console.print(f"  hashcat: {'[green]disponible[/green]' if hc else '[yellow]no encontrado — se usará CPU[/yellow]'}")
    console.print()

    if args.hash:
        r = crack(args.hash, args.wordlist,
                  fmt=args.fmt, engine=args.engine, rules=args.rules)
        _print_result(r)

    elif args.file:
        results = crack_file(args.file, args.wordlist,
                             fmt=args.fmt, engine=args.engine, rules=args.rules)
        crackeados = sum(1 for r in results if r['password'])
        console.print()
        for r in results:
            _print_result(r)
        console.print()
        console.print(f"  [bold]Resultado:[/bold] {crackeados}/{len(results)} crackeados")

    elif args.from_db:
        results = crack_from_db(args.wordlist, engine=args.engine,
                                only_uncracked=args.only_uncracked)
        crackeados = sum(1 for r in results if r.get('password'))
        console.print()
        console.print(f"  [bold]Resultado:[/bold] {crackeados}/{len(results)} crackeados")


if __name__ == '__main__':
    main()
