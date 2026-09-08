# scripts/kerberos/enum/user_enum.py
#
# Técnica: Kerberos User Enumeration via AS-REQ sin pre-auth
#
# Fundamento:
#   El KDC (Key Distribution Center) responde de forma DIFERENTE según si el
#   usuario existe o no en Active Directory, incluso cuando no tenemos credenciales.
#
#   Enviamos un AS-REQ sin pre-auth para cada usuario de la lista.
#   El KDC responde:
#
#   ┌─────────────────────────────────────────────────────────────────────┐
#   │ KRB-ERROR 6  → KDC_ERR_C_PRINCIPAL_UNKNOWN → USUARIO NO EXISTE     │
#   │ KRB-ERROR 25 → KDC_ERR_PREAUTH_REQUIRED    → USUARIO EXISTE        │
#   │ KRB-ERROR 24 → KDC_ERR_PREAUTH_FAILED      → USUARIO EXISTE        │
#   │ AS-REP       → respuesta directa            → USUARIO EXISTE +      │
#   │                                               DONT_REQUIRE_PREAUTH  │
#   └─────────────────────────────────────────────────────────────────────┘
#
# Por qué funciona sin credenciales:
#   Kerberos necesita decirle al cliente cuál etype usar para cifrar su
#   pre-auth (el Encrypted Timestamp). Para eso, el KDC tiene que consultar
#   la cuenta en AD y devolver la info de etype. Si la cuenta no existe, el
#   KDC devuelve error 6 ANTES de llegar a esa lógica → diferencia observable.
#
# Detección / defensa:
#   - Windows Event ID 4768 (AS-REQ recibido) con el campo "Result Code".
#   - Error 6 = usuario no existe.
#   - Error 25 = usuario existe (normal, ocurre en todo login legítimo).
#   - Un volumen alto de 4768 con error 25 desde una sola IP = enumeración.

import time
from scripts.base import BaseScript
from core.kerberos_transport import send_krb_message, check_kdc_reachable
from core.asn1_helpers import (
    build_as_req, is_krb_error, is_as_rep, parse_krb_error,
    KDC_ERR_C_PRINCIPAL_UNKNOWN, KDC_ERR_PREAUTH_REQUIRED,
    KDC_ERR_PREAUTH_FAILED, ETYPE_RC4_HMAC
)
from core.output import print_result, print_table, console
from core import session_db


class UserEnumScript(BaseScript):
    name = "user-enum"
    description = "Enumera usuarios válidos de AD enviando AS-REQ sin pre-auth al KDC (puerto 88)"

    examples = [
        {"flag": "--userlist",
         "desc": "Fichero con un usuario por línea (obligatorio)",
         "good": "kerberos --script=user-enum -t 10.129.1.5 -d CORP.LOCAL --userlist users.txt",
         "bad": "kerberos --script=user-enum -t 10.129.1.5 --userlist users.txt  [sin -d no hay realm → falla el AS-REQ]"},
        {"flag": "-d / --domain",
         "desc": "Realm Kerberos EN MAYÚSCULAS (ej. CORP.LOCAL). Obligatorio para construir el AS-REQ",
         "good": "kerberos --script=user-enum -t 10.129.1.5 -d CORP.LOCAL --userlist users.txt",
         "bad": "kerberos --script=user-enum -t 10.129.1.5 -d corp.local --userlist users.txt  [minúsculas: Kerberos es case-sensitive en el realm]"},
    ]

    def run(self, **kwargs):
        userlist_path = kwargs.get("userlist")
        if not userlist_path:
            console.print("[red]Falta --userlist: user-enum necesita un fichero con usuarios.[/red]")
            return

        realm = (self.creds.domain or self.target.domain or "").upper()
        if not realm:
            console.print("[red]Falta -d/--domain: necesario para construir el AS-REQ (realm Kerberos).[/red]")
            return

        try:
            with open(userlist_path) as f:
                users = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except OSError as e:
            console.print(f"[red]No se pudo leer {userlist_path}: {e}[/red]")
            return

        if not users:
            console.print("[yellow]El fichero de usuarios está vacío.[/yellow]")
            return

        # Verificación de conectividad antes de iterar
        kdc = self.target.ip
        if not check_kdc_reachable(kdc, timeout=self.target.timeout):
            print_result("KRB", kdc, "fail",
                         f"KDC no alcanzable en {kdc}:88 — ¿es realmente un DC?")
            return

        print_result("KRB", kdc, "info",
                     f"user-enum: probando {len(users)} usuario(s) contra {realm}")

        valid_users = []
        no_preauth_users = []  # DONT_REQUIRE_PREAUTH — candidatos a AS-REP Roasting

        for username in users:
            result = self._probe_user(kdc, username, realm)
            label, status = result

            if status == "exists":
                valid_users.append(username)
                print_result("KRB", kdc, "pwned", f"{username} → EXISTE")
                session_db.save_finding(kdc, "KRB", "valid_user", username)

            elif status == "no_preauth":
                valid_users.append(username)
                no_preauth_users.append(username)
                print_result("KRB", kdc, "pwned",
                             f"{username} → EXISTE + DONT_REQUIRE_PREAUTH (candidato AS-REP Roasting)")
                session_db.save_finding(kdc, "KRB", "asrep_roastable", username)

            elif status == "not_found":
                print_result("KRB", kdc, "info", f"{username} → no existe")

            else:
                print_result("KRB", kdc, "fail", f"{username} → error inesperado: {label}")

            # Pausa mínima para no saturar el KDC (y reducir el TTM de detección)
            time.sleep(0.1)

        # Resumen
        console.print()
        if valid_users:
            rows = [(u, "DONT_REQUIRE_PREAUTH" if u in no_preauth_users else "") for u in valid_users]
            print_table(f"Usuarios válidos en {realm}", ["Usuario", "Nota"], rows)
            print_result("KRB", kdc, "pwned",
                         f"{len(valid_users)} usuario(s) válido(s), "
                         f"{len(no_preauth_users)} con DONT_REQUIRE_PREAUTH")
        else:
            print_result("KRB", kdc, "info", "No se encontró ningún usuario válido")

        return valid_users

    def _probe_user(self, kdc: str, username: str, realm: str) -> tuple:
        """
        Envía un AS-REQ sin pre-auth para un único usuario y clasifica
        la respuesta del KDC.

        Devuelve (descripción, status):
            status = "exists"     → usuario existe (PREAUTH_REQUIRED)
            status = "no_preauth" → existe + DONT_REQUIRE_PREAUTH
            status = "not_found"  → no existe (C_PRINCIPAL_UNKNOWN)
            status = "error"      → otro error inesperado
        """
        try:
            # AS-REQ con solo RC4 para maximizar compatibilidad con DCs legacy.
            # Si el DC no soporta RC4 (política NoLMHash), añadiremos AES.
            # Con RC4, el error 25 (PREAUTH_REQUIRED) siempre viene con e-data
            # que incluye ETYPE-INFO2, confirmando que la cuenta existe.
            req = build_as_req(username, realm, etypes=[ETYPE_RC4_HMAC])
            response = send_krb_message(kdc, req, timeout=self.target.timeout)

        except (socket_timeout := __import__('socket').timeout):
            return ("timeout", "error")
        except OSError as e:
            return (str(e), "error")

        if is_as_rep(response):
            # AS-REP sin haber enviado pre-auth → DONT_REQUIRE_PREAUTH activo
            return ("AS-REP recibido", "no_preauth")

        if is_krb_error(response):
            try:
                err = parse_krb_error(response)
            except Exception:
                return ("parse error", "error")

            ec = err['error_code']
            if ec == KDC_ERR_C_PRINCIPAL_UNKNOWN:
                return ("KDC_ERR_C_PRINCIPAL_UNKNOWN", "not_found")
            elif ec in (KDC_ERR_PREAUTH_REQUIRED, KDC_ERR_PREAUTH_FAILED):
                return (err['error_name'], "exists")
            else:
                return (err['error_name'], "error")

        return ("respuesta desconocida", "error")
