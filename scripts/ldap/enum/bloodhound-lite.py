# scripts/ldap/enum/bloodhound-lite.py
"""
Recopila en una sola pasada toda la información relevante del dominio vía LDAP
y construye un resumen de rutas de ataque al estilo BloodHound (sin necesidad
de instalar BloodHound ni neo4j).

Ejecuta internamente:
  • domain-info      — info básica del dominio
  • users            — lista de usuarios y atributos de interés
  • groups           — grupos y sus miembros
  • admins           — miembros de Domain/Enterprise Admins y Administrators
  • computers        — equipos del dominio
  • kerberoast-targets — SPNs kerberoasteables
  • asreproast-targets — usuarios sin preauth (AS-REP Roasting)
  • dacl-enum        — ACEs peligrosas

Al final imprime una tabla de resumen con "rutas de ataque" identificadas.
"""

from scripts.base import BaseScript
from core.output import print_result, print_table, console
from core import session_db

try:
    from modules.ldap import LDAPModule
    _LDAP_OK = True
except ImportError:
    _LDAP_OK = False


class Script(BaseScript):
    name        = "bloodhound-lite"
    protocol    = "ldap"
    category    = "enum"
    description = (
        "Enumera dominio completo vía LDAP en una pasada y muestra rutas de "
        "ataque identificadas: kerberoast, AS-REP, ACLs peligrosas, admins."
    )

    EXAMPLES = [
        {
            "flag":  "-t / -u / -p / -d",
            "desc":  "Credenciales de dominio para consultar LDAP",
            "good":  "lobera.py ldap --script=bloodhound-lite -t 10.129.1.5 -u iker -p 'Pass1' -d CORP.LOCAL",
            "bad":   "lobera.py ldap --script=bloodhound-lite -t 10.129.1.5  [sin credenciales no se puede enumerar]",
        },
    ]

    # Derechos de ACL que permiten escalada directa
    _DANGEROUS_RIGHTS = {
        "GenericAll":    "Control total del objeto",
        "WriteDACL":     "Puede añadir ACEs arbitrarias → WriteDACL → DA",
        "WriteOwner":    "Puede cambiar propietario → después WriteDACL",
        "GenericWrite":  "Puede modificar atributos críticos (msDS-AllowedToActOnBehalfOfOtherIdentity, etc.)",
        "AllExtendedRights": "Incluye DCSync si el objeto es el dominio",
    }

    def run(self, **kwargs):
        if not _LDAP_OK:
            print_result("LDAP", str(self.target.ip), "fail",
                         "modules/ldap.py no disponible"); return

        use_ssl = kwargs.get("ldaps", False)
        port    = kwargs.get("port")

        ldap = LDAPModule(self.target, self.creds, use_ssl=use_ssl, port=port)
        if not ldap.connect():
            return

        attack_paths = []

        try:
            console.rule("[bold yellow]BloodHound-lite — enumeración completa[/bold yellow]")

            # ── 1. Info del dominio ───────────────────────────────────────────
            console.print("\n[bold cyan]▶ Información del dominio[/bold cyan]")
            try:
                domain_info = ldap.get_domain_info()
                if domain_info:
                    for k, v in domain_info.items():
                        if v:
                            console.print(f"  [dim]{k}:[/dim] {v}")
            except Exception as e:
                console.print(f"  [red]Error: {e}[/red]")

            # ── 2. Usuarios ───────────────────────────────────────────────────
            console.print("\n[bold cyan]▶ Usuarios del dominio[/bold cyan]")
            users = []
            try:
                users = ldap.get_users() or []
                console.print(f"  {len(users)} usuario(s) encontrados")
                # Atributos de interés
                pwd_not_req = [u for u in users if u.get("userAccountControl") and
                               int(u.get("userAccountControl", 0)) & 0x20]
                no_expire   = [u for u in users if u.get("userAccountControl") and
                               int(u.get("userAccountControl", 0)) & 0x10000]
                disabled    = [u for u in users if u.get("userAccountControl") and
                               int(u.get("userAccountControl", 0)) & 0x2]
                if pwd_not_req:
                    console.print(f"  [yellow]⚠ {len(pwd_not_req)} usuario(s) sin password requerida[/yellow]")
                    attack_paths.append(("MEDIO", "Usuarios sin password requerida",
                                         ", ".join(u.get("sAMAccountName","?") for u in pwd_not_req[:5])))
                if no_expire:
                    console.print(f"  [yellow]⚠ {len(no_expire)} usuario(s) con password que no expira[/yellow]")
            except Exception as e:
                console.print(f"  [red]Error enumerando usuarios: {e}[/red]")

            # ── 3. Grupos privilegiados ───────────────────────────────────────
            console.print("\n[bold cyan]▶ Grupos privilegiados[/bold cyan]")
            try:
                admins = ldap.get_admin_users() or []
                if admins:
                    print_table(
                        f"Miembros de grupos privilegiados ({len(admins)})",
                        ["Grupo", "Usuario", "DN"],
                        [(a.get("group","?"), a.get("sAMAccountName","?"), a.get("dn","?"))
                         for a in admins[:20]],
                    )
            except Exception as e:
                console.print(f"  [red]Error enumerando admins: {e}[/red]")

            # ── 4. Kerberoasting ─────────────────────────────────────────────
            console.print("\n[bold cyan]▶ Objetivos Kerberoasting (SPNs)[/bold cyan]")
            try:
                kerb_targets = ldap.get_kerberoastable_users() or []
                if kerb_targets:
                    print_table(
                        f"Usuarios kerberoasteables ({len(kerb_targets)})",
                        ["Usuario", "SPN", "Password Expirada"],
                        [(u.get("sAMAccountName","?"), u.get("servicePrincipalName","?"),
                          u.get("pwdLastSet","?")) for u in kerb_targets],
                    )
                    for u in kerb_targets:
                        attack_paths.append((
                            "ALTO",
                            f"Kerberoasting — {u.get('sAMAccountName','?')}",
                            f"SPN: {u.get('servicePrincipalName','?')}",
                        ))
                else:
                    console.print("  No se encontraron SPNs kerberoasteables")
            except Exception as e:
                console.print(f"  [red]Error buscando SPNs: {e}[/red]")

            # ── 5. AS-REP Roasting ───────────────────────────────────────────
            console.print("\n[bold cyan]▶ Objetivos AS-REP Roasting (sin pre-auth)[/bold cyan]")
            try:
                asrep_targets = ldap.get_asreproastable_users() or []
                if asrep_targets:
                    names = [u.get("sAMAccountName","?") for u in asrep_targets]
                    console.print(f"  [bold red]⚠ {len(asrep_targets)} usuario(s) sin preauth:[/bold red] {', '.join(names)}")
                    for u in asrep_targets:
                        attack_paths.append((
                            "CRÍTICO",
                            f"AS-REP Roasting — {u.get('sAMAccountName','?')}",
                            "No requiere preautenticación → hash offline crackeable",
                        ))
                else:
                    console.print("  No se encontraron usuarios sin preauth")
            except Exception as e:
                console.print(f"  [red]Error buscando AS-REP targets: {e}[/red]")

            # ── 6. ACLs peligrosas ───────────────────────────────────────────
            console.print("\n[bold cyan]▶ ACLs peligrosas (DACL)[/bold cyan]")
            try:
                aces = ldap.get_interesting_aces() or []
                if aces:
                    for ace in aces:
                        for right in ace.get("rights", []):
                            if right in self._DANGEROUS_RIGHTS:
                                obj_cn = ace["object_dn"].split(",")[0].replace("CN=","").replace("DC=","")
                                attack_paths.append((
                                    "CRÍTICO" if right in ("GenericAll","WriteDACL","AllExtendedRights") else "ALTO",
                                    f"ACL — {right} sobre {obj_cn}",
                                    f"Trustee: {ace['trustee_sid']} · {self._DANGEROUS_RIGHTS[right]}",
                                ))
                else:
                    console.print("  No se detectaron ACEs peligrosas (o sin permisos para leer DACL)")
            except Exception as e:
                console.print(f"  [red]Error leyendo DACLs: {e}[/red]")

            # ── 7. Política de contraseñas ───────────────────────────────────
            console.print("\n[bold cyan]▶ Política de contraseñas[/bold cyan]")
            try:
                policy = ldap.get_password_policy() or {}
                if policy:
                    for k, v in policy.items():
                        console.print(f"  [dim]{k}:[/dim] {v}")
                    lockout = policy.get("lockout_threshold", 0)
                    if lockout == 0:
                        attack_paths.append(("ALTO", "Sin política de lockout",
                                             "Password spray sin riesgo de bloqueo"))
                    elif isinstance(lockout, int) and lockout <= 3:
                        attack_paths.append(("MEDIO", f"Lockout threshold bajo ({lockout})",
                                             "Spray limitado; usar --delay alto"))
            except Exception as e:
                console.print(f"  [red]Error leyendo política de contraseñas: {e}[/red]")

            # ── Resumen de rutas de ataque ────────────────────────────────────
            if attack_paths:
                _ORDER = {"CRÍTICO": 0, "ALTO": 1, "MEDIO": 2, "INFO": 3}
                attack_paths.sort(key=lambda x: _ORDER.get(x[0], 9))
                console.rule("\n[bold red]🎯 Rutas de ataque identificadas[/bold red]")
                print_table(
                    f"Rutas de ataque ({len(attack_paths)})",
                    ["Severidad", "Ruta", "Detalle"],
                    attack_paths,
                )
                # Guardar en session_db
                for sev, ruta, detalle in attack_paths:
                    session_db.save_finding(
                        self.target.ip, "LDAP",
                        f"attack_path_{sev.lower()}",
                        f"{ruta}: {detalle}",
                    )
                print_result("LDAP", str(self.target.ip), "pwned",
                             f"{len(attack_paths)} ruta(s) de ataque identificada(s)")
            else:
                console.print("\n[green]No se identificaron rutas de ataque obvias.[/green]")

        finally:
            ldap.disconnect()
