# modules/ldap_shell.py
#
# Consola interactiva LDAP — búsquedas libres + comandos de alto nivel.

import pyfiglet
from core.output import console, print_table

try:
    from modules.ldap import LDAPModule
    _LDAP_OK = True
except ImportError:
    _LDAP_OK = False


class LDAPShell:
    """
    Consola interactiva sobre LDAPModule.
    Permite búsquedas LDAP libres y comandos de alto nivel
    (usuarios, grupos, equipos, política, SPNs, ACLs…).
    """

    def __init__(self, target, creds, use_ssl=False, port=None):
        self.target  = target
        self.creds   = creds
        self.use_ssl = use_ssl
        self.port    = port
        self.ldap    = None
        self._base   = ""

    def run(self):
        self._mini_banner()

        if not _LDAP_OK:
            console.print("[red]modules/ldap.py no disponible.[/red]")
            return

        self.ldap = LDAPModule(self.target, self.creds,
                               use_ssl=self.use_ssl, port=self.port)
        if not self.ldap.connect():
            console.print("[red]No se pudo conectar. Abortando.[/red]")
            return

        self._base = self.ldap._base_dn
        console.print(f"  Base DN: [bold yellow]{self._base}[/bold yellow]")
        console.print("  Escribe [bold]help[/bold] para ver los comandos.\n")

        while True:
            try:
                raw = console.input(self._prompt()).strip()
            except (EOFError, KeyboardInterrupt):
                console.print("\n[dim]Saliendo de LDAP shell...[/dim]")
                break

            if not raw:
                continue

            # Separar comando del resto
            parts = raw.split(None, 1)
            cmd   = parts[0].lower()
            rest  = parts[1].strip() if len(parts) > 1 else ""

            if cmd in ("exit", "quit", "q"):
                break
            elif cmd == "help":
                self._help()
            elif cmd == "cls":
                console.clear()
            elif cmd == "basedn":
                self._set_basedn(rest)
            # Búsqueda libre
            elif cmd == "search":
                self._search_free(rest)
            elif cmd == "get":
                self._get_object(rest)
            # Alto nivel
            elif cmd == "users":
                self._users(rest)
            elif cmd == "groups":
                self._groups(rest)
            elif cmd == "computers":
                self._computers(rest)
            elif cmd == "admins":
                self._admins()
            elif cmd == "domaininfo":
                self._domaininfo()
            elif cmd == "pwdpolicy":
                self._pwdpolicy()
            elif cmd == "spns":
                self._spns()
            elif cmd == "asrep":
                self._asrep()
            elif cmd == "dacl":
                self._dacl(rest)
            elif cmd == "trusts":
                self._trusts()
            elif cmd == "ous":
                self._ous()
            elif cmd == "gpos":
                self._gpos()
            elif cmd == "psos":
                self._psos()
            elif cmd == "certtemplates":
                self._certtemplates()
            # Modificaciones
            elif cmd == "setattr":
                self._setattr(rest)
            elif cmd == "addmember":
                self._addmember(rest)
            elif cmd == "delmember":
                self._delmember(rest)
            elif cmd == "setpwd":
                self._setpwd(rest)
            else:
                console.print(f"[red]Comando desconocido: '{cmd}'[/red]  (escribe help)")

        if self.ldap:
            self.ldap.disconnect()

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------

    def _mini_banner(self):
        art = pyfiglet.figlet_format("LDAP Shell", font="small")
        console.print(f"[bold yellow]{art}[/bold yellow]")
        proto = "LDAPS" if self.use_ssl else "LDAP"
        console.print(
            f"  [bold yellow]{proto}[/bold yellow] → "
            f"[dim]{self.target.ip}[/dim]  "
            f"[dim]usuario: {self.creds.user or 'anónimo'}[/dim]\n"
        )

    def _prompt(self):
        user = self.creds.user or "anon"
        return f"[yellow][LDAP@{user}][/yellow]> "

    # ------------------------------------------------------------------
    # Comandos generales
    # ------------------------------------------------------------------

    def _set_basedn(self, new_base):
        if not new_base:
            console.print(f"[dim]Base DN actual: {self._base}[/dim]"); return
        self._base = new_base
        self.ldap._base_dn = new_base
        console.print(f"[dim]Base DN → {self._base}[/dim]")

    def _search_free(self, rest):
        """
        search <filtro> [attr1,attr2,...]
        Ejemplo: search (objectClass=user) sAMAccountName,mail
        """
        if not rest:
            console.print("[red]Uso: search <filtro LDAP> [atributos separados por coma][/red]")
            return
        parts  = rest.split(None, 1)
        filt   = parts[0]
        attrs  = [a.strip() for a in parts[1].split(",")] if len(parts) > 1 else ["*"]
        try:
            entries = self.ldap._search(filt, attrs)
            console.print(f"[dim]{len(entries)} resultado(s)[/dim]")
            for e in entries[:50]:   # máximo 50 para no saturar la terminal
                dn = str(e.get("dn", ""))
                console.print(f"  [cyan]dn:[/cyan] {dn}")
                try:
                    for attr in e["attributes"]:
                        name = str(attr["type"])
                        vals = [str(v) for v in attr["vals"]]
                        console.print(f"    [yellow]{name}:[/yellow] {', '.join(vals[:3])}")
                except Exception:
                    pass
                console.print()
            if len(entries) > 50:
                console.print(f"[dim]... y {len(entries)-50} más (usa filtros más específicos)[/dim]")
        except Exception as exc:
            console.print(f"[red]Error: {exc}[/red]")

    def _get_object(self, dn):
        """get <DN> — muestra todos los atributos de un objeto."""
        if not dn:
            console.print("[red]Uso: get <DN completo>[/red]"); return
        try:
            entries = self.ldap._search(
                "(objectClass=*)", ["*"], base_dn=dn
            )
            if not entries:
                console.print("[dim]No encontrado.[/dim]"); return
            e = entries[0]
            console.print(f"[bold cyan]DN:[/bold cyan] {dn}")
            try:
                for attr in e["attributes"]:
                    name = str(attr["type"])
                    vals = [str(v) for v in attr["vals"]]
                    console.print(f"  [yellow]{name}:[/yellow] {', '.join(vals[:5])}")
            except Exception:
                pass
        except Exception as exc:
            console.print(f"[red]Error: {exc}[/red]")

    # ------------------------------------------------------------------
    # Comandos de alto nivel — enumeración
    # ------------------------------------------------------------------

    def _users(self, filt_extra=""):
        """users [enabled|disabled|asrep|kerberoast|admins]"""
        users = self.ldap.get_all_users()
        if filt_extra == "enabled":
            users = [u for u in users if u["enabled"]]
        elif filt_extra == "disabled":
            users = [u for u in users if not u["enabled"]]
        elif filt_extra == "asrep":
            users = [u for u in users if u["no_preauth"]]
        elif filt_extra == "kerberoast":
            users = [u for u in users if u["spns"]]
        elif filt_extra == "admins":
            users = [u for u in users if u["admin_count"] == 1]

        if not users:
            console.print("[dim]Sin resultados.[/dim]"); return
        rows = [
            (u["user"], "Sí" if u["enabled"] else "[red]No[/red]",
             str(u["bad_pwd_count"]), u["pwd_last_set"],
             "SÍ" if u["no_preauth"] else "-",
             str(len(u["spns"])) if u["spns"] else "-")
            for u in users
        ]
        print_table(f"Usuarios ({len(users)})",
                    ["Usuario","Activo","BadPwd","PwdLastSet","NoPreauth","SPNs"],
                    rows)

    def _groups(self, filt_extra=""):
        """groups [privileged]"""
        groups = self.ldap.get_all_groups()
        from modules.ldap import PRIVILEGED_RIDS
        if filt_extra == "privileged":
            groups = [g for g in groups
                      if g["rid"] in PRIVILEGED_RIDS or g["admin_count"] == 1]
        if not groups:
            console.print("[dim]Sin resultados.[/dim]"); return
        rows = [(g["name"], str(g["member_count"]),
                 g["sid"].rsplit("-",1)[-1] if g["sid"] else "-",
                 g["description"][:40] or "-")
                for g in sorted(groups, key=lambda x: x["member_count"], reverse=True)]
        print_table(f"Grupos ({len(groups)})",
                    ["Nombre","Miembros","RID","Descripción"], rows)

    def _computers(self, filt_extra=""):
        """computers [undeleg|legacy]"""
        computers = self.ldap.get_all_computers()
        if filt_extra == "undeleg":
            computers = [c for c in computers if c["unconstrained_deleg"]]
        elif filt_extra == "legacy":
            legacy = ["Windows XP","Windows 7","Server 2003","Server 2008"]
            computers = [c for c in computers
                         if any(lo in c["os"] for lo in legacy)]
        if not computers:
            console.print("[dim]Sin resultados.[/dim]"); return
        rows = [(c["name"].rstrip("$"), c["os"] or "-", c["last_logon"],
                 "SÍ" if c["unconstrained_deleg"] else "-")
                for c in computers]
        print_table(f"Equipos ({len(computers)})",
                    ["Nombre","OS","LastLogon","UnDeleg"], rows)

    def _admins(self):
        admin_groups = self.ldap.get_admin_groups()
        if not admin_groups:
            console.print("[dim]Sin grupos privilegiados con miembros.[/dim]"); return
        for gname, members in admin_groups.items():
            console.print(f"\n[bold red]{gname}[/bold red] — {len(members)} miembro(s):")
            for m in members:
                cn = m.split(",")[0].replace("CN=","").replace("cn=","") if "=" in m else m
                console.print(f"  [yellow]→[/yellow] {cn}")

    def _domaininfo(self):
        info = self.ldap.get_domain_info()
        if not info:
            console.print("[dim]Sin resultados.[/dim]"); return
        rows = [(k, str(v)) for k, v in info.items() if not isinstance(v, list)]
        print_table("Dominio", ["Campo","Valor"], rows)
        dcs = info.get("dc_list", [])
        if dcs:
            print_table("DCs", ["DNS","OS","Versión"],
                        [(d["dns"],d["os"],d["os_ver"]) for d in dcs])

    def _pwdpolicy(self):
        pol = self.ldap.get_password_policy()
        if not pol:
            console.print("[dim]Sin resultados.[/dim]"); return
        rows = [(k, str(v)) for k, v in pol.items()]
        print_table("Política de contraseñas", ["Parámetro","Valor"], rows)

    def _spns(self):
        spn_accounts = self.ldap.get_spn_accounts()
        if not spn_accounts:
            console.print("[dim]Sin cuentas con SPN.[/dim]"); return
        rows = []
        for a in spn_accounts:
            for spn in a["spns"]:
                rows.append((a["user"], spn))
        print_table(f"SPNs ({len(spn_accounts)} cuentas)", ["Usuario","SPN"], rows)

    def _asrep(self):
        targets = self.ldap.get_asreproastable_users()
        if not targets:
            console.print("[dim]Sin cuentas ASREPRoastables.[/dim]"); return
        print_table("ASREPRoastables", ["Usuario","PwdLastSet","SID"],
                    [(t["user"],t["pwd_last_set"],t["sid"]) for t in targets])

    def _dacl(self, target_dn=""):
        aces = self.ldap.get_interesting_aces(target_dn=target_dn or None)
        if not aces:
            console.print("[dim]Sin ACEs interesantes.[/dim]"); return
        rows = [(ace["object_dn"].split(",")[0].replace("CN=",""),
                 ace["trustee_sid"], ", ".join(ace["rights"]))
                for ace in aces]
        print_table(f"ACEs interesantes ({len(aces)})",
                    ["Objeto","Trustee","Derechos"], rows)

    def _trusts(self):
        # Reutilizar vía búsqueda LDAP directa
        entries = self.ldap._search(
            "(objectClass=trustedDomain)",
            ["name","trustDirection","trustType","securityIdentifier"],
        )
        if not entries:
            console.print("[dim]Sin dominios de confianza.[/dim]"); return
        from modules.ldap import _attr
        rows = [
            (_attr(e,"name","-"),
             {1:"INBOUND",2:"OUTBOUND",3:"BIDIRECTIONAL"}.get(
                 int(_attr(e,"trustDirection","0")),"-"),
             _attr(e,"trustType","-"))
            for e in entries
        ]
        print_table("Trusts", ["Nombre","Dirección","Tipo"], rows)

    def _ous(self):
        entries = self.ldap._search(
            "(objectClass=organizationalUnit)",
            ["distinguishedName","description"],
        )
        if not entries:
            console.print("[dim]Sin OUs.[/dim]"); return
        from modules.ldap import _attr
        rows = [(_attr(e,"distinguishedName","-"), _attr(e,"description","-"))
                for e in entries]
        print_table(f"OUs ({len(entries)})", ["DN","Descripción"], rows)

    def _gpos(self):
        entries = self.ldap._search(
            "(objectClass=groupPolicyContainer)",
            ["displayName","distinguishedName","gPCFileSysPath"],
        )
        if not entries:
            console.print("[dim]Sin GPOs.[/dim]"); return
        from modules.ldap import _attr
        rows = [(_attr(e,"displayName","-"),
                 _attr(e,"gPCFileSysPath","-"))
                for e in entries]
        print_table(f"GPOs ({len(entries)})", ["Nombre","Ruta SYSVOL"], rows)

    def _psos(self):
        psos = self.ldap.get_fine_grained_policies()
        if not psos:
            console.print("[dim]Sin PSOs (o sin permisos para leerlos).[/dim]"); return
        for pso in psos:
            rows = [(k, str(v)) for k, v in pso.items() if k != "applies_to"]
            print_table(f"PSO: {pso['name']}", ["Parámetro","Valor"], rows)

    def _certtemplates(self):
        templates = self.ldap.find_vulnerable_cert_templates()
        if not templates:
            console.print("[dim]Sin plantillas de certificado vulnerables (o AD CS no instalado).[/dim]")
            return
        rows = [(t["name"],
                 "ESC1" if t["esc1"] else "",
                 "ESC3" if t["esc3"] else "")
                for t in templates]
        print_table("Plantillas vulnerables", ["Nombre","ESC1","ESC3"], rows)

    # ------------------------------------------------------------------
    # Comandos de modificación
    # ------------------------------------------------------------------

    def _setattr(self, rest):
        """setattr <DN> <atributo> <valor>"""
        parts = rest.split(None, 2)
        if len(parts) < 3:
            console.print("[red]Uso: setattr <DN> <atributo> <valor>[/red]"); return
        dn, attr, value = parts
        ok = self.ldap._modify(dn, [(attr, "replace", [value])])
        if ok:
            console.print(f"[green]✓ {attr} actualizado en {dn}[/green]")
        else:
            console.print("[red]Fallo en la modificación.[/red]")

    def _addmember(self, rest):
        """addmember <DN_grupo> <DN_usuario>"""
        parts = rest.split(None, 1)
        if len(parts) < 2:
            console.print("[red]Uso: addmember <DN_grupo> <DN_usuario>[/red]"); return
        group_dn, user_dn = parts
        ok = self.ldap._modify(group_dn, [("member", "add", [user_dn])])
        if ok:
            console.print(f"[green]✓ miembro añadido al grupo[/green]")

    def _delmember(self, rest):
        """delmember <DN_grupo> <DN_usuario>"""
        parts = rest.split(None, 1)
        if len(parts) < 2:
            console.print("[red]Uso: delmember <DN_grupo> <DN_usuario>[/red]"); return
        group_dn, user_dn = parts
        ok = self.ldap._modify(group_dn, [("member", "delete", [user_dn])])
        if ok:
            console.print(f"[green]✓ miembro eliminado del grupo[/green]")

    def _setpwd(self, rest):
        """setpwd <DN_usuario> <nueva_contraseña>"""
        parts = rest.split(None, 1)
        if len(parts) < 2:
            console.print("[red]Uso: setpwd <DN_usuario> <nueva_contraseña>[/red]"); return
        dn, new_pwd = parts
        pwd_enc = ('"{}"'.format(new_pwd)).encode("utf-16-le")
        ok = self.ldap._modify(dn, [("unicodePwd", "replace", [pwd_enc])])
        if ok:
            console.print(f"[green]✓ contraseña cambiada[/green]")

    # ------------------------------------------------------------------
    # Help
    # ------------------------------------------------------------------

    def _help(self):
        console.print("""
[bold yellow]═══ LDAP Shell — Comandos disponibles ═══[/bold yellow]

[bold cyan]BÚSQUEDA[/bold cyan]
  [white]search[/white] <filtro> [attrs]        Búsqueda LDAP libre (ej: search (cn=admin) sAMAccountName,mail)
  [white]get[/white] <DN>                       Todos los atributos de un objeto
  [white]basedn[/white] [nuevo_base_dn]         Ver/cambiar el base DN de búsqueda

[bold cyan]ENUMERACIÓN[/bold cyan]
  [white]users[/white] [enabled|disabled|asrep|kerberoast|admins]
  [white]groups[/white] [privileged]
  [white]computers[/white] [undeleg|legacy]
  [white]admins[/white]                         Miembros de grupos privilegiados
  [white]domaininfo[/white]                     Info del dominio (SID, nivel funcional, DCs)
  [white]pwdpolicy[/white]                      Política de contraseñas
  [white]spns[/white]                           Cuentas con SPN (Kerberoastables)
  [white]asrep[/white]                          Cuentas sin preauth (ASREPRoastables)
  [white]dacl[/white] [DN]                      ACEs interesantes (GenericAll, WriteDACL…)
  [white]trusts[/white]                         Dominios de confianza
  [white]ous[/white]                            Unidades organizativas
  [white]gpos[/white]                           Políticas de grupo (GPOs)
  [white]psos[/white]                           Fine-Grained Password Policies
  [white]certtemplates[/white]                  Plantillas AD CS vulnerables (ESC1, ESC3)

[bold cyan]MODIFICACIÓN[/bold cyan]  [dim](requiere permisos)[/dim]
  [white]setattr[/white] <DN> <attr> <valor>    Modifica un atributo
  [white]addmember[/white] <DN_grupo> <DN_user> Añade usuario a grupo
  [white]delmember[/white] <DN_grupo> <DN_user> Elimina usuario de grupo
  [white]setpwd[/white] <DN_user> <password>    Cambia contraseña

[bold cyan]MISC[/bold cyan]
  [white]cls[/white]  /  [white]help[/white]  /  [white]exit[/white]
""")
