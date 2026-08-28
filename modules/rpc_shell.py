# modules/rpc_shell.py
#
# Consola interactiva RPC — comparable a rpcclient de Samba.
# Comandos disponibles: ver _help() al final del fichero.

import pyfiglet
from core.output import console
from core import session_db

try:
    from modules.rpc import RPCModule
    _RPC_OK = True
except ImportError:
    _RPC_OK = False


class RPCShell:
    """
    Consola interactiva sobre RPCModule.
    Conecta al objetivo y ofrece comandos SAMR/LSA/SRVSVC/WKSSVC/SCM/WINREG.
    """

    def __init__(self, target, creds):
        self.target = target
        self.creds  = creds
        self.rpc    = None

    # ------------------------------------------------------------------
    # Arranque
    # ------------------------------------------------------------------

    def run(self):
        self._mini_banner()

        if not _RPC_OK:
            console.print("[red]modules/rpc.py no disponible.[/red]")
            return

        self.rpc = RPCModule(self.target, self.creds)
        if not self.rpc.connect():
            console.print("[red]No se pudo conectar. Abortando.[/red]")
            return

        console.print("  Escribe [bold]help[/bold] para ver los comandos disponibles.\n")

        while True:
            try:
                raw = console.input(self._prompt()).strip()
            except (EOFError, KeyboardInterrupt):
                console.print("\n[dim]Saliendo de RPC shell...[/dim]")
                break

            if not raw:
                continue

            parts = raw.split(None, 2)
            cmd   = parts[0].lower()
            args  = parts[1:] if len(parts) > 1 else []

            if cmd in ("exit", "quit", "q"):
                break
            elif cmd == "help":
                self._help()
            elif cmd == "cls":
                console.clear()
            # ---- SAMR ----
            elif cmd == "enumdomusers":
                self._enumdomusers()
            elif cmd == "enumdomgroups":
                self._enumdomgroups()
            elif cmd == "queryuser":
                self._queryuser(args)
            elif cmd == "querygroupmem":
                self._querygroupmem(args)
            elif cmd == "querydominfo":
                self._querydominfo()
            elif cmd == "localadmins":
                self._localadmins()
            # ---- LSA ----
            elif cmd == "lsadomaininfo":
                self._lsadomaininfo()
            elif cmd == "lookupsid":
                self._lookupsid(args)
            elif cmd == "lookupname":
                self._lookupname(args)
            elif cmd == "enumpriv":
                self._enumpriv()
            elif cmd == "whohaspriv":
                self._whohaspriv(args)
            elif cmd == "enumtrusts":
                self._enumtrusts()
            elif cmd == "lsasecrets":
                self._lsasecrets()
            # ---- SRVSVC ----
            elif cmd == "srvinfo":
                self._srvinfo()
            elif cmd == "netshareenum":
                self._netshareenum()
            elif cmd == "netsessionenum":
                self._netsessionenum()
            elif cmd == "netopenfiles":
                self._netopenfiles()
            # ---- WKSSVC ----
            elif cmd == "wksinfo":
                self._wksinfo()
            elif cmd == "netloggedon":
                self._netloggedon()
            # ---- SCM ----
            elif cmd == "svcenum":
                self._svcenum(args)
            elif cmd == "svcstart":
                self._svcstart(args)
            elif cmd == "svcstop":
                self._svcstop(args)
            elif cmd == "svccreate":
                self._svccreate(args)
            elif cmd == "svcdelete":
                self._svcdelete(args)
            elif cmd == "exec":
                self._exec(args)
            # ---- WINREG ----
            elif cmd == "regquery":
                self._regquery(args)
            elif cmd == "regenum":
                self._regenum(args)
            elif cmd == "regvals":
                self._regvals(args)
            # ---- EPM ----
            elif cmd == "epm":
                self._epm()
            # ---- RID brute ----
            elif cmd == "ridbrute":
                self._ridbrute(args)
            else:
                console.print(f"[red]Comando desconocido: '{cmd}'[/red]  (escribe help)")

        if self.rpc:
            self.rpc.disconnect()

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------

    def _mini_banner(self):
        art = pyfiglet.figlet_format("RPC Shell", font="small")
        console.print(f"[bold blue]{art}[/bold blue]")
        console.print(
            f"  [bold blue]RPC[/bold blue] → "
            f"[dim]{self.target.ip}[/dim]  "
            f"[dim]usuario: {self.creds.user or 'anónimo'}[/dim]\n"
        )

    def _prompt(self):
        user = self.creds.user or "anon"
        return f"[blue][RPC@{user}][/blue]> "

    # ------------------------------------------------------------------
    # Comandos SAMR
    # ------------------------------------------------------------------

    def _enumdomusers(self):
        users = self.rpc.get_users()
        if not users:
            console.print("[dim]Sin resultados.[/dim]"); return
        from core.output import print_table
        rows = [
            (str(u["rid"]), u["username"], u["full_name"] or "-",
             "[red]No[/red]" if u["disabled"] else "Sí",
             "SÍ" if u["no_preauth"] else "-")
            for u in users
        ]
        print_table(
            f"Usuarios ({len(users)})",
            ["RID","Usuario","Nombre","Activo","NoPreauth"],
            rows,
        )

    def _enumdomgroups(self):
        groups = self.rpc.get_groups()
        if not groups:
            console.print("[dim]Sin resultados.[/dim]"); return
        from core.output import print_table
        print_table(
            f"Grupos ({len(groups)})",
            ["RID","Nombre","Miembros"],
            [(str(g["rid"]), g["name"], str(g["member_count"])) for g in groups],
        )

    def _queryuser(self, args):
        if not args:
            console.print("[red]Uso: queryuser <username>[/red]"); return
        info = self.rpc.get_user_info(args[0])
        if not info:
            console.print("[dim]Usuario no encontrado o acceso denegado.[/dim]"); return
        from core.output import print_table
        rows = [(k, str(v)) for k, v in info.items()]
        print_table(f"Info de {args[0]}", ["Campo","Valor"], rows)

    def _querygroupmem(self, args):
        if not args:
            console.print("[red]Uso: querygroupmem <nombre_grupo>[/red]"); return
        # Buscar RID del grupo
        groups = self.rpc.get_groups()
        group  = next((g for g in groups if g["name"].lower() == args[0].lower()), None)
        if not group:
            console.print(f"[red]Grupo '{args[0]}' no encontrado.[/red]"); return
        console.print(f"Grupo [bold]{group['name']}[/bold] — {group['member_count']} miembro(s)")

    def _querydominfo(self):
        info = self.rpc.get_domain_info()
        if not info:
            console.print("[dim]Sin resultados.[/dim]"); return
        from core.output import print_table
        rows = [(k, str(v)) for k, v in info.items()]
        print_table("Información del dominio", ["Campo","Valor"], rows)

    def _localadmins(self):
        admins = self.rpc.enumerate_local_admins()
        if not admins:
            console.print("[dim]Sin resultados (o acceso denegado).[/dim]"); return
        from core.output import print_table
        print_table("Local Admins", ["SID","Nombre"],
                    [(a["sid"], a["name"]) for a in admins])

    # ------------------------------------------------------------------
    # Comandos LSA
    # ------------------------------------------------------------------

    def _lsadomaininfo(self):
        info = self.rpc.get_lsa_domain_info()
        if not info:
            console.print("[dim]Sin resultados.[/dim]"); return
        from core.output import print_table
        print_table("LSA Domain Info", ["Campo","Valor"],
                    [(k, str(v)) for k, v in info.items()])

    def _lookupsid(self, args):
        if not args:
            console.print("[red]Uso: lookupsid <SID>[/red]"); return
        results = self.rpc.lookup_sids(list(args))
        from core.output import print_table
        print_table("SID → Nombre", ["SID","Nombre","Dominio"],
                    [(r["sid"], r["name"], r["domain"]) for r in results])

    def _lookupname(self, args):
        if not args:
            console.print("[red]Uso: lookupname <nombre>[/red]"); return
        results = self.rpc.lookup_names(list(args))
        from core.output import print_table
        print_table("Nombre → SID", ["Nombre","SID","Dominio"],
                    [(r["name"], r["sid"], r["domain"]) for r in results])

    def _enumpriv(self):
        privs = self.rpc.enumerate_privileges()
        from core.output import print_table
        rows = [
            (p["name"],
             "[bold red]SÍ[/bold red]" if p["interesting"] else "-",
             p["abuse_note"][:50] if p["abuse_note"] else "-")
            for p in privs
        ]
        print_table(f"Privilegios ({len(privs)})",
                    ["Nombre","Abusable","Nota"], rows)

    def _whohaspriv(self, args):
        if not args:
            console.print("[red]Uso: whohaspriv <NombrePrivilegio>[/red]"); return
        holders = self.rpc.enumerate_accounts_with_privilege(args[0])
        if not holders:
            console.print("[dim]Ninguna cuenta con ese privilegio (o acceso denegado).[/dim]")
            return
        from core.output import print_table
        print_table(f"Cuentas con {args[0]}", ["SID","Nombre"],
                    [(h["sid"], h["name"]) for h in holders])

    def _enumtrusts(self):
        trusts = self.rpc.enumerate_trusted_domains()
        if not trusts:
            console.print("[dim]Sin dominios de confianza.[/dim]"); return
        from core.output import print_table
        print_table("Trust Domains", ["Nombre","SID","Dirección","Tipo"],
                    [(t["name"],t["sid"],t["direction"],t["type"]) for t in trusts])

    def _lsasecrets(self):
        console.print("[dim]Intentando volcar secretos LSA (requiere SYSTEM/DA)...[/dim]")
        secrets = self.rpc.get_lsa_secrets()
        if not secrets:
            console.print("[dim]Sin resultados (o acceso denegado).[/dim]"); return
        from core.output import print_table
        print_table("LSA Secrets", ["Key","Data (hex)"],
                    [(s["key_name"], s["secret_bytes_hex"][:64]) for s in secrets])

    # ------------------------------------------------------------------
    # Comandos SRVSVC
    # ------------------------------------------------------------------

    def _srvinfo(self):
        info = self.rpc.get_server_info()
        if not info:
            console.print("[dim]Sin resultados.[/dim]"); return
        from core.output import print_table
        print_table("Server Info", ["Campo","Valor"],
                    [(k, str(v)) for k, v in info.items()])

    def _netshareenum(self):
        shares = self.rpc.get_shares()
        if not shares:
            console.print("[dim]Sin shares.[/dim]"); return
        from core.output import print_table
        print_table("Shares", ["Nombre","Comentario","Tipo"],
                    [(s["name"], s["comment"], str(s["type"])) for s in shares])

    def _netsessionenum(self):
        sessions = self.rpc.get_active_sessions()
        if not sessions:
            console.print("[dim]Sin sesiones activas.[/dim]"); return
        from core.output import print_table
        print_table("Sesiones activas", ["Usuario","Cliente","Tiempo(min)","Idle(min)"],
                    [(s["user"],s["client"],str(s["time_min"]),str(s["idle_min"]))
                     for s in sessions])

    def _netopenfiles(self):
        files = self.rpc.get_open_files()
        if not files:
            console.print("[dim]Sin ficheros abiertos.[/dim]"); return
        from core.output import print_table
        print_table("Ficheros abiertos", ["ID","Usuario","Ruta","Locks"],
                    [(str(f["file_id"]),f["user"],f["path"],str(f["num_locks"]))
                     for f in files])

    # ------------------------------------------------------------------
    # Comandos WKSSVC
    # ------------------------------------------------------------------

    def _wksinfo(self):
        info = self.rpc.get_workstation_info()
        if not info:
            console.print("[dim]Sin resultados.[/dim]"); return
        from core.output import print_table
        print_table("Workstation Info", ["Campo","Valor"],
                    [(k, str(v)) for k, v in info.items()])

    def _netloggedon(self):
        users = self.rpc.get_logged_on_users()
        if not users:
            console.print("[dim]Sin usuarios interactivos.[/dim]"); return
        from core.output import print_table
        print_table("Usuarios interactivos", ["Usuario","Dominio","Servidor"],
                    [(u["username"],u["domain"],u["logon_server"]) for u in users])

    # ------------------------------------------------------------------
    # Comandos SCM
    # ------------------------------------------------------------------

    def _svcenum(self, args):
        running = "--running" in args
        services = self.rpc.list_services()
        if running:
            services = [s for s in services if s["state"] == "RUNNING"]
        if not services:
            console.print("[dim]Sin servicios.[/dim]"); return
        from core.output import print_table
        print_table(f"Servicios ({len(services)})",
                    ["Nombre","Display","Estado"],
                    [(s["name"], s["display_name"][:30], s["state"]) for s in services])

    def _svcstart(self, args):
        if not args:
            console.print("[red]Uso: svcstart <nombre>[/red]"); return
        self.rpc.start_service(args[0])

    def _svcstop(self, args):
        if not args:
            console.print("[red]Uso: svcstop <nombre>[/red]"); return
        self.rpc.stop_service(args[0])

    def _svccreate(self, args):
        # svccreate <nombre> <display> <binary_path>
        if len(args) < 3:
            console.print("[red]Uso: svccreate <nombre> <display> <binary_path>[/red]"); return
        self.rpc.create_service(args[0], args[1], args[2])

    def _svcdelete(self, args):
        if not args:
            console.print("[red]Uso: svcdelete <nombre>[/red]"); return
        self.rpc.delete_service(args[0])

    def _exec(self, args):
        # exec <comando completo>
        if not args:
            console.print("[red]Uso: exec <comando>[/red]"); return
        cmd = " ".join(args)
        self.rpc.exec_via_service(cmd)

    # ------------------------------------------------------------------
    # Comandos WINREG
    # ------------------------------------------------------------------

    def _regquery(self, args):
        # regquery [HKLM|HKCU] <key> <value>
        if len(args) < 3:
            console.print("[red]Uso: regquery <HIVE> <KEY> <VALUE>[/red]"); return
        dtype, data = self.rpc.reg_query(args[0], args[1], args[2])
        if data is not None:
            console.print(f"  [cyan]{args[0]}\\{args[1]}\\{args[2]}[/cyan] = {data!r}")
        else:
            console.print("[dim]No se pudo leer el valor.[/dim]")

    def _regenum(self, args):
        if len(args) < 2:
            console.print("[red]Uso: regenum <HIVE> <KEY>[/red]"); return
        subkeys = self.rpc.reg_enum_keys(args[0], args[1])
        if not subkeys:
            console.print("[dim]Sin subkeys.[/dim]"); return
        for k in subkeys:
            console.print(f"  [cyan]{k}[/cyan]")

    def _regvals(self, args):
        if len(args) < 2:
            console.print("[red]Uso: regvals <HIVE> <KEY>[/red]"); return
        values = self.rpc.reg_enum_values(args[0], args[1])
        if not values:
            console.print("[dim]Sin valores.[/dim]"); return
        from core.output import print_table
        print_table(f"{args[0]}\\{args[1]}", ["Nombre","Tipo","Data (hex)"],
                    [(v["name"], str(v["type"]), v["data"][:16].hex()) for v in values])

    # ------------------------------------------------------------------
    # EPM
    # ------------------------------------------------------------------

    def _epm(self):
        endpoints = self.rpc.enumerate_endpoints()
        if not endpoints:
            console.print("[dim]Sin endpoints (o EPM no accesible).[/dim]"); return
        from core.output import print_table
        print_table(f"RPC Endpoints ({len(endpoints)})",
                    ["UUID","Anotación","Dirección"],
                    [(e["uuid"][:36], e["annotation"][:30], e["address"][:30])
                     for e in endpoints])

    # ------------------------------------------------------------------
    # RID brute
    # ------------------------------------------------------------------

    def _ridbrute(self, args):
        # ridbrute [start] [end]
        start = int(args[0]) if len(args) > 0 else 500
        end   = int(args[1]) if len(args) > 1 else 2000
        console.print(f"[dim]RID brute {start}-{end}...[/dim]")

        from impacket.dcerpc.v5 import samr as _samr
        from impacket.dcerpc.v5.rpcrt import DCERPCException
        from core.output import print_result

        try:
            dce = self.rpc._dce_samr()
            _, dom_h, domain_name, _ = self.rpc._samr_open_domain(dce)
            found = []
            for rid in range(start, end + 1):
                try:
                    resp    = _samr.hSamrRidToSid(dce, dom_h, rid)
                    sid_str = resp["Sid"].formatCanonical()
                    name_info = self.rpc.lookup_sids([sid_str])
                    name = name_info[0]["name"] if name_info else sid_str
                    found.append((rid, name, sid_str))
                    print_result("RPC", str(self.target.ip), "ok",
                                 f"RID {rid} → {name}")
                except DCERPCException:
                    pass
            console.print(f"[dim]{len(found)} cuenta(s) encontrada(s).[/dim]")
        except Exception as exc:
            console.print(f"[red]Error en ridbrute: {exc}[/red]")

    # ------------------------------------------------------------------
    # Help
    # ------------------------------------------------------------------

    def _help(self):
        console.print("""
[bold blue]═══ RPC Shell — Comandos disponibles ═══[/bold blue]

[bold yellow]SAMR[/bold yellow]
  [cyan]enumdomusers[/cyan]                  Enumera usuarios del dominio
  [cyan]enumdomgroups[/cyan]                 Enumera grupos del dominio
  [cyan]queryuser[/cyan] <username>          Detalles de un usuario
  [cyan]querygroupmem[/cyan] <grupo>         Miembros de un grupo
  [cyan]querydominfo[/cyan]                  Info del dominio (política de contraseñas, SID)
  [cyan]localadmins[/cyan]                   Miembros del grupo Administrators local

[bold yellow]LSA[/bold yellow]
  [cyan]lsadomaininfo[/cyan]                 DNS domain, NetBIOS, SID vía LSA
  [cyan]lookupsid[/cyan] <SID>              Resuelve SID → nombre
  [cyan]lookupname[/cyan] <nombre>           Resuelve nombre → SID
  [cyan]enumpriv[/cyan]                      Lista todos los privilegios del sistema
  [cyan]whohaspriv[/cyan] <privilegio>       Quién tiene ese privilegio (ej: SeDebugPrivilege)
  [cyan]enumtrusts[/cyan]                    Dominios de confianza
  [cyan]lsasecrets[/cyan]                    Volcado de secretos LSA (requiere SYSTEM/DA)

[bold yellow]SRVSVC[/bold yellow]
  [cyan]srvinfo[/cyan]                       Información del servidor
  [cyan]netshareenum[/cyan]                  Shares disponibles vía SRVSVC
  [cyan]netsessionenum[/cyan]                Sesiones de red activas
  [cyan]netopenfiles[/cyan]                  Ficheros abiertos en el servidor

[bold yellow]WKSSVC[/bold yellow]
  [cyan]wksinfo[/cyan]                       Información de la workstation
  [cyan]netloggedon[/cyan]                   Usuarios con sesión interactiva

[bold yellow]SCM (Service Control Manager)[/bold yellow]
  [cyan]svcenum[/cyan] [--running]           Lista servicios (--running: solo activos)
  [cyan]svcstart[/cyan] <nombre>             Arranca un servicio
  [cyan]svcstop[/cyan]  <nombre>             Para un servicio
  [cyan]svccreate[/cyan] <nom> <disp> <bin>  Crea un servicio
  [cyan]svcdelete[/cyan] <nombre>            Elimina un servicio
  [cyan]exec[/cyan] <comando>                Ejecuta como SYSTEM (create+start+delete)

[bold yellow]WINREG[/bold yellow]
  [cyan]regquery[/cyan] <HIVE> <KEY> <VAL>   Lee un valor del registro remoto
  [cyan]regenum[/cyan]  <HIVE> <KEY>         Enumera subkeys
  [cyan]regvals[/cyan]  <HIVE> <KEY>         Enumera valores de una key

[bold yellow]MISC[/bold yellow]
  [cyan]epm[/cyan]                            Enumera endpoints RPC (EPM)
  [cyan]ridbrute[/cyan] [start] [end]         RID brute (default: 500-2000)
  [cyan]cls[/cyan]                            Limpia la pantalla
  [cyan]help[/cyan]                           Este menú
  [cyan]exit / quit[/cyan]                    Salir
""")
