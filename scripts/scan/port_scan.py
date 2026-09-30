# scripts/scan/port-scan.py
"""
Scanner de puertos y servicios — powered by lobera-scan (Go).

Escanea rangos de red a alta velocidad usando el binario Go interno.
Detecta automáticamente qué protocolos de Lobera están activos en cada host.

Modos de puertos:
  ad    — Puertos Active Directory (SMB, RPC, LDAP, Kerberos, WinRM, RDP...)  [por defecto]
  all   — Puertos comunes (~60 puertos)
  <lista> — Puertos específicos: 80,443,445 o rango 80-1000

Uso:
  lobera.py scan -t 10.10.10.5
  lobera.py scan -t 10.10.10.0/24
  lobera.py scan -t 10.10.10.1-50 -p all
  lobera.py scan -t 10.10.10.5 -p 445,80,443 --banners
  lobera.py scan -t 10.10.10.0/24 --threads 500 --timeout 300
"""

import json
import subprocess
import shutil
from pathlib import Path
from scripts.base import BaseScript
from core.output import print_result, print_table, console
from core import session_db

# Mapeo puerto → protocolo Lobera
PORT_TO_PROTO = {
    21:   "ftp",
    22:   "ssh",
    80:   "http",
    88:   "kerberos",
    135:  "rpc",
    139:  "smb",
    389:  "ldap",
    443:  "https",
    445:  "smb",
    464:  "kerberos",
    593:  "rpc",
    636:  "ldap",
    1433: "mssql",
    3268: "ldap",
    3269: "ldap",
    3389: "rdp",
    5985: "winrm",
    5986: "winrm",
    9389: "adws",
}

SERVICE_COLORS = {
    "smb":      "green",
    "kerberos": "magenta",
    "rpc":      "blue",
    "ldap":     "yellow",
    "winrm":    "cyan",
    "ssh":      "turquoise2",
    "ftp":      "orange1",
    "mssql":    "bright_red",
    "http":     "bright_cyan",
    "https":    "deep_sky_blue1",
    "rdp":      "violet",
    "adws":     "gold1",
    "unknown":  "dim",
}


class Script(BaseScript):
    name        = "port-scan"
    protocol    = "scan"
    category    = "recon"
    description = (
        "Scanner de puertos y servicios a alta velocidad (Go). "
        "Soporta IPs, CIDR y rangos. Detecta protocolos Lobera activos. "
        "Perfiles: ad (AD ports), all (60 puertos comunes), o lista manual."
    )

    EXAMPLES = [
        {
            "flag":  "-t (CIDR)",
            "desc":  "Escanear toda una subred buscando hosts AD",
            "good":  "lobera.py scan -t 10.10.10.0/24",
            "bad":   "lobera.py scan  [falta -t]",
        },
        {
            "flag":  "--banners",
            "desc":  "Intentar leer banners de servicios abiertos",
            "good":  "lobera.py scan -t 10.10.10.5 --banners",
            "bad":   "",
        },
    ]

    def run(self, **kwargs):
        target   = str(self.target.ip)
        ports    = kwargs.get("ports") or kwargs.get("p") or "ad"
        threads  = kwargs.get("threads") or 200
        timeout  = kwargs.get("timeout") or 500
        banners  = kwargs.get("banners", False)
        closed   = kwargs.get("closed", False)

        # Localizar el binario
        bin_path = self._find_binary()
        if not bin_path:
            console.print("[red]lobera-scan no encontrado. Compilar con:[/red]")
            console.print("  cd src/scanner && go build -o ../../bin/lobera-scan .")
            return

        console.rule(f"[bold yellow]Port Scan — {target}[/bold yellow]")
        console.print(f"  Objetivo : [cyan]{target}[/cyan]")
        console.print(f"  Puertos  : [cyan]{ports}[/cyan]")
        console.print(f"  Threads  : [cyan]{threads}[/cyan]   Timeout: [cyan]{timeout}ms[/cyan]")
        console.print()

        # Construir comando
        cmd = [
            str(bin_path),
            "-t", target,
            "-p", str(ports),
            "-threads", str(threads),
            "-timeout", str(timeout),
        ]
        if banners:
            cmd.append("-banners")
        if closed:
            cmd.append("-closed")

        # Ejecutar
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )
        except subprocess.TimeoutExpired:
            console.print("[red]Timeout global del scanner (>300s)[/red]")
            return
        except Exception as e:
            console.print(f"[red]Error ejecutando lobera-scan: {e}[/red]")
            return

        if result.returncode != 0:
            console.print(f"[red]lobera-scan error: {result.stderr}[/red]")
            return

        # Parsear JSON
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            console.print(f"[red]Output JSON inválido: {e}[/red]")
            console.print(f"[dim]{result.stdout[:500]}[/dim]")
            return

        self._display_results(data)

    # ── Display ───────────────────────────────────────────────────────────────

    def _display_results(self, data: dict):
        hosts    = data.get("hosts") or []
        duration = data.get("duration", "?")
        total    = data.get("total_hosts", 0)
        up       = data.get("up_hosts", 0)

        if not hosts:
            console.print(f"[yellow]No se encontraron hosts activos[/yellow]")
            console.print(f"  Escaneados: {total} hosts en {duration}")
            return

        console.print(f"[bold green]Hosts activos: {up}/{total} en {duration}[/bold green]\n")

        for host in hosts:
            ip   = host["ip"]
            open_ports = host.get("open", [])

            # Detectar protocolos Lobera
            lobera_protos = sorted(set(
                PORT_TO_PROTO.get(p["port"], "") for p in open_ports
                if PORT_TO_PROTO.get(p["port"])
            ))

            proto_str = ""
            if lobera_protos:
                parts = []
                for p in lobera_protos:
                    color = SERVICE_COLORS.get(p, "white")
                    parts.append(f"[{color}]{p}[/{color}]")
                proto_str = "  →  " + " · ".join(parts)

            console.print(f"[bold white]{ip}[/bold white]{proto_str}")

            # Tabla de puertos
            rows = []
            for p in open_ports:
                port    = p["port"]
                service = p.get("service", "unknown")
                banner  = p.get("banner", "")
                color   = SERVICE_COLORS.get(PORT_TO_PROTO.get(port, service), "dim")
                rows.append((
                    str(port),
                    f"[{color}]{service}[/{color}]",
                    banner or "-",
                ))

            print_table(
                "",
                ["Puerto", "Servicio", "Banner"],
                rows,
            )
            console.print()

            # Guardar en session_db
            open_str = ",".join(str(p["port"]) for p in open_ports)
            session_db.save_finding(
                ip, "SCAN", "port_scan",
                f"open={open_str} protos={','.join(lobera_protos)}",
            )

            # Sugerir siguiente paso
            if lobera_protos:
                self._suggest_next(ip, lobera_protos)

    def _suggest_next(self, ip: str, protos: list):
        """Sugiere el siguiente comando lobera según los protocolos detectados."""
        suggestions = []
        if "smb" in protos:
            suggestions.append(f"lobera.py smb -t {ip} --script=null-session")
        if "ldap" in protos:
            suggestions.append(f"lobera.py ldap -t {ip} --script=domain-info")
        if "kerberos" in protos:
            suggestions.append(f"lobera.py kerberos -t {ip} --script=asrep-roasting -d DOMAIN")
        if "winrm" in protos:
            suggestions.append(f"lobera.py winrm -t {ip} -u USER -p PASS")
        if "mssql" in protos:
            suggestions.append(f"lobera.py mssql -t {ip} --script=auth")

        if suggestions:
            console.print(f"  [dim]Siguiente paso:[/dim]")
            for s in suggestions[:3]:
                console.print(f"  [dim cyan]{s}[/dim cyan]")
            console.print()

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _find_binary(self) -> Path | None:
        """Busca lobera-scan en bin/ relativo al proyecto o en PATH."""
        # Relativo al script
        here = Path(__file__).parent
        for candidate in [
            here / "../../bin/lobera-scan",
            here / "../../../bin/lobera-scan",
        ]:
            resolved = candidate.resolve()
            if resolved.exists():
                return resolved

        # PATH del sistema
        which = shutil.which("lobera-scan")
        if which:
            return Path(which)

        return None
