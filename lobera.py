#!/usr/bin/env python3
# lobera.py — Consola interactiva estilo Metasploit para Lobera
# Autor: mitr0kerb

import sys
import os
from pathlib import Path

_ROOT = Path(__file__).parent

from core.output import console
from core.session_db import init_db

# ── Banner ────────────────────────────────────────────────────────────────────

def show_banner():
    import pyfiglet
    art = pyfiglet.figlet_format("LOBERA", font="slant")
    console.print(f"[bold cyan]{art}[/bold cyan]")
    console.print("[dim]  AD enumeration & attack toolkit — SMB · RPC · Kerberos · LDAP · WinRM · SSH · SSL · HTTP · HTTPS · FTP · MSSQL · Scan · Listen[/dim]")
    console.print("[dim]  v0.2 — by [/dim][bold cyan]mitr0kerb[/bold cyan]\n")

# ── Colores por módulo ────────────────────────────────────────────────────────

_PROTO_COLORS = {
    "smb":      "green",
    "kerberos": "magenta",
    "rpc":      "blue",
    "ldap":     "yellow",
    "winrm":    "cyan",
    "ssh":      "turquoise2",
    "ssl":      "gold1",
    "http":     "bright_cyan",
    "https":    "deep_sky_blue1",
    "ftp":      "orange1",
    "mssql":    "bright_red",
    "scan":     "white",
    "crack":    "white",
    "listen":   "white",
}

# Lista de módulos disponibles (en orden de presentación)
_MODULOS = [
    "smb", "kerberos", "rpc", "ldap", "winrm",
    "ssh", "ssl", "http", "https", "ftp",
    "mssql", "scan", "crack", "listen",
]

# Binarios disponibles en bin/
_BINS_DISPONIBLES = [
    "lobera-smb", "lobera-kerb", "lobera-scan", "lobera-spray",
    "lobera-winrm", "lobera-crack", "lobera-check", "lobera-exploit",
    "lobera-server",
]

# ── Lectura de scripts disponibles ───────────────────────────────────────────

def _leer_descripcion_script(ruta: Path) -> str:
    """
    Extrae la descripción de un script Python. Busca en orden:
    1. Atributo de clase description = "..."
    2. Primera línea no vacía del docstring del módulo
    Devuelve cadena vacía si no encuentra nada.
    """
    try:
        with open(ruta, encoding="utf-8", errors="replace") as f:
            contenido = f.read(4096)

        import ast, re

        # 1) Buscar patrón: description = "texto" o description = ("texto" ...)
        #    Captura la primera cadena que aparezca tras el signo =
        m = re.search(r'description\s*=\s*[\(\s]*["\']([^"\']{5,})["\']', contenido)
        if m:
            return m.group(1).strip()

        # 2) Fallback: docstring del módulo
        try:
            arbol = ast.parse(contenido)
        except SyntaxError:
            return ""
        for nodo in arbol.body:
            if isinstance(nodo, ast.Expr) and isinstance(nodo.value, ast.Constant):
                doc = nodo.value.value
                if isinstance(doc, str):
                    for linea in doc.splitlines():
                        linea = linea.strip()
                        if linea:
                            return linea
            break  # sólo primer stmt

    except Exception:
        pass
    return ""


def _listar_scripts_modulo(modulo: str) -> dict:
    """
    Busca en scripts/<modulo>/ y devuelve un dict:
      {subcarpeta: [(nombre_sin_ext, descripcion), ...]}
    """
    scripts_dir = _ROOT / "scripts" / modulo
    resultado = {}

    if not scripts_dir.exists():
        return resultado

    # Recorremos sólo las subcarpetas directas (enum/, attack/, etc.)
    for entrada in sorted(scripts_dir.iterdir()):
        if not entrada.is_dir():
            continue
        if entrada.name.startswith("_") or entrada.name == "__pycache__":
            continue

        scripts = []
        for fichero in sorted(entrada.iterdir()):
            if fichero.suffix == ".py" and not fichero.name.startswith("_"):
                desc = _leer_descripcion_script(fichero)
                scripts.append((fichero.stem, desc))

        if scripts:
            resultado[entrada.name] = scripts

    return resultado


# ── Listado de módulos ────────────────────────────────────────────────────────

def _mostrar_modulos():
    """Imprime la tabla de módulos disponibles con sus colores."""
    console.print("\n[bold]Módulos disponibles:[/bold]\n")
    for modulo in _MODULOS:
        color = _PROTO_COLORS.get(modulo, "white")
        console.print(f"  [{color}]{modulo:<12}[/{color}]", end="")
    console.print("\n")


# ── Ayuda principal ───────────────────────────────────────────────────────────

def _mostrar_ayuda_principal():
    console.print("""
[bold]Comandos disponibles:[/bold]

  [cyan]use <módulo>[/cyan]     — Entra en la consola del módulo (smb, kerberos, rpc...)
  [cyan]modules[/cyan]          — Lista los módulos disponibles
  [cyan]clear / cls[/cyan]      — Limpia la pantalla
  [cyan]help[/cyan]             — Muestra esta ayuda
  [cyan]exit / quit[/cyan]      — Sale de Lobera
  [dim]Ctrl+L[/dim]             — Limpia la pantalla
  [dim]Ctrl+C[/dim]             — Sale de Lobera
""")


# ── Ayuda del módulo ──────────────────────────────────────────────────────────

def _mostrar_ayuda_modulo(modulo: str):
    color = _PROTO_COLORS.get(modulo, "white")
    console.print(f"""
[bold]Comandos en el módulo [{color}]{modulo}[/{color}]:[/bold]

  [cyan]list scripts[/cyan]   — Lista los scripts disponibles con descripción
  [cyan]clear / cls[/cyan]    — Limpia la pantalla
  [cyan]back[/cyan]           — Vuelve al prompt principal
  [cyan]help[/cyan]           — Muestra esta ayuda
  [cyan]exit / quit[/cyan]    — Sale de Lobera
  [dim]Ctrl+L[/dim]           — Limpia la pantalla
""")


# ── Consola del módulo ────────────────────────────────────────────────────────

def _consola_modulo(modulo: str):
    """Bucle interactivo dentro de un módulo concreto."""
    color = _PROTO_COLORS.get(modulo, "white")
    prompt_modulo = f"lobera [{color}]{modulo}[/{color}]"

    console.print(f"\n[dim]Entrando en módulo [{color}]{modulo}[/{color}]. Escribe 'help' para ver comandos.[/dim]\n")

    while True:
        try:
            linea = _leer_input(f"lobera [[{color}]{modulo}[/{color}]] > ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Volviendo al prompt principal...[/dim]")
            break

        if not linea:
            continue

        partes = linea.split(maxsplit=1)
        cmd = partes[0].lower()
        resto = partes[1].strip() if len(partes) > 1 else ""

        if cmd in ("exit", "quit"):
            console.print("[dim]Saliendo de Lobera...[/dim]")
            sys.exit(0)

        elif cmd == "back":
            break

        elif cmd in ("clear", "cls"):
            _limpiar_pantalla()

        elif cmd == "help":
            _mostrar_ayuda_modulo(modulo)

        elif cmd == "list" and resto == "scripts":
            _mostrar_scripts_modulo(modulo)

        elif cmd == "list":
            console.print(f"[yellow]¿Quizás quisiste decir 'list scripts'?[/yellow]")

        else:
            console.print(f"[red]Comando desconocido: {cmd}[/red]  (escribe 'help' para ver comandos)")


def _mostrar_scripts_modulo(modulo: str):
    """Imprime los scripts del módulo agrupados por subcarpeta, con descripción."""
    color = _PROTO_COLORS.get(modulo, "white")
    scripts = _listar_scripts_modulo(modulo)

    if not scripts:
        console.print(f"[yellow]No se encontraron scripts para el módulo '{modulo}'.[/yellow]")
        console.print(f"[dim]Ruta buscada: scripts/{modulo}/[/dim]")
        return

    from rich.table import Table
    from rich import box

    console.print(f"\n[bold]Scripts disponibles — [{color}]{modulo}[/{color}]:[/bold]\n")
    for subcarpeta, scripts_lista in scripts.items():
        console.print(f"  [bold dim]{subcarpeta}/[/bold dim]")
        t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2), show_edge=False)
        t.add_column("nombre", style=f"bold {color}", no_wrap=True, min_width=28)
        t.add_column("desc",   style="dim")
        for nombre, desc in scripts_lista:
            t.add_row(nombre, desc if desc else "")
        console.print(t)
    console.print()


# ── Limpiar pantalla ─────────────────────────────────────────────────────────

def _limpiar_pantalla():
    """Limpia la terminal de forma portable."""
    os.system("clear" if os.name != "nt" else "cls")


# ── Input interactivo ─────────────────────────────────────────────────────────

def _rich_a_ansi(markup: str) -> str:
    """
    Convierte markup de Rich a una cadena ANSI plana.
    force_terminal=True para que emita colores aunque stdout no sea TTY.
    """
    from io import StringIO
    from rich.console import Console as _Console
    buf = StringIO()
    c = _Console(file=buf, highlight=False, markup=True, force_terminal=True)
    c.print(markup, end="")
    return buf.getvalue()


def _ansi_para_readline(texto_ansi: str) -> str:
    """
    Envuelve cada secuencia de escape ANSI en \\001...\\002 para que
    readline calcule correctamente el ancho visible del prompt.
    Sin esto, Ctrl+L redibuja el prompt desplazado hacia la derecha.
    """
    import re
    # Patrón estándar de secuencias de escape ANSI
    return re.sub(r'(\x1b\[[0-9;]*[mK])', r'\001\1\002', texto_ansi)


def _leer_input(prompt_rich: str) -> str:
    """
    Lee una línea de input con readline.
    - Convierte markup Rich → ANSI → envuelto en \\001\\002
    - Ctrl+L limpia la pantalla y redibuja el prompt correctamente
    - Historial de comandos dentro de la sesión
    """
    try:
        import readline
        readline.parse_and_bind(r'"\C-l": clear-screen')
    except ImportError:
        pass

    prompt_ansi = _rich_a_ansi(prompt_rich)
    prompt_rl   = _ansi_para_readline(prompt_ansi)

    try:
        return input(prompt_rl)
    except EOFError:
        raise


# ── Consola principal ─────────────────────────────────────────────────────────

def _consola_principal():
    """Bucle principal de la consola interactiva estilo Metasploit."""

    # Mensaje informativo sobre binarios directos
    bins_str = "  ".join(_BINS_DISPONIBLES)
    console.print(
        "[dim]Modo interactivo — para uso directo usa los comandos: "
        + "  ".join(_BINS_DISPONIBLES)
        + "[/dim]"
    )

    _mostrar_modulos()
    console.print("[dim]Escribe 'help' para ver los comandos disponibles.[/dim]\n")

    while True:
        try:
            linea = _leer_input("lobera [bold cyan]>[/bold cyan] ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Saliendo...[/dim]")
            break

        if not linea:
            continue

        partes = linea.split(maxsplit=1)
        cmd = partes[0].lower()
        resto = partes[1].strip() if len(partes) > 1 else ""

        if cmd in ("exit", "quit"):
            console.print("[dim]Hasta la próxima.[/dim]")
            break

        elif cmd in ("clear", "cls"):
            _limpiar_pantalla()

        elif cmd == "help":
            _mostrar_ayuda_principal()

        elif cmd == "modules":
            _mostrar_modulos()

        elif cmd == "use":
            if not resto:
                console.print("[red]Uso: use <módulo>[/red]  (ej: use smb, use kerberos)")
                continue
            modulo = resto.lower()
            if modulo not in _MODULOS:
                console.print(f"[red]Módulo desconocido: '{modulo}'[/red]")
                console.print(f"[dim]Módulos disponibles: {', '.join(_MODULOS)}[/dim]")
                continue
            _consola_modulo(modulo)

        else:
            console.print(f"[red]Comando desconocido: {cmd}[/red]  (escribe 'help' para ver comandos)")


# ── Tablas de shells / scanners (mantenidas para compatibilidad) ──────────────

_SHELL_CLASSES = {
    "smb":      ("modules.smb_script_shell",      "SMBScriptShell"),
    "kerberos": ("modules.kerberos_script_shell",  "KerberosScriptShell"),
    "rpc":      ("modules.rpc_script_shell",       "RPCScriptShell"),
    "ldap":     ("modules.ldap_script_shell",      "LDAPScriptShell"),
    "winrm":    ("modules.winrm_script_shell",     "WinRMScriptShell"),
    "ssh":      ("modules.ssh_script_shell",       "SSHScriptShell"),
    "ssl":      ("modules.ssl_script_shell",       "SSLScriptShell"),
    "http":     ("modules.http_script_shell",      "HTTPScriptShell"),
    "https":    ("modules.https_script_shell",     "HTTPSScriptShell"),
    "ftp":      ("modules.ftp_script_shell",       "FTPScriptShell"),
    "mssql":    ("modules.mssql_script_shell",     "MSSQLScriptShell"),
}

_SCANNER_FUNCS = {
    "smb":      ("scripts.smb.scanner",       "run_smb_scanner"),
    "kerberos": ("scripts.kerberos.scanner",  "run_kerberos_scanner"),
    "rpc":      ("scripts.rpc.scanner",       "run_rpc_scanner"),
    "ldap":     ("scripts.ldap.scanner",      "run_ldap_scanner"),
    "winrm":    ("scripts.winrm.scanner",     "run_winrm_scanner"),
    "ssh":      ("scripts.ssh.scanner",       "run_ssh_scanner"),
    "ssl":      ("scripts.ssl.scanner",       "run_ssl_scanner"),
    "http":     ("scripts.http.scanner",      "run_http_scanner"),
    "https":    ("scripts.https.scanner",     "run_https_scanner"),
    "ftp":      ("scripts.ftp.scanner",       "run_ftp_scanner"),
    "mssql":    ("scripts.mssql.scanner",     "run_mssql_scanner"),
}

# ── Dispatcher genérico (conservado para uso directo desde otros módulos) ─────

def _run_proto_single(protocol, args):
    """Ejecuta el protocolo contra un único objetivo ya fijado en args.target."""
    root  = _ROOT
    color = _PROTO_COLORS.get(protocol, "white")

    scanner     = getattr(args, "scanner",           False)
    inter_shell = getattr(args, "interactive_shell", False)
    script      = getattr(args, "script",            None)
    script_fam  = getattr(args, "script_fam",        None)

    if scanner:
        mod_name, func_name = _SCANNER_FUNCS[protocol]
        mod  = __import__(mod_name, fromlist=[func_name])
        func = getattr(mod, func_name)
        func(args)
        return

    if inter_shell:
        mod_name, cls_name = _SHELL_CLASSES[protocol]
        mod = __import__(mod_name, fromlist=[cls_name])
        cls = getattr(mod, cls_name)
        cls(root).run()
        return

    from modules.classic import list_scripts, run_script, run_script_family

    if script:
        run_script(protocol, script, root, color, args)
        return

    if script_fam:
        run_script_family(protocol, script_fam, root, color, args)
        return

    # Sin flags: listar scripts
    list_scripts(protocol, root, color)


def _run_proto(protocol, args):
    """
    Punto de entrada principal. Si -t contiene CIDR/rango/lista, expande
    los objetivos y los procesa en paralelo con --workers hilos.
    """
    from core.cidr import expand_targets
    import copy
    from concurrent.futures import ThreadPoolExecutor, as_completed

    raw_target = getattr(args, "target", None)
    targets    = expand_targets(raw_target)

    # Sin expansión (IP única o hostname sin CIDR): ruta directa
    if not targets or len(targets) == 1:
        if targets:
            args.target = targets[0]
        _run_proto_single(protocol, args)
        return

    # Modo multi-objetivo
    workers = int(getattr(args, "workers", None) or 1)
    console.print(
        f"[bold]Modo batch:[/bold] {len(targets)} objetivo(s) · {workers} hilo(s)"
    )

    def _run_one(ip):
        args_copy = copy.copy(args)
        args_copy.target = ip
        _run_proto_single(protocol, args_copy)

    if workers == 1:
        for ip in targets:
            _run_one(ip)
    else:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {pool.submit(_run_one, ip): ip for ip in targets}
            for fut in as_completed(futs):
                ip = futs[fut]
                try:
                    fut.result()
                except Exception as exc:
                    console.print(f"[red]Error en {ip}: {exc}[/red]")


# ── Funciones por protocolo (conservadas) ─────────────────────────────────────

def run_report(args):
    from core.report import generate_report
    target = getattr(args, "target", None)
    fmt    = getattr(args, "format", "html") or "html"
    output = getattr(args, "output", None)
    path   = generate_report(target_ip=target, fmt=fmt, output=output)
    console.print(f"[bold green]Informe generado:[/bold green] {path}")


def run_completion(args):
    """Muestra instrucciones de instalación del autocompletado."""
    shell  = getattr(args, "shell", "bash") or "bash"
    lobera_dir = os.path.dirname(os.path.abspath(__file__))
    comp_dir   = os.path.join(lobera_dir, "tools", "completions")

    if shell == "bash":
        src = os.path.join(comp_dir, "lobera_completion.bash")
        console.print(f"\n[bold cyan]Autocompletado Bash[/bold cyan]")
        console.print(f"  Añade esta línea a tu [bold]~/.bashrc[/bold]:")
        console.print(f"  [bold yellow]source {src}[/bold yellow]\n")
        console.print(f"  O actívalo solo para esta sesión:")
        console.print(f"  [bold yellow]source {src}[/bold yellow]\n")
    elif shell == "zsh":
        src = os.path.join(comp_dir, "lobera_completion.zsh")
        console.print(f"\n[bold cyan]Autocompletado Zsh[/bold cyan]")
        console.print(f"  Copia el fichero a la carpeta de funciones Zsh:")
        console.print(f"  [bold yellow]cp {src} /usr/local/share/zsh/site-functions/_lobera[/bold yellow]")
        console.print(f"  [bold yellow]autoload -Uz compinit && compinit[/bold yellow]")
        console.print(f"  O actívalo solo para esta sesión:")
        console.print(f"  [bold yellow]source {src}[/bold yellow]\n")
    else:
        console.print(f"[red]Shell no soportado: {shell}. Usa 'bash' o 'zsh'.[/red]")


def run_smb(args):      _run_proto("smb",      args)
def run_kerberos(args): _run_proto("kerberos", args)
def run_rpc(args):      _run_proto("rpc",      args)
def run_ldap(args):     _run_proto("ldap",     args)
def run_winrm(args):    _run_proto("winrm",    args)
def run_ssh(args):      _run_proto("ssh",      args)
def run_ssl(args):      _run_proto("ssl",      args)
def run_http(args):     _run_proto("http",     args)
def run_https(args):    _run_proto("https",    args)
def run_ftp(args):      _run_proto("ftp",      args)
def run_mssql(args):    _run_proto("mssql",    args)


def run_exploit(args):
    """Redirige a lobera-exploit (binario especializado)."""
    sub = getattr(args, "exploit_module", None)

    if sub == "ms17010":
        console.print("[cyan]Usa [bold]lobera-check[/bold] para MS17-010 o [bold]lobera-exploit[/bold] para lanzar exploits desde BD.[/cyan]")
        console.print("[dim]  lobera-check --target IP --port 445[/dim]")
        console.print("[dim]  lobera-exploit --target IP --vuln MS17-010 --payload cmd --cmd whoami[/dim]")
    else:
        console.print("[yellow]Usa los binarios especializados:[/yellow]")
        console.print("  [bold]lobera-check[/bold]    — detecta MS17-010 y otros CVEs")
        console.print("  [bold]lobera-exploit[/bold]  — lanza exploits (--target+--vuln | --from-db)")
        console.print("\n[dim]Estos comandos reemplazaron al antiguo 'lobera exploit'.[/dim]")


def run_crack(args):
    """Dispatcher para el cracker offline (Rust binary)."""
    from core.target import Target
    from core.credentials import Credentials
    from scripts.crack.hash_crack import Script

    target = Target(ip="localhost")
    creds  = Credentials()
    script = Script(target=target, creds=creds)
    script.run(args)


def run_scan(args):
    """Dispatcher para el módulo scan (Go binary)."""
    from core.target import Target
    from core.credentials import Credentials
    from scripts.scan.port_scan import Script

    target_str = getattr(args, "target", None) or getattr(args, "t", None)
    if not target_str:
        console.print("[red]Falta -t <objetivo>[/red]")
        console.print("  Ejemplos:")
        console.print("    lobera.py scan -t 10.10.10.5")
        console.print("    lobera.py scan -t 10.10.10.0/24")
        console.print("    lobera.py scan -t 10.10.10.1-50 -p all")
        return

    target = Target(ip=target_str)
    creds  = Credentials()
    script = Script(target=target, creds=creds)
    script.run(
        ports   = getattr(args, "ports",   None),
        threads = getattr(args, "threads", 200),
        timeout = getattr(args, "scan_timeout", 500),
        banners = getattr(args, "banners", False),
        closed  = getattr(args, "closed",  False),
    )


def run_listen(args):
    """Arranca el handler/listener para reverse shells."""
    from scripts.listener.handler import Handler

    port     = getattr(args, "port",  4444)
    ltype    = getattr(args, "type",  "tcp")
    certfile = getattr(args, "cert",  None)
    multi    = getattr(args, "multi", False)
    log_file = getattr(args, "log",   None)

    h = Handler(port, ltype, certfile, multi, log_file)
    h.start()


def run_amsi(args):
    """Wrapper Python para el binario AMSI/ETW bypass (C)."""
    import subprocess, json

    bin_path = os.path.join(os.path.dirname(__file__), "bin", "lobera-amsi-bypass.exe")
    if not os.path.isfile(bin_path):
        console.print(f"[red]Binario no encontrado: {bin_path}[/red]")
        console.print("[dim]Compila primero: cd src/exploits && make windows[/dim]")
        console.print("\n[yellow]Instrucciones manuales:[/yellow]")
        console.print("  1. Compila en Windows o cross-compila con mingw:")
        console.print("     x86_64-w64-mingw32-gcc -O2 -o lobera-amsi-bypass.exe src/exploits/amsi/amsi_bypass.c -lkernel32")
        console.print("  2. Transfiere lobera-amsi-bypass.exe al objetivo Windows")
        console.print("  3. Ejecuta: lobera-amsi-bypass.exe --patch-amsi [--patch-etw] [--check]")
        return

    cmd = [bin_path]
    if getattr(args, "patch_amsi", False): cmd.append("--patch-amsi")
    if getattr(args, "patch_etw",  False): cmd.append("--patch-etw")
    if getattr(args, "check",      False): cmd.append("--check")
    if getattr(args, "delay",      False): cmd.append("--delay")
    delay_ms = getattr(args, "delay_ms", 5000)
    if delay_ms != 5000: cmd += ["--delay-ms", str(delay_ms)]
    load_dll = getattr(args, "load_dll", None)
    if load_dll: cmd += ["--load", load_dll]

    if len(cmd) == 1:
        console.print("[yellow]Especifica al menos una opción:[/yellow]")
        console.print("  --patch-amsi   Parchear AmsiScanBuffer")
        console.print("  --patch-etw    Silenciar ETW (NtTraceEvent)")
        console.print("  --check        Verificar si AMSI está activo")
        console.print("  --delay        Delay de evasión de sandbox")
        console.print("  --load DLL     Cargar DLL reflectiva")
        return

    console.print(f"  [dim]Ejecutando: {' '.join(cmd)}[/dim]")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.stdout:
        try:
            data = json.loads(result.stdout)
            for k, v in data.items():
                color = "green" if v is True else ("red" if v is False else "dim")
                console.print(f"  [{color}]{k}[/{color}]: {v}")
        except json.JSONDecodeError:
            console.print(result.stdout)
    if result.stderr:
        console.print(f"  [dim]{result.stderr.strip()}[/dim]")


# ── db ────────────────────────────────────────────────────────────────────────

def run_db(args):
    from core.session_db import (get_targets, get_findings,
                                  get_credentials, delete_target)
    from core.output import print_table

    action = getattr(args, "db_action", None)

    if action == "targets":
        targets = get_targets()
        if not targets:
            console.print("[yellow]No hay ningún objetivo guardado.[/yellow]")
            return
        rows = [(t["ip"], t["domain"] or "-", t["hostname"] or "-", t["first_seen"])
                for t in targets]
        print_table("Objetivos vistos", ["IP", "Dominio", "Hostname", "Primera vez"], rows)

    elif action == "findings":
        if not args.target:
            console.print("[red]Falta -t/--target.[/red]"); return
        findings = get_findings(args.target)
        if getattr(args, "protocol", None):
            findings = [f for f in findings if f["protocol"] == args.protocol]
        if not findings:
            console.print(f"[yellow]Sin hallazgos para {args.target}.[/yellow]"); return
        rows = [(f["protocol"], f["finding_type"], f["detail"], f["timestamp"])
                for f in findings]
        print_table(f"Hallazgos para {args.target}",
                    ["Protocolo", "Tipo", "Detalle", "Timestamp"], rows)

    elif action == "creds":
        if not args.target:
            console.print("[red]Falta -t/--target.[/red]"); return
        creds = get_credentials(args.target, only_valid=not getattr(args, "all", False))
        if not creds:
            console.print(f"[yellow]Sin credenciales para {args.target}.[/yellow]"); return
        show_secret = getattr(args, "show_secret", False)
        rows = []
        for c in creds:
            secret = c["secret"] if show_secret else ("*" * 8 if c["secret"] else "")
            rows.append((c["user"] or "(vacío)", secret, c["secret_type"],
                         "Sí" if c["valid"] else "No", c["source"], c["timestamp"]))
        print_table(f"Credenciales para {args.target}",
                    ["Usuario", "Secreto", "Tipo", "Válida", "Origen", "Timestamp"], rows)
        if not show_secret:
            console.print("[dim]Secretos ocultos. Usa --show-secret para verlos.[/dim]")

    elif action == "delete":
        if not args.target:
            console.print("[red]Falta -t/--target.[/red]"); return
        findings = get_findings(args.target)
        creds    = get_credentials(args.target, only_valid=False)
        targets  = [t for t in get_targets() if t["ip"] == args.target]
        if not targets and not findings and not creds:
            console.print(f"[yellow]Nada guardado para {args.target}.[/yellow]"); return
        console.print(f"[bold red]Vas a borrar TODO para {args.target}:[/bold red]")
        console.print(f"  • {len(targets)} target(s)")
        console.print(f"  • {len(creds)} credencial(es)")
        console.print(f"  • {len(findings)} finding(s)")
        console.print("[bold red]Irreversible.[/bold red]\n")
        if not getattr(args, "yes", False):
            answer = console.input("¿Estás seguro? Escribe [bold]sí[/bold]: ").strip().lower()
            if answer not in ("si", "sí", "s", "yes", "y"):
                console.print("[yellow]Cancelado.[/yellow]"); return
        counts = delete_target(args.target)
        console.print(f"[green]Borrado: {sum(counts.values())} fila(s) eliminadas.[/green]")

    else:
        console.print("[yellow]Acciones disponibles: targets, findings, creds, delete[/yellow]")
        console.print("[dim]lobera.py db <acción> -h[/dim]")


# ── Parser (conservado para modo CLI directo) ─────────────────────────────────

def _add_proto_flags(p):
    """
    Flags de modo (cómo lanzar el módulo) + todos los parámetros posibles
    de todos los scripts, para que el modo clásico los pueda recibir por CLI.
    """
    # ── modos ────────────────────────────────────────────────────────────────
    p.add_argument("--scanner",           action="store_true",
                   help="Autopwn scanner interactivo")
    p.add_argument("--interactive-shell", action="store_true",
                   dest="interactive_shell",
                   help="Consola interactiva de scripts")
    p.add_argument("--script",     default=None, metavar="NOMBRE",
                   help="Ejecuta un script por nombre")
    p.add_argument("--script-fam", default=None, metavar="FAMILIA",
                   dest="script_fam",
                   help="Ejecuta toda una familia de scripts")

    # ── credenciales / target base ────────────────────────────────────────────
    p.add_argument("-t", "--target",   default=None,   help="IP/hostname del objetivo")
    p.add_argument("-u", "--user",     default=None,   help="Usuario")
    p.add_argument("-p", "--password", default=None,   help="Contraseña")
    p.add_argument("-H", "--hash",     default=None,   help="Hash NT (pass-the-hash)")
    p.add_argument("-d", "--domain",   default=None,   help="Dominio FQDN")
    p.add_argument("--timeout",        default=None, type=int, help="Timeout (segundos)")

    # ── red / servicio ────────────────────────────────────────────────────────
    p.add_argument("--port",           default=None, type=int, help="Puerto del servicio")
    p.add_argument("--instance",       default=None,   help="Nombre de instancia (MSSQL)")
    p.add_argument("--ldaps",          action="store_true", default=False, help="Usar LDAPS")
    p.add_argument("--ssl",            action="store_true", default=False, help="Usar SSL")
    p.add_argument("--sni",            default=None,   help="Server Name Indication (HTTPS)")
    p.add_argument("--http-port",      default=None, type=int, dest="http_port",
                   help="Puerto HTTP (para TLS stripping)")

    # ── ficheros / listas ─────────────────────────────────────────────────────
    p.add_argument("--userlist",       default=None,   help="Wordlist de usuarios")
    p.add_argument("--passlist",       default=None,   help="Wordlist de passwords")
    p.add_argument("--wordlist",       default=None,   help="Wordlist genérica (dir brute, etc.)")

    # ── SMB específico ────────────────────────────────────────────────────────
    p.add_argument("--share",          default=None,   help="Share SMB concreto")
    p.add_argument("--ext",            default=None,   help="Extensiones a buscar (ej: .txt,.kdbx)")
    p.add_argument("--keywords",       default=None,   help="Palabras clave en nombres de fichero")
    p.add_argument("--depth",          default=None, type=int, help="Profundidad de recursión")

    # ── Kerberos específico ───────────────────────────────────────────────────
    p.add_argument("--spn",            default=None,   help="SPN objetivo (ej: cifs/DC01.CORP.LOCAL)")
    p.add_argument("--ccache",         default=None,   help="Ruta al fichero .ccache")
    p.add_argument("--kirbi",          default=None,   help="Ruta al fichero .kirbi")
    p.add_argument("--krbtgt-hash",    default=None, dest="krbtgt_hash",
                   help="Hash NT del krbtgt")
    p.add_argument("--service-hash",   default=None, dest="service_hash",
                   help="Hash NT de la cuenta de servicio")
    p.add_argument("--domain-sid",     default=None, dest="domain_sid",
                   help="SID del dominio (S-1-5-21-...)")
    p.add_argument("--user-id",        default=None, type=int, dest="user_id",
                   help="RID del usuario a impersonar (default: 500)")
    p.add_argument("--groups",         default=None,
                   help="RIDs de grupos separados por coma")
    p.add_argument("--target-user",    default=None, dest="target_user",
                   help="Usuario objetivo a impersonar")
    p.add_argument("--target-computer",default=None, dest="target_computer",
                   help="Nombre del equipo objetivo")
    p.add_argument("--attacker-account",default=None, dest="attacker_account",
                   help="Cuenta controlada por el atacante")
    p.add_argument("--cert",           default=None,   help="Ruta al certificado .pem")
    p.add_argument("--pfx",            default=None,   help="Ruta al certificado .pfx")
    p.add_argument("--template",       default=None,   help="Plantilla ADCS")
    p.add_argument("--ca",             default=None,   help="CA authority (ej: CORP-CA)")
    p.add_argument("--alt-name",       default=None, dest="alt_name",
                   help="Nombre alternativo para el certificado")
    p.add_argument("--dc-name",        default=None, dest="dc_name",
                   help="Nombre del DC (para noPac)")
    p.add_argument("--user-sid",       default=None, dest="user_sid",
                   help="SID del usuario (para ms14-068)")
    p.add_argument("--vector",         default=None,
                   help="Vector de ataque (kerber-loss)")
    p.add_argument("--new-password",   default=None, dest="new_password",
                   help="Nueva contraseña a establecer")

    # ── LDAP específico ───────────────────────────────────────────────────────
    p.add_argument("--target-dn",      default=None, dest="target_dn",
                   help="DN del objeto LDAP objetivo")
    p.add_argument("--target-obj",     default=None, dest="target_obj",
                   help="DN/sAMAccountName objetivo (acl-abuse)")
    p.add_argument("--out-dir",        default=None, dest="out_dir",
                   help="Directorio de salida (bloodhound)")
    p.add_argument("--save-list",      default=None, dest="save_list",
                   help="Ruta para guardar lista resultante")
    p.add_argument("--filter-flag",    default=None, dest="filter_flag",
                   help="Filtro por flag UAC")
    p.add_argument("--enabled-only",   action="store_true", default=False,
                   dest="enabled_only", help="Solo cuentas habilitadas")
    p.add_argument("--privileged-only",action="store_true", default=False,
                   dest="privileged_only", help="Solo grupos privilegiados")
    p.add_argument("--os-filter",      default=None, dest="os_filter",
                   help="Filtro por sistema operativo")
    p.add_argument("--undeleg",        action="store_true", default=False,
                   help="Solo equipos con delegación sin restricciones")
    p.add_argument("--action",         default=None,
                   help="Acción ACL (detect/reset-password/add-member/...)")
    p.add_argument("--source-user",    default=None, dest="source_user",
                   help="Usuario origen del ACE")
    p.add_argument("--save-key",       default=None, dest="save_key",
                   help="Ruta para guardar clave privada (shadow-creds)")
    p.add_argument("--mode",           default=None,
                   help="Modo relay (add-da/rbcd/dump/shadow-creds)")
    p.add_argument("--relay-target-user", default=None, dest="relay_target_user",
                   help="Usuario objetivo del relay")
    p.add_argument("--continue-on-lockout", action="store_true", default=False,
                   dest="continue_on_lockout",
                   help="Continuar aunque se detecte lockout")

    # ── MSSQL específico ──────────────────────────────────────────────────────
    p.add_argument("--command",        default=None,
                   help="Comando OS a ejecutar (xp_cmdshell)")
    p.add_argument("--query",          default=None,
                   help="Query SQL arbitraria")
    p.add_argument("--attacker-ip",    default=None, dest="attacker_ip",
                   help="IP del atacante (NTLM steal)")

    # ── Spray / rate-limiting ─────────────────────────────────────────────────
    p.add_argument("--delay",          default=None, type=float,
                   help="Delay fijo entre intentos de spray (segundos)")
    p.add_argument("--jitter",         default=None, type=float,
                   help="Variación aleatoria adicional al delay (0..N segundos)")

    # ── Modo batch / CIDR ─────────────────────────────────────────────────────
    p.add_argument("--workers",        default=1, type=int,
                   help="Hilos paralelos en modo batch/CIDR (default: 1)")

    # ── Dry-run ───────────────────────────────────────────────────────────────
    p.add_argument("--dry-run",        action="store_true", dest="dry_run",
                   help="Simular: mostrar lo que se ejecutaría sin hacerlo")

    # ── HTTP/HTTPS específico ─────────────────────────────────────────────────
    p.add_argument("--path",           default=None,
                   help="Ruta HTTP inicial (default: /)")
    p.add_argument("--param",          default=None,
                   help="Parámetro a inyectar (sqli, xss, lfi, ssrf)")
    p.add_argument("--listener",       default=None,
                   help="Dominio OOB para log4shell")
    p.add_argument("--client-id",      default=None, dest="client_id",
                   help="Client ID OAuth (oauth-misconfig)")
    p.add_argument("--max-depth",      default=None, type=int, dest="max_depth",
                   help="Profundidad máxima de crawling")
    p.add_argument("--max-pages",      default=None, type=int, dest="max_pages",
                   help="Páginas máximas de crawling")

    # ── Pass-the-Hash / lateral movement ─────────────────────────────────────
    p.add_argument("--exec",           default=None,
                   help="Comando a ejecutar (pass-the-hash, dcom-exec, persistencia)")
    p.add_argument("--shell",          action="store_true", default=False,
                   help="Modo shell interactivo (pass-the-hash)")
    p.add_argument("--method",         default=None,
                   help="Método: smbexec|wmiexec|atexec (PtH) · schtask|registry|wmi-sub|startup|service (persistencia)")
    p.add_argument("--object",         default=None,
                   choices=["MMC20", "ShellWindows", "ShellBrowserWindow"],
                   help="Objeto DCOM para dcom-exec (default: MMC20)")

    # ── Persistencia ──────────────────────────────────────────────────────────
    p.add_argument("--persist-name",   default="WindowsUpdate", dest="persist_name",
                   help="Nombre del artefacto de persistencia (tarea, clave, servicio)")
    p.add_argument("--hive",           default="HKLM", choices=["HKLM", "HKCU"],
                   help="Hive de registro para método registry (default: HKLM)")
    p.add_argument("--trigger",        default="logon",
                   help="Trigger para schtask (logon|startup|hourly|daily) o expresión cron para SSH (default: logon)")
    p.add_argument("--local-file",     default=None, dest="local_file",
                   help="Ruta al archivo local para subir (método startup)")

    # ── DCSync ────────────────────────────────────────────────────────────────
    p.add_argument("--dc-user",        default=None, dest="dc_user",
                   help="Usuario específico a extraer con DCSync")
    p.add_argument("--all",            action="store_true", default=False,
                   help="Volcar todos los hashes (DCSync --all)")

    # ── Privesc check ─────────────────────────────────────────────────────────
    p.add_argument("--full",           action="store_true", default=False,
                   help="Checks adicionales (tareas programadas, DLL hijack, etc.)")

    # ── Coerción NTLM ─────────────────────────────────────────────────────────
    p.add_argument("--technique",      default=None,
                   choices=["petitpotam", "printerbug", "dfscoerce", "shadowcoerce"],
                   help="Técnica de coerción NTLM")

    # ── Phishing ──────────────────────────────────────────────────────────────
    p.add_argument("--type",           default=None, dest="phishing_type",
                   choices=["macro", "lnk", "hta", "scf", "url"],
                   help="Tipo de payload phishing")


def build_parser():
    import argparse
    parser = argparse.ArgumentParser(
        prog="lobera",
        description="Lobera — AD enumeration & attack toolkit",
    )
    subs = parser.add_subparsers(dest="module", metavar="módulo")

    # ── Protocolos ──────────────────────────────────────────────────────────
    proto_help = {
        "smb":      "Scripts SMB",
        "kerberos": "Scripts Kerberos",
        "rpc":      "Scripts RPC",
        "ldap":     "Scripts LDAP",
        "winrm":    "Scripts WinRM",
        "ssh":      "Scripts SSH",
        "ssl":      "Scripts SSL",
        "http":     "Scripts HTTP",
        "https":    "Scripts HTTPS",
        "ftp":      "Scripts FTP",
        "mssql":    "Scripts MSSQL",
    }
    for proto, help_text in proto_help.items():
        p = subs.add_parser(proto, help=help_text)
        _add_proto_flags(p)

    # ── exploit ──────────────────────────────────────────────────────────────
    exp_p = subs.add_parser("exploit", help="→ usa lobera-check / lobera-exploit")
    exp_s = exp_p.add_subparsers(dest="exploit_module", metavar="módulo")
    exp_s.add_parser("ms17010", help="→ usa lobera-check --target IP")

    # ── crack ────────────────────────────────────────────────────────────────
    crack_p = subs.add_parser("crack", help="Crackeo offline de hashes Kerberos/NTLM")
    crack_p.add_argument("-f", "--format",   required=True,
                         choices=["asrep", "tgs", "ntlm", "ntlmv2", "auto"],
                         help="Formato del hash")
    crack_p.add_argument("-H", "--hash",     required=True,
                         help="Hash en texto o ruta a fichero")
    crack_p.add_argument("-w", "--wordlist", required=True,
                         help="Ruta al diccionario")
    crack_p.add_argument("-t", "--threads",  default=None, type=int,
                         help="Número de threads")
    crack_p.add_argument("--progress",       default=10000, type=int,
                         help="Mostrar progreso cada N contraseñas")
    crack_p.add_argument("--json-only",      action="store_true", dest="json_only",
                         help="Solo JSON a stdout")

    # ── scan ─────────────────────────────────────────────────────────────────
    scan_p = subs.add_parser("scan", help="Scanner de puertos y servicios (Go)")
    scan_p.add_argument("-t", "--target",  required=True,
                        help="IP, CIDR o rango (ej: 10.10.10.0/24)")
    scan_p.add_argument("-p", "--ports",   default="ad",
                        help="ad (default) | all | 80,443,445 | 80-1000")
    scan_p.add_argument("--threads",       default=200, type=int,
                        help="Goroutines paralelas (default: 200)")
    scan_p.add_argument("--timeout",       default=500, type=int, dest="scan_timeout",
                        help="Timeout por puerto en ms (default: 500)")
    scan_p.add_argument("--banners",       action="store_true",
                        help="Leer banner de puertos abiertos")
    scan_p.add_argument("--closed",        action="store_true",
                        help="Mostrar también puertos cerrados")

    # ── db ────────────────────────────────────────────────────────────────────
    db_p = subs.add_parser("db", help="Base de datos de sesión")
    db_s = db_p.add_subparsers(dest="db_action", metavar="acción")

    db_s.add_parser("targets", help="Lista objetivos")

    db_findings = db_s.add_parser("findings", help="Lista hallazgos de un objetivo")
    db_findings.add_argument("-t", "--target",  default=None)
    db_findings.add_argument("--protocol",      default=None)

    db_creds = db_s.add_parser("creds", help="Lista credenciales de un objetivo")
    db_creds.add_argument("-t", "--target",     default=None)
    db_creds.add_argument("--all",              action="store_true")
    db_creds.add_argument("--show-secret",      action="store_true", dest="show_secret")

    db_delete = db_s.add_parser("delete", help="Borra todo lo de un objetivo")
    db_delete.add_argument("-t", "--target",    default=None)
    db_delete.add_argument("--yes",             action="store_true")

    # ── report ────────────────────────────────────────────────────────────────
    rep_p = subs.add_parser("report", help="Genera informe HTML/Markdown a partir de la DB")
    rep_p.add_argument("-t", "--target",  default=None)
    rep_p.add_argument("--format",        default="html", choices=["html", "md"], dest="format")
    rep_p.add_argument("-o", "--output",  default=None)

    # ── completion ────────────────────────────────────────────────────────────
    comp_p = subs.add_parser("completion", help="Instrucciones para instalar el autocompletado")
    comp_p.add_argument("--shell", default="bash", choices=["bash", "zsh"])

    # ── listen ────────────────────────────────────────────────────────────────
    lst_p = subs.add_parser("listen", help="Handler/listener para reverse shells TCP/HTTP/HTTPS")
    lst_p.add_argument("-p", "--port",  default=4444, type=int)
    lst_p.add_argument("--type",        default="tcp", choices=["tcp", "http", "https"], dest="type")
    lst_p.add_argument("--cert",        default=None)
    lst_p.add_argument("--multi",       action="store_true", default=False)
    lst_p.add_argument("--log",         default=None)

    # ── amsi-bypass ───────────────────────────────────────────────────────────
    amsi_p = subs.add_parser("amsi", help="AMSI/ETW bypass (requiere compilar src/exploits/amsi/)")
    amsi_p.add_argument("-t", "--target",    default=None)
    amsi_p.add_argument("--patch-amsi",      action="store_true", dest="patch_amsi")
    amsi_p.add_argument("--patch-etw",       action="store_true", dest="patch_etw")
    amsi_p.add_argument("--check",           action="store_true")
    amsi_p.add_argument("--delay",           action="store_true")
    amsi_p.add_argument("--delay-ms",        default=5000, type=int, dest="delay_ms")
    amsi_p.add_argument("--load",            default=None, dest="load_dll")

    return parser


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    root_str = str(_ROOT)
    if root_str not in sys.path:
        sys.path.insert(0, root_str)

    # Inicializar BD (muestra bienvenida en la primera ejecución)
    init_db()

    # Autenticación
    from core.auth import login
    if not login():
        sys.exit(1)

    # Si se pasaron argumentos por CLI, usar el modo clásico (no interactivo)
    if len(sys.argv) > 1:
        parser = build_parser()
        args   = parser.parse_args()

        if args.module is None:
            show_banner()
            console.print("[yellow]No se ha especificado ningún módulo.[/yellow]")
            console.print("[dim]Ejecuta 'lobera.py' sin argumentos para la consola interactiva.[/dim]")
            return

        dispatch = {
            "smb":        run_smb,
            "kerberos":   run_kerberos,
            "rpc":        run_rpc,
            "ldap":       run_ldap,
            "winrm":      run_winrm,
            "ssh":        run_ssh,
            "ssl":        run_ssl,
            "http":       run_http,
            "https":      run_https,
            "ftp":        run_ftp,
            "mssql":      run_mssql,
            "exploit":    run_exploit,
            "crack":      run_crack,
            "scan":       run_scan,
            "listen":     run_listen,
            "amsi":       run_amsi,
            "db":         run_db,
            "report":     run_report,
            "completion": run_completion,
        }
        runner = dispatch.get(args.module)
        if runner:
            runner(args)
        else:
            console.print(f"[red]Módulo desconocido: {args.module}[/red]")
        return

    # Sin argumentos: modo consola interactiva
    show_banner()
    _consola_principal()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[dim]Interrumpido.[/dim]")
        sys.exit(130)
    finally:
        # Cerrar todas las conexiones en caché al salir
        try:
            from core.conn_cache import conn_cache
            if len(conn_cache) > 0:
                conn_cache.close_all()
        except Exception:
            pass
