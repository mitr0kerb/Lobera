#!/usr/bin/env python3
# tools/https/main.py
"""
lobera-https — Operaciones HTTPS sobre un objetivo web seguro.

Subcomandos:
  enum     Detección de tecnologías y fingerprinting web (HTTPS)
  scan     Captura de banner HTTPS
  headers  Análisis de cabeceras de seguridad HTTP
  sqli     Detección de inyección SQL
  xss      Detección de Cross-Site Scripting
  lfi      Detección de inclusión de ficheros locales
  exploit  Explotación con log4shell
  crawl    Rastreo de URLs y extracción de enlaces

Uso:
  lobera-https enum    -t https://10.0.0.1
  lobera-https scan    -t 10.0.0.1 --port 443
  lobera-https headers -t https://10.0.0.1
  lobera-https sqli    -t https://10.0.0.1/page?id=1
  lobera-https xss     -t https://10.0.0.1/search
  lobera-https lfi     -t https://10.0.0.1/file?path=
  lobera-https exploit -t 10.0.0.1
  lobera-https crawl   -t https://10.0.0.1 --depth 3
"""

import sys
import os
import argparse

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from core.output import console
from core.session_db import init_db


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _leer_lista(fichero, valor_unico):
    if fichero:
        try:
            with open(fichero) as f:
                return [l.strip() for l in f if l.strip()]
        except OSError as e:
            console.print(f"[red]No se puede leer {fichero}: {e}[/red]")
            return []
    if valor_unico:
        return [valor_unico]
    return []


# ──────────────────────────────────────────────────────────────────────────────
# Subcomando: enum
# ──────────────────────────────────────────────────────────────────────────────

def cmd_enum(args):
    try:
        from scripts.https.enum.tech_detect import run
    except ImportError as e:
        console.print(f"[red]No se pudo importar el módulo de detección de tecnologías HTTPS: {e}[/red]")
        return
    console.print(f"\n[bold cyan][ HTTPS ENUM ] {args.target}[/bold cyan]")
    run(target=args.target, port=args.port, timeout=args.timeout)


# ──────────────────────────────────────────────────────────────────────────────
# Subcomando: scan
# ──────────────────────────────────────────────────────────────────────────────

def cmd_scan(args):
    try:
        from scripts.https.enum.banner_grab import run
    except ImportError as e:
        console.print(f"[red]No se pudo importar el módulo de banner HTTPS: {e}[/red]")
        return
    console.print(f"\n[bold cyan][ HTTPS SCAN ] {args.target}[/bold cyan]")
    run(target=args.target, port=args.port, timeout=args.timeout)


# ──────────────────────────────────────────────────────────────────────────────
# Subcomando: headers
# ──────────────────────────────────────────────────────────────────────────────

def cmd_headers(args):
    try:
        from scripts.https.enum.security_headers import run
    except ImportError as e:
        console.print(f"[red]No se pudo importar el módulo de cabeceras de seguridad HTTPS: {e}[/red]")
        return
    console.print(f"\n[bold cyan][ HTTPS HEADERS ] {args.target}[/bold cyan]")
    run(target=args.target, port=args.port, timeout=args.timeout)


# ──────────────────────────────────────────────────────────────────────────────
# Subcomando: sqli
# ──────────────────────────────────────────────────────────────────────────────

def cmd_sqli(args):
    try:
        from scripts.https.attack.sqli_detect import run
    except ImportError as e:
        console.print(f"[red]No se pudo importar el módulo de detección SQLi HTTPS: {e}[/red]")
        return
    console.print(f"\n[bold cyan][ HTTPS SQLI ] {args.target}[/bold cyan]")
    run(target=args.target, port=args.port, timeout=args.timeout)


# ──────────────────────────────────────────────────────────────────────────────
# Subcomando: xss
# ──────────────────────────────────────────────────────────────────────────────

def cmd_xss(args):
    try:
        from scripts.https.attack.xss_detect import run
    except ImportError as e:
        console.print(f"[red]No se pudo importar el módulo de detección XSS HTTPS: {e}[/red]")
        return
    console.print(f"\n[bold cyan][ HTTPS XSS ] {args.target}[/bold cyan]")
    run(target=args.target, port=args.port, timeout=args.timeout)


# ──────────────────────────────────────────────────────────────────────────────
# Subcomando: lfi
# ──────────────────────────────────────────────────────────────────────────────

def cmd_lfi(args):
    try:
        from scripts.https.attack.lfi_detect import run
    except ImportError as e:
        console.print(f"[red]No se pudo importar el módulo de detección LFI HTTPS: {e}[/red]")
        return
    console.print(f"\n[bold cyan][ HTTPS LFI ] {args.target}[/bold cyan]")
    run(target=args.target, port=args.port, timeout=args.timeout)


# ──────────────────────────────────────────────────────────────────────────────
# Subcomando: exploit
# ──────────────────────────────────────────────────────────────────────────────

def cmd_exploit(args):
    try:
        from scripts.https.exploit.log4shell import run
    except ImportError as e:
        console.print(f"[red]No se pudo importar el módulo de exploit log4shell HTTPS: {e}[/red]")
        return
    console.print(f"\n[bold cyan][ HTTPS EXPLOIT ] {args.target}[/bold cyan]")
    run(target=args.target, port=args.port, timeout=args.timeout)


# ──────────────────────────────────────────────────────────────────────────────
# Subcomando: crawl
# ──────────────────────────────────────────────────────────────────────────────

def cmd_crawl(args):
    try:
        from scripts.https.post.crawl import run
    except ImportError as e:
        console.print(f"[red]No se pudo importar el módulo de rastreo HTTPS: {e}[/red]")
        return
    console.print(f"\n[bold cyan][ HTTPS CRAWL ] {args.target}[/bold cyan]")
    run(target=args.target, port=args.port, timeout=args.timeout, depth=args.depth)


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

def _flags_comunes(sub, puerto_default=443):
    sub.add_argument('-t', '--target', '--url', dest='target', required=True,
                     metavar='URL/IP')
    sub.add_argument('--port', type=int, default=puerto_default, metavar='PUERTO')
    sub.add_argument('--timeout', type=int, default=10)


def build_parser():
    parser = argparse.ArgumentParser(
        prog='lobera-https',
        description='Operaciones HTTPS — lobera',
    )
    subs = parser.add_subparsers(dest='subcomando', required=True)

    # ── enum ──────────────────────────────────────────────────────────────────
    p_enum = subs.add_parser('enum', help='Detectar tecnologías y fingerprinting web (HTTPS)')
    _flags_comunes(p_enum)
    p_enum.set_defaults(func=cmd_enum)

    # ── scan ──────────────────────────────────────────────────────────────────
    p_scan = subs.add_parser('scan', help='Capturar banner del servidor HTTPS')
    _flags_comunes(p_scan)
    p_scan.set_defaults(func=cmd_scan)

    # ── headers ───────────────────────────────────────────────────────────────
    p_headers = subs.add_parser('headers', help='Analizar cabeceras de seguridad HTTP')
    _flags_comunes(p_headers)
    p_headers.set_defaults(func=cmd_headers)

    # ── sqli ──────────────────────────────────────────────────────────────────
    p_sqli = subs.add_parser('sqli', help='Detectar inyección SQL')
    _flags_comunes(p_sqli)
    p_sqli.set_defaults(func=cmd_sqli)

    # ── xss ───────────────────────────────────────────────────────────────────
    p_xss = subs.add_parser('xss', help='Detectar Cross-Site Scripting')
    _flags_comunes(p_xss)
    p_xss.set_defaults(func=cmd_xss)

    # ── lfi ───────────────────────────────────────────────────────────────────
    p_lfi = subs.add_parser('lfi', help='Detectar inclusión de ficheros locales')
    _flags_comunes(p_lfi)
    p_lfi.set_defaults(func=cmd_lfi)

    # ── exploit ───────────────────────────────────────────────────────────────
    p_exploit = subs.add_parser('exploit', help='Explotar vulnerabilidad log4shell')
    _flags_comunes(p_exploit)
    p_exploit.set_defaults(func=cmd_exploit)

    # ── crawl ─────────────────────────────────────────────────────────────────
    p_crawl = subs.add_parser('crawl', help='Rastrear URLs y extraer enlaces')
    _flags_comunes(p_crawl)
    p_crawl.add_argument('--depth', type=int, default=2, metavar='PROFUNDIDAD',
                         help='Profundidad máxima de rastreo (default: 2)')
    p_crawl.set_defaults(func=cmd_crawl)

    return parser


def _banner():
    from tools.common import banner, tabla_modos, ejemplos
    banner("lobera-https")
    tabla_modos([
        ("enum",    "Detectar tecnologías y fingerprinting web (HTTPS)"),
        ("scan",    "Capturar banner del servidor HTTPS"),
        ("headers", "Analizar cabeceras de seguridad HTTP"),
        ("sqli",    "Detectar inyección SQL"),
        ("xss",     "Detectar Cross-Site Scripting"),
        ("lfi",     "Detectar inclusión de ficheros locales"),
        ("exploit", "Explotar vulnerabilidad log4shell"),
        ("crawl",   "Rastrear URLs y extraer enlaces"),
    ])
    ejemplos([
        "lobera-https enum    -t https://10.10.10.5",
        "lobera-https scan    -t 10.10.10.5 --port 8443",
        "lobera-https headers -t https://10.10.10.5",
        "lobera-https sqli    -t https://10.10.10.5/page?id=1",
        "lobera-https xss     -t https://10.10.10.5/search?q=test",
        "lobera-https lfi     -t https://10.10.10.5/file?path=",
        "lobera-https exploit -t 10.10.10.5 --port 443",
        "lobera-https crawl   -t https://10.10.10.5 --depth 3",
    ])


def main():
    import sys
    init_db()
    if not sys.argv[1:]:
        _banner()
        return
    parser = build_parser()
    args = parser.parse_args()
    try:
        args.func(args)
    except KeyboardInterrupt:
        console.print("\n[dim]Interrumpido.[/dim]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


if __name__ == '__main__':
    main()
