#!/usr/bin/env python3
# tools/scan/main.py
"""
lobera-scan — Escáner de puertos y servicios en Python puro.

Realiza un TCP connect scan con hilos, detección de banners opcional
y guardado de resultados en la BD de sesión.

Uso:
  lobera-scan -t 10.10.10.5
  lobera-scan -t 10.10.10.0/24 -p 22,80,443,445,3389
  lobera-scan -t 10.10.10.1-50 -p top100 --banners
  lobera-scan -t 10.10.10.5 -p all --threads 500 --timeout 300
"""

import sys
import os
import socket
import struct
import ipaddress
import threading
import time
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from core.output import console
from core.session_db import init_db

# ──────────────────────────────────────────────────────────────────────────────
# Puertos de interés por defecto
# ──────────────────────────────────────────────────────────────────────────────

_TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 88, 110, 111, 119,
    135, 139, 143, 443, 445, 465, 514, 587, 593,
    636, 993, 995, 1080, 1194, 1433, 1521, 1723,
    2049, 2181, 3306, 3389, 4444, 4899, 5432, 5900,
    5985, 5986, 6379, 8080, 8443, 8888, 9200, 9300,
    27017, 47001,
]

_SERVICIOS = {
    21:    "ftp",       22:    "ssh",       23:    "telnet",
    25:    "smtp",      53:    "dns",       80:    "http",
    88:    "kerberos",  110:   "pop3",      111:   "rpcbind",
    135:   "msrpc",     139:   "netbios",   143:   "imap",
    443:   "https",     445:   "smb",       465:   "smtps",
    593:   "rpc-http",  636:   "ldaps",     993:   "imaps",
    995:   "pop3s",     1080:  "socks",     1194:  "openvpn",
    1433:  "mssql",     1521:  "oracle",    1723:  "pptp",
    2049:  "nfs",       2181:  "zookeeper", 3306:  "mysql",
    3389:  "rdp",       4444:  "meterp",    4899:  "radmin",
    5432:  "postgres",  5900:  "vnc",       5985:  "winrm",
    5986:  "winrm-ssl", 6379:  "redis",     8080:  "http-alt",
    8443:  "https-alt", 8888:  "http-alt2", 9200:  "elasticsearch",
    9300:  "es-cluster",27017: "mongodb",   47001: "winrm2",
}


# ──────────────────────────────────────────────────────────────────────────────
# Parseo de rangos de IPs y puertos
# ──────────────────────────────────────────────────────────────────────────────

def _expandir_ips(target_str):
    """Expande CIDR, rango (10.0.0.1-50) o IP individual."""
    ips = []
    if '/' in target_str:
        net = ipaddress.ip_network(target_str, strict=False)
        ips = [str(h) for h in net.hosts()]
    elif '-' in target_str.split('.')[-1]:
        base  = '.'.join(target_str.split('.')[:3])
        rango = target_str.split('.')[-1]
        inicio, fin = rango.split('-')
        ips = [f"{base}.{i}" for i in range(int(inicio), int(fin) + 1)]
    else:
        ips = [target_str]
    return ips


def _expandir_puertos(ports_str):
    """Convierte string de puertos a lista de ints."""
    if ports_str in ('top', 'top100', None, ''):
        return _TOP_PORTS[:]
    if ports_str == 'all':
        return list(range(1, 65536))

    puertos = []
    for parte in ports_str.split(','):
        parte = parte.strip()
        if '-' in parte:
            a, b = parte.split('-', 1)
            puertos.extend(range(int(a), int(b) + 1))
        elif parte.isdigit():
            puertos.append(int(parte))
    return sorted(set(puertos))


# ──────────────────────────────────────────────────────────────────────────────
# Escaneo TCP
# ──────────────────────────────────────────────────────────────────────────────

def _tcp_connect(ip, port, timeout_ms):
    """Intenta conexión TCP. Devuelve True si el puerto está abierto."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout_ms / 1000.0)
        resultado = s.connect_ex((ip, port))
        s.close()
        return resultado == 0
    except Exception:
        return False


def _grab_banner(ip, port, timeout_ms=2000):
    """Intenta leer un banner tras conectar."""
    banner = ''
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout_ms / 1000.0)
        s.connect((ip, port))
        # Enviar petición mínima para provocar respuesta en HTTP
        if port in (80, 8080, 8443, 8888):
            s.sendall(b"HEAD / HTTP/1.0\r\nHost: lobera\r\n\r\n")
        raw = s.recv(256)
        banner = raw.decode('utf-8', errors='replace').strip().split('\n')[0][:120]
        s.close()
    except Exception:
        pass
    return banner


# ──────────────────────────────────────────────────────────────────────────────
# Núcleo del scan
# ──────────────────────────────────────────────────────────────────────────────

def escanear_host(ip, puertos, timeout_ms, banners):
    """Escanea todos los puertos de un host. Devuelve lista de dicts."""
    abiertos = []
    with ThreadPoolExecutor(max_workers=min(len(puertos), 500)) as ex:
        futuros = {ex.submit(_tcp_connect, ip, p, timeout_ms): p for p in puertos}
        for fut in as_completed(futuros):
            puerto = futuros[fut]
            try:
                if fut.result():
                    servicio = _SERVICIOS.get(puerto, '')
                    banner   = _grab_banner(ip, puerto, timeout_ms) if banners else ''
                    abiertos.append({
                        'ip':       ip,
                        'port':     puerto,
                        'servicio': servicio,
                        'banner':   banner,
                    })
            except Exception:
                pass
    return sorted(abiertos, key=lambda x: x['port'])


def _guardar_en_bd(resultados):
    """Guarda puertos abiertos en la tabla scan_results de la BD (si existe)."""
    try:
        from core.session_db import _con
        con = _con()
        cur = con.cursor()
        # Tabla scan_results — crearla si no existe
        cur.execute("""
            CREATE TABLE IF NOT EXISTS scan_results (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                target_ip TEXT NOT NULL,
                port      INTEGER NOT NULL,
                servicio  TEXT,
                banner    TEXT,
                timestamp TEXT DEFAULT (datetime('now'))
            )
        """)
        for r in resultados:
            cur.execute("""
                INSERT OR REPLACE INTO scan_results (target_ip, port, servicio, banner)
                VALUES (?, ?, ?, ?)
            """, (r['ip'], r['port'], r['servicio'], r['banner']))
        con.commit()
    except Exception as e:
        console.print(f"  [dim][bd] No se pudo guardar en BD: {e}[/dim]")


# ──────────────────────────────────────────────────────────────────────────────
# Output
# ──────────────────────────────────────────────────────────────────────────────

def _imprimir_resultados(ip, abiertos):
    if not abiertos:
        console.print(f"  [dim]{ip}[/dim]  sin puertos abiertos")
        return

    console.print(f"\n  [bold cyan]{ip}[/bold cyan]  —  {len(abiertos)} puerto(s) abierto(s)\n")
    console.print(f"  {'PUERTO':<8} {'SERVICIO':<14} {'BANNER'}")
    console.print(f"  {'─'*7} {'─'*13} {'─'*50}")
    for r in abiertos:
        puerto   = f"{r['port']}/tcp"
        servicio = r['servicio'] or '?'
        banner   = r['banner'][:60] if r['banner'] else ''
        color    = "green"
        console.print(f"  [bold {color}]{puerto:<8}[/bold {color}] {servicio:<14} [dim]{banner}[/dim]")
    console.print()


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

def build_parser():
    parser = argparse.ArgumentParser(
        prog='lobera-scan',
        description='Escáner de puertos TCP — Python puro, sin dependencias externas',
    )
    parser.add_argument('-t', '--target', required=True, metavar='IP/CIDR/RANGO',
                        help='Objetivo: IP, CIDR (10.0.0.0/24) o rango (10.0.0.1-50)')
    parser.add_argument('-p', '--ports', default='top100', metavar='PUERTOS',
                        help='Puertos: 22,80,443 | 1-1024 | top100 | all (default: top100)')
    parser.add_argument('--threads', type=int, default=200, metavar='N',
                        help='Hilos por host (default: 200)')
    parser.add_argument('--timeout', type=int, default=500, metavar='MS',
                        help='Timeout de conexión en ms (default: 500)')
    parser.add_argument('--banners', action='store_true',
                        help='Intentar leer banner de cada puerto abierto')
    parser.add_argument('--no-db', action='store_true',
                        help='No guardar resultados en BD de sesión')
    parser.add_argument('-o', '--output', metavar='FICHERO',
                        help='Guardar resultados en fichero de texto')
    return parser


def _banner_tool():
    from tools.common import banner, tabla_flags, ejemplos
    banner("lobera-scan  —  Escáner de puertos TCP")
    tabla_flags([
        ("-t / --target",  "str", "IP, CIDR o rango (10.0.0.1-50)"),
        ("-p / --ports",   "str", "Puertos: 22,80 | 1-1024 | top100 | all"),
        ("--threads",      "int", "Hilos por host (default: 200)"),
        ("--timeout",      "int", "Timeout de conexión en ms (default: 500)"),
        ("--banners",      "flag","Intentar leer banner de puertos abiertos"),
        ("--no-db",        "flag","No guardar en BD de sesión"),
        ("-o / --output",  "file","Guardar resultados en fichero"),
    ])
    ejemplos([
        "lobera-scan -t 10.10.10.5",
        "lobera-scan -t 10.10.10.0/24 -p 22,80,443,445,3389 --banners",
        "lobera-scan -t 10.10.10.1-50 -p top100 --threads 500 --timeout 300",
        "lobera-scan -t 10.10.10.5 -p all -o resultados.txt",
    ])


def main():
    import sys
    init_db()
    if not sys.argv[1:]:
        _banner_tool()
        return
    parser = build_parser()
    args   = parser.parse_args()

    ips     = _expandir_ips(args.target)
    puertos = _expandir_puertos(args.ports)

    console.print(f"[cyan]Escaneando {len(ips)} host(s) — {len(puertos)} puerto(s) — "
                  f"{args.threads} hilos — timeout {args.timeout}ms[/cyan]\n")

    todos_resultados = []

    for ip in ips:
        console.print(f"[dim]→ {ip}...[/dim]", end='\r')
        abiertos = escanear_host(ip, puertos, args.timeout, args.banners)
        _imprimir_resultados(ip, abiertos)
        todos_resultados.extend(abiertos)

    # Guardar en BD
    if todos_resultados and not args.no_db:
        _guardar_en_bd(todos_resultados)
        console.print(f"  [dim][bd] {len(todos_resultados)} resultado(s) guardados en BD.[/dim]")

    # Guardar en fichero
    if args.output and todos_resultados:
        try:
            with open(args.output, 'w') as f:
                for r in todos_resultados:
                    linea = f"{r['ip']}\t{r['port']}\t{r['servicio']}\t{r['banner']}"
                    f.write(linea + '\n')
            console.print(f"  [dim]Resultados guardados en: {args.output}[/dim]")
        except Exception as e:
            console.print(f"  [red]Error guardando fichero: {e}[/red]")

    # Resumen final
    hosts_con_puertos = len({r['ip'] for r in todos_resultados})
    console.print(f"\n[bold]Resumen:[/bold] {hosts_con_puertos}/{len(ips)} host(s) con puertos abiertos — "
                  f"{len(todos_resultados)} puerto(s) en total.")


if __name__ == '__main__':
    main()
