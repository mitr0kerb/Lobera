#!/usr/bin/env python3
# tools/tunnel/main.py
"""
lobera-tunnel — Túnel SOCKS5 y reenvío de puertos sobre SSH para pivoting.

Modos:
  socks5   — Proxy SOCKS5 local sobre SSH dinámico (como ssh -D)
  forward  — Reenvío de puerto local→remoto (como ssh -L)
  reverse  — Reenvío de puerto remoto→local (como ssh -R)
  multi    — Varios reenvíos en paralelo desde fichero de configuración

Uso:
  lobera-tunnel socks5  -t 10.10.10.5 -u user -p PASS --local-port 1080
  lobera-tunnel forward -t 10.10.10.5 -u user -p PASS --local-port 8080 --remote-host 192.168.1.10 --remote-port 80
  lobera-tunnel reverse -t 10.10.10.5 -u user -p PASS --local-port 4444 --remote-port 4444
  lobera-tunnel multi   -t 10.10.10.5 -u user -p PASS --config tunnels.yaml

Fichero de configuración YAML para modo multi:
  - type: forward
    local_port: 8080
    remote_host: 192.168.1.10
    remote_port: 80
  - type: forward
    local_port: 1433
    remote_host: 192.168.1.20
    remote_port: 1433
  - type: socks5
    local_port: 1080
"""

import sys
import os
import time
import socket
import threading
import select
import struct

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from core.output import console


# ── Conexión SSH base ─────────────────────────────────────────────────────────

def _ssh_connect(target, port, user, password, key_file):
    """Devuelve cliente paramiko autenticado."""
    try:
        import paramiko
    except ImportError:
        console.print("  [red]Falta paramiko — pip install paramiko[/red]")
        sys.exit(1)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    kwargs = dict(
        hostname=target, port=int(port), username=user,
        timeout=10, allow_agent=False, look_for_keys=False,
    )
    if key_file:
        kwargs["key_filename"] = key_file
    else:
        kwargs["password"] = password

    client.connect(**kwargs)
    return client


# ── SOCKS5 sobre SSH dinámico ─────────────────────────────────────────────────

SOCKS5_VER       = 0x05
SOCKS5_NO_AUTH   = 0x00
SOCKS5_AUTH_NONE = 0xFF
SOCKS5_CMD_CONN  = 0x01
SOCKS5_ATYP_IPV4 = 0x01
SOCKS5_ATYP_DOM  = 0x03
SOCKS5_ATYP_IPV6 = 0x04
SOCKS5_OK        = 0x00
SOCKS5_FAIL      = 0x01


def _socks5_handshake(sock):
    """Realiza el handshake SOCKS5 sin autenticación."""
    # Fase 1: negociación de método
    data = sock.recv(257)
    if not data or data[0] != SOCKS5_VER:
        return None
    sock.sendall(bytes([SOCKS5_VER, SOCKS5_NO_AUTH]))

    # Fase 2: petición de conexión
    data = sock.recv(262)
    if len(data) < 4 or data[0] != SOCKS5_VER or data[1] != SOCKS5_CMD_CONN:
        return None

    atyp = data[3]
    if atyp == SOCKS5_ATYP_IPV4:
        host = socket.inet_ntoa(data[4:8])
        port = struct.unpack("!H", data[8:10])[0]
    elif atyp == SOCKS5_ATYP_DOM:
        n    = data[4]
        host = data[5:5+n].decode("utf-8", errors="replace")
        port = struct.unpack("!H", data[5+n:7+n])[0]
    elif atyp == SOCKS5_ATYP_IPV6:
        host = socket.inet_ntop(socket.AF_INET6, data[4:20])
        port = struct.unpack("!H", data[20:22])[0]
    else:
        return None

    return host, port


def _socks5_reply(sock, ok, bind_addr="0.0.0.0", bind_port=0):
    """Envía respuesta SOCKS5."""
    status = SOCKS5_OK if ok else SOCKS5_FAIL
    bnd    = socket.inet_aton(bind_addr)
    reply  = bytes([SOCKS5_VER, status, 0x00, SOCKS5_ATYP_IPV4]) + bnd + struct.pack("!H", bind_port)
    sock.sendall(reply)


def _relay(a, b):
    """Reenvío bidireccional de bytes entre dos sockets."""
    try:
        while True:
            r, _, _ = select.select([a, b], [], [], 60)
            if not r:
                break
            for sock in r:
                other = b if sock is a else a
                try:
                    data = sock.recv(4096)
                    if not data:
                        return
                    other.sendall(data)
                except Exception:
                    return
    except Exception:
        pass
    finally:
        for s in (a, b):
            try:
                s.close()
            except Exception:
                pass


def _handle_socks5_client(client_sock, ssh_transport):
    """Atiende una conexión SOCKS5: negocia, abre canal SSH y retransmite."""
    try:
        result = _socks5_handshake(client_sock)
        if not result:
            _socks5_reply(client_sock, False)
            client_sock.close()
            return

        host, port = result

        try:
            chan = ssh_transport.open_channel(
                "direct-tcpip",
                (host, port),
                ("127.0.0.1", 0),
            )
        except Exception as e:
            console.print(f"  [red]Error abriendo canal SSH → {host}:{port}: {e}[/red]")
            _socks5_reply(client_sock, False)
            client_sock.close()
            return

        _socks5_reply(client_sock, True)
        console.print(f"  [dim]SOCKS5 → {host}:{port}[/dim]")
        _relay(client_sock, chan)

    except Exception as e:
        console.print(f"  [red]Error en cliente SOCKS5: {e}[/red]")
        try:
            client_sock.close()
        except Exception:
            pass


def run_socks5(ssh_client, local_ip, local_port):
    """Proxy SOCKS5 local que reenvía conexiones a través del SSH."""
    transport = ssh_client.get_transport()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((local_ip, int(local_port)))
    srv.listen(50)

    console.print(f"  [bold cyan]SOCKS5 proxy[/bold cyan] escuchando en {local_ip}:{local_port}")
    console.print(f"  [dim]Configura tu herramienta con: socks5 127.0.0.1 {local_port}[/dim]")
    console.print(f"  [dim]proxychains: socks5 127.0.0.1 {local_port}[/dim]")
    console.print(f"  [dim]Esperando conexiones... (Ctrl+C para parar)[/dim]\n")

    try:
        while True:
            try:
                client_sock, addr = srv.accept()
                t = threading.Thread(
                    target=_handle_socks5_client,
                    args=(client_sock, transport),
                    daemon=True,
                )
                t.start()
            except Exception as e:
                console.print(f"  [red]Error aceptando conexión: {e}[/red]")
    except KeyboardInterrupt:
        console.print("\n  [yellow]Proxy SOCKS5 detenido[/yellow]")
    finally:
        srv.close()


# ── Reenvío de puerto local→remoto (forward) ──────────────────────────────────

def _handle_forward_client(client_sock, ssh_transport, remote_host, remote_port):
    """Abre canal SSH a destino y retransmite datos."""
    try:
        chan = ssh_transport.open_channel(
            "direct-tcpip",
            (remote_host, int(remote_port)),
            ("127.0.0.1", 0),
        )
        console.print(f"  [dim]FORWARD → {remote_host}:{remote_port}[/dim]")
        _relay(client_sock, chan)
    except Exception as e:
        console.print(f"  [red]Error abriendo canal forward: {e}[/red]")
        try:
            client_sock.close()
        except Exception:
            pass


def run_forward(ssh_client, local_ip, local_port, remote_host, remote_port):
    """Reenvío local:port → remoto_host:remoto_port a través de SSH."""
    transport = ssh_client.get_transport()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((local_ip, int(local_port)))
    srv.listen(20)

    console.print(f"  [bold cyan]Forward[/bold cyan] {local_ip}:{local_port} → {remote_host}:{remote_port}")
    console.print(f"  [dim]Esperando conexiones... (Ctrl+C para parar)[/dim]\n")

    try:
        while True:
            try:
                client_sock, _ = srv.accept()
                t = threading.Thread(
                    target=_handle_forward_client,
                    args=(client_sock, transport, remote_host, remote_port),
                    daemon=True,
                )
                t.start()
            except Exception as e:
                console.print(f"  [red]Error: {e}[/red]")
    except KeyboardInterrupt:
        console.print("\n  [yellow]Forward detenido[/yellow]")
    finally:
        srv.close()


# ── Reenvío inverso remoto→local (reverse) ────────────────────────────────────

def _reverse_handler(chan, local_host, local_port):
    """Conecta a local_host:local_port y retransmite desde canal SSH inverso."""
    try:
        fwd = socket.create_connection((local_host, int(local_port)), timeout=10)
        console.print(f"  [dim]REVERSE ← {local_host}:{local_port}[/dim]")
        _relay(chan, fwd)
    except Exception as e:
        console.print(f"  [red]Error conectando a destino local: {e}[/red]")
        try:
            chan.close()
        except Exception:
            pass


def run_reverse(ssh_client, remote_port, local_host, local_port):
    """Reenvío inverso: el SSH remoto escucha en remote_port y reenvía a local_host:local_port."""
    transport = ssh_client.get_transport()

    try:
        transport.request_port_forward("", int(remote_port))
    except Exception as e:
        console.print(f"  [red]✗ No se pudo solicitar puerto remoto {remote_port}: {e}[/red]")
        return

    console.print(f"  [bold cyan]Reverse[/bold cyan] remoto:{remote_port} → {local_host}:{local_port}")
    console.print(f"  [dim]Esperando conexiones en el extremo remoto... (Ctrl+C para parar)[/dim]\n")

    try:
        while True:
            chan = transport.accept(timeout=1)
            if chan is None:
                continue
            t = threading.Thread(
                target=_reverse_handler,
                args=(chan, local_host, local_port),
                daemon=True,
            )
            t.start()
    except KeyboardInterrupt:
        console.print("\n  [yellow]Reverse detenido[/yellow]")
    finally:
        try:
            transport.cancel_port_forward("", int(remote_port))
        except Exception:
            pass


# ── Modo multi (varios túneles simultáneos desde YAML) ────────────────────────

def run_multi(ssh_client, config_file):
    """Levanta varios túneles en paralelo según fichero YAML."""
    try:
        import yaml
    except ImportError:
        console.print("  [red]Falta pyyaml — pip install pyyaml[/red]")
        return

    with open(config_file) as f:
        entries = yaml.safe_load(f)

    if not isinstance(entries, list):
        console.print("  [red]El fichero YAML debe contener una lista de túneles[/red]")
        return

    hilos = []

    for entry in entries:
        tipo = entry.get("type", "").lower()
        local_port  = entry.get("local_port", 0)
        local_ip    = entry.get("local_ip", "127.0.0.1")

        if tipo == "socks5":
            t = threading.Thread(
                target=run_socks5,
                args=(ssh_client, local_ip, local_port),
                daemon=True,
            )
            t.start()
            hilos.append(t)

        elif tipo == "forward":
            remote_host = entry.get("remote_host", "127.0.0.1")
            remote_port = entry.get("remote_port", 0)
            t = threading.Thread(
                target=run_forward,
                args=(ssh_client, local_ip, local_port, remote_host, remote_port),
                daemon=True,
            )
            t.start()
            hilos.append(t)

        elif tipo == "reverse":
            remote_port = entry.get("remote_port", local_port)
            local_host  = entry.get("local_host", "127.0.0.1")
            t = threading.Thread(
                target=run_reverse,
                args=(ssh_client, remote_port, local_host, local_port),
                daemon=True,
            )
            t.start()
            hilos.append(t)

        else:
            console.print(f"  [yellow]Tipo desconocido en config: {tipo}[/yellow]")

    console.print(f"  [bold green]✓ {len(hilos)} túneles activos[/bold green] (Ctrl+C para parar)\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        console.print("\n  [yellow]Túneles detenidos[/yellow]")


# ── CLI ───────────────────────────────────────────────────────────────────────

def build_parser():
    import argparse

    parser = argparse.ArgumentParser(
        prog="lobera-tunnel",
        description="Túnel SOCKS5 y reenvío de puertos sobre SSH para pivoting",
    )
    subs = parser.add_subparsers(dest="mode", metavar="modo")

    # ── Argumentos SSH comunes ────────────────────────────────────────────────
    def _ssh_args(p):
        p.add_argument("-t", "--target",   required=True,  help="IP/hostname del salto SSH")
        p.add_argument("-u", "--user",     required=True,  help="Usuario SSH")
        p.add_argument("-p", "--password", default="",     help="Contraseña SSH")
        p.add_argument("--key-file",       default=None, dest="key_file", help="Clave privada SSH")
        p.add_argument("--ssh-port",       default=22, type=int, dest="ssh_port", help="Puerto SSH (default: 22)")
        p.add_argument("--local-ip",       default="127.0.0.1", dest="local_ip",
                       help="IP local donde escuchar (default: 127.0.0.1)")

    # ── socks5 ────────────────────────────────────────────────────────────────
    p_s5 = subs.add_parser("socks5", help="Proxy SOCKS5 sobre SSH dinámico")
    _ssh_args(p_s5)
    p_s5.add_argument("--local-port", default=1080, type=int, dest="local_port",
                      help="Puerto SOCKS5 local (default: 1080)")

    # ── forward ───────────────────────────────────────────────────────────────
    p_fwd = subs.add_parser("forward", help="Reenvío local→remoto (ssh -L)")
    _ssh_args(p_fwd)
    p_fwd.add_argument("--local-port",   required=True, type=int, dest="local_port",  help="Puerto local")
    p_fwd.add_argument("--remote-host",  required=True,            dest="remote_host", help="Host destino en red remota")
    p_fwd.add_argument("--remote-port",  required=True, type=int, dest="remote_port", help="Puerto destino en red remota")

    # ── reverse ───────────────────────────────────────────────────────────────
    p_rev = subs.add_parser("reverse", help="Reenvío remoto→local (ssh -R)")
    _ssh_args(p_rev)
    p_rev.add_argument("--remote-port",  required=True, type=int, dest="remote_port",
                       help="Puerto a abrir en el SSH remoto")
    p_rev.add_argument("--local-port",   required=True, type=int, dest="local_port",
                       help="Puerto local al que reenviar")
    p_rev.add_argument("--local-host",   default="127.0.0.1", dest="local_host",
                       help="Host local al que reenviar (default: 127.0.0.1)")

    # ── multi ─────────────────────────────────────────────────────────────────
    p_multi = subs.add_parser("multi", help="Varios túneles desde fichero YAML")
    _ssh_args(p_multi)
    p_multi.add_argument("--config", required=True, help="Fichero YAML con la lista de túneles")

    return parser


def _banner():
    from tools.common import banner, panel_info, tabla_modos, tabla_flags, ejemplos

    banner("lobera-tunnel")

    tabla_modos([
        ("socks5",  "Proxy SOCKS5 local sobre SSH dinámico  (equivalente a ssh -D)"),
        ("forward", "Reenvío de puerto local → remoto  (equivalente a ssh -L)"),
        ("reverse", "Reenvío de puerto remoto → local  (equivalente a ssh -R)"),
        ("multi",   "Varios túneles simultáneos desde fichero YAML"),
    ])

    tabla_flags([
        ("-t / --target",    "IP",   "IP o hostname del salto SSH"),
        ("-u / --user",      "str",  "Usuario SSH"),
        ("-p / --password",  "str",  "Contraseña SSH"),
        ("--key-file",       "file", "Clave privada SSH"),
        ("--ssh-port",       "int",  "Puerto SSH  (default: 22)"),
        ("--local-ip",       "IP",   "IP local donde escuchar  (default: 127.0.0.1)"),
        ("--local-port",     "int",  "Puerto local"),
        ("--remote-host",    "IP",   "Host destino en la red remota  (modo forward)"),
        ("--remote-port",    "int",  "Puerto en la red remota"),
        ("--local-host",     "IP",   "Host local al que reenviar  (modo reverse, default: 127.0.0.1)"),
        ("--config",         "file", "Fichero YAML con lista de túneles  (modo multi)"),
    ], titulo="Opciones")

    panel_info("Configuración YAML para modo multi", [
        "- type: socks5",
        "  local_port: 1080",
        "",
        "- type: forward",
        "  local_port: 8080",
        "  remote_host: 192.168.1.10",
        "  remote_port: 80",
        "",
        "- type: reverse",
        "  remote_port: 4444",
        "  local_port: 4444",
        "  local_host: 127.0.0.1",
    ])

    ejemplos([
        "# Proxy SOCKS5 en 127.0.0.1:1080 — usa con proxychains",
        "lobera-tunnel socks5 -t 10.10.10.5 -u user -p 'P@ss' --local-port 1080",
        "proxychains nmap -sV 192.168.1.0/24",
        "",
        "# Acceder a RDP interno (192.168.1.10:3389) desde tu máquina en :13389",
        "lobera-tunnel forward -t 10.10.10.5 -u user -p 'P@ss' --local-port 13389 --remote-host 192.168.1.10 --remote-port 3389",
        "",
        "# Recibir shell reversa del objetivo en tu máquina  (víctima → pivot:4444 → tú:4444)",
        "lobera-tunnel reverse -t 10.10.10.5 -u user -p 'P@ss' --remote-port 4444 --local-port 4444",
        "",
        "# Varios túneles a la vez desde YAML",
        "lobera-tunnel multi -t 10.10.10.5 -u user -p 'P@ss' --config tunnels.yaml",
    ])


def main():
    parser = build_parser()
    args   = parser.parse_args()

    if not args.mode:
        _banner()
        return

    _banner()
    console.print(f"  [bold]Salto SSH:[/bold]  {args.user}@{args.target}:{args.ssh_port}")

    try:
        ssh = _ssh_connect(
            args.target, args.ssh_port,
            args.user, args.password,
            getattr(args, "key_file", None),
        )
        console.print(f"  [green]✓ Sesión SSH establecida[/green]\n")
    except Exception as e:
        console.print(f"  [red]✗ No se pudo conectar: {e}[/red]")
        sys.exit(1)

    try:
        if args.mode == "socks5":
            run_socks5(ssh, args.local_ip, args.local_port)

        elif args.mode == "forward":
            run_forward(ssh, args.local_ip, args.local_port,
                        args.remote_host, args.remote_port)

        elif args.mode == "reverse":
            run_reverse(ssh, args.remote_port,
                        getattr(args, "local_host", "127.0.0.1"),
                        args.local_port)

        elif args.mode == "multi":
            run_multi(ssh, args.config)

    except KeyboardInterrupt:
        console.print("\n  [yellow]Túnel detenido[/yellow]")
    finally:
        try:
            ssh.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()
