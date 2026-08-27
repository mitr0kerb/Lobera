# core/session_db.py

import sqlite3
import os
import time
from datetime import datetime
from rich.panel import Panel
from rich.align import Align
from rich.text import Text
from core.output import console

DB_PATH = os.path.join(os.path.expanduser("~"), ".lobera", "session.db")

WOLF_ART = r"""⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⠁⠸⢳⡄⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠃⠀⠀⢸⠸⠀⡠⣄⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡠⠃⠀⠀⢠⣞⣀⡿⠀⠀⣧⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⡖⠁⠀⠀⠀⢸⠈⢈⡇⠀⢀⡏⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⡴⠩⢠⡴⠀⠀⠀⠀⠀⠈⡶⠉⠀⠀⡸⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⠎⢠⣇⠏⠀⠀⠀⠀⠀⠀⠀⠁⠀⢀⠄⡇⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢠⠏⠀⢸⣿⣴⠀⠀⠀⠀⠀⠀⣆⣀⢾⢟⠴⡇⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢀⣿⠀⠠⣄⠸⢹⣦⠀⠀⡄⠀⠀⢋⡟⠀⠀⠁⣇⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢀⡾⠁⢠⠀⣿⠃⠘⢹⣦⢠⣼⠀⠀⠉⠀⠀⠀⠀⢸⡀⠀⠀⠀⠀
⠀⠀⢀⣴⠫⠤⣶⣿⢀⡏⠀⠀⠘⢸⡟⠋⠀⠀⠀⠀⠀⠀⠀⠀⢳⠀⠀⠀⠀
⠐⠿⢿⣿⣤⣴⣿⣣⢾⡄⠀⠀⠀⠀⠳⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢣⠀⠀⠀
⠀⠀⠀⣨⣟⡍⠉⠚⠹⣇⡄⠀⠀⠀⠀⠀⠀⠀⠀⠈⢦⠀⠀⢀⡀⣾⡇⠀⠀
⠀⠀⢠⠟⣹⣧⠃⠀⠀⢿⢻⡀⢄⠀⠀⠀⠀⠐⣦⡀⣸⣆⠀⣾⣧⣯⢻⠀⠀
⠀⠀⠘⣰⣿⣿⡄⡆⠀⠀⠀⠳⣼⢦⡘⣄⠀⠀⡟⡷⠃⠘⢶⣿⡎⠻⣆⠀⠀
⠀⠀⠀⡟⡿⢿⡿⠀⠀⠀⠀⠀⠙⠀⠻⢯⢷⣼⠁⠁⠀⠀⠀⠙⢿⡄⡈⢆⠀
⠀⠀⠀⠀⡇⣿⡅⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠦⠀⠀⠀⠀⠀⠀⡇⢹⢿⡀
⠀⠀⠀⠀⠁⠛⠓⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠼⠇⠁"""

TABLES = {
    "targets": """
        CREATE TABLE IF NOT EXISTS targets (
            ip TEXT PRIMARY KEY,
            hostname TEXT,
            domain TEXT,
            first_seen TEXT
        )
    """,
    "credentials": """
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_ip TEXT,
            user TEXT,
            secret TEXT,
            secret_type TEXT,
            valid INTEGER,
            source TEXT,
            timestamp TEXT
        )
    """,
    "findings": """
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_ip TEXT,
            protocol TEXT,
            finding_type TEXT,
            detail TEXT,
            timestamp TEXT
        )
    """,
    "attack_log": """
        CREATE TABLE IF NOT EXISTS attack_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_ip TEXT,
            action TEXT,
            result TEXT,
            timestamp TEXT
        )
    """,
}


def _connect():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _show_wolf():
    """
    Muestra el lobo ASCII de forma fija en pantalla. A diferencia de una
    animación con Live, este print permanece visible durante el resto de
    la secuencia de bienvenida (creación de tablas, panel final).
    """
    console.print(Align.center(Text(WOLF_ART, style="bold cyan")))
    time.sleep(2.0)


def _welcome_header():
    console.print()
    console.print(Align.center("[bold cyan]Bienvenido a Lobera[/bold cyan]"))
    console.print(Align.center("[dim]Primera ejecución detectada en este equipo.[/dim]"))
    console.print()
    time.sleep(0.6)


def _create_tables_with_feedback(cur):
    """Crea cada tabla y va imprimiendo confirmación una por una."""
    console.print()
    for name, ddl in TABLES.items():
        cur.execute(ddl)
        console.print(f"  [green]✓[/green] Tabla [bold]{name}[/bold] creada")
        time.sleep(0.25)


def _welcome_summary():
    body = (
        f"[bold]Ruta:[/bold] [green]{DB_PATH}[/green]\n\n"
        "Aquí se guardará memoria persistente entre ejecuciones:\n"
        "  • Objetivos que has escaneado\n"
        "  • Credenciales válidas encontradas\n"
        "  • Hallazgos por protocolo (shares, usuarios, null sessions...)\n\n"
        "[dim]Esto permite retomar un engagement donde lo dejaste, "
        "y en el futuro dar recomendaciones basadas en lo ya descubierto.[/dim]"
    )
    console.print()
    console.print(Panel(body, title="[bold cyan]Base de datos lista[/bold cyan]", border_style="cyan", expand=False))
    console.print()
    time.sleep(1.0)


def init_db():
    """
    Crea las tablas si no existen. Llamar una vez al arrancar la herramienta.
    Si es la primera vez que se ejecuta Lobera, muestra una secuencia de bienvenida
    con el lobo ASCII y confirmación por tabla. Si ya existe, no dice nada.
    """
    is_first_run = not os.path.exists(DB_PATH)

    if is_first_run:
        _welcome_header()
        _show_wolf()

    conn = _connect()
    cur = conn.cursor()

    if is_first_run:
        _create_tables_with_feedback(cur)
    else:
        for ddl in TABLES.values():
            cur.execute(ddl)

    conn.commit()
    conn.close()

    if is_first_run:
        _welcome_summary()

    return is_first_run


def save_target(ip, hostname=None, domain=None):
    conn = _connect()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO targets (ip, hostname, domain, first_seen)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(ip) DO UPDATE SET
            hostname = COALESCE(excluded.hostname, targets.hostname),
            domain = COALESCE(excluded.domain, targets.domain)
    """, (ip, hostname, domain, datetime.now().isoformat()))
    conn.commit()
    conn.close()


def save_credential(target_ip, user, secret, secret_type, valid, source):
    conn = _connect()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO credentials (target_ip, user, secret, secret_type, valid, source, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (target_ip, user, secret, secret_type, int(valid), source, datetime.now().isoformat()))
    conn.commit()
    conn.close()


def save_finding(target_ip, protocol, finding_type, detail):
    conn = _connect()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO findings (target_ip, protocol, finding_type, detail, timestamp)
        VALUES (?, ?, ?, ?, ?)
    """, (target_ip, protocol, finding_type, detail, datetime.now().isoformat()))
    conn.commit()
    conn.close()


def save_attack(target_ip, action, result):
    conn = _connect()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO attack_log (target_ip, action, result, timestamp)
        VALUES (?, ?, ?, ?)
    """, (target_ip, action, result, datetime.now().isoformat()))
    conn.commit()
    conn.close()


def get_findings(target_ip):
    conn = _connect()
    cur = conn.cursor()
    cur.execute("SELECT * FROM findings WHERE target_ip = ? ORDER BY timestamp", (target_ip,))
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_credentials(target_ip, only_valid=True):
    conn = _connect()
    cur = conn.cursor()
    if only_valid:
        cur.execute("SELECT * FROM credentials WHERE target_ip = ? AND valid = 1", (target_ip,))
    else:
        cur.execute("SELECT * FROM credentials WHERE target_ip = ?", (target_ip,))
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]
