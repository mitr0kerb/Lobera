# core/session_db.py

import sqlite3
import os
import time
import hashlib
import hmac
import secrets
import string
import getpass
from datetime import datetime, timedelta
from rich.panel import Panel
from rich.align import Align
from rich.text import Text
from core.output import console

DB_PATH = os.path.join(os.path.expanduser("~"), ".lobera", "session.db")

PBKDF2_ITERATIONS = 200_000
_PASSWORD_ALPHABET = string.ascii_letters + string.digits + "!@#$%^&*-_="

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
    "auth": """
        CREATE TABLE IF NOT EXISTS auth (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            username TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            must_change_password INTEGER NOT NULL DEFAULT 1,
            created_at TEXT,
            updated_at TEXT
        )
    """,
    "session": """
        CREATE TABLE IF NOT EXISTS session (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            expires_at TEXT NOT NULL,
            created_at TEXT
        )
    """,
}


def _connect():
    """
    Abre la conexión SQLite con dos mejoras de robustez:

    timeout=30:  En vez de fallar inmediatamente cuando hay lock de escritura
                 (ej. dos terminales corriendo en paralelo), SQLite espera
                 hasta 30 s antes de lanzar OperationalError. Más que suficiente
                 para cualquier operación de Lobera — las escrituras son breves.

    WAL mode:   Write-Ahead Logging permite lectura concurrente mientras hay
                una escritura activa. Sin WAL, SQLite bloquea lectores durante
                cada INSERT. Con WAL, 'db findings' puede correr mientras otro
                proceso guarda hallazgos — sin errores de lock.

    Ambas opciones son seguras con SQLite en un único host y no requieren
    cambiar el formato del fichero .db.
    """
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
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


def _welcome_summary(username=None, plaintext_password=None):
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

    if username and plaintext_password:
        cred_body = (
            f"[bold]Usuario:[/bold] [cyan]{username}[/cyan]\n"
            f"[bold]Contraseña temporal:[/bold] [yellow]{plaintext_password}[/yellow]\n\n"
            "[bold red]Esta contraseña NO se volverá a mostrar.[/bold red]\n"
            "Se te pedirá cambiarla en el próximo inicio de sesión."
        )
        console.print(Panel(cred_body, title="[bold red]Credenciales de acceso — guárdalas ahora[/bold red]",
                             border_style="red", expand=False))

    console.print()
    time.sleep(1.0)


def init_db():
    """
    Crea las tablas si no existen. Llamar una vez al arrancar la herramienta.
    Si es la primera vez que se ejecuta Lobera, muestra una secuencia de bienvenida
    con el lobo ASCII, confirmación por tabla, y genera el usuario inicial de acceso
    (username = usuario del SO, password aleatoria mostrada una única vez).
    Si ya existe, no dice nada.
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
        username, plaintext_password = create_initial_user()
        _welcome_summary(username, plaintext_password)

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


def get_targets():
    conn = _connect()
    cur = conn.cursor()
    cur.execute("SELECT * FROM targets ORDER BY first_seen")
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def delete_target(target_ip):
    """
    Borra TODO lo relacionado con un target_ip en las 4 tablas:
    targets, credentials, findings, attack_log.
    Devuelve un dict con cuántas filas se borraron de cada tabla.
    """
    conn = _connect()
    cur = conn.cursor()

    counts = {}
    for table in ("credentials", "findings", "attack_log"):
        cur.execute(f"SELECT COUNT(*) FROM {table} WHERE target_ip = ?", (target_ip,))
        counts[table] = cur.fetchone()[0]
        cur.execute(f"DELETE FROM {table} WHERE target_ip = ?", (target_ip,))

    cur.execute("SELECT COUNT(*) FROM targets WHERE ip = ?", (target_ip,))
    counts["targets"] = cur.fetchone()[0]
    cur.execute("DELETE FROM targets WHERE ip = ?", (target_ip,))

    conn.commit()
    conn.close()
    return counts


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


# ============================================================
# Autenticación de acceso a Lobera (tabla auth)
# ============================================================

def _generate_random_password(length=16):
    """
    Genera una contraseña aleatoria criptográficamente segura usando `secrets`
    (no `random`, que no es apto para fines de seguridad).
    Garantiza al menos una mayúscula, una minúscula, un dígito y un símbolo.
    """
    while True:
        pwd = "".join(secrets.choice(_PASSWORD_ALPHABET) for _ in range(length))
        if (any(c.islower() for c in pwd) and any(c.isupper() for c in pwd)
                and any(c.isdigit() for c in pwd)
                and any(c in "!@#$%^&*-_=" for c in pwd)):
            return pwd


def _hash_password(password, salt=None):
    """
    PBKDF2-HMAC-SHA256 con salt aleatorio. No usamos bcrypt/argon2 para
    mantener cero dependencias externas en session_db.py (mismo criterio
    que ya se aplicó al elegir sqlite3 de la stdlib en ADR-01).
    """
    if salt is None:
        salt = secrets.token_hex(16)
    pwd_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt), PBKDF2_ITERATIONS
    ).hex()
    return pwd_hash, salt


def _verify_password(password, salt, expected_hash):
    """Comparación en tiempo constante para evitar timing attacks."""
    computed, _ = _hash_password(password, salt)
    return hmac.compare_digest(computed, expected_hash)


def create_initial_user():
    """
    Se llama SOLO durante la secuencia de primera ejecución, desde init_db().
    Crea el usuario inicial: username = usuario del sistema operativo,
    password = aleatoria. Devuelve (username, password_en_claro) para que
    el llamador la muestre en pantalla UNA vez — no se vuelve a poder
    recuperar en claro después de esta llamada.
    """
    username = getpass.getuser()
    plaintext_password = _generate_random_password()
    pwd_hash, salt = _hash_password(plaintext_password)
    now = datetime.now().isoformat()

    conn = _connect()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO auth (id, username, password_hash, salt, must_change_password, created_at, updated_at)
        VALUES (1, ?, ?, ?, 1, ?, ?)
        ON CONFLICT(id) DO NOTHING
    """, (username, pwd_hash, salt, now, now))
    conn.commit()
    conn.close()

    return username, plaintext_password


def get_auth():
    """Devuelve {'username':..., 'must_change_password': 0/1} o None si aún no existe."""
    conn = _connect()
    cur = conn.cursor()
    cur.execute("SELECT username, must_change_password FROM auth WHERE id = 1")
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def verify_login(username, password):
    conn = _connect()
    cur = conn.cursor()
    cur.execute("SELECT username, password_hash, salt FROM auth WHERE id = 1")
    row = cur.fetchone()
    conn.close()
    if not row or row["username"] != username:
        return False
    return _verify_password(password, row["salt"], row["password_hash"])


def change_password(new_password):
    pwd_hash, salt = _hash_password(new_password)
    conn = _connect()
    cur = conn.cursor()
    cur.execute("""
        UPDATE auth SET password_hash = ?, salt = ?, must_change_password = 0, updated_at = ?
        WHERE id = 1
    """, (pwd_hash, salt, datetime.now().isoformat()))
    conn.commit()
    conn.close()


# ============================================================
# Sesión de acceso ("recuérdame X tiempo") — tabla session
# ============================================================
#
# No usamos token/hash aquí: la propia session.db ya es el límite de
# confianza (contiene credenciales/hashes de las máquinas atacadas en
# claro). Si alguien ya tiene acceso de lectura a este fichero, la sesión
# guardada no añade una superficie de ataque nueva. Guardamos solo un
# timestamp de expiración.

def start_session(ttl_minutes):
    """
    Marca la sesión de acceso a Lobera como activa durante ttl_minutes
    a partir de ahora. Se llama justo después de un login correcto
    (y, si aplicaba, después del cambio de contraseña obligatorio).
    """
    expires_at = (datetime.now() + timedelta(minutes=ttl_minutes)).isoformat()
    now = datetime.now().isoformat()
    conn = _connect()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO session (id, expires_at, created_at)
        VALUES (1, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            expires_at = excluded.expires_at,
            created_at = excluded.created_at
    """, (expires_at, now))
    conn.commit()
    conn.close()


def get_active_session():
    """
    Devuelve el datetime de expiración si hay una sesión válida (no
    expirada), o None si no hay sesión guardada o ya caducó.
    """
    conn = _connect()
    cur = conn.cursor()
    cur.execute("SELECT expires_at FROM session WHERE id = 1")
    row = cur.fetchone()
    conn.close()

    if not row:
        return None

    expires_at = datetime.fromisoformat(row["expires_at"])
    if datetime.now() >= expires_at:
        return None
    return expires_at


def clear_session():
    """Invalida la sesión guardada (logout manual). No usada aún desde la CLI."""
    conn = _connect()
    cur = conn.cursor()
    cur.execute("DELETE FROM session WHERE id = 1")
    conn.commit()
    conn.close()
