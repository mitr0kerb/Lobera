# core/output.py

from rich.console import Console
from rich.table import Table

console = Console()

PROTOCOL_COLORS = {
    "SMB": "green",
    "RPC": "blue",
    "LDAP": "yellow",
    "KRB": "magenta",
    "WINRM": "cyan",
}

STATUS_LABELS = {
    "ok": ("bold green", "OK"),
    "pwned": ("bold green", "P"),
    "fail": ("bold red", "F"),
    "info": ("bold blue", "I"),
}


def _get_protocol_color(protocol):
    """
    Busca el color por coincidencia de prefijo, para que protocolos con
    versión (ej: "SMBv2.1", "SMBv1") sigan usando el color de su base ("SMB").
    """
    protocol_upper = protocol.upper()
    for key, color in PROTOCOL_COLORS.items():
        if protocol_upper.startswith(key):
            return color
    return "white"


def print_result(protocol, target_ip, status, message):
    """
    Línea de output homogénea para eventos puntuales.
    'protocol' puede ser la base ("SMB") o incluir versión ("SMBv2.1") —
    el color se resuelve por prefijo en ambos casos.
    El status se marca con una letra: OK, P (pwned), F (fail), I (info).

    Ej: OK [SMBv2.1] 10.129.61.52 - null session permitida
    """
    color = _get_protocol_color(protocol)
    label_color, label = STATUS_LABELS.get(status, ("white", "?"))
    console.print(f"[{label_color}]{label}[/{label_color}] [{color}][{protocol}][/{color}] {target_ip} - {message}")


def print_check(message, ok=True):
    """
    Línea informativa compacta, sin repetir protocolo/IP. Pensada para
    chequeos que se hacen justo después de un evento principal ya impreso
    con print_result (ej: connect() ya mostró [SMBv3.0] IP - conexión
    establecida; check_signing() solo añade una línea corta debajo).
    """
    color = "green" if ok else "red"
    symbol = "✓" if ok else "✗"
    console.print(f"  [{color}]{symbol}[/{color}] {message}")


def print_table(title, headers, rows):
    """
    Para listados: usuarios, shares, grupos...
    headers: lista de nombres de columna
    rows: lista de tuplas/listas con los valores de cada fila
    """
    table = Table(title=title)
    for h in headers:
        table.add_column(h)
    for row in rows:
        table.add_row(*[str(x) for x in row])
    console.print(table)
