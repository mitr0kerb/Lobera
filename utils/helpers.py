# utils/helpers.py

"""
Utilidades comunes compartidas entre scripts y módulos.
Centraliza funciones que estaban duplicadas en múltiples scripts SMB.
"""


def parse_csv(raw):
    """
    Convierte un string CSV a lista de strings limpios.

    raw=None  → None  (no especificado, el caller usa su default)
    raw=""    → []    (especificado explícito vacío)
    raw="a,b" → ["a", "b"]
    """
    if raw is None:
        return None
    if raw == "":
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]


def detect_hash_format(secret, secret_type):
    """
    Clasifica el formato de un secreto almacenado para mostrarlo de forma
    legible en 'db creds'.

    Retorna string descriptivo del tipo/formato.
    """
    if secret_type == "null":
        return "null session"
    if secret_type == "password":
        return "texto claro"
    if secret_type == "hash":
        if ":" in (secret or ""):
            lm, nt = secret.split(":", 1)
            if len(nt) == 32:
                return "LM:NTLM (NT hash 32 hex)"
            return "LM:NT (formato no estándar)"
        if secret and len(secret) == 32:
            return "NTLM (NT hash, 32 hex)"
        return "hash ({} caracteres, formato no reconocido)".format(
            len(secret) if secret else 0
        )
    return secret_type or "desconocido"


def require_field(value, name):
    """
    Valida que un campo obligatorio no sea None ni vacío.
    Retorna True si el campo es válido, False si falta.
    Imprime un mensaje de error usando rich si falta.

    Uso:
        if not require_field(args.target, "-t/--target"):
            return
    """
    from core.output import console
    if not value:
        console.print("[red]Falta {} (obligatorio salvo con --example).[/red]".format(name))
        return False
    return True


def format_size(size_bytes):
    """Formatea un tamaño en bytes a string legible (KB, MB, GB)."""
    if size_bytes < 1024:
        return "{} B".format(size_bytes)
    if size_bytes < 1024 ** 2:
        return "{:.1f} KB".format(size_bytes / 1024)
    if size_bytes < 1024 ** 3:
        return "{:.1f} MB".format(size_bytes / 1024 ** 2)
    return "{:.1f} GB".format(size_bytes / 1024 ** 3)


def read_lines(filepath):
    """
    Lee un fichero de texto y devuelve lista de líneas no vacías
    (stripped). Lanza OSError si no se puede leer.
    """
    with open(filepath, encoding="utf-8", errors="replace") as f:
        return [line.strip() for line in f if line.strip()]
