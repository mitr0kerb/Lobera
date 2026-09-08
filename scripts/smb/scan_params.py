# scripts/smb/scan_params.py

# Parámetros requeridos y opcionales para el SMB scanner.
# El scanner lee este fichero para saber qué preguntar al usuario
# y en qué orden ejecutar los scripts.

EXPORT_FORMATS = ["json", "html", "xml", "yaml"]

# required=True  → se pide en bucle hasta que se da un valor
# required=False → enter omite (usa default)
# secret=True    → se oculta al escribir (getpass)

REQUIRED = [
    {
        "key":      "target",
        "label":    "Target IP/hostname",
        "required": True,
        "secret":   False,
        "default":  None,
    },
    {
        "key":      "user",
        "label":    "Usuario",
        "required": False,
        "secret":   False,
        "default":  "",
        "hint":     "enter = null session",
    },
    {
        "key":      "password",
        "label":    "Contraseña",
        "required": False,
        "secret":   True,
        "default":  "",
        "hint":     "enter = vacío",
    },
    {
        "key":      "hash",
        "label":    "Hash NT (formato NT o LM:NT)",
        "required": False,
        "secret":   True,
        "default":  None,
        "hint":     "enter = omitir",
    },
    {
        "key":      "domain",
        "label":    "Dominio",
        "required": False,
        "secret":   False,
        "default":  "",
        "hint":     "enter = omitir",
    },
]

OPTIONAL = [
    {
        "key":     "userlist",
        "label":   "Wordlist de usuarios para password spray",
        "default": None,
        "hint":    "ruta al fichero — enter para omitir spray",
    },
]

# Orden de ejecución de scripts y condición para lanzar cada uno.
# condition=None           → siempre se ejecuta
# condition="has_auth"     → solo si hay user+pass o hash
# condition="has_shares"   → solo si shares encontró shares no especiales
# condition="has_userlist" → solo si se proporcionó wordlist válida

SCAN_ORDER = [
    {"script": "signing-check",  "condition": None},
    {"script": "null-session",   "condition": None},
    {"script": "shares",         "condition": None},
    {"script": "gpp-password",   "condition": "has_auth"},
    {"script": "spider",         "condition": "has_shares"},
    {"script": "password-spray", "condition": "has_userlist"},
]
