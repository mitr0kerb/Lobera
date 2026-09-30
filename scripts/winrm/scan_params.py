# scripts/winrm/scan_params.py

# Parámetros requeridos y opcionales para el WinRM scanner.
# El scanner lee este fichero para saber qué preguntar al usuario
# y en qué orden ejecutar los scripts.

EXPORT_FORMATS = ["json", "html", "xml", "yaml"]

# required=True  → se pide en bucle hasta que se da un valor
# required=False → enter omite (usa default)
# secret=True    → se oculta al escribir (getpass)

REQUIRED = [
    {
        "key":      "target",
        "label":    "IP/hostname del objetivo",
        "required": True,
        "secret":   False,
        "default":  None,
    },
    {
        "key":      "user",
        "label":    "Usuario",
        "required": True,
        "secret":   False,
        "default":  None,
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
        "label":    "Dominio FQDN",
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
# condition="has_userlist" → solo si se proporcionó wordlist válida

SCAN_ORDER = [
    {"script": "check",           "condition": None},
    {"script": "sysinfo",         "condition": "has_auth"},
    {"script": "privesc-check",   "condition": "has_auth"},
    {"script": "password-spray",  "condition": "has_userlist"},
]
