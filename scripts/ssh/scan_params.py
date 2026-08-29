# scripts/ssh/scan_params.py

EXPORT_FORMATS = ["json", "html", "xml", "yaml"]

REQUIRED = [
    {"key": "target",   "label": "IP/hostname del objetivo", "required": True,  "secret": False, "default": None},
    {"key": "user",     "label": "Usuario SSH",              "required": False, "secret": False, "default": ""},
    {"key": "password", "label": "Contraseña",               "required": False, "secret": True,  "default": ""},
]

OPTIONAL = [
    {"key": "port",     "label": "Puerto SSH (default: 22)",       "default": 22},
    {"key": "timeout",  "label": "Timeout (segundos)",             "default": 5},
    {"key": "userlist", "label": "Wordlist de usuarios",           "default": None},
    {"key": "delay",    "label": "Delay entre intentos (segundos)","default": 1},
    {"key": "pub_key",  "label": "Clave pública para persistencia","default": None},
    {"key": "out_dir",  "label": "Directorio de salida (loot)",    "default": None},
]

SCAN_ORDER = [
    # FASE 1 — fingerprint sin credenciales
    {"script": "banner-grab",          "condition": None},
    {"script": "host-key-fingerprint", "condition": None},
    {"script": "key-exchange-enum",    "condition": None},
    {"script": "auth-methods",         "condition": None},
    {"script": "terrapin-check",       "condition": None},
    # FASE 2 — CVE checks sin credenciales
    {"script": "regresshion",          "condition": None},
    {"script": "libssh-bypass",        "condition": None},
    # FASE 3 — enumeración con userlist
    {"script": "user-enum",            "condition": "has_userlist"},
    {"script": "password-spray",       "condition": "has_userlist_and_auth"},
    # FASE 4 — post-explotación autenticada
    {"script": "config-dump",          "condition": "has_auth"},
    {"script": "key-harvest",          "condition": "has_auth"},
    {"script": "lateral-move",         "condition": "has_auth"},
]
