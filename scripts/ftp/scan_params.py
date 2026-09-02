# scripts/ftp/scan_params.py

EXPORT_FORMATS = ["json", "html", "xml", "yaml"]

REQUIRED = [
    {"key": "target",   "label": "IP/hostname del objetivo", "required": True,  "secret": False, "default": None},
    {"key": "user",     "label": "Usuario FTP",              "required": False, "secret": False, "default": ""},
    {"key": "password", "label": "Contraseña FTP",           "required": False, "secret": True,  "default": ""},
]

OPTIONAL = [
    {"key": "port",     "label": "Puerto FTP",                          "default": 21},
    {"key": "userlist", "label": "Wordlist de usuarios (para spray)",    "default": None},
    {"key": "passlist",  "label": "Wordlist de passwords (para brute)",   "default": None},
    {"key": "timeout",  "label": "Timeout (segundos)",                   "default": 5},
    {"key": "delay",    "label": "Delay entre intentos (segundos)",      "default": 0},
]

SCAN_ORDER = [
    # FASE 1 — Enumeración sin credenciales
    {"script": "banner-grab",        "condition": None},
    {"script": "service-info",       "condition": None},
    {"script": "anon-check",         "condition": None},
    {"script": "user-enum",          "condition": "has_userlist"},
    # FASE 2 — Ataques con credenciales o diccionarios
    {"script": "password-spray",     "condition": "has_userlist"},
    {"script": "write-check",        "condition": "has_auth"},
    {"script": "bounce-scan",        "condition": "has_auth"},
    # FASE 3 — Exploits conocidos
    {"script": "vsftpd-backdoor",    "condition": None},
    {"script": "proftpd-bypass",     "condition": None},
    {"script": "ssl-strip",          "condition": None},
    {"script": "anonymous-webshell", "condition": "has_anon"},
    # FASE 4 — Post-explotación
    {"script": "list-files",         "condition": "has_auth"},
    {"script": "download-loot",      "condition": "has_auth"},
    {"script": "pivot-setup",        "condition": "has_auth"},
]
