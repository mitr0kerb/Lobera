# scripts/rpc/scan_params.py

EXPORT_FORMATS = ["json", "html", "xml", "yaml"]

REQUIRED = [
    {"key": "target",   "label": "IP/hostname del objetivo",  "required": True,  "secret": False, "default": None},
    {"key": "user",     "label": "Usuario",                   "required": False, "secret": False, "default": ""},
    {"key": "password", "label": "Contraseña",                "required": False, "secret": True,  "default": ""},
    {"key": "hash",     "label": "Hash NT (LM:NT o NT solo)", "required": False, "secret": True,  "default": None},
    {"key": "domain",   "label": "Dominio FQDN",              "required": False, "secret": False, "default": ""},
]

OPTIONAL = [
    {"key": "listener", "label": "IP del listener (petitpotam)",    "default": None},
    {"key": "out_dir",  "label": "Directorio de salida (sam-dump)", "default": "."},
    {"key": "command",  "label": "Comando remoto (exec-service)",   "default": None},
]

SCAN_ORDER = [
    # FASE 1 — enumeración autenticada
    {"script": "domain-info",    "condition": "has_auth"},
    {"script": "users",          "condition": "has_auth"},
    {"script": "groups",         "condition": "has_auth"},
    {"script": "sessions",       "condition": "has_auth"},
    {"script": "privileges",     "condition": "has_auth"},
    {"script": "services",       "condition": "has_auth"},
    # FASE 2 — sin credenciales
    {"script": "rid-brute",      "condition": None},
    # FASE 3 — exploits
    {"script": "printnightmare", "condition": "has_auth"},
    {"script": "petitpotam",     "condition": "has_listener"},
    {"script": "sam-dump",       "condition": "has_auth"},
    # FASE 4 — ejecución remota
    {"script": "exec-service",   "condition": "has_command"},
]
