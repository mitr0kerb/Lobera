# scripts/mssql/scan_params.py

EXPORT_FORMATS = ["json", "html", "xml", "yaml"]

REQUIRED = [
    {"key": "target",   "label": "IP/hostname del objetivo", "required": True,  "secret": False, "default": None},
    {"key": "user",     "label": "Usuario MSSQL",             "required": False, "secret": False, "default": ""},
    {"key": "password", "label": "Contraseña MSSQL",          "required": False, "secret": True,  "default": ""},
]

OPTIONAL = [
    {"key": "port",        "label": "Puerto MSSQL",                        "default": 1433},
    {"key": "instance",    "label": "Nombre de instancia",                 "default": ""},
    {"key": "domain",      "label": "Dominio (para auth Windows)",         "default": ""},
    {"key": "hash",        "label": "Hash NT (pass-the-hash)",             "default": None},
    {"key": "userlist",    "label": "Wordlist de usuarios (spray)",        "default": None},
    {"key": "passlist",    "label": "Wordlist de passwords (brute)",       "default": None},
    {"key": "timeout",     "label": "Timeout (segundos)",                  "default": 5},
    {"key": "delay",       "label": "Delay entre intentos (segundos)",     "default": 0},
    {"key": "command",     "label": "Comando OS a ejecutar (xp_cmdshell)", "default": None},
    {"key": "query",       "label": "Query SQL a ejecutar",                "default": None},
    {"key": "attacker_ip", "label": "IP del atacante (para NTLM relay)",   "default": None},
]

SCAN_ORDER = [
    # FASE 1 — Enumeración sin credenciales
    {"script": "version-enum",        "condition": None},
    {"script": "instance-enum",       "condition": None},
    {"script": "auth-check",          "condition": None},
    # FASE 2 — Enumeración autenticada
    {"script": "db-enum",             "condition": "has_auth"},
    {"script": "user-enum",           "condition": "has_auth"},
    {"script": "privs-check",         "condition": "has_auth"},
    {"script": "linked-servers",      "condition": "has_auth"},
    # FASE 3 — Ataques
    {"script": "password-spray",      "condition": "has_userlist"},
    {"script": "xp-cmdshell",         "condition": "has_auth_and_cmd"},
    {"script": "ntlm-steal",          "condition": "has_attacker_ip"},
    # FASE 4 — Exploits
    {"script": "xp-cmdshell-enable",  "condition": "has_auth"},
    {"script": "clr-exec",            "condition": "has_auth"},
    {"script": "agent-job",           "condition": "has_auth"},
    {"script": "linked-exec",         "condition": "has_auth"},
    # FASE 5 — Post-explotación
    {"script": "dump-hashes",         "condition": "has_auth"},
    {"script": "read-file",           "condition": "has_auth"},
    {"script": "custom-query",        "condition": "has_auth_and_query"},
]
