# scripts/kerberos/scan_params.py

EXPORT_FORMATS = ["json", "html", "xml", "yaml"]

REQUIRED = [
    {"key": "target",      "label": "IP/hostname del DC",              "required": True,  "secret": False, "default": None},
    {"key": "domain",      "label": "Dominio FQDN (ej: CORP.LOCAL)",   "required": True,  "secret": False, "default": None},
    {"key": "user",        "label": "Usuario",                         "required": False, "secret": False, "default": ""},
    {"key": "password",    "label": "Contraseña",                      "required": False, "secret": True,  "default": ""},
    {"key": "hash",        "label": "Hash NT (LM:NT o NT solo)",       "required": False, "secret": True,  "default": None},
    {"key": "domain_sid",  "label": "SID del dominio (S-1-5-21-...)",  "required": False, "secret": False, "default": None},
    {"key": "krbtgt_hash", "label": "Hash NT del krbtgt",              "required": False, "secret": True,  "default": None},
]

OPTIONAL = [
    {"key": "userlist",    "label": "Wordlist de usuarios",            "default": None},
    {"key": "spn",         "label": "SPN concreto (opcional)",         "default": None},
    {"key": "ccache",      "label": "Ruta a .ccache existente",        "default": None},
    {"key": "target_user", "label": "Usuario a impersonar",            "default": "Administrator"},
]

# Condiciones disponibles:
#   None                → siempre se ejecuta
#   "has_userlist"      → si hay userlist válida
#   "has_auth"          → si hay user + (password o hash)
#   "has_hash"          → si hay hash NT
#   "has_krbtgt_sid"    → si hay krbtgt_hash + domain_sid
#   "has_ccache"        → si hay ccache (dado o generado durante el scan)
#   "has_auth_and_spn"  → si hay credenciales + spn

SCAN_ORDER = [
    # FASE 1 — sin credenciales
    {"script": "user-enum",           "condition": "has_userlist"},
    {"script": "asrep-roasting",      "condition": "has_userlist"},
    # FASE 2 — con credenciales
    {"script": "spn-scan",            "condition": "has_auth"},
    {"script": "kerberoasting",       "condition": "has_auth"},
    {"script": "overpass-the-hash",   "condition": "has_hash"},
    # FASE 3 — con hash krbtgt + SID
    {"script": "golden-ticket",       "condition": "has_krbtgt_sid"},
    {"script": "diamond-ticket",      "condition": "has_krbtgt_sid"},
    {"script": "sapphire-ticket",     "condition": "has_krbtgt_sid"},
    # FASE 4 — usar ticket
    {"script": "pass-the-ticket",     "condition": "has_ccache"},
    # FASE 5 — delegación
    {"script": "unconstrained-deleg", "condition": "has_auth"},
    {"script": "constrained-s4u",     "condition": "has_auth_and_spn"},
    {"script": "rbcd",                "condition": "has_auth"},
    # FASE 6 — credenciales avanzadas
    {"script": "shadow-credentials",  "condition": "has_auth"},
    {"script": "adcs",                "condition": "has_auth"},
    # FASE 7 — exploits
    {"script": "sam-spoofing",        "condition": "has_auth"},
    {"script": "ms14-068",            "condition": "has_auth"},
    {"script": "kerber-loss",         "condition": "has_auth_and_spn"},
    {"script": "reset-nightmare",     "condition": "has_auth"},
]
