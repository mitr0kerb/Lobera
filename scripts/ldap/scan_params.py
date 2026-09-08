# scripts/ldap/scan_params.py

EXPORT_FORMATS = ["json", "html", "xml", "yaml"]

REQUIRED = [
    {"key": "target",   "label": "IP/hostname del DC",            "required": True,  "secret": False, "default": None},
    {"key": "domain",   "label": "Dominio FQDN (ej: CORP.LOCAL)", "required": True,  "secret": False, "default": None},
    {"key": "user",     "label": "Usuario",                       "required": False, "secret": False, "default": ""},
    {"key": "password", "label": "Contraseña",                    "required": False, "secret": True,  "default": ""},
    {"key": "hash",     "label": "Hash NT (LM:NT o NT solo)",     "required": False, "secret": True,  "default": None},
]

OPTIONAL = [
    {"key": "ldaps",       "label": "Usar LDAPS (true/false)",              "default": False},
    {"key": "port",        "label": "Puerto LDAP",                          "default": None},
    {"key": "userlist",    "label": "Wordlist de usuarios (para spray)",     "default": None},
    {"key": "attacker_ip", "label": "IP del atacante (para relay)",         "default": None},
    {"key": "target_dn",   "label": "DN del objeto LDAP (para dacl-enum)",  "default": None},
    {"key": "target_obj",  "label": "DN/sAMAccountName objetivo (acl-abuse)","default": None},
    {"key": "out_dir",     "label": "Directorio de salida (bloodhound)",    "default": None},
]

SCAN_ORDER = [
    # FASE 1 — enumeración autenticada
    {"script": "domain-info",         "condition": "has_auth"},
    {"script": "users",               "condition": "has_auth"},
    {"script": "groups",              "condition": "has_auth"},
    {"script": "computers",           "condition": "has_auth"},
    {"script": "admins",              "condition": "has_auth"},
    {"script": "password-policy",     "condition": "has_auth"},
    # FASE 2 — targets para ataques Kerberos
    {"script": "asreproast-targets",  "condition": "has_auth"},
    {"script": "kerberoast-targets",  "condition": "has_auth"},
    # FASE 3 — análisis de ACLs
    {"script": "dacl-enum",           "condition": "has_target_dn"},
    # FASE 4 — exportación y ataques
    {"script": "bloodhound-export",   "condition": "has_auth"},
    {"script": "password-spray-ldap", "condition": "has_userlist"},
    {"script": "acl-abuse",           "condition": "has_target_obj"},
    {"script": "ntlm-relay-setup",    "condition": "has_attacker_ip"},
]
