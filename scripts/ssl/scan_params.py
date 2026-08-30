# scripts/ssl/scan_params.py

EXPORT_FORMATS = ["json", "html", "xml", "yaml"]

REQUIRED = [
    {"key": "target", "label": "IP/hostname del objetivo",      "required": True,  "secret": False, "default": None},
    {"key": "port",   "label": "Puerto SSL/TLS (default: 443)", "required": False, "secret": False, "default": 443},
]

OPTIONAL = [
    {"key": "timeout",  "label": "Timeout (segundos)",           "default": 5},
    {"key": "sni",      "label": "SNI hostname",                 "default": None},
    {"key": "domain",   "label": "Dominio para CT log search",   "default": None},
    {"key": "attempts", "label": "Conexiones para TLS analysis", "default": 3},
]

SCAN_ORDER = [
    # FASE 1 — enumeración e información
    {"script": "cert-info",             "condition": None},
    {"script": "protocol-version",      "condition": None},
    {"script": "cipher-enum",           "condition": None},
    {"script": "san-enum",              "condition": None},
    {"script": "hsts-check",            "condition": None},
    {"script": "ocsp-check",            "condition": None},
    {"script": "ct-log-search",         "condition": "has_domain"},
    # FASE 2 — CVE checks
    {"script": "heartbleed",            "condition": None},
    {"script": "poodle",                "condition": None},
    {"script": "openssl-cve-2022-0778", "condition": None},
    # FASE 3 — exploits propios
    {"script": "cert-spoof-check",      "condition": None},
    {"script": "tls-poison",            "condition": None},
    {"script": "alpn-confusion",        "condition": None},
]
