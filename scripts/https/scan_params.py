# scripts/https/scan_params.py

EXPORT_FORMATS = ["json", "html", "xml", "yaml"]

REQUIRED = [
    {"key": "target", "label": "IP/hostname del objetivo",    "required": True,  "secret": False, "default": None},
    {"key": "port",   "label": "Puerto HTTPS (default: 443)", "required": False, "secret": False, "default": 443},
]

OPTIONAL = [
    {"key": "timeout",   "label": "Timeout (segundos)",        "default": 5},
    {"key": "sni",       "label": "SNI hostname",              "default": None},
    {"key": "path",      "label": "Ruta inicial",              "default": "/"},
    {"key": "param",     "label": "Parámetro a inyectar",      "default": None},
    {"key": "wordlist",  "label": "Wordlist de rutas",         "default": None},
    {"key": "listener",  "label": "Listener OOB (log4shell)",  "default": None},
    {"key": "client_id", "label": "Client ID OAuth",           "default": None},
    {"key": "http_port", "label": "Puerto HTTP (stripping)",   "default": 80},
]

SCAN_ORDER = [
    # FASE 1 — enumeración
    {"script": "banner-grab",         "condition": None},
    {"script": "tech-detect",         "condition": None},
    {"script": "security-headers",    "condition": None},
    {"script": "certificate-pinning", "condition": None},
    {"script": "robots-sitemap",      "condition": None},
    {"script": "cors-check",          "condition": None},
    {"script": "js-secrets",          "condition": None},
    {"script": "dir-bruteforce",      "condition": "has_wordlist"},
    # FASE 2 — ataques
    {"script": "cache-poisoning",     "condition": None},
    {"script": "oauth-misconfig",     "condition": "has_client_id"},
    {"script": "jwt-attack",          "condition": None},
    {"script": "sqli-detect",         "condition": "has_param"},
    {"script": "xss-detect",          "condition": "has_param"},
    {"script": "lfi-detect",          "condition": "has_param"},
    {"script": "ssrf-detect",         "condition": "has_param"},
    # FASE 3 — exploits
    {"script": "tls-stripping",       "condition": None},
    {"script": "php-cgi-rce",         "condition": None},
    {"script": "log4shell",           "condition": "has_listener"},
    {"script": "spring4shell",        "condition": None},
    {"script": "jenkins-file-read",   "condition": None},
    # FASE 4 — post
    {"script": "extract-links",       "condition": None},
    {"script": "crawl",               "condition": None},
]
