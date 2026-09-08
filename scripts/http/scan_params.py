# scripts/http/scan_params.py

EXPORT_FORMATS = ["json", "html", "xml", "yaml"]

REQUIRED = [
    {"key": "target", "label": "IP/hostname del objetivo",   "required": True,  "secret": False, "default": None},
    {"key": "port",   "label": "Puerto HTTP (default: 80)",  "required": False, "secret": False, "default": 80},
]

OPTIONAL = [
    {"key": "timeout",  "label": "Timeout (segundos)",       "default": 5},
    {"key": "path",     "label": "Ruta inicial",             "default": "/"},
    {"key": "param",    "label": "Parámetro a inyectar",     "default": None},
    {"key": "wordlist", "label": "Wordlist de rutas",        "default": None},
    {"key": "listener", "label": "Listener OOB (log4shell)", "default": None},
]

SCAN_ORDER = [
    # FASE 1 — enumeración
    {"script": "banner-grab",          "condition": None},
    {"script": "tech-detect",          "condition": None},
    {"script": "robots-sitemap",       "condition": None},
    {"script": "ssl-redirect",         "condition": None},
    {"script": "cors-check",           "condition": None},
    {"script": "js-secrets",           "condition": None},
    {"script": "http2-check",          "condition": None},
    {"script": "dir-bruteforce",       "condition": "has_wordlist"},
    # FASE 2 — ataques
    {"script": "header-injection",     "condition": None},
    {"script": "open-redirect",        "condition": None},
    {"script": "sqli-detect",          "condition": "has_param"},
    {"script": "xss-detect",           "condition": "has_param"},
    {"script": "lfi-detect",           "condition": "has_param"},
    {"script": "ssrf-detect",          "condition": "has_param"},
    {"script": "graphql-enum",         "condition": None},
    {"script": "jwt-attack",           "condition": None},
    # FASE 3 — exploits
    {"script": "shellshock",           "condition": None},
    {"script": "apache-path-traversal","condition": None},
    {"script": "php-cgi-rce",          "condition": None},
    {"script": "log4shell",            "condition": "has_listener"},
    {"script": "http-request-smuggling","condition": None},
    # FASE 4 — post
    {"script": "extract-links",        "condition": None},
    {"script": "crawl",                "condition": None},
]
