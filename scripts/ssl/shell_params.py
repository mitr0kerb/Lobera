# scripts/ssl/shell_params.py

EXPORT_FORMATS = ["json", "html", "xml", "yaml"]

SCRIPT_PARAMS = {
    # ── enum ──────────────────────────────────────────────────────────────────
    "cert-info": {
        "description": "Extrae información completa del certificado SSL/TLS: CN, SAN, emisor, expiración, algoritmo y huella.",
        "required": ["target"],
        "optional": ["port", "timeout", "sni"],
        "defaults": {"port": 443, "timeout": 5},
        "example": [
            "set target 10.10.10.5",
            "set port 443",
            "run",
        ],
    },
    "protocol-version": {
        "description": "Detecta qué versiones de SSL/TLS acepta el servidor. Alerta sobre versiones obsoletas y peligrosas.",
        "required": ["target"],
        "optional": ["port", "timeout"],
        "defaults": {"port": 443, "timeout": 5},
        "example": [
            "set target 10.10.10.5",
            "run",
        ],
    },
    "cipher-enum": {
        "description": "Enumera cipher suites soportadas y marca las débiles o inseguras.",
        "required": ["target"],
        "optional": ["port", "timeout"],
        "defaults": {"port": 443, "timeout": 5},
        "example": [
            "set target 10.10.10.5",
            "run",
        ],
    },
    "san-enum": {
        "description": "Extrae todos los SANs del certificado. Descubre subdominios y hosts relacionados.",
        "required": ["target"],
        "optional": ["port", "timeout", "sni"],
        "defaults": {"port": 443, "timeout": 5},
        "example": [
            "set target 10.10.10.5",
            "run",
        ],
    },
    "ocsp-check": {
        "description": "Comprueba el estado de revocación del certificado via OCSP.",
        "required": ["target"],
        "optional": ["port", "timeout", "sni"],
        "defaults": {"port": 443, "timeout": 5},
        "example": [
            "set target 10.10.10.5",
            "run",
        ],
    },
    "hsts-check": {
        "description": "Verifica la presencia y configuración correcta de HSTS.",
        "required": ["target"],
        "optional": ["port", "timeout", "sni"],
        "defaults": {"port": 443, "timeout": 5},
        "example": [
            "set target 10.10.10.5",
            "run",
        ],
    },
    "ct-log-search": {
        "description": "Busca en Certificate Transparency logs (crt.sh) todos los certificados del dominio. Descubre subdominios ocultos, entornos de staging y APIs no públicas.",
        "required": ["target", "domain"],
        "optional": ["port", "timeout", "wildcard"],
        "defaults": {"port": 443, "timeout": 10, "wildcard": True},
        "example": [
            "set target 10.10.10.5",
            "set domain ejemplo.com",
            "run",
        ],
    },
    # ── attack ────────────────────────────────────────────────────────────────
    "heartbleed": {
        "description": "CVE-2014-0160: detecta si el servidor es vulnerable a Heartbleed (lectura de memoria en OpenSSL 1.0.1-1.0.1f).",
        "required": ["target"],
        "optional": ["port", "timeout"],
        "defaults": {"port": 443, "timeout": 5},
        "example": [
            "set target 10.10.10.5",
            "run",
        ],
    },
    "poodle": {
        "description": "CVE-2014-3566 (POODLE): detecta si el servidor acepta SSLv3 (padding oracle sobre SSL 3.0 CBC).",
        "required": ["target"],
        "optional": ["port", "timeout"],
        "defaults": {"port": 443, "timeout": 5},
        "example": [
            "set target 10.10.10.5",
            "run",
        ],
    },
    # ── exploit ───────────────────────────────────────────────────────────────
    "cert-spoof-check": {
        "description": "Script propio: analiza wildcards peligrosos, SANs que permiten domain spoofing y CA intermedias mal configuradas.",
        "required": ["target"],
        "optional": ["port", "timeout", "sni"],
        "defaults": {"port": 443, "timeout": 5},
        "example": [
            "set target 10.10.10.5",
            "run",
        ],
    },
    "tls-poison": {
        "description": "Script propio: detecta reutilización de TLS Session Ticket Keys. Si no se rotan, sesiones futuras son descifrables con acceso previo a la clave.",
        "required": ["target"],
        "optional": ["port", "timeout", "sni", "attempts"],
        "defaults": {"port": 443, "timeout": 5, "attempts": 3},
        "example": [
            "set target 10.10.10.5",
            "set attempts 5",
            "run",
        ],
    },
    "alpn-confusion": {
        "description": "Script propio: detecta ALPN protocol confusion para bypass de WAF/proxies que inspeccionan solo el protocolo inicial.",
        "required": ["target"],
        "optional": ["port", "timeout", "sni"],
        "defaults": {"port": 443, "timeout": 5},
        "example": [
            "set target 10.10.10.5",
            "run",
        ],
    },
    "openssl-cve-2022-0778": {
        "description": "CVE-2022-0778: detecta si el servidor es potencialmente vulnerable al bucle infinito en OpenSSL BN_mod_sqrt() (DoS via certificado malformado).",
        "required": ["target"],
        "optional": ["port", "timeout", "sni"],
        "defaults": {"port": 443, "timeout": 5},
        "example": [
            "set target 10.10.10.5",
            "run",
        ],
    },
}

PARAM_LABELS = {
    "target":   "IP/hostname del objetivo",
    "port":     "Puerto SSL/TLS (default: 443)",
    "timeout":  "Timeout de conexión (segundos)",
    "sni":      "Server Name Indication (default: IP del objetivo)",
    "domain":   "Dominio para búsqueda en CT logs (ej: ejemplo.com)",
    "wildcard": "Incluir wildcards en CT log search (True/False)",
    "attempts": "Número de conexiones para TLS session analysis (default: 3)",
}
