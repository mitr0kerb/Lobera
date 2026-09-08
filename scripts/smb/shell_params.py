# scripts/smb/shell_params.py
#
# Mapa de parámetros por script SMB.
# La SMBScriptShell lee este fichero para saber qué pedir al usuario,
# qué es obligatorio, y qué ejemplo mostrar al cargar cada script.

SCRIPT_PARAMS = {
    "null-session": {
        "description": "Comprueba si el objetivo permite SMB null session sin usar credenciales reales.",
        "required": ["target"],
        "optional": ["domain", "timeout"],
        "defaults": {"timeout": 5},
        "example": [
            "set target 10.10.10.5",
            "run",
        ],
    },
    "signing-check": {
        "description": "Comprueba si el servidor exige SMB signing (vulnerable a NTLM relay si no).",
        "required": ["target"],
        "optional": ["timeout"],
        "defaults": {"timeout": 5},
        "example": [
            "set target 10.10.10.5",
            "run",
        ],
    },
    "shares": {
        "description": "Lista los shares SMB disponibles. Sin credenciales intenta null session.",
        "required": ["target"],
        "optional": ["user", "password", "hash", "domain", "timeout"],
        "defaults": {"timeout": 5},
        "example": [
            "set target 10.10.10.5",
            "set user administrator",
            "set password Pass123!",
            "run",
        ],
    },
    "gpp-password": {
        "description": "Busca credenciales en ficheros GPP (Groups.xml). Vulnerabilidad MS14-025.",
        "required": ["target", "user"],
        "optional": ["password", "hash", "domain", "timeout"],
        "defaults": {"timeout": 5},
        "mutually_exclusive": [["password", "hash"]],
        "example": [
            "set target 10.10.10.5",
            "set user iker",
            "set password Pass123!",
            "run",
        ],
    },
    "spider": {
        "description": "Rastrea shares recursivamente y descarga ficheros con extensiones o keywords de interés.",
        "required": ["target"],
        "optional": ["user", "password", "hash", "domain", "share", "ext", "keywords", "depth", "timeout"],
        "defaults": {"depth": 5, "timeout": 5},
        "example": [
            "set target 10.10.10.5",
            "set user iker",
            "set password Pass123!",
            "set share Users",
            "set keywords password,backup",
            "run",
        ],
    },
    "password-spray": {
        "description": "Prueba una misma contraseña o hash contra una lista de usuarios.",
        "required": ["target", "userlist"],
        "optional": ["password", "hash", "domain", "timeout"],
        "defaults": {"timeout": 5},
        "mutually_exclusive": [["password", "hash"]],
        "at_least_one": [["password", "hash"]],
        "example": [
            "set target 10.10.10.5",
            "set userlist /ruta/users.txt",
            "set password Summer2024!",
            "run",
        ],
    },
    "interactive-shell": {
        "description": "Abre una consola interactiva SMB para navegar shares, descargar ficheros, etc.",
        "required": ["target"],
        "optional": ["user", "password", "hash", "domain", "timeout"],
        "defaults": {"timeout": 5},
        "example": [
            "set target 10.10.10.5",
            "set user iker",
            "set password Pass123!",
            "run",
        ],
    },
}

# Etiquetas legibles para mostrar en la consola
PARAM_LABELS = {
    "target":   "IP/hostname del objetivo",
    "user":     "Usuario",
    "password": "Contraseña",
    "hash":     "Hash NT (formato NT o LM:NT)",
    "domain":   "Dominio FQDN",
    "timeout":  "Timeout de conexión (segundos)",
    "userlist": "Ruta al fichero de usuarios",
    "share":    "Share concreto a rastrear",
    "ext":      "Extensiones a buscar (ej: .txt,.kdbx)",
    "keywords": "Palabras clave en nombres de fichero",
    "depth":    "Profundidad máxima de recursión",
}
