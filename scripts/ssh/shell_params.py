# scripts/ssh/shell_params.py

EXPORT_FORMATS = ["json", "html", "xml", "yaml"]

SCRIPT_PARAMS = {
    # ── enum ──────────────────────────────────────────────────────────────────
    "banner-grab": {
        "description": "Obtiene el banner SSH, versión del servidor y fingerprint del OS.",
        "required": ["target"],
        "optional": ["port", "timeout"],
        "defaults": {"port": 22, "timeout": 5},
        "example": ["set target 10.10.10.5", "run"],
    },
    "auth-methods": {
        "description": "Enumera métodos de autenticación permitidos por el servidor.",
        "required": ["target"],
        "optional": ["user", "port", "timeout"],
        "defaults": {"port": 22, "timeout": 5},
        "example": ["set target 10.10.10.5", "set user root", "run"],
    },
    "key-exchange-enum": {
        "description": "Enumera KEX, ciphers y MACs del servidor. Detecta algoritmos débiles.",
        "required": ["target"],
        "optional": ["port", "timeout"],
        "defaults": {"port": 22, "timeout": 5},
        "example": ["set target 10.10.10.5", "run"],
    },
    "host-key-fingerprint": {
        "description": "Extrae el host key y detecta honeypots o instancias por defecto conocidas.",
        "required": ["target"],
        "optional": ["port", "timeout"],
        "defaults": {"port": 22, "timeout": 5},
        "example": ["set target 10.10.10.5", "run"],
    },
    "terrapin-check": {
        "description": "CVE-2023-48795: detecta vulnerabilidad Terrapin (prefix truncation SSH).",
        "required": ["target"],
        "optional": ["port", "timeout"],
        "defaults": {"port": 22, "timeout": 5},
        "example": ["set target 10.10.10.5", "run"],
    },
    "user-enum": {
        "description": "CVE-2018-15473: enumera usuarios SSH válidos via timing attack (OpenSSH < 7.7).",
        "required": ["target", "userlist"],
        "optional": ["port", "timeout", "threshold"],
        "defaults": {"port": 22, "timeout": 5, "threshold": 50},
        "example": ["set target 10.10.10.5", "set userlist users.txt", "run"],
    },
    # ── attack ────────────────────────────────────────────────────────────────
    "password-spray": {
        "description": "Spray de contraseñas SSH contra lista de usuarios con delay configurable.",
        "required": ["target", "userlist", "password"],
        "optional": ["port", "timeout", "delay"],
        "defaults": {"port": 22, "timeout": 5, "delay": 1},
        "example": [
            "set target 10.10.10.5",
            "set userlist users.txt",
            "set password Pass123!",
            "run",
        ],
    },
    "brute-force": {
        "description": "Fuerza bruta SSH con fichero de pares usuario:contraseña.",
        "required": ["target", "credfile"],
        "optional": ["port", "timeout", "delay"],
        "defaults": {"port": 22, "timeout": 5, "delay": 0.5},
        "example": ["set target 10.10.10.5", "set credfile creds.txt", "run"],
    },
    "key-auth-test": {
        "description": "Prueba autenticación SSH con claves privadas locales o una clave específica.",
        "required": ["target"],
        "optional": ["user", "port", "timeout", "key_path"],
        "defaults": {"port": 22, "timeout": 5},
        "example": [
            "set target 10.10.10.5",
            "set user root",
            "set key_path /root/.ssh/id_rsa",
            "run",
        ],
    },
    "known-keys": {
        "description": "CVE-2008-0166: prueba claves SSH Debian débiles (OpenSSL PRNG roto).",
        "required": ["target"],
        "optional": ["user", "port", "timeout", "keys_dir"],
        "defaults": {"port": 22, "timeout": 5},
        "example": [
            "set target 10.10.10.5",
            "set user root",
            "set keys_dir /opt/ssh-badkeys/",
            "run",
        ],
    },
    # ── exploit ───────────────────────────────────────────────────────────────
    "libssh-bypass": {
        "description": "CVE-2018-10933: auth bypass en libssh 0.6-0.8.3 enviando MSG_USERAUTH_SUCCESS.",
        "required": ["target"],
        "optional": ["user", "port", "timeout"],
        "defaults": {"port": 22, "timeout": 5},
        "example": ["set target 10.10.10.5", "set user root", "run"],
    },
    "regresshion": {
        "description": "CVE-2024-6387 (regreSSHion): detecta race condition RCE en OpenSSH < 9.8p1.",
        "required": ["target"],
        "optional": ["port", "timeout"],
        "defaults": {"port": 22, "timeout": 5},
        "example": ["set target 10.10.10.5", "run"],
    },
    "terrapin-exploit": {
        "description": "CVE-2023-48795 (Terrapin): verifica y genera config para MitM SSH.",
        "required": ["target"],
        "optional": ["port", "timeout", "attacker_ip"],
        "defaults": {"port": 22, "timeout": 5},
        "example": [
            "set target 10.10.10.5",
            "set attacker_ip 10.10.14.5",
            "run",
        ],
    },
    # ── post ──────────────────────────────────────────────────────────────────
    "config-dump": {
        "description": "Lee sshd_config via sesión autenticada y extrae config de seguridad.",
        "required": ["target", "user"],
        "optional": ["password", "port", "timeout"],
        "defaults": {"port": 22, "timeout": 5},
        "at_least_one": [["password"]],
        "example": [
            "set target 10.10.10.5",
            "set user root",
            "set password Pass123!",
            "run",
        ],
    },
    "key-harvest": {
        "description": "Recoge claves SSH privadas y authorized_keys via sesión autenticada.",
        "required": ["target", "user"],
        "optional": ["password", "port", "timeout", "out_dir"],
        "defaults": {"port": 22, "timeout": 5},
        "at_least_one": [["password"]],
        "example": [
            "set target 10.10.10.5",
            "set user root",
            "set password Pass123!",
            "run",
        ],
    },
    "persistence": {
        "description": "Añade clave pública SSH a authorized_keys para persistencia de acceso.",
        "required": ["target", "user", "pub_key"],
        "optional": ["password", "port", "timeout", "target_user"],
        "defaults": {"port": 22, "timeout": 5},
        "at_least_one": [["password"]],
        "example": [
            "set target 10.10.10.5",
            "set user root",
            "set password Pass123!",
            "set pub_key /root/.ssh/id_rsa.pub",
            "run",
        ],
    },
    "lateral-move": {
        "description": "Detecta hosts SSH accesibles desde el objetivo usando claves locales (pivoting).",
        "required": ["target", "user"],
        "optional": ["password", "port", "timeout"],
        "defaults": {"port": 22, "timeout": 5},
        "at_least_one": [["password"]],
        "example": [
            "set target 10.10.10.5",
            "set user root",
            "set password Pass123!",
            "run",
        ],
    },
}

PARAM_LABELS = {
    "target":      "IP/hostname del objetivo",
    "user":        "Usuario SSH",
    "password":    "Contraseña",
    "port":        "Puerto SSH (default: 22)",
    "timeout":     "Timeout de conexión (segundos)",
    "userlist":    "Ruta al fichero de usuarios",
    "credfile":    "Ruta al fichero usuario:contraseña",
    "key_path":    "Ruta a clave privada SSH",
    "keys_dir":    "Directorio con claves débiles conocidas",
    "threshold":   "Umbral timing en ms para user-enum (default: 50)",
    "delay":       "Delay entre intentos (segundos)",
    "out_dir":     "Directorio de salida para loot",
    "attacker_ip": "IP del atacante (para MitM Terrapin)",
    "pub_key":     "Clave pública a añadir (ruta o contenido)",
    "target_user": "Usuario objetivo en el sistema remoto",
}
