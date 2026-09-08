# scripts/ftp/shell_params.py

EXPORT_FORMATS = ["json", "html", "xml", "yaml"]

SCRIPT_PARAMS = {
    # ── enum ──────────────────────────────────────────────────────────────────
    "banner-grab": {
        "description": "Captura el banner FTP y fingerprinta el software (vsftpd, ProFTPD, IIS, FileZilla...).",
        "required": ["target"],
        "optional": ["port", "timeout"],
        "defaults": {"port": 21, "timeout": 5},
        "example": ["set target 10.10.10.5", "run"],
    },
    "anon-check": {
        "description": "Comprueba acceso anónimo (anonymous/ftp/guest), lista la raíz y detecta escritura.",
        "required": ["target"],
        "optional": ["port", "timeout"],
        "defaults": {"port": 21, "timeout": 5},
        "example": ["set target 10.10.10.5", "run"],
    },
    "service-info": {
        "description": "Extrae SYST, FEAT, modo pasivo y detecta FTPS/STARTTLS.",
        "required": ["target"],
        "optional": ["port", "timeout"],
        "defaults": {"port": 21, "timeout": 5},
        "example": ["set target 10.10.10.5", "run"],
    },
    "list-files": {
        "description": "Listado recursivo del servidor. Detecta configs, backups, claves y dumps por extensión/nombre.",
        "required": ["target", "user"],
        "optional": ["password", "port", "timeout"],
        "defaults": {"port": 21, "timeout": 5},
        "example": ["set target 10.10.10.5", "set user ftpuser", "set password Pass123!", "run"],
    },
    "user-enum": {
        "description": "Enumera usuarios FTP via respuestas diferenciales al comando USER (timing + código de error).",
        "required": ["target", "userlist"],
        "optional": ["port", "timeout"],
        "defaults": {"port": 21, "timeout": 5},
        "example": ["set target 10.10.10.5", "set userlist /ruta/users.txt", "run"],
    },
    # ── attack ────────────────────────────────────────────────────────────────
    "password-spray": {
        "description": "Prueba una contraseña contra lista de usuarios con delay configurable.",
        "required": ["target", "userlist"],
        "optional": ["password", "port", "timeout", "delay"],
        "defaults": {"port": 21, "timeout": 5, "delay": 1},
        "example": ["set target 10.10.10.5", "set userlist users.txt", "set password Summer2024!", "run"],
    },
    "brute-force": {
        "description": "Brute force FTP: un usuario contra wordlist de passwords.",
        "required": ["target", "user", "passlist"],
        "optional": ["port", "timeout", "delay"],
        "defaults": {"port": 21, "timeout": 5, "delay": 0},
        "example": ["set target 10.10.10.5", "set user admin", "set passlist /ruta/rockyou.txt", "run"],
    },
    "write-check": {
        "description": "Prueba escritura en múltiples directorios. Detecta si es posible subir una webshell.",
        "required": ["target", "user"],
        "optional": ["password", "port", "timeout"],
        "defaults": {"port": 21, "timeout": 5},
        "example": ["set target 10.10.10.5", "set user ftpuser", "set password Pass123!", "run"],
    },
    "bounce-scan": {
        "description": "FTP Bounce Attack (RFC 959): usa el servidor como proxy para escanear puertos internos.",
        "required": ["target", "user"],
        "optional": ["password", "port", "timeout"],
        "defaults": {"port": 21, "timeout": 5},
        "example": ["set target 10.10.10.5", "set user ftpuser", "set password Pass123!", "run"],
    },
    # ── exploit ───────────────────────────────────────────────────────────────
    "vsftpd-backdoor": {
        "description": "CVE-2011-2523: backdoor vsftpd 2.3.4. Username ':)' abre shell root en puerto 6200.",
        "required": ["target"],
        "optional": ["port", "timeout"],
        "defaults": {"port": 21, "timeout": 5},
        "example": ["set target 10.10.10.5", "run"],
    },
    "proftpd-bypass": {
        "description": "CVE-2011-4130: mod_copy de ProFTPD permite SITE CPFR/CPTO sin auth → copia /etc/passwd.",
        "required": ["target"],
        "optional": ["port", "timeout"],
        "defaults": {"port": 21, "timeout": 5},
        "example": ["set target 10.10.10.5", "run"],
    },
    "ssl-strip": {
        "description": "Detecta STARTTLS downgrade: fuerza FTP en claro aunque el servidor ofrezca TLS.",
        "required": ["target"],
        "optional": ["port", "timeout"],
        "defaults": {"port": 21, "timeout": 5},
        "example": ["set target 10.10.10.5", "run"],
    },
    "anonymous-webshell": {
        "description": "FTP anón write + webserver detectado → sube webshell PHP/ASP automáticamente.",
        "required": ["target"],
        "optional": ["port", "timeout"],
        "defaults": {"port": 21, "timeout": 5},
        "example": ["set target 10.10.10.5", "run"],
    },
    # ── post ──────────────────────────────────────────────────────────────────
    "download-loot": {
        "description": "Descarga automática de ficheros sensibles por extensión y nombre.",
        "required": ["target", "user"],
        "optional": ["password", "port", "timeout"],
        "defaults": {"port": 21, "timeout": 5},
        "example": ["set target 10.10.10.5", "set user ftpuser", "set password Pass123!", "run"],
    },
    "pivot-setup": {
        "description": "Lee /etc/hosts y /proc/net/arp via FTP para mapear red interna. Pivoting discovery.",
        "required": ["target", "user"],
        "optional": ["password", "port", "timeout"],
        "defaults": {"port": 21, "timeout": 5},
        "example": ["set target 10.10.10.5", "set user ftpuser", "set password Pass123!", "run"],
    },
}

PARAM_LABELS = {
    "target":   "IP/hostname del objetivo",
    "user":     "Usuario FTP",
    "password": "Contraseña FTP",
    "port":     "Puerto FTP (default: 21)",
    "timeout":  "Timeout de conexión (segundos)",
    "userlist": "Ruta al fichero de usuarios",
    "passlist":  "Ruta al fichero de passwords",
    "delay":    "Delay entre intentos (segundos)",
}
