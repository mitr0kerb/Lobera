# Cómo añadir scripts y módulos a Lobera

Lobera usa un sistema de descubrimiento automático: cualquier fichero Python
colocado bajo `scripts/<protocolo>/<familia>/` se detecta y registra sin
tocar nada más.

---

## Estructura de carpetas

```
scripts/
├── smb/
│   ├── enum/         ← enumeración (shares, usuarios, política...)
│   ├── attack/       ← ataques activos (spray, relay...)
│   ├── exploits/     ← explotación directa
│   └── scan_params.py
├── ldap/
│   ├── enum/
│   ├── exploits/
│   └── ...
├── kerberos/
│   ├── tickets/
│   ├── extraction/
│   └── ...
└── base.py           ← clase base BaseScript
```

El loader usa la carpeta de protocolo y la de familia para asignar
`protocol` y `category` automáticamente: un fichero en
`scripts/smb/attack/mi_script.py` recibirá `protocol="smb"` y
`category="attack"`.

---

## Plantilla mínima

```python
# scripts/<protocolo>/<familia>/mi_script.py
"""
Descripción larga del script (se muestra en --help).
"""

from scripts.base import BaseScript
from core.output import print_result, print_table, console
from core import session_db


class Script(BaseScript):
    # ── Metadatos ──────────────────────────────────────────────────────
    name        = "mi-script"          # identificador para --script=mi-script
    protocol    = "smb"                # el loader lo sobreescribe, pero
    category    = "enum"               # conviene declararlo igualmente
    description = "Una línea de qué hace este script"

    # ── Ejemplos de uso (se muestran en la ayuda del script) ──────────
    EXAMPLES = [
        {
            "flag": "-t / -u / -p",
            "desc": "Credenciales obligatorias",
            "good": "lobera.py smb --script=mi-script -t 10.10.10.5 -u iker -p 'Pass1'",
            "bad":  "lobera.py smb --script=mi-script -t 10.10.10.5  [sin credenciales]",
        },
    ]

    # ── Lógica ────────────────────────────────────────────────────────
    def run(self, **kwargs):
        # self.target  → objeto Target con .ip, .domain, .hostname, .port, .timeout
        # self.creds   → objeto Creds con .user, .password, .hash, .ccache, .domain
        # kwargs       → parámetros extra del CLI (delay, jitter, path, etc.)

        print_result(self.protocol.upper(), str(self.target.ip), "info",
                     "Iniciando mi-script")

        # Guardar hallazgo en la base de datos de sesión
        session_db.save_finding(
            self.target.ip,
            self.protocol.upper(),
            "mi_hallazgo",                # tipo de hallazgo (snake_case)
            "Descripción del hallazgo",
        )

        print_result(self.protocol.upper(), str(self.target.ip), "ok",
                     "mi-script completado")
```

El loader descubre la clase buscando cualquier subclase de `BaseScript`
cuyo atributo `name` no sea `None`. La clase **debe** llamarse `Script`
(por convención) o al menos heredar de `BaseScript`.

---

## Objetos disponibles en `run()`

### `self.target` — `core.target.Target`

| Atributo   | Tipo    | Descripción                                      |
|------------|---------|--------------------------------------------------|
| `ip`       | `str`   | IP o hostname del objetivo                       |
| `domain`   | `str`   | Dominio AD (ej. `CORP.LOCAL`)                    |
| `hostname` | `str`   | Nombre NetBIOS / FQDN                            |
| `port`     | `int`   | Puerto personalizado (puede ser `None`)           |
| `timeout`  | `int`   | Timeout de red en segundos (default: 5)           |

### `self.creds` — `core.credentials.Creds`

| Atributo   | Tipo    | Descripción                                      |
|------------|---------|--------------------------------------------------|
| `user`     | `str`   | Nombre de usuario                                |
| `password` | `str`   | Contraseña en claro                              |
| `domain`   | `str`   | Dominio de las credenciales                      |
| `hash`     | `str`   | Hash NT o LM:NT (pass-the-hash)                  |
| `ccache`   | `str`   | Ruta al fichero `.ccache` (pass-the-ticket)      |

Método útil: `creds.is_null_session()` → `True` si no hay credencial alguna.

### `kwargs` — parámetros extra del CLI

El framework mapea automáticamente los argumentos del CLI a kwargs.
Los más comunes:

| kwarg                | Flag CLI             | Descripción                     |
|----------------------|----------------------|---------------------------------|
| `delay`              | `--delay`            | Delay entre intentos (float, s) |
| `jitter`             | `--jitter`           | Jitter aleatorio (float, s)     |
| `continue_on_lockout`| `--continue-on-lockout` | No abortar si hay lockout   |
| `ldaps`              | `--ldaps`            | Usar LDAPS en módulos LDAP      |
| `port`               | `--port`             | Puerto personalizado             |
| `path`               | `--path`             | Ruta HTTP inicial                |

---

## Módulos de protocolo reutilizables

En lugar de abrir conexiones a mano, usa los módulos de `modules/`:

```python
from modules.smb  import SMBModule
from modules.ldap import LDAPModule

smb = SMBModule(self.target, self.creds)
if smb.connect() and smb.login():
    shares = smb.list_shares()
    smb.disconnect()
```

Módulos disponibles:

| Módulo           | Clase         | Protocolo   |
|------------------|---------------|-------------|
| `modules/smb`    | `SMBModule`   | SMB/CIFS    |
| `modules/ldap`   | `LDAPModule`  | LDAP/LDAPS  |
| `modules/winrm`  | `WinRMModule` | WinRM       |
| `modules/rpc`    | `RPCModule`   | RPC/MSRPC   |
| `modules/ssh`    | `SSHModule`   | SSH         |
| `modules/ftp`    | `FTPModule`   | FTP         |
| `modules/mssql`  | `MSSQLModule` | MSSQL       |

---

## Registrar hallazgos en la DB de sesión

```python
from core import session_db

# Hallazgo
session_db.save_finding(ip, protocolo, tipo, detalle)

# Credencial válida
session_db.save_credential(ip, user, secret, secret_type, valid=True, source="mi_script")
# secret_type puede ser: "password", "hash", "ccache"

# Objetivo descubierto
session_db.save_target(ip, domain="CORP.LOCAL", hostname="DC01")
```

Todo lo guardado aparecerá en `lobera.py report` (HTML/Markdown).

---

## Usar la caché de conexiones

Para evitar reconexiones cuando varios scripts se encadenan:

```python
from core.conn_cache import conn_cache
from modules.smb import SMBModule

ckey = conn_cache.creds_key(self.creds)
smb  = conn_cache.get("smb", self.target.ip, ckey)
if smb is None:
    smb = SMBModule(self.target, self.creds)
    if not smb.connect() or not smb.login():
        return
    conn_cache.set("smb", self.target.ip, ckey, smb)

shares = smb.list_shares()
# No llames a smb.disconnect() — el caché lo gestiona al salir
```

---

## Declarar parámetros del script (opcional)

Si tu script necesita parámetros que no son los globales (`-t/-u/-p/-d/...`),
puedes documentarlos en `scripts/<protocolo>/scan_params.py`:

```python
# scripts/smb/scan_params.py  (ejemplo)
PARAMS = {
    "mi-script": {
        "required": [],
        "optional": ["delay", "path"],
        "description": "Descripción del script",
        "family": "attack",
    },
    ...
}
```

Si no declaras nada, el framework asume que solo necesita los parámetros
globales y ejecuta el script sin preguntar.

---

## Probar el script

```bash
# Ver que aparece en el árbol de scripts
python3 lobera.py smb

# Ver sus parámetros (sin ejecutar)
python3 lobera.py smb --script=mi-script

# Simular sin ejecutar nada
python3 lobera.py smb --script=mi-script -t 10.10.10.5 -u admin -p 'Pass1' --dry-run

# Ejecutar de verdad
python3 lobera.py smb --script=mi-script -t 10.10.10.5 -u admin -p 'Pass1'
```

---

## Convenciones de estilo

- Nombres de script en kebab-case: `mi-script`, `pass-the-hash`, `bloodhound-lite`.
- Clases de Python en PascalCase: `MiScript`. El loader busca cualquier subclase de `BaseScript`.
- Comentarios y texto por consola **en castellano**.
- Usa `print_result()` para líneas de estado y `print_table()` para listados.
- Llama siempre a `session_db.save_finding()` para cada hallazgo relevante.
- No pongas `time.sleep()` fuera de lógica de spray; usa el sistema de delay de `spray_guard`.
