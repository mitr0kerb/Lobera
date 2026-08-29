<div align="center">

```
    __    ____  ____  __________  ___ 
   / /   / __ \/ __ )/ ____/ __ \/   |
  / /   / / / / __  / __/ / /_/ / /| |
 / /___/ /_/ / /_/ / /___/ _, _/ ___ |
/_____/\____/_____/_____/_/ |_/_/  |_|
```

**AD enumeration & attack toolkit**

*SMB · RPC · Kerberos · LDAP · WinRM · SSH*

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active%20Development-orange?style=flat-square)
![Author](https://img.shields.io/badge/Author-mitr0kerb-red?style=flat-square)

> ⚠️ **Para uso exclusivo en entornos controlados y con autorización explícita.**  
> El autor no se hace responsable del uso indebido de esta herramienta.

</div>

---

## ¿Qué es Lobera?

Lobera es un toolkit modular de enumeración y ataque contra entornos **Active Directory**, construido desde cero sobre [impacket](https://github.com/fortra/impacket) y [paramiko](https://www.paramiko.org/).

### Características principales

- **Consola interactiva por módulo** — cada protocolo tiene su propia shell con comandos `load`, `set`, `run`, persistencia de parámetros entre scripts y ejemplos integrados.
- **Scanner autopwn** — motor de ejecución automática que encadena scripts según los hallazgos anteriores. Con solo el target lanza todo lo que puede; con credenciales, más.
- **Persistencia entre sesiones** — base de datos SQLite que almacena targets, credenciales válidas y hallazgos. Todo lo encontrado en una sesión está disponible en la siguiente.
- **Implementación a bajo nivel** — los módulos implementan SMB, Kerberos, LDAP y RPC directamente sobre impacket, sin capas de abstracción que oculten lo que ocurre en el protocolo.
- **CVEs recientes implementados** — regreSSHion (CVE-2024-6387), Terrapin (CVE-2023-48795), libssh bypass (CVE-2018-10933), PrintNightmare, PetitPotam, noPac y más.
- **Exportación de resultados** — JSON, HTML, XML y YAML al terminar cada scan.
- **Autenticación local** — acceso protegido con PBKDF2-HMAC-SHA256 y sesiones de 8 horas.

---

## Instalación

```bash
git clone https://github.com/mitr0kerb/Lobera.git
cd Lobera
pip install -r requirements.txt
python3 lobera.py
```

**Requisitos:** Python 3.10+, Kali Linux / Parrot OS recomendado.

En el primer arranque se generan credenciales de acceso temporales que deberás cambiar.

---

## Uso

### Abrir la consola de un módulo

```bash
python3 lobera.py smb
python3 lobera.py ssh
python3 lobera.py kerberos
python3 lobera.py rpc
python3 lobera.py ldap
python3 lobera.py winrm
```

### Lanzar el autopwn scanner

```bash
python3 lobera.py <módulo> --scanner
```

### Comandos de la consola

| Comando | Descripción |
|---|---|
| `list` | Lista scripts disponibles agrupados por familia |
| `load <script>` | Carga un script individual |
| `load-fam <familia>` | Carga y ejecuta todos los scripts de una familia |
| `params` | Muestra parámetros actuales, obligatorios y opcionales |
| `set <k> <v>` | Asigna un parámetro |
| `unset <k>` | Elimina un parámetro |
| `run` | Ejecuta el script cargado |
| `clear` | Limpia la pantalla |
| `exit` | Sale de la consola |

### Ejemplo de sesión

```
❯ python3 lobera.py ssh

ssh-shell > load regresshion
# Muestra parámetros obligatorios, opcionales y ejemplo de uso

ssh-shell(regresshion) > set target 10.10.10.5
  ✓ target = 10.10.10.5

ssh-shell(regresshion) > run
[SSH] 10.10.10.5 - VULNERABLE a CVE-2024-6387 — OpenSSH 8.9p1

# Cambiar de script sin perder el target
ssh-shell(regresshion) > load terrapin-check
ssh-shell(terrapin-check) > run
```

---

## Módulos y scripts

### SMB
`signing-check` · `null-session` · `shares` · `gpp-password` · `spider` · `password-spray` · `interactive-shell`

### RPC
`domain-info` · `users` · `groups` · `sessions` · `privileges` · `services` · `registry` · `exec-service` · `rid-brute` · `printnightmare` · `petitpotam` · `sam-dump`

### Kerberos
`user-enum` · `spn-scan` · `asrep-roasting` · `kerberoasting` · `pass-the-ticket` · `overpass-the-hash` · `golden-ticket` · `silver-ticket` · `diamond-ticket` · `sapphire-ticket` · `unconstrained-deleg` · `constrained-s4u` · `rbcd` · `shadow-credentials` · `pkinit` · `adcs` · `sam-spoofing` · `ms14-068` · `kerber-loss` · `reset-nightmare`

### LDAP
`domain-info` · `users` · `groups` · `computers` · `admins` · `password-policy` · `asreproast-targets` · `kerberoast-targets` · `dacl-enum` · `bloodhound-export` · `acl-abuse` · `password-spray-ldap` · `ntlm-relay-setup`

### WinRM
`check` · `sysinfo` · `password-spray` · `privesc-check` · `evil-winrm-payload`

### SSH
`banner-grab` · `auth-methods` · `key-exchange-enum` · `host-key-fingerprint` · `terrapin-check` · `user-enum` · `password-spray` · `brute-force` · `key-auth-test` · `known-keys` · `libssh-bypass` · `regresshion` · `terrapin-exploit` · `config-dump` · `key-harvest` · `persistence` · `lateral-move`

---

## Base de datos de sesión

```bash
python3 lobera.py db

db > targets              # Objetivos descubiertos
db > credentials          # Credenciales válidas encontradas
db > findings             # Todos los hallazgos
db > findings 10.10.10.5  # Hallazgos de un objetivo específico
db > clear                # Limpia la base de datos
```

---

## Implementar nuevos scripts

Lobera está diseñado para ser extensible. Cualquier script nuevo es una clase Python que hereda de `BaseScript`.

### Estructura de un script

```python
# scripts/<protocolo>/<familia>/<nombre_del_script>.py

from scripts.base import BaseScript
from modules.<protocolo> import <Módulo>
from core.output import print_result, print_table
from core import session_db

class Script(BaseScript):
    name        = "nombre-del-script"   # identificador usado en load/run
    protocol    = "protocolo"           # smb, rpc, ssh, ldap...
    category    = "familia"             # enum, attack, exploit, post
    description = "Descripción clara de lo que hace el script."

    EXAMPLES = [
        {
            "flag": "--parametro",
            "desc": "Descripción del parámetro",
            "good": "protocolo --script=nombre -t 10.10.10.5 --parametro valor",
            "bad":  "protocolo --script=nombre -t 10.10.10.5  (sin --parametro)",
        },
    ]

    def run(self, **kwargs):
        # 1. Obtener parámetros del kwargs
        param = kwargs.get("param", "valor_por_defecto")

        # 2. Conectar al objetivo
        module = <Módulo>(self.target, self.creds)
        if not module.connect():
            return None

        # 3. Ejecutar la lógica
        resultado = module.hacer_algo(param)

        # 4. Guardar hallazgos importantes en la base de datos
        session_db.save_finding(self.target.ip, "PROTOCOLO", "tipo_hallazgo", str(resultado))

        # 5. Mostrar resultados con el sistema de output de Lobera
        print_result("PROTOCOLO", self.target.ip, "ok", f"resultado: {resultado}")

        # 6. Devolver el resultado (el scanner lo usa para tomar decisiones)
        return resultado
```

### Dónde va cada fichero

```
scripts/
└── <protocolo>/
    └── <familia>/
        └── <nombre_del_script>.py
```

Por ejemplo, un script de enumeración SSH iría en:
```
scripts/ssh/enum/mi_script.py
```

Las familias disponibles son `enum`, `attack`, `exploit` y `post`. Puedes crear nuevas si tiene sentido para tu protocolo.

### Registrarlo en la consola interactiva

Añade la entrada en `scripts/<protocolo>/shell_params.py`:

```python
"nombre-del-script": {
    "description": "Descripción del script.",
    "required": ["target"],                        # parámetros obligatorios
    "optional": ["password", "timeout"],           # parámetros opcionales
    "defaults": {"timeout": 5},                    # valores por defecto
    "mutually_exclusive": [["password", "hash"]],  # si aplica
    "at_least_one": [["password", "hash"]],        # si aplica
    "example": [
        "set target 10.10.10.5",
        "set password Pass123!",
        "run",
    ],
},
```

### Registrarlo en el scanner autopwn

Añade la entrada en `scripts/<protocolo>/scan_params.py`:

```python
{"script": "nombre-del-script", "condition": "has_auth"},
```

**Condiciones disponibles:**

| Condición | Se ejecuta cuando |
|---|---|
| `None` | Siempre |
| `"has_auth"` | Hay usuario + contraseña o hash |
| `"has_userlist"` | Se proporcionó userlist válida |
| `"has_listener"` | Se proporcionó IP de listener |
| `"has_command"` | Se proporcionó comando a ejecutar |

Con esos tres pasos el script aparece automáticamente en `list`, en `load`, en `load-fam` y en el scanner.

---

## Colaboración

Si quieres contribuir con nuevos scripts, módulos o mejoras, puedes contactar en:

📧 **mitr0kerb@gmail.com**

---

<div align="center">

*by [mitr0kerb](https://github.com/mitr0kerb)*

</div>
