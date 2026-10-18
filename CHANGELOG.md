# Changelog

## [0.2.0] — 2024-10-18

### Añadido
- Packaging como paquete Python instalable (`pip install lobera`)
- Punto de entrada `lobera` instalable vía PyPI
- Soporte para Python 3.10, 3.11 y 3.12
- `lobera_pkg/` como módulo de entrada del paquete

### Corregido
- Importaciones de impacket protegidas con guard `_LIB_OK` en todos los módulos
- Firma correcta `run(**kwargs)` en todos los scripts heredados de `BaseScript`
- Pipes SMB con raw strings (`r"\srvsvc"`) para evitar errores de escape
- `print_result()` con firma de 4 argumentos en todos los scripts
- `session_db.DB.SaveFinding()` con argumentos posicionales correctos
- `Credentials.hash` en lugar de `Credentials.nt_hash` en módulo kerberos
- Módulo SSH con guard `_PARAMIKO_OK` para importación opcional
- Módulo MSSQL con guard `_IMPACKET_OK`
- Scripts de persistencia SSH/WinRM: herencia de `BaseScript` y `self.creds.user`
- Script `bloodhound-lite`: métodos LDAP correctos (`get_all_users`, `get_spn_accounts`)
- Generador de reportes: columna `secret_type` en lugar de `type`

### Cambiado
- Versión de `1.0.0` a `0.2.0` (refleja estado beta)
- README reestructurado con badges dinámicos de PyPI y secciones colapsables

## [0.1.0] — versión inicial

- Suite modular con +230 scripts para SMB, Kerberos, LDAP, RPC, WinRM, SSH, SSL, HTTP, HTTPS, FTP y MSSQL
- CLI interactivo con tres modos: clásico, shell interactivo y scanner autopwn
- Herramientas independientes: lobera-server, lobera-watch, lobera-spray, lobera-tunnel, lobera-check
- Base de datos SQLite de hallazgos y credenciales
- Autocompletado para Bash y Zsh
