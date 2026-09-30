# core/conn_cache.py
"""
Caché de conexiones para evitar reconexiones repetidas al mismo target.

Dentro de una misma sesión de Lobera, si varios scripts se ejecutan sobre
el mismo host con las mismas credenciales, la conexión ya establecida se
reutiliza en lugar de abrir una nueva. Esto reduce el ruido en los logs
del DC y acelera la ejecución de scripts encadenados.

Uso desde un módulo:

    from core.conn_cache import conn_cache

    # Obtener o crear una conexión SMB
    smb_conn = conn_cache.get("smb", target.ip, creds_key)
    if smb_conn is None:
        smb = SMBModule(target, creds)
        smb.connect()
        smb.login()
        conn_cache.set("smb", target.ip, creds_key, smb)
        smb_conn = smb

    # Al final del proceso, liberar todas las conexiones
    conn_cache.close_all()

La clave de credenciales se obtiene con: conn_cache.creds_key(creds)
"""

import threading
from typing import Any


class ConnectionCache:
    """
    Diccionario thread-safe de conexiones activas, indexadas por
    (protocolo, ip, creds_key).
    """

    def __init__(self):
        self._lock  = threading.Lock()
        self._store: dict[tuple, Any] = {}
        self._stats = {"hits": 0, "misses": 0}

    # ── Clave de credenciales ──────────────────────────────────────────────────

    @staticmethod
    def creds_key(creds) -> str:
        """
        Genera una clave de texto que identifica unívocamente las credenciales,
        sin exponer secretos en memoria de forma innecesaria.
        """
        if creds is None:
            return "null"
        parts = [creds.user or "", creds.domain or ""]
        if creds.ccache:
            parts.append(f"ccache:{creds.ccache}")
        elif creds.hash:
            # Solo los últimos 8 chars del hash NT para identificar sin exponer
            parts.append(f"hash:{creds.hash[-8:]}")
        elif creds.password:
            # Longitud como proxy — no guardamos la contraseña
            parts.append(f"pwd:{len(creds.password)}")
        return "|".join(parts)

    # ── Acceso al caché ────────────────────────────────────────────────────────

    def get(self, protocol: str, ip: str, creds_key: str) -> Any:
        """
        Devuelve la conexión en caché si existe, None en caso contrario.
        """
        key = (protocol.lower(), ip, creds_key)
        with self._lock:
            conn = self._store.get(key)
            if conn is not None:
                self._stats["hits"] += 1
            else:
                self._stats["misses"] += 1
            return conn

    def set(self, protocol: str, ip: str, creds_key: str, conn: Any) -> None:
        """
        Almacena una conexión en el caché.
        """
        key = (protocol.lower(), ip, creds_key)
        with self._lock:
            self._store[key] = conn

    def invalidate(self, protocol: str, ip: str, creds_key: str) -> None:
        """
        Elimina una conexión del caché (tras un error, por ejemplo).
        """
        key = (protocol.lower(), ip, creds_key)
        with self._lock:
            self._store.pop(key, None)

    def invalidate_target(self, ip: str) -> None:
        """
        Elimina todas las conexiones al mismo host (útil tras un error de red).
        """
        with self._lock:
            to_del = [k for k in self._store if k[1] == ip]
            for k in to_del:
                self._store.pop(k, None)

    # ── Ciclo de vida ──────────────────────────────────────────────────────────

    def close_all(self) -> None:
        """
        Desconecta todas las conexiones activas.
        Llama a disconnect() si el objeto lo tiene, o close(), o lo ignora.
        """
        with self._lock:
            items = list(self._store.items())
            self._store.clear()

        for (_proto, _ip, _ckey), conn in items:
            try:
                if hasattr(conn, "disconnect"):
                    conn.disconnect()
                elif hasattr(conn, "close"):
                    conn.close()
            except Exception:
                pass  # Ignorar errores al cerrar

    def stats(self) -> dict:
        """Devuelve estadísticas de uso del caché."""
        with self._lock:
            return dict(self._stats, active=len(self._store))

    def __len__(self):
        with self._lock:
            return len(self._store)


# Instancia global de la sesión
conn_cache = ConnectionCache()
