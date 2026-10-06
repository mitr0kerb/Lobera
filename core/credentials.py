class Creds:

    """
    Encapsula las credenciales del usuario. Soporta tres modos:
    - password: autenticación normal
    - hash: pass-the-hash (NT hash, formato "NT" o "LM:NT")
    - kerberos ticket (ccache): para ataques Pass-the-Ticket

    Dejamos todo opcional -> user="" y password="" representa una null session.
    """

    def __init__(self, user="", password="", domain="", hash=None, nt_hash=None, ccache=None):
        self.user = user or ""
        self.password = password or ""
        self.domain = domain or ""
        self.hash = nt_hash or hash  # acepta tanto 'hash' como 'nt_hash' (alias)
        self.ccache = ccache         # ruta a fichero .ccache si usamos ticket Kerberos

    def is_null_session(self):
        return not self.user and not self.password and not self.hash and not self.ccache

    def __repr__(self):
        auth_mode = "ccache" if self.ccache else "hash" if self.hash else "password" if self.password else "null"
        return f"<Creds user={self.user!r} domain={self.domain!r} mode={auth_mode}>"


# Alias para compatibilidad con importaciones existentes
Credentials = Creds
