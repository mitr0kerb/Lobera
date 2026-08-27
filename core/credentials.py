class Creds:

    """
    Encapsula las credenciales del usuario. Soporta tres modos:
    - password: autenticación normal
    - hash: pass-the-hash (NT hash, formato "NT" o "LM:NT")
    - kerberos ticket (ccache): para ataques Pass-the-Ticket

    Dejamos todo opcional -> user="" y password="" representa una null session.
    """

    def __init__(self, user="", password="", domain="", hash=None, ccache=None):
        self.user = user
        self.password = password
        self.domain = domain
        self.hash = hash        # ej: "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c"
        self.ccache = ccache    # ruta a fichero .ccache si usamos ticket Kerberos

    def is_null_session(self):
        return not self.user and not self.password and not self.hash and not self.ccache

    def __repr__(self):
        auth_mode = "ccache" if self.ccache else "hash" if self.hash else "password" if self.password else "null"
        return f"<Creds user={self.user!r} domain={self.domain!r} mode={auth_mode}>"
