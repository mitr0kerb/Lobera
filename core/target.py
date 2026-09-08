class Target:

    """
    Representa la máquina/dominio objetivo.
    Se pasa a todos los módulos (smb, rpc, kerberos, ldap, winrm).
    """

    def __init__(self, ip, hostname=None, domain=None, timeout=5):

        self.ip = ip
        self.hostname = hostname      
        self.domain = domain          # ej: "corp.local"
        self.timeout = timeout

    def __repr__(self):
        return f"<Target ip={self.ip} domain={self.domain}>"
