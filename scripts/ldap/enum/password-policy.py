# scripts/ldap/enum/password-policy.py

from scripts.base import BaseScript
from core.output import print_result, print_table, console

try:
    from modules.ldap import LDAPModule
    _LDAP_AVAILABLE = True
except ImportError:
    _LDAP_AVAILABLE = False


class Script(BaseScript):
    name        = "password-policy"
    protocol    = "ldap"
    category    = "enum"
    description = (
        "Enumera la política de contraseñas por defecto del dominio "
        "y las Fine-Grained Password Policies (PSOs) si las hay. "
        "Imprescindible antes de un password spray para evitar bloqueos."
    )
    requires_auth = False  # la política de dominio es legible como null session en muchos entornos

    EXAMPLES = [
        {
            "flag":  "-t / -d",
            "desc":  "IP del DC y dominio (obligatorios)",
            "good":  "lobera.py ldap --script=password-policy -t 10.129.1.5 -d CORP.LOCAL",
            "bad":   "lobera.py ldap --script=password-policy -t 10.129.1.5  [sin -d el base DN queda vacío]",
        },
        {
            "flag":  "-u / -p",
            "desc":  "Con credenciales se pueden leer también las PSOs (Fine-Grained)",
            "good":  "lobera.py ldap --script=password-policy -t 10.129.1.5 -u iker -p 'Pass1' -d CORP.LOCAL",
            "bad":   "lobera.py ldap --script=password-policy -t 10.129.1.5 -d CORP.LOCAL  [PSOs pueden no ser visibles sin credenciales]",
        },
    ]

    def run(self, **kwargs):
        if not _LDAP_AVAILABLE:
            print_result("LDAP", str(self.target.ip), "fail",
                         "modules/ldap.py no encontrado")
            return None

        ldap = LDAPModule(
            self.target, self.creds,
            use_ssl=kwargs.get("ldaps", False),
            port=kwargs.get("port"),
        )
        if not ldap.connect():
            return None

        try:
            policy = ldap.get_password_policy()
            psos   = ldap.get_fine_grained_policies()

            # Tabla política por defecto
            rows = [
                ("Longitud mínima",            str(policy.get("min_pwd_length", 0))),
                ("Historial de contraseñas",   str(policy.get("pwd_history_length", 0))),
                ("Complejidad obligatoria",     "Sí" if policy.get("complexity_enabled") else "No"),
                ("Lockout threshold",           str(policy.get("lockout_threshold", 0))),
                ("Lockout duration (minutos)",  str(policy.get("lockout_duration_min", 0))),
                ("Ventana observación (min)",   str(policy.get("lockout_window_min", 0))),
                ("Edad máxima (días)",          str(policy.get("max_pwd_age_days", 0))),
                ("Edad mínima (días)",          str(policy.get("min_pwd_age_days", 0))),
            ]
            print_table("Política de contraseñas — dominio", ["Parámetro", "Valor"], rows)

            # Análisis ofensivo de la política
            threshold = policy.get("lockout_threshold", 0)
            if threshold == 0:
                print_result("LDAP", str(self.target.ip), "pwned",
                             "lockout_threshold = 0 — spray sin riesgo de bloqueo de cuentas")
            elif threshold <= 3:
                print_result("LDAP", str(self.target.ip), "info",
                             "lockout_threshold = {} — CUIDADO: máximo {} intentos antes de bloqueo".format(
                                 threshold, threshold))
            else:
                window = policy.get("lockout_window_min", 0)
                print_result("LDAP", str(self.target.ip), "info",
                             "lockout_threshold = {} — safe spray: 1 intento cada {} min por usuario".format(
                                 threshold, window if window else "?"))

            if not policy.get("complexity_enabled"):
                print_result("LDAP", str(self.target.ip), "info",
                             "Complejidad desactivada — contraseñas simples permitidas")

            if policy.get("min_pwd_length", 0) < 8:
                print_result("LDAP", str(self.target.ip), "info",
                             "Longitud mínima < 8 — contraseñas débiles posibles")

            # Fine-Grained Policies
            if psos:
                console.print()
                console.print("[bold yellow]Fine-Grained Password Policies detectadas:[/bold yellow]")
                for pso in psos:
                    pso_rows = [
                        ("Precedencia",      str(pso["precedence"])),
                        ("Longitud mínima",  str(pso["min_length"])),
                        ("Lockout threshold",str(pso["lockout_thresh"])),
                        ("Complejidad",      "Sí" if pso["complexity"] else "No"),
                        ("Aplica a",         "; ".join(
                            m.split(",")[0].replace("CN=", "") for m in pso["applies_to"]
                        ) or "-"),
                    ]
                    print_table("PSO: {}".format(pso["name"]), ["Parámetro", "Valor"], pso_rows)
            else:
                console.print("[dim]  No se encontraron Fine-Grained Password Policies "
                              "(o no tienes permisos para leerlas)[/dim]")

            return {"default": policy, "psos": psos}

        finally:
            ldap.disconnect()
