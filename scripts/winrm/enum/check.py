# scripts/winrm/enum/check.py

from scripts.base import BaseScript
from core.output import print_result, print_table, console

try:
    from modules.winrm import WinRMModule
    _WINRM_OK = True
except ImportError:
    _WINRM_OK = False


class Script(BaseScript):
    name        = "check"
    protocol    = "winrm"
    category    = "enum"
    description = "Comprueba si WinRM está activo en el objetivo y qué métodos de autenticación acepta (sin autenticarse)."

    EXAMPLES = [
        {
            "flag":  "-t",
            "desc":  "Solo necesita la IP del objetivo",
            "good":  "lobera.py winrm --script=check -t 10.129.1.5",
            "bad":   "lobera.py winrm --script=check -t 10.129.1.5 --ssl  [prueba el puerto 5985; --ssl para 5986]",
        },
        {
            "flag":  "--ssl",
            "desc":  "Probar WinRM sobre HTTPS (puerto 5986)",
            "good":  "lobera.py winrm --script=check -t 10.129.1.5 --ssl",
            "bad":   "lobera.py winrm --script=check -t 10.129.1.5 --port 5986  [usa --ssl que es más claro]",
        },
    ]

    def run(self, **kwargs):
        if not _WINRM_OK:
            print_result("WINRM", str(self.target.ip), "fail",
                         "modules/winrm.py no disponible"); return None

        use_ssl = kwargs.get("ssl", False)
        port    = kwargs.get("port")

        # Probar ambos puertos si no se especificó
        ports_to_try = []
        if port:
            ports_to_try = [(port, use_ssl)]
        else:
            ports_to_try = [(5985, False), (5986, True)]

        found = []
        for p, ssl in ports_to_try:
            w = WinRMModule(self.target, self.creds, use_ssl=ssl, port=p)
            if w.check_winrm_enabled_on_target():
                found.append({"port": p, "ssl": ssl})

        if not found:
            print_result("WINRM", str(self.target.ip), "fail",
                         "WinRM no detectado en ningún puerto")
        else:
            print_result("WINRM", str(self.target.ip), "ok",
                         "WinRM activo — puertos: {}".format(
                             ", ".join(str(f["port"]) for f in found)))
            console.print(
                "\n[dim]→ Siguiente paso si tienes credenciales:\n"
                "  lobera.py winrm --script=sysinfo -t {} -u USER -p PASS[/dim]".format(
                    self.target.ip)
            )
        return found
