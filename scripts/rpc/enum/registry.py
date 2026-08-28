# scripts/rpc/enum/registry.py

from scripts.base import BaseScript
from core.output import print_result, print_table, console
from core import session_db

try:
    from modules.rpc import RPCModule
    _RPC_OK = True
except ImportError:
    _RPC_OK = False

# Claves de registro interesantes desde perspectiva ofensiva
INTERESTING_KEYS = [
    {
        "hive":  "HKLM",
        "key":   r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        "value": "ProductName",
        "desc":  "Versión del OS",
    },
    {
        "hive":  "HKLM",
        "key":   r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        "value": "BuildLabEx",
        "desc":  "Build exacto del OS",
    },
    {
        "hive":  "HKLM",
        "key":   r"SYSTEM\CurrentControlSet\Control\Lsa",
        "value": "LmCompatibilityLevel",
        "desc":  "NTLMv1/v2 — 0-2 permite NTLMv1 (downgrade posible)",
    },
    {
        "hive":  "HKLM",
        "key":   r"SYSTEM\CurrentControlSet\Control\Lsa",
        "value": "NoLMHash",
        "desc":  "0 = LM hashes almacenados (crackeable)",
    },
    {
        "hive":  "HKLM",
        "key":   r"SYSTEM\CurrentControlSet\Control\Lsa",
        "value": "RestrictAnonymous",
        "desc":  "0 = null session permitida",
    },
    {
        "hive":  "HKLM",
        "key":   r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
        "value": "EnableMulticast",
        "desc":  "0 = mDNS desactivado (Responder inútil)",
    },
    {
        "hive":  "HKLM",
        "key":   r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
        "value": "EnableSecuritySignature",
        "desc":  "SMB signing — 0 y RequireSecuritySignature=0 → relay posible",
    },
    {
        "hive":  "HKLM",
        "key":   r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
        "value": "RequireSecuritySignature",
        "desc":  "SMB signing obligatorio — 0 → vulnerable a relay",
    },
    {
        "hive":  "HKLM",
        "key":   r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "value": "EnableLUA",
        "desc":  "0 = UAC desactivado (privesc directa posible)",
    },
    {
        "hive":  "HKLM",
        "key":   r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "value": "ConsentPromptBehaviorAdmin",
        "desc":  "UAC nivel — 0 = sin prompt (bypasseable fácilmente)",
    },
    {
        "hive":  "HKLM",
        "key":   r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
        "value": "UseLogonCredential",
        "desc":  "1 = credenciales en claro en LSASS (Mimikatz directo)",
    },
    {
        "hive":  "HKLM",
        "key":   r"SYSTEM\CurrentControlSet\Services\NTDS\Parameters",
        "value": "DSA Database file",
        "desc":  "Ruta del NTDS.dit (solo DCs)",
    },
    {
        "hive":  "HKLM",
        "key":   r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "value": "DefaultUserName",
        "desc":  "Autologon — usuario configurado",
    },
    {
        "hive":  "HKLM",
        "key":   r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "value": "DefaultPassword",
        "desc":  "Autologon — contraseña en claro (goldmine)",
    },
    {
        "hive":  "HKLM",
        "key":   r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "value": "AutoAdminLogon",
        "desc":  "1 = autologon activo",
    },
]


class Script(BaseScript):
    name        = "registry"
    protocol    = "rpc"
    category    = "enum"
    description = (
        "Consulta claves de registro remotas (WINREG) con información ofensiva: "
        "nivel NTLM, SMB signing, UAC, WDigest, autologon, NTDS.dit path…"
    )

    EXAMPLES = [
        {
            "flag":  "-t / -u / -p",
            "desc":  "Requiere que el servicio RemoteRegistry esté activo en el objetivo",
            "good":  "lobera.py rpc --script=registry -t 10.129.1.5 -u iker -p 'Pass1'",
            "bad":   "lobera.py rpc --script=registry -t 10.129.1.5  [null session → acceso denegado]",
        },
        {
            "flag":  "--key / --value / --hive",
            "desc":  "Consulta un valor específico del registro",
            "good":  "lobera.py rpc --script=registry -t 10.129.1.5 -u iker -p 'Pass1' --hive HKLM --key 'SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion' --value ProductName",
            "bad":   "lobera.py rpc --script=registry -t 10.129.1.5 -u iker -p 'Pass1' --key 'SOFTWARE\\\\...' [sin --hive asume HKLM]",
        },
    ]

    def run(self, **kwargs):
        if not _RPC_OK:
            print_result("RPC", str(self.target.ip), "fail", "modules/rpc.py no disponible"); return []
        rpc = RPCModule(self.target, self.creds)
        if not rpc.connect(): return []
        try:
            # Modo consulta de una clave específica
            if kwargs.get("key") and kwargs.get("value"):
                hive  = kwargs.get("hive", "HKLM")
                key   = kwargs["key"]
                value = kwargs["value"]
                dtype, data = rpc.reg_query(hive, key, value)
                if data is not None:
                    data_str = self._decode_reg_value(dtype, data)
                    print_result("RPC", str(self.target.ip), "ok",
                                 "{}\\{}\\{} = {}".format(hive, key, value, data_str))
                    session_db.save_finding(
                        str(self.target.ip), "RPC", "registry_value",
                        "{}\\{}\\{} = {}".format(hive, key, value, data_str),
                    )
                return [{"hive": hive, "key": key, "value": value, "data": data}]

            # Modo scan completo de claves interesantes
            results = []
            rows    = []
            for item in INTERESTING_KEYS:
                dtype, data = rpc.reg_query(item["hive"], item["key"], item["value"])
                if data is not None:
                    data_str = self._decode_reg_value(dtype, data)
                    rows.append((
                        "{}\\{}".format(item["hive"], item["value"]),
                        data_str,
                        item["desc"],
                    ))
                    results.append({**item, "data": data_str})
                    # Detectar hallazgos críticos
                    self._check_finding(item, data_str)

            if rows:
                print_table(
                    "Valores de registro interesantes ({})".format(len(rows)),
                    ["Clave\\Valor", "Dato", "Descripción"],
                    rows,
                )
            else:
                console.print("[yellow]No se pudieron leer claves de registro "
                              "(¿RemoteRegistry activo? ¿permisos suficientes?)[/yellow]")

            return results
        finally:
            rpc.disconnect()

    def _decode_reg_value(self, dtype, data):
        """Decodifica un valor de registro a string legible."""
        try:
            if isinstance(data, (bytes, bytearray)):
                # REG_SZ / REG_EXPAND_SZ (1, 2) → UTF-16LE
                if dtype in (1, 2):
                    return data.decode("utf-16-le", errors="replace").rstrip("\x00")
                # REG_DWORD (4)
                if dtype == 4 and len(data) >= 4:
                    import struct
                    return str(struct.unpack_from("<I", data)[0])
                # REG_QWORD (11)
                if dtype == 11 and len(data) >= 8:
                    import struct
                    return str(struct.unpack_from("<Q", data)[0])
                # Fallback hex
                return data[:32].hex()
            return str(data)
        except Exception:
            return repr(data)[:60]

    def _check_finding(self, item, data_str):
        """Detecta valores de registro peligrosos y lanza alertas."""
        value = item["value"].lower()
        try:
            num = int(data_str)
        except (ValueError, TypeError):
            num = None

        alerts = {
            "lmcompatibilitylevel": (
                num is not None and num < 3,
                "NTLMv1 permitido (LmCompatibilityLevel={}) → downgrade + captura".format(data_str),
            ),
            "nolmhash": (
                num == 0,
                "LM hashes almacenados en SAM (crackeable con john/hashcat)",
            ),
            "restrictanonymous": (
                num == 0,
                "Null session permitida por registro",
            ),
            "requiresecuritysignature": (
                num == 0,
                "SMB signing NO obligatorio → relay posible",
            ),
            "enablelua": (
                num == 0,
                "UAC desactivado → privesc directa sin prompt",
            ),
            "uselogoncredential": (
                num == 1,
                "WDigest activo → credenciales en claro en LSASS (Mimikatz)",
            ),
            "defaultpassword": (
                bool(data_str and data_str not in ("", "(null)")),
                "Autologon password en claro: {}".format(data_str),
            ),
        }

        key_check = alerts.get(value.lower())
        if key_check and key_check[0]:
            print_result("RPC", str(self.target.ip), "pwned", key_check[1])
            session_db.save_finding(
                str(self.target.ip), "RPC", "registry_finding", key_check[1],
            )
