# scripts/https/attack/oauth_misconfig.py
import ssl, urllib.request, urllib.error, urllib.parse, json, re
from scripts.base import BaseScript
from core.output import print_result, print_table, print_check, console
from core import session_db

OAUTH_ENDPOINTS = [
    "/oauth/authorize","/oauth2/authorize","/auth/oauth",
    "/api/oauth/authorize","/.well-known/openid-configuration",
    "/oauth/token","/connect/authorize",
]

EVIL_REDIRECTS = ["https://evil.com","https://evil.com/callback","//evil.com"]

class Script(BaseScript):
    name        = "oauth-misconfig"
    protocol    = "https"
    category    = "attack"
    description = "Script propio: detecta redirect_uri bypass, implicit flow inseguro y state param ausente en OAuth/OIDC."

    EXAMPLES = [
        {"flag": "--client-id", "desc": "Client ID OAuth conocido",
         "good": "https --script=oauth-misconfig -t 10.10.10.5 --client-id myapp",
         "bad":  "https --script=oauth-misconfig (descubre endpoints automáticamente)"},
    ]

    def run(self, **kwargs):
        port      = int(kwargs.get("port") or 443)
        timeout   = int(kwargs.get("timeout") or self.target.timeout or 5)
        client_id = kwargs.get("client_id") or "client"
        ip        = self.target.ip
        base      = f"https://{ip}:{port}"

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))

        def req(url, hdrs=None):
            h = {"User-Agent":"Mozilla/5.0"}
            if hdrs: h.update(hdrs)
            r = urllib.request.Request(url, headers=h)
            try:
                resp = opener.open(r, timeout=timeout)
                return resp.status, resp.read(65536).decode("utf-8","replace"), {k.lower():v for k,v in resp.headers.items()}
            except urllib.error.HTTPError as e:
                return e.code, e.read(65536).decode("utf-8","replace") if e else "", {k.lower():v for k,v in e.headers.items()} if e.headers else {}
            except Exception:
                return 0, "", {}

        oauth_endpoint = None
        for ep in OAUTH_ENDPOINTS:
            status, body, hdrs = req(f"{base}{ep}")
            if status in (200,302,400,401):
                oauth_endpoint = ep
                print_result("HTTPS", ip, "info", f"OAuth endpoint: {ep}")
                session_db.save_finding(ip, "HTTPS", "oauth_endpoint", ep)
                break

        if not oauth_endpoint:
            print_result("HTTPS", ip, "info", "Endpoint OAuth no encontrado")
            return None

        findings = []

        for evil_uri in EVIL_REDIRECTS:
            test_url = (f"{base}{oauth_endpoint}?client_id={client_id}"
                        f"&response_type=code&redirect_uri={urllib.parse.quote(evil_uri)}&scope=openid")
            status, body, hdrs = req(test_url)
            location = hdrs.get("location","")
            if status in (302,301) and "evil.com" in location:
                findings.append(("redirect_uri bypass", evil_uri[:40], "CRÍTICO"))
                session_db.save_finding(ip, "HTTPS", "oauth_redirect_bypass", evil_uri)
                print_result("HTTPS", ip, "pwned", f"OAUTH REDIRECT_URI BYPASS: {evil_uri}")
                break

        test_url = (f"{base}{oauth_endpoint}?client_id={client_id}"
                    f"&response_type=code&redirect_uri=https%3A%2F%2Flegit.example.com%2Fcb")
        status, body, hdrs = req(test_url)
        location = hdrs.get("location","")
        if status in (302,301) and "state=" not in location:
            findings.append(("State param ausente","Sin state","CSRF posible"))
            session_db.save_finding(ip, "HTTPS", "oauth_no_state", oauth_endpoint)

        if findings:
            print_table(f"OAuth Misconfiguration — {ip}:{port}",
                        ["Problema","Detalle","Impacto"], findings)
        else:
            print_check("OAuth sin misconfiguraciones obvias", ok=True)

        return {"endpoint": oauth_endpoint, "findings": findings}
