# scripts/http/attack/graphql_enum.py
import urllib.request, urllib.error, json
from scripts.base import BaseScript
from core.output import print_result, print_table, print_check, console
from core import session_db

GRAPHQL_ENDPOINTS = [
    "/graphql","/api/graphql","/graphql/console",
    "/graphiql","/graphql/playground","/api/v1/graphql",
    "/gql","/query",
]

INTROSPECTION = '{"query":"{ __schema { queryType { name } types { name kind } } }"}'

DANGEROUS_TYPES = ["User","Admin","Password","Secret","Token","Key",
                   "Auth","Session","Permission","Role","Credential"]

class Script(BaseScript):
    name        = "graphql-enum"
    protocol    = "http"
    category    = "attack"
    description = "Script propio: descubre endpoints GraphQL, lanza introspección y detecta tipos peligrosos sin auth."

    EXAMPLES = [
        {"flag": "--path", "desc": "Endpoint GraphQL (default: prueba rutas comunes)",
         "good": "http --script=graphql-enum -t 10.10.10.5 --path /graphql",
         "bad":  "http --script=graphql-enum (prueba rutas automáticamente)"},
    ]

    def run(self, **kwargs):
        port    = int(kwargs.get("port") or 80)
        timeout = int(kwargs.get("timeout") or self.target.timeout or 5)
        path    = kwargs.get("path")
        ip      = self.target.ip
        base    = f"http://{ip}:{port}"
        endpoints = [path] if path else GRAPHQL_ENDPOINTS
        graphql_url = None

        for ep in endpoints:
            url = f"{base}{ep}"
            try:
                req = urllib.request.Request(url, headers={
                    "User-Agent":   "Mozilla/5.0",
                    "Content-Type": "application/json",
                }, method="POST")
                req.data = INTROSPECTION.encode()
                try:
                    resp = urllib.request.urlopen(req, timeout=timeout)
                    body = resp.read(65536).decode("utf-8", errors="replace")
                except urllib.error.HTTPError as e:
                    body = e.read(65536).decode("utf-8", errors="replace") if e else ""
                if "__schema" in body or "queryType" in body:
                    graphql_url = url
                    print_result("HTTP", ip, "pwned", f"GraphQL con introspección: {ep}")
                    session_db.save_finding(ip, "HTTP", "graphql_introspection", ep)
                    break
            except Exception:
                pass

        if not graphql_url:
            print_result("HTTP", ip, "info", "GraphQL no encontrado")
            return None

        findings = []
        try:
            req = urllib.request.Request(graphql_url, headers={
                "User-Agent":"Mozilla/5.0","Content-Type":"application/json"}, method="POST")
            req.data = INTROSPECTION.encode()
            resp = urllib.request.urlopen(req, timeout=timeout)
            data = json.loads(resp.read(512*1024).decode())
            types = data.get("data",{}).get("__schema",{}).get("types",[])
            type_names = [t.get("name","") for t in types if t.get("name")]
            dangerous  = [t for t in type_names
                          if any(d.lower() in t.lower() for d in DANGEROUS_TYPES)]
            if dangerous:
                for d in dangerous:
                    findings.append((d, "Tipo sensible expuesto"))
                    session_db.save_finding(ip, "HTTP", "graphql_sensitive_type", d)
                print_result("HTTP", ip, "pwned", f"Tipos sensibles: {', '.join(dangerous)}")
            print_table(f"GraphQL Types — {ip}:{port}",
                        ["Tipo","Observación"],
                        [(t, "⚠ sensible" if t in dangerous else "normal") for t in type_names[:30]])
        except Exception as e:
            print_result("HTTP", ip, "fail", f"error schema: {e}")

        return {"endpoint": graphql_url, "findings": findings}
