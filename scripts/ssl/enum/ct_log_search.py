# scripts/ssl/enum/ct_log_search.py
import json, urllib.request, urllib.parse
from scripts.base import BaseScript
from core.output import print_result, print_table, console
from core import session_db

class Script(BaseScript):
    name        = "ct-log-search"
    protocol    = "ssl"
    category    = "enum"
    description = "Busca en Certificate Transparency logs (crt.sh) todos los certificados del dominio. Descubre subdominios ocultos, entornos de staging y APIs no públicas."

    EXAMPLES = [
        {"flag": "--domain", "desc": "Dominio a buscar en CT logs",
         "good": "ssl --script=ct-log-search -t 10.10.10.5 --domain ejemplo.com",
         "bad":  "ssl --script=ct-log-search -t 10.10.10.5 (sin --domain)"},
    ]

    CT_API = "https://crt.sh/?q={}&output=json"

    INTERESTING_KW = [
        "dev","staging","test","admin","api","internal",
        "vpn","mail","jenkins","gitlab","jira","confluence",
        "backup","prod","db","database","ssh","ftp",
    ]

    def run(self, **kwargs):
        domain   = kwargs.get("domain") or self.target.domain or self.target.ip
        wildcard = kwargs.get("wildcard", True)
        timeout  = int(kwargs.get("timeout") or 10)
        ip       = self.target.ip

        if not domain or domain == ip:
            console.print("[yellow]Especifica --domain (ej: set domain ejemplo.com)[/yellow]")
            return None

        queries = [domain]
        if wildcard:
            queries.append(f"%.{domain}")

        all_entries = {}
        for query in queries:
            url = self.CT_API.format(urllib.parse.quote(query))
            print_result("SSL", ip, "info", f"consultando CT logs: {query}")
            try:
                req  = urllib.request.Request(url, headers={"User-Agent": "Lobera/1.0"})
                resp = urllib.request.urlopen(req, timeout=timeout)
                data = json.loads(resp.read().decode())
                for entry in data:
                    for sub in entry.get("name_value","").split("\n"):
                        sub = sub.strip().lower()
                        if sub and sub not in all_entries:
                            all_entries[sub] = {
                                "issuer":     entry.get("issuer_name","?"),
                                "not_after":  entry.get("not_after","?"),
                            }
            except Exception as e:
                print_result("SSL", ip, "fail", f"error CT logs: {e}")

        if not all_entries:
            print_result("SSL", ip, "info", "Sin entradas en CT logs")
            return []

        wildcards    = sorted([s for s in all_entries if s.startswith("*")])
        subdomains   = sorted([s for s in all_entries if not s.startswith("*") and s != domain])
        interesting  = [s for s in subdomains if any(kw in s for kw in self.INTERESTING_KW)]

        rows = [(name, e["not_after"][:10], e["issuer"][:40])
                for name, e in sorted(all_entries.items())]
        print_table(f"CT Logs — {domain} ({len(all_entries)} entradas)",
                    ["Nombre", "Expira", "Emisor"], rows)

        if interesting:
            print_result("SSL", ip, "pwned",
                         f"Subdominios interesantes: {', '.join(interesting)}")
            for s in interesting:
                session_db.save_finding(ip, "SSL", "ct_interesting_subdomain", s)

        print_result("SSL", ip, "info",
                     f"{len(all_entries)} certificados | {len(wildcards)} wildcards | "
                     f"{len(subdomains)} subdominios | {len(interesting)} interesantes")

        for name in all_entries:
            session_db.save_finding(ip, "SSL", "ct_subdomain", name)

        return list(all_entries.keys())
