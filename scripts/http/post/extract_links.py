# scripts/http/post/extract_links.py
import urllib.request, urllib.error, re
from scripts.base import BaseScript
from core.output import print_result, print_table, console
from core import session_db

class Script(BaseScript):
    name        = "extract-links"
    protocol    = "http"
    category    = "post"
    description = "Extrae todos los links, formularios y endpoints de la aplicación HTTP."

    EXAMPLES = [
        {"flag": "-t / --port / --path", "desc": "IP, puerto y ruta inicial",
         "good": "http --script=extract-links -t 10.10.10.5 --port 80 --path /",
         "bad":  "http --script=extract-links (sin -t)"},
    ]

    def run(self, **kwargs):
        port    = int(kwargs.get("port") or 80)
        timeout = int(kwargs.get("timeout") or self.target.timeout or 5)
        path    = kwargs.get("path") or "/"
        ip      = self.target.ip
        base    = f"http://{ip}:{port}"
        url     = f"{base}{path}"

        try:
            req  = urllib.request.Request(url, headers={"User-Agent":"Mozilla/5.0"})
            resp = urllib.request.urlopen(req, timeout=timeout)
            body = resp.read(1024 * 1024).decode("utf-8", errors="replace")
        except Exception as e:
            print_result("HTTP", ip, "fail", f"error: {e}")
            return None

        links  = re.findall(r'href=["\']([^"\']+)["\']', body, re.I)
        srcs   = re.findall(r'src=["\']([^"\']+)["\']', body, re.I)
        forms  = re.findall(r'<form[^>]+action=["\']([^"\']*)["\']', body, re.I)
        apis   = re.findall(r'(?:fetch|axios)\(["\']([^"\']+)["\']', body, re.I)

        internal = []
        external = []
        for link in links + srcs + forms + apis:
            if link.startswith(("http://","https://")) and ip not in link:
                external.append(link)
            elif link and not link.startswith(("#","javascript:","mailto:")):
                full = link if link.startswith("http") else f"{base}{link if link.startswith('/') else '/'+link}"
                internal.append(full)

        internal = sorted(set(internal))
        external = sorted(set(external))
        api_eps  = [l for l in internal if any(kw in l for kw in ["/api/","/v1/","/v2/","/graphql","/rest/"])]

        print_result("HTTP", ip, "info",
                     f"{len(internal)} internos, {len(external)} externos, {len(api_eps)} API")

        if internal:
            print_table(f"Links internos — {ip}:{port}",
                        ["URL"], [(l,) for l in internal[:20]])
        if api_eps:
            print_result("HTTP", ip, "pwned", f"API endpoints: {', '.join(api_eps[:3])}")
            for ep in api_eps:
                session_db.save_finding(ip, "HTTP", "api_endpoint", ep)

        return {"internal": internal, "external": external, "api": api_eps}
