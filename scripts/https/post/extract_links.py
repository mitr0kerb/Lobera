# scripts/https/post/extract_links.py
import ssl, urllib.request, urllib.error, re
from scripts.base import BaseScript
from core.output import print_result, print_table, console
from core import session_db

class Script(BaseScript):
    name        = "extract-links"
    protocol    = "https"
    category    = "post"
    description = "Extrae todos los links, formularios y endpoints de la aplicación HTTPS."

    EXAMPLES = [
        {"flag": "-t / --port / --path", "desc": "IP, puerto y ruta",
         "good": "https --script=extract-links -t 10.10.10.5 --port 443",
         "bad":  "https --script=extract-links (sin -t)"},
    ]

    def run(self, **kwargs):
        port    = int(kwargs.get("port") or 443)
        timeout = int(kwargs.get("timeout") or self.target.timeout or 5)
        path    = kwargs.get("path") or "/"
        ip      = self.target.ip
        base    = f"https://{ip}:{port}"
        url     = f"{base}{path}"

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))

        try:
            req  = urllib.request.Request(url, headers={"User-Agent":"Mozilla/5.0"})
            resp = opener.open(req, timeout=timeout)
            body = resp.read(1024*1024).decode("utf-8", errors="replace")
        except Exception as e:
            print_result("HTTPS", ip, "fail", f"error: {e}")
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

        print_result("HTTPS", ip, "info",
                     f"{len(internal)} internos, {len(external)} externos, {len(api_eps)} API")
        if internal:
            print_table(f"Links HTTPS — {ip}:{port}", ["URL"], [(l,) for l in internal[:20]])
        if api_eps:
            print_result("HTTPS", ip, "pwned", f"API: {', '.join(api_eps[:3])}")
            for ep in api_eps:
                session_db.save_finding(ip, "HTTPS", "api_endpoint", ep)

        return {"internal": internal, "external": external, "api": api_eps}
