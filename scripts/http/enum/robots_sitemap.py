# scripts/http/enum/robots_sitemap.py
import urllib.request, urllib.error, re
from scripts.base import BaseScript
from core.output import print_result, print_table, console
from core import session_db

INTERESTING_PATHS = [
    "admin","administrator","login","wp-admin","phpmyadmin",
    "backup","config","secret","private","api","dev",
    "test",".git",".env","dashboard","panel",
]

class Script(BaseScript):
    name        = "robots-sitemap"
    protocol    = "http"
    category    = "enum"
    description = "Parsea robots.txt y sitemap.xml buscando rutas ocultas, paneles de admin y endpoints sensibles."

    EXAMPLES = [
        {"flag": "-t / --port", "desc": "IP y puerto",
         "good": "http --script=robots-sitemap -t 10.10.10.5 --port 80",
         "bad":  "http --script=robots-sitemap (sin -t)"},
    ]

    def run(self, **kwargs):
        port    = int(kwargs.get("port") or 80)
        timeout = int(kwargs.get("timeout") or self.target.timeout or 5)
        ip      = self.target.ip
        base    = f"http://{ip}:{port}"

        all_paths   = []
        interesting = []

        try:
            req  = urllib.request.Request(f"{base}/robots.txt",
                                          headers={"User-Agent": "Mozilla/5.0"})
            resp = urllib.request.urlopen(req, timeout=timeout)
            if resp.status == 200:
                content = resp.read(65536).decode("utf-8", errors="replace")
                print_result("HTTP", ip, "info", "robots.txt encontrado")
                for line in content.splitlines():
                    line = line.strip()
                    if line.lower().startswith(("disallow:","allow:","sitemap:")):
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            directive = parts[0].strip()
                            path      = parts[1].strip()
                            all_paths.append((directive, path))
                            if any(kw in path.lower() for kw in INTERESTING_PATHS):
                                interesting.append(path)
        except Exception:
            print_result("HTTP", ip, "info", "robots.txt no accesible")

        for sitemap_url in [f"{base}/sitemap.xml", f"{base}/sitemap_index.xml"]:
            try:
                req  = urllib.request.Request(sitemap_url, headers={"User-Agent": "Mozilla/5.0"})
                resp = urllib.request.urlopen(req, timeout=timeout)
                if resp.status == 200:
                    content = resp.read(512 * 1024).decode("utf-8", errors="replace")
                    urls = re.findall(r'<loc>(.*?)</loc>', content)
                    print_result("HTTP", ip, "info", f"sitemap.xml: {len(urls)} URLs")
                    for u in urls[:50]:
                        all_paths.append(("sitemap", u))
                        if any(kw in u.lower() for kw in INTERESTING_PATHS):
                            interesting.append(u)
                    break
            except Exception:
                pass

        if all_paths:
            print_table(f"robots.txt / sitemap — {ip}:{port}", ["Directiva", "Ruta"], all_paths[:50])

        if interesting:
            print_result("HTTP", ip, "pwned", f"Rutas interesantes: {', '.join(interesting[:5])}")
            for p in interesting:
                session_db.save_finding(ip, "HTTP", "interesting_path", p)

        return {"paths": all_paths, "interesting": interesting}
