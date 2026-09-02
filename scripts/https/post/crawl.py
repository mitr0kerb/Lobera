# scripts/https/post/crawl.py
import ssl, urllib.request, urllib.error, re
from scripts.base import BaseScript
from core.output import print_result, print_table, console
from core import session_db

class Script(BaseScript):
    name        = "crawl"
    protocol    = "https"
    category    = "post"
    description = "Script propio: spider recursivo sobre HTTPS. Mapea estructura, rutas y parámetros."

    EXAMPLES = [
        {"flag": "--max-depth / --max-pages", "desc": "Profundidad y límite",
         "good": "https --script=crawl -t 10.10.10.5 --max-depth 3 --max-pages 50",
         "bad":  "https --script=crawl --max-depth 10 (puede tardar mucho)"},
    ]

    def run(self, **kwargs):
        port      = int(kwargs.get("port") or 443)
        timeout   = int(kwargs.get("timeout") or self.target.timeout or 5)
        start     = kwargs.get("path") or "/"
        max_depth = int(kwargs.get("max_depth") or 3)
        max_pages = int(kwargs.get("max_pages") or 30)
        ip        = self.target.ip
        base      = f"https://{ip}:{port}"

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        opener  = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
        visited = set()
        queue   = [(f"{base}{start}", 0)]
        found   = []
        forms   = []
        params  = set()

        print_result("HTTPS", ip, "info",
                     f"crawl HTTPS: max_depth={max_depth} max_pages={max_pages}")

        while queue and len(visited) < max_pages:
            url, depth = queue.pop(0)
            if url in visited or depth > max_depth:
                continue
            visited.add(url)
            try:
                req = urllib.request.Request(url, headers={
                    "User-Agent":"Mozilla/5.0","Connection":"close"})
                try:
                    resp   = opener.open(req, timeout=timeout)
                    status = resp.status
                    body   = resp.read(512*1024).decode("utf-8", errors="replace")
                except urllib.error.HTTPError as e:
                    status = e.code; body = ""

                path_part = url.replace(base,"") or "/"
                found.append((path_part, str(status)))

                if status == 200 and body:
                    for match in re.finditer(r'href=["\']([^"\']+)["\']', body, re.I):
                        href = match.group(1)
                        if href.startswith("/"):
                            next_url = f"{base}{href.split('?')[0]}"
                            if next_url not in visited: queue.append((next_url, depth+1))
                        elif href.startswith(base):
                            if href not in visited: queue.append((href.split('?')[0], depth+1))

                    for match in re.finditer(r'<form[^>]+>', body, re.I):
                        tag    = match.group(0)
                        action = re.search(r'action=["\']([^"\']*)["\']', tag, re.I)
                        method = re.search(r'method=["\']([^"\']*)["\']', tag, re.I)
                        if action:
                            forms.append((action.group(1)[:50],
                                          method.group(1) if method else "GET",
                                          path_part))

                    for p in re.findall(r'name=["\']([^"\']+)["\']', body, re.I):
                        params.add(p)
            except Exception:
                pass

        print_result("HTTPS", ip, "info",
                     f"crawl: {len(found)} pág., {len(forms)} forms, {len(params)} params")
        if found:
            print_table(f"Mapa HTTPS — {ip}:{port}", ["Ruta","Código"], found[:30])
        if forms:
            print_table(f"Formularios HTTPS — {ip}:{port}", ["Action","Método","Página"], forms[:15])
        if params:
            print_result("HTTPS", ip, "info", f"Params: {', '.join(sorted(params)[:20])}")
            session_db.save_finding(ip, "HTTPS", "crawl_params", ", ".join(sorted(params)[:30]))

        for path_part, _ in found:
            session_db.save_finding(ip, "HTTPS", "crawled_url", f"{base}{path_part}")

        return {"pages": found, "forms": forms, "params": list(params)}
